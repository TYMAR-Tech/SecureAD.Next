using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Reflection;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

public sealed class LdapDirectoryChannelCancellationTests
{
    [Fact]
    public async Task CancellationBeforeCompletionReturnsTheCallersCancellationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var ldap = new OfflineSearch();
        using var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        cancellation.Cancel();

        var failure = await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal(cancellation.Token, Assert.IsAssignableFrom<OperationCanceledException>(failure).CancellationToken);
    }

    [Fact]
    public async Task CancellationConsumesOnlyAbortEvenWhenCompletionSignalsAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var ldap = new OfflineSearch();
        using var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        cancellation.Cancel();
        await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Equal(["Begin", "Abort"], ldap.Operations);
    }

    [Fact]
    public async Task CancellationWhileStartingStillAbortsTheReturnedOperationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var ldap = new OfflineSearch { OnBegin = cancellation.Cancel };
        using var channel = ldap.Connect();

        await Record.ExceptionAsync(() => channel.SendAsync(new SearchRequest(), cancellation.Token));

        Assert.Equal(["Begin", "Abort"], ldap.Operations);
    }

    [Fact]
    public async Task AnAlreadyCancelledCallDoesNotStartASearchAsync()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var ldap = new OfflineSearch();
        using var channel = ldap.Connect();

        await Record.ExceptionAsync(() => channel.SendAsync(new SearchRequest(), cancellation.Token));

        Assert.Empty(ldap.Operations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationInsideCompletionCannotAbortTheConsumedOperationAsync(bool alreadyCompleted)
    {
        using var cancellation = new CancellationTokenSource();
        var ldap = new OfflineSearch { OnEnd = cancellation.Cancel, CompleteOnBegin = alreadyCompleted };
        using var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        ldap.Complete();
        await sending.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(["Begin", "End"], ldap.Operations);
    }

    [Fact]
    public async Task CancellationDoesNotReturnBeforeAbortedResponseProcessingFinishesAsync()
    {
        // Cancel on the default scheduler without the runner's synchronization context.
        // WaitAsync's cancellation continuation runs inline there, so Cancel returning
        // has reached either the drain await or the deliberately mutated early return.
        var returnedBeforeDrain = await Task.Run(async () =>
        {
            using var cancellation = new CancellationTokenSource();
            var ldap = new OfflineSearch { CompleteOnAbort = false };
            using var channel = ldap.Connect();
            var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

            cancellation.Cancel();
            var returned = sending.IsCompleted;
            ldap.Complete();
            await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));
            return returned;
        });

        Assert.False(returnedBeforeDrain);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CompletionPreservesTheDirectoryErrorEvenWhenCancellationArrivesAsync(bool serverError)
    {
        using var cancellation = new CancellationTokenSource();
        var failure = DirectoryFailure(serverError);
        var ldap = new OfflineSearch { OnEnd = cancellation.Cancel, EndFailure = failure };
        using var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        ldap.Complete();
        var observed = await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Same(failure, observed);
    }

    [Fact]
    public async Task AnAbortFailureIsNotHiddenAsCancellationAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var failure = new InvalidOperationException("Synthetic abort failure.");
        var ldap = new OfflineSearch { AbortFailure = failure };
        using var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        cancellation.Cancel();
        var observed = await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));

        Assert.Same(failure, observed);
    }

    [Fact]
    public async Task ACancelledChannelStillDisposesItsConnectionAsync()
    {
        using var cancellation = new CancellationTokenSource();
        var ldap = new OfflineSearch();
        var channel = ldap.Connect();
        var sending = channel.SendAsync(new SearchRequest(), cancellation.Token);

        cancellation.Cancel();
        await Record.ExceptionAsync(() => sending.WaitAsync(TimeSpan.FromSeconds(10)));
        channel.Dispose();

        Assert.Throws<ObjectDisposedException>(() => ldap.Connection.SessionOptions.ProtocolVersion);
    }

    private static DirectoryException DirectoryFailure(bool serverError) => serverError
        ? ServerResultFailure.AnsweredWith(ResultCode.Busy, "Synthetic busy response.")
        : new LdapException(81, "Synthetic connection loss.");

    private sealed class OfflineSearch
    {
        // Protocols 9.0.0 LdapConnection.cs: Abort and EndSendRequest both remove the
        // async-result table entry; ResponseCallback signals even after Abort. The model
        // deliberately rejects a second consumer instead of making a broken race harmless.
        private readonly TaskCompletionSource _responseFinished = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _consumed;
        private LdapConnection? _connection;
        public bool CompleteOnBegin { get; init; }
        public bool CompleteOnAbort { get; init; } = true;
        public Action OnBegin { get; init; } = () => { };
        public Action OnEnd { get; init; } = () => { };
        public DirectoryException? EndFailure { get; init; }
        public InvalidOperationException? AbortFailure { get; init; }
        public ConcurrentQueue<string> Operations { get; } = new();
        public LdapConnection Connection => _connection ?? throw new InvalidOperationException("No connection was created.");

        public IDirectoryChannel Connect() => new LdapDirectoryChannelFactory(
            DirectoryConnectionSettings.Default, new ConnectionSecurityLog(),
            connection => _connection = connection,
            (_, _) => RootDse(), Begin, End, Abort).Connect("dc.example.invalid").Value;

        public void Complete() => _responseFinished.TrySetResult();

        private IAsyncResult Begin(LdapConnection connection, SearchRequest request)
        {
            Operations.Enqueue("Begin");
            OnBegin();
            if (CompleteOnBegin)
                Complete();
            return _responseFinished.Task;
        }

        private DirectoryResponse End(LdapConnection connection, IAsyncResult pending)
        {
            Consume("End", pending);
            OnEnd();
            if (EndFailure is not null)
                throw EndFailure;
            return ServerResultFailure.AnsweredWith(ResultCode.Success, "").Response;
        }

        private void Abort(LdapConnection connection, IAsyncResult pending)
        {
            try
            {
                Consume("Abort", pending);
                if (AbortFailure is not null)
                    throw AbortFailure;
            }
            finally
            {
                if (CompleteOnAbort)
                    Complete();
            }
        }

        private void Consume(string operation, IAsyncResult pending)
        {
            Operations.Enqueue(operation);
            if (!ReferenceEquals(pending, _responseFinished.Task) || Interlocked.Exchange(ref _consumed, 1) != 0)
                throw new ArgumentException("Invalid asynchronous result.", nameof(pending));
        }

        private static SearchResponse RootDse()
        {
            // Only Microsoft's wire-response constructors are reflected; product internals
            // are not involved, and no bind or search reaches a network.
            var response = (SearchResponse)ServerResultFailure.AnsweredWith(ResultCode.Success, "").Response;
            var attributes = Assert.IsType<SearchResultAttributeCollection>(Activator.CreateInstance(
                typeof(SearchResultAttributeCollection), nonPublic: true));
            var add = typeof(SearchResultAttributeCollection).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(add);
            add.Invoke(attributes, ["supportedControl", new DirectoryAttribute("supportedControl", "1.2.840.113556.1.4.1339")]);
            add.Invoke(attributes, ["namingContexts", new DirectoryAttribute("namingContexts", "DC=example,DC=invalid")]);
            var entry = Activator.CreateInstance(typeof(SearchResultEntry), BindingFlags.Instance | BindingFlags.NonPublic,
                binder: null, ["", attributes], culture: null);
            var addEntry = typeof(SearchResultEntryCollection).GetMethod("Add", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(addEntry);
            addEntry.Invoke(response.Entries, [entry]);
            return response;
        }
    }
}

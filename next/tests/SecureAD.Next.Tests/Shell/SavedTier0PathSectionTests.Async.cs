using System.Windows.Threading;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    [Fact]
    public async Task P246LoadingDoesNotClaimQuestionsAreAbsent()
    {
        var section = Read(Saved());
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, (_, _, _) => pending.Task);
        section.Read();
        Assert.Equal(("Loading and validating saved results...", "Saved results have not been read.", 0, ""),
            (section.Result, section.AutomaticChecks, Steps(section).Count, section.Provenance));
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await section.ReadCompletion;
    }

    [Fact]
    public async Task P246AsyncCompletionDisplaysTheSameProof()
    {
        var saved = Saved();
        var expected = Read(saved);
        var section = Section();
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, (_, _, _) => pending.Task);
        section.Read();
        pending.SetResult(Result<SavedTier0Path?>.Success(saved));
        await section.ReadCompletion;
        Assert.Equal((expected.Result, expected.Provenance, expected.AutomaticChecks, expected.Severity),
            (section.Result, section.Provenance, section.AutomaticChecks, section.Severity));
        Assert.Equal(Questions(expected).SelectMany(value => value.RecordDetails), Questions(section).SelectMany(value => value.RecordDetails));
        Assert.Equal(Steps(expected), Steps(section));
        Assert.NotEmpty(Steps(section));
        Assert.Contains(saved.Description.GenerationId.ToString(), section.Provenance);
        Assert.Equal(expected.Limitations, section.Limitations);
    }

    [Fact]
    public async Task P246CancellationRejectsLateSuccessEvenWhenSourceIgnoresToken()
    {
        var section = Section();
        var pending = PendingPath();
        CancellationToken observed = default;
        section.ConfigureAsync(UserDn, (_, _, token) => { observed = token; return pending.Task; });
        section.Read();
        var completion = section.ReadCompletion;
        section.CancelRead();
        Assert.True(observed.IsCancellationRequested);
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await completion;
        Assert.Equal(("Saved results have not been read.", 0, ""), (section.Result, Steps(section).Count, section.Provenance));
    }

    [Fact]
    public async Task P246RebindingDoesNotPublishThePreviousGeneration()
    {
        var section = Section();
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, (_, _, _) => pending.Task);
        section.Read();
        var first = section.ReadCompletion;
        var replacement = Saved();
        section.ConfigureAsync(UserDn, (_, _, _) => Task.FromResult(Result<SavedTier0Path?>.Success(replacement)));
        section.Read();
        await section.ReadCompletion;
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await first;
        Assert.Contains(replacement.Description.GenerationId.ToString(), section.Provenance);
    }

    [Fact]
    public async Task P246SectionNavigationCancelsAndReselectionReadsFresh()
    {
        var source = Source();
        var screen = OpenScreen(source);
        var first = new PendingNavigationRead();
        var second = new PendingNavigationRead();
        source.CompleteRead = first.Hold;
        screen.Opened!.Show(ObjectSectionCatalog.SavedTier0Path);
        var originalCompletion = screen.Opened.ReadCompletion;
        source.CompleteRead = null;
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        Assert.True(first.Token.IsCancellationRequested);
        source.CompleteRead = second.Hold;
        screen.Opened.Show(ObjectSectionCatalog.SavedTier0Path);
        Assert.Equal(2, source.PathQueries.Count);
        second.Release();
        await screen.Opened.ReadCompletion;
        first.Release();
        await originalCompletion;
        var section = Assert.IsType<SavedTier0PathSectionViewModel>(screen.Opened.Selected);
        Assert.Contains(source.SavedPath.Value!.Description.GenerationId.ToString(), section.Provenance);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task P246ChangingObjectOrRunCancelsThePreviousRead(bool changeRun)
    {
        var source = Source();
        var screen = OpenScreen(source);
        var pending = new PendingNavigationRead();
        source.CompleteRead = pending.Hold;
        screen.Opened!.Show(ObjectSectionCatalog.SavedTier0Path);
        var section = Assert.IsType<SavedTier0PathSectionViewModel>(screen.Opened.Selected);
        var completion = screen.Opened.ReadCompletion;
        source.CompleteRead = null;
        if (changeRun) screen.Show(@"C:\synthetic-runs\other", false);
        else screen.OpenObject(new(new(UserDn, "User", Guid.NewGuid(), "user", "DC=contoso,DC=com")));
        Assert.True(pending.Token.IsCancellationRequested);
        pending.Release();
        await completion;
        Assert.Equal("Saved results have not been read.", section.Result);
    }

    [Fact]
    public async Task P246LeavingTheAssetsPaneCancelsAndReturningReadsFresh()
    {
        var source = Source();
        var screen = OpenScreen(source);
        var pending = new PendingNavigationRead();
        source.CompleteRead = pending.Hold;
        screen.Opened!.Show(ObjectSectionCatalog.SavedTier0Path);
        var completion = screen.Opened.ReadCompletion;
        source.CompleteRead = null;
        screen.Pane = AssetsPane.Findings;
        Assert.True(pending.Token.IsCancellationRequested);
        pending.Release();
        await completion;
        screen.Pane = AssetsPane.Objects;
        await screen.ReadCompletion;
        var section = Assert.IsType<SavedTier0PathSectionViewModel>(screen.Opened.Selected);
        Assert.Equal(2, source.PathQueries.Count);
        Assert.Equal("SEC-071 — Unexpected route to Tier 0", section.Result);
    }

    private sealed class PendingNavigationRead
    {
        private readonly TaskCompletionSource<object> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private object? _value;
        internal CancellationToken Token { get; private set; }
        internal Task<object> Hold(object value, CancellationToken token)
        {
            _value = value;
            Token = token;
            return _completion.Task;
        }
        internal void Release() => _completion.SetResult(_value ?? throw new InvalidOperationException("No read is pending."));
    }

    [Fact]
    public async Task P246AsyncFailureIsUnavailableNotAnEmptySecurityAnswer()
    {
        var section = Section();
        section.ConfigureAsync(UserDn, (_, _, _) => Task.FromException<Result<SavedTier0Path?>>(new IOException("synthetic failure")));
        section.Read();
        await section.ReadCompletion;
        Assert.Equal("Saved result unavailable", section.Result);
        Assert.Contains("synthetic failure", section.Detail);
        Assert.Empty(Steps(section));
    }

    [Fact]
    public void P246AsyncPublicationReturnsToTheDispatcher() => OnPathSta(() =>
    {
        var section = Section();
        var pending = PendingPath();
        var thread = Environment.CurrentManagedThreadId;
        var notifications = new List<int>();
        section.PropertyChanged += (_, _) => notifications.Add(Environment.CurrentManagedThreadId);
        section.ConfigureAsync(UserDn, (_, _, _) => pending.Task);
        section.Read();
        var frame = new DispatcherFrame();
        var dispatcher = Dispatcher.CurrentDispatcher;
        _ = section.ReadCompletion.ContinueWith(_ => dispatcher.BeginInvoke(new Action(() => frame.Continue = false)), TaskScheduler.Default);
        _ = Task.Run(() => pending.SetResult(Result<SavedTier0Path?>.Success(Saved())));
        Dispatcher.PushFrame(frame);
        section.ReadCompletion.GetAwaiter().GetResult();
        Assert.Equal("SEC-071 — Unexpected route to Tier 0", section.Result);
        Assert.NotEmpty(notifications);
        Assert.All(notifications, id => Assert.Equal(thread, id));
    });

    private static TaskCompletionSource<Result<SavedTier0Path?>> PendingPath() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

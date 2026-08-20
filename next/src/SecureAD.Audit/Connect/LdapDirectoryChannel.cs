using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;

namespace SecureAD.Audit.Connect;

/// <summary>
/// A live connection to one domain controller: the implementation of the product's one seam onto a
/// customer's forest.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A2, and <c>docs/next/S-14-the-connection.md</c> is the document bound to it.
/// It is the other half of the seam inventory row B6 wrote and left open. Everything above it -
/// <see cref="PartitionCapture"/>, the paging loop, the range retrievals - was written against
/// <see cref="IDirectoryChannel"/> and exercised against a controller model. This is what puts a
/// real domain controller on the other end.
/// </para>
/// <para>
/// <b>It interprets nothing.</b> A result code that is not success is raised as an
/// <see cref="LdapException"/> carrying the controller's own code, because that is the shape the
/// platform's client produces and inventing a second one would mean translating twice. What that
/// code means - retry, restart the naming context, or stop - is <see cref="RetryPolicy"/>'s, and a
/// channel that quietly retried would be a second failure policy.
/// </para>
/// <para>
/// <b>One request at a time.</b> Nothing here fans work out, and
/// <c>SerializedDirectoryAccessGateTests</c> fails the build if anything in this project both
/// speaks to a directory and runs work in parallel. That is not politeness alone: the state a
/// controller keeps between the pages of a paged search comes out of one per-controller budget
/// which it relieves by discarding the oldest, so two reads at one server can truncate each other
/// silently.
/// </para>
/// </remarks>
public sealed class LdapDirectoryChannel : IDirectoryChannel
{
    private readonly LdapConnection _connection;
    private bool _disposed;

    internal LdapDirectoryChannel(
        LdapConnection connection,
        string domainController,
        ConnectionSecurityLevel securityLevel,
        IReadOnlyList<string> supportedControls,
        IReadOnlyList<string> namingContextsServed)
    {
        _connection = connection;
        DomainController = domainController;
        SecurityLevel = securityLevel;
        SupportedControls = supportedControls;
        NamingContextsServed = namingContextsServed;
    }

    /// <inheritdoc/>
    public string DomainController { get; }

    /// <summary>
    /// Which rung of the ladder this connection is on. Carried on the connection rather than
    /// looked up, because the answer belongs to this connection and not to the host.
    /// </summary>
    public ConnectionSecurityLevel SecurityLevel { get; }

    /// <summary>
    /// The partitions this controller says it serves, from the <c>namingContexts</c> attribute of
    /// its RootDSE.
    /// </summary>
    /// <remarks>
    /// Read here because it arrives in the same answer as the control list and costs nothing extra.
    /// What asks the question is <c>CaptureUnit.ConfirmServedBy</c>, from inventory row A8.
    /// </remarks>
    public IReadOnlyList<string> NamingContextsServed { get; }

    /// <inheritdoc/>
    public ReferralChasingOptions ReferralChasing
    {
        get { return _connection.SessionOptions.ReferralChasing; }
    }

    /// <inheritdoc/>
    public IReadOnlyList<string> SupportedControls { get; }

    /// <inheritdoc/>
    /// <remarks>
    /// True only where the RootDSE answered with at least one advertised control. A controller that
    /// advertises none does not exist, so an empty list means the question was not answered - and a
    /// capture pass refuses to run on a connection that cannot say.
    /// </remarks>
    public bool IsComplete
    {
        get { return SupportedControls.Count > 0; }
    }

    /// <inheritdoc/>
    public async Task<DirectoryPage> SendAsync(
        SearchRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        var response = await SendOneAsync(request, cancellationToken).ConfigureAwait(false);

        return ReadPage(response);
    }

    /// <summary>
    /// Sends one request and waits for the answer, cancelling the request itself rather than
    /// abandoning it.
    /// </summary>
    /// <remarks>
    /// A cancelled capture that left a request running would leave a controller building a page
    /// nobody will read, and the connection would then be closed under it. Aborting the pending
    /// operation is what the platform's client offers for exactly this.
    /// </remarks>
    private async Task<SearchResponse> SendOneAsync(
        SearchRequest request, CancellationToken cancellationToken)
    {
        var pending = _connection.BeginSendRequest(
            request, PartialResultProcessing.NoPartialResultSupport, callback: null, state: null);

        using var abort = cancellationToken.Register(() => _connection.Abort(pending));

        var response = await Task<DirectoryResponse>.Factory
            .FromAsync(pending, _connection.EndSendRequest)
            .ConfigureAwait(false);

        if (response is not SearchResponse search)
        {
            throw new LdapException(
                (int)ResultCode.ProtocolError,
                $"{DomainController} answered a search with a {response.GetType().Name}. An "
                + "answer that is not a search result cannot be read as one, and reading it as an "
                + "empty page would report a partition as finished.");
        }

        if (search.ResultCode != ResultCode.Success)
            throw new LdapException((int)search.ResultCode, search.ErrorMessage);

        return search;
    }

    /// <summary>
    /// Turns one answer into the three facts the capture loop acts on: the entries, whether there
    /// is more, and what the controller mentioned below what was searched.
    /// </summary>
    /// <remarks>
    /// The paging cookie is passed through as <c>null</c> where the response carried no paging
    /// control at all, because <see cref="DirectoryPage.From"/> is the one place that decides what
    /// the absence of a bookmark means - and it means two different things.
    /// </remarks>
    private static DirectoryPage ReadPage(SearchResponse response)
    {
        var entries = new List<LdapEntryReader>(response.Entries.Count);
        foreach (SearchResultEntry entry in response.Entries)
            entries.Add(LdapEntryReader.ForEntry(entry));

        byte[]? cookie = null;
        foreach (var control in response.Controls)
        {
            if (control is PageResultResponseControl paging)
            {
                cookie = paging.Cookie ?? [];
                break;
            }
        }

        // A reference is one or more LDAP URLs naming somewhere else the search would have gone.
        // Nothing is followed - referral chasing is off - but they are evidence, so every URL is
        // carried rather than the first of each.
        var references = new List<string>();
        foreach (SearchResultReference reference in response.References)
        {
            foreach (var url in reference.Reference)
                references.Add(url.ToString());
        }

        return DirectoryPage.From(entries, cookie, references);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _connection.Dispose();
    }
}

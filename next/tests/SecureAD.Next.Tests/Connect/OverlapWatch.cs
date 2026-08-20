using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Watches how many connections are open to each host at the same moment, so a test can state
/// whether two reads ever met on one controller.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the reads are made to linger.</b> Concurrency that is asserted by counting after the
/// fact proves nothing: work that happened to run one after another produces the same counts as
/// work that was forced to. So every connection opened here waits until the expected number of
/// connections is open, or until a short deadline passes. A pass that relies on serialization sees
/// the deadline and reports one at a time; a pass that runs together sees the others arrive and
/// reports the overlap. Both outcomes are reached deterministically rather than by timing.
/// </para>
/// <para>
/// <b>It counts the open channel, not the connect call.</b> A read is bracketed by opening the
/// channel and disposing it, so that is the window in which two requests could compete for one
/// controller's paged-search budget.
/// </para>
/// </remarks>
internal sealed class OverlapWatch : IDirectoryChannelFactory
{
    private readonly IDirectoryChannelFactory _forest;
    private readonly int _waitingFor;
    private readonly TimeSpan _deadline;
    private readonly object _tally = new();
    private readonly Dictionary<string, int> _openNow = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _mostAtOnce = new(StringComparer.OrdinalIgnoreCase);
    private readonly ManualResetEventSlim _enough = new(false);
    private int _openAnywhere;
    private int _mostAnywhere;

    /// <summary>
    /// Watches <paramref name="forest"/>, holding each connection open until
    /// <paramref name="waitingFor"/> are open or <paramref name="deadlineMilliseconds"/> passes.
    /// </summary>
    public OverlapWatch(
        IDirectoryChannelFactory forest, int waitingFor, int deadlineMilliseconds = 1000)
    {
        _forest = forest;
        _waitingFor = waitingFor;
        _deadline = TimeSpan.FromMilliseconds(deadlineMilliseconds);
    }

    /// <summary>The most connections that were ever open to one host at the same moment.</summary>
    public int MostAtOnceOn(string host)
    {
        lock (_tally)
        {
            return _mostAtOnce.TryGetValue(host, out var most) ? most : 0;
        }
    }

    /// <summary>The most connections that were ever open at the same moment, to any hosts.</summary>
    public int MostAtOnceAnywhere
    {
        get
        {
            lock (_tally)
            {
                return _mostAnywhere;
            }
        }
    }

    /// <inheritdoc/>
    public Result<IDirectoryChannel> Connect(CaptureUnit unit)
    {
        ArgumentNullException.ThrowIfNull(unit);

        return Watched(unit.DomainController, _forest.Connect(unit));
    }

    /// <inheritdoc/>
    public Result<IDirectoryChannel> Connect(string domainController) =>
        Watched(domainController, _forest.Connect(domainController));

    private Result<IDirectoryChannel> Watched(string host, Result<IDirectoryChannel> opened)
    {
        if (!opened.IsSuccess)
        {
            return opened;
        }

        Arrived(host);

        // Wait for company. Whether any comes is the thing under test.
        _enough.Wait(_deadline);

        return Result<IDirectoryChannel>.Success(
            new WatchedChannel(opened.Value!, () => Left(host)));
    }

    private void Arrived(string host)
    {
        lock (_tally)
        {
            var here = _openNow.TryGetValue(host, out var open) ? open + 1 : 1;
            _openNow[host] = here;

            if (here > (_mostAtOnce.TryGetValue(host, out var most) ? most : 0))
            {
                _mostAtOnce[host] = here;
            }

            _openAnywhere++;
            _mostAnywhere = Math.Max(_mostAnywhere, _openAnywhere);

            if (_openAnywhere >= _waitingFor)
            {
                _enough.Set();
            }
        }
    }

    private void Left(string host)
    {
        lock (_tally)
        {
            _openNow[host] = _openNow[host] - 1;
            _openAnywhere--;
        }
    }

    /// <summary>
    /// One of the forest's channels, which reports when it is closed and changes nothing else.
    /// </summary>
    private sealed class WatchedChannel(IDirectoryChannel channel, Action onClosed) : IDirectoryChannel
    {
        /// <inheritdoc/>
        public string DomainController => channel.DomainController;

        /// <inheritdoc/>
        public ConnectionSecurityLevel SecurityLevel => channel.SecurityLevel;

        /// <inheritdoc/>
        public ReferralChasingOptions ReferralChasing => channel.ReferralChasing;

        /// <inheritdoc/>
        public IReadOnlyList<string> SupportedControls => channel.SupportedControls;

        /// <inheritdoc/>
        public IReadOnlyList<string> NamingContextsServed => channel.NamingContextsServed;

        /// <inheritdoc/>
        public bool IsComplete => channel.IsComplete;

        /// <inheritdoc/>
        public Task<DirectoryPage> SendAsync(
            SearchRequest request, CancellationToken cancellationToken) =>
            channel.SendAsync(request, cancellationToken);

        /// <inheritdoc/>
        public void Dispose()
        {
            onClosed();
            channel.Dispose();
        }
    }
}

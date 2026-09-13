using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Capture;

namespace SecureAD.Next.Tests.EndToEnd;

/// <summary>
/// A forest of several domains on several controllers, which can say whether two of them were ever
/// being read at the same moment.
/// </summary>
/// <remarks>
/// <para>
/// <b>One <see cref="ControllerModel"/> per host rather than one shared between them.</b> A shared
/// model would have several domains incrementing its request counters at once, which is a race in
/// the fixture rather than in the product - and a test that fails intermittently for a reason that
/// is not the reason it was written teaches the next reader to rerun the build.
/// </para>
/// <para>
/// <b>The rendezvous is what makes the concurrency assertion honest.</b> Each domain announces
/// that its read has begun and then waits for as many others as the test says to expect. Under a
/// serial run the first one waits alone and the wait expires, so the test fails on the property it
/// is about rather than on how long the run took. Under a parallel run it completes as soon as the
/// last domain arrives.
/// </para>
/// </remarks>
internal sealed class ForestModel
{
    private readonly Dictionary<string, ControllerModel> _byHost =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, string> _hostByDomain =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, int> _objectsByDomain =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly HashSet<string> _refusing = new(StringComparer.OrdinalIgnoreCase);

    private readonly TaskCompletionSource _everyoneArrived =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly int _expected;
    private readonly TimeSpan _waitForOthers;
    private readonly Lock _gate = new();

    private int _arrivals;
    private int _readsOpen;

    /// <summary>
    /// How long a domain that has begun reading waits for the others before carrying on.
    /// </summary>
    /// <remarks>
    /// <b>Long, because it is only ever waited out by a run that is genuinely serial.</b> A run
    /// that is free to overlap reaches the rendezvous in microseconds, so a passing test never pays
    /// this. A short value here would let a loaded machine report a parallel capture as a
    /// serialised one.
    /// </remarks>
    public static readonly TimeSpan UntilTheOthersArrive = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long a domain waits when the test expects it to be held back.
    /// </summary>
    /// <remarks>
    /// <b>Short, because here the wait expiring is the correct outcome and is paid every run.</b>
    /// The asymmetry is deliberate and is what makes these assertions measure anything: a domain
    /// that is being held back cannot arrive however long we wait, while one that is free to run
    /// arrives at once. Two seconds is four orders of magnitude more than the fixture needs to
    /// start a second read, so a run that was allowed to overlap will be caught overlapping.
    /// </remarks>
    public static readonly TimeSpan LongEnoughToCatchAnOverlap = TimeSpan.FromSeconds(2);

    /// <param name="domains">Each domain's naming context and the controller it is pinned to.</param>
    /// <param name="waitForOthers">
    /// How long each domain pauses once its read has begun, so that a run which is free to overlap
    /// always does rather than merely being able to. <see cref="TimeSpan.Zero"/> for the tests that
    /// are not about concurrency.
    /// </param>
    public ForestModel(
        IReadOnlyList<(string Domain, string Host)> domains, TimeSpan waitForOthers)
    {
        _expected = domains.Count;
        _waitForOthers = waitForOthers;

        // The controller the operator named, which serves the forest-wide partitions. It is a
        // machine of its own here so that the prologue cannot be mistaken for one of the domains.
        Add("dc0.example.com", "CN=Configuration,DC=example,DC=com", 2);
        Add("dc0.example.com", "CN=Schema,CN=Configuration,DC=example,DC=com", 2);

        for (var at = 0; at < domains.Count; at++)
        {
            var (domain, host) = domains[at];

            _hostByDomain[domain] = host;

            // A different number of objects per domain, so a merge that folded one shard in twice
            // and dropped another would not come to the same total.
            Add(host, domain, 3 + at);
        }
    }

    /// <summary>Whether every domain the test expected to meet actually did.</summary>
    public bool EveryoneArrived { get; private set; } = true;

    /// <summary>The most reads that were open at any one moment.</summary>
    public int MostReadsOpenAtOnce { get; private set; }

    /// <summary>Which controller a domain is read from.</summary>
    public string HostOf(string domain) => _hostByDomain[domain];

    /// <summary>How many objects a domain holds, for the merge to be checked against.</summary>
    public long ObjectsIn(string domain) => _objectsByDomain[domain];

    /// <summary>Makes a controller unreachable, as a machine that has lost power is.</summary>
    public void Refuse(string host) => _refusing.Add(host);

    public IDirectoryChannelFactory Connections() => new Factory(this);

    private void Add(string host, string namingContext, int objects)
    {
        if (!_byHost.TryGetValue(host, out var model))
        {
            model = new ControllerModel(host);
            model.NamingContexts.Clear();
            model.RootDomainNamingContext = "DC=example,DC=com";
            _byHost[host] = model;
        }

        model.NamingContexts.Add(namingContext);
        model.AddObjects(objects, namingContext);

        if (namingContext.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            _objectsByDomain[namingContext] = objects;
    }

    /// <summary>
    /// Notes that a domain's read has begun, then holds it there long enough for any other domain
    /// that is free to run to be caught running.
    /// </summary>
    /// <remarks>
    /// <b>The hold is the whole mechanism, and without it these tests measured nothing.</b> The
    /// fixture answers from memory, so two domains left to themselves finish one after the other
    /// whether or not anything forced them to - and an assertion that no two reads overlapped
    /// passed against a capture with its turn-taking removed. Blocking here makes the window
    /// during which an overlap could be seen as wide as the test needs it to be.
    /// </remarks>
    private void Arrive()
    {
        lock (_gate)
        {
            _readsOpen++;
            MostReadsOpenAtOnce = Math.Max(MostReadsOpenAtOnce, _readsOpen);

            if (++_arrivals >= _expected)
                _everyoneArrived.TrySetResult();
        }

        if (_waitForOthers == TimeSpan.Zero)
            return;

        if (!_everyoneArrived.Task.Wait(_waitForOthers))
            EveryoneArrived = false;
    }

    private void Leave()
    {
        lock (_gate)
        {
            _readsOpen--;
        }
    }

    private sealed class Factory(ForestModel forest) : IDirectoryChannelFactory
    {
        public Result<IDirectoryChannel> Connect(CaptureUnit unit) =>
            Connect(unit.DomainController);

        public Result<IDirectoryChannel> Connect(string domainController)
        {
            if (forest._refusing.Contains(domainController))
            {
                return Result<IDirectoryChannel>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "ControllerUnreachable",
                    ErrorSeverity.Failed,
                    $"{domainController} did not answer on any rung of the ladder.",
                    domainController));
            }

            var opened = forest._byHost[domainController].Connections().Connect(domainController);

            return opened.IsSuccess
                ? new WatchedChannel(forest, opened.Value!)
                : opened;
        }
    }

    /// <summary>
    /// One controller's channel, which tells the forest when a domain's read starts and stops.
    /// </summary>
    /// <remarks>
    /// The first request on a channel is taken as the read beginning. A capture opens one
    /// connection per attempt and pages over it, so that is the moment the domain is genuinely in
    /// flight - and it is after the connection ladder, which would otherwise let a run that
    /// connected in parallel and read in series pass.
    /// </remarks>
    private sealed class WatchedChannel(ForestModel forest, IDirectoryChannel inner)
        : IDirectoryChannel
    {
        private bool _arrived;

        public string DomainController => inner.DomainController;

        public ConnectionSecurityLevel SecurityLevel => inner.SecurityLevel;

        public ReferralChasingOptions ReferralChasing => inner.ReferralChasing;

        public IReadOnlyList<string> SupportedControls => inner.SupportedControls;

        public IReadOnlyList<string> NamingContextsServed => inner.NamingContextsServed;

        public bool IsComplete => inner.IsComplete;

        public Task<DirectoryPage> SendAsync(
            SearchRequest request, CancellationToken cancellationToken)
        {
            if (!_arrived && IsADomainRead(request))
            {
                _arrived = true;
                forest.Arrive();
            }

            return inner.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// Whether this request is the paged read of a domain, rather than one of the base-scope
        /// questions a capture asks on the way in.
        /// </summary>
        private static bool IsADomainRead(SearchRequest request) =>
            request.Scope != SearchScope.Base
            && request.DistinguishedName.StartsWith("DC=", StringComparison.OrdinalIgnoreCase);

        public void Dispose()
        {
            if (_arrived)
                forest.Leave();

            inner.Dispose();
        }
    }
}

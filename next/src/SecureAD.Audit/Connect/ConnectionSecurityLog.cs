using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;
/// <summary>
/// Which rung of the ladder answered, for one domain controller.
/// </summary>
/// <param name="DomainController">The host, as the run named it.</param>
/// <param name="Level">The rung that answered.</param>
/// <param name="RungsRefused">
/// How many better rungs were tried first and declined. Zero means the controller accepted the best
/// this product offers; three means it declined everything above the bottom.
/// </param>
public sealed record ControllerConnectionSecurity(
    string DomainController,
    ConnectionSecurityLevel Level,
    int RungsRefused);

/// <summary>
/// What each domain controller a run spoke to would accept.
/// </summary>
/// <remarks>
/// <para>
/// Walking the ladder produces this at no extra cost, and it is worth more than the run that
/// produced it. A capture has to connect to every controller it reads from anyway; recording which
/// rung each one answered on turns that into a per-controller inventory of a customer's LDAP
/// posture - which is a security finding they would otherwise pay for separately.
/// </para>
/// <para>
/// <b>Two things come out of here, and they are different claims.</b> One is about the run:
/// evidence gathered over an unprotected channel could have been altered in transit, and per
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> that difference is never rendered
/// away. The other is about the forest: a controller declining a signed connection is a weakness in
/// the customer's environment whether or not this product minded. Microsoft's guidance treats
/// unsigned LDAP as something to eliminate, and Windows Server 2025 requires signing by default on
/// new deployments
/// (<see href="https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing">LDAP signing
/// for Active Directory Domain Services</see>).
/// </para>
/// <para>
/// <b>Where those two claims are made is not here.</b> Saying them is the report's and the rule
/// catalogue's, which are phase 3 and branch E. This type carries the facts across the gap, and the
/// obligation to say them is registered against the inventory rows that will - findings F-S13-1 and
/// F-S13-2, on rows E1 and I3 - rather than left as an intention.
/// </para>
/// <para>
/// <b>It is append-only and it never forgets a worse answer.</b> A controller is recorded once, at
/// the moment it answered. Nothing later overwrites a level with a better one, because the question
/// this answers is what the run actually used.
/// </para>
/// <para>
/// <b>One of these is shared by every domain a run reads, and as of 2026-09-13 those are read at
/// once.</b> <c>CaptureSession</c> builds a single log per run and hands it to one channel factory;
/// the fan-out of <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> then connects to
/// nine controllers from nine threads through it. Every member here is therefore guarded.
/// </para>
/// <para>
/// <b>What that guard is actually preventing is worth naming, because none of it is theoretical.</b>
/// <see cref="Record"/> tested a key and then wrote it, so two threads reaching the same controller
/// could both pass the test and both append - one controller, two entries. Plain
/// <see cref="List{T}.Add"/> called concurrently drops entries or throws, and this list is the record
/// of how the forest was reached: an operator would be shown a run that connected to eight
/// controllers when it connected to nine, with nothing saying one was lost. And a
/// <see cref="Dictionary{TKey,TValue}"/> written from two threads can corrupt its own buckets, which
/// surfaces later as an exception in an unrelated read and would end a capture measured in hours.
/// Recorded as <c>P-171</c> from a review that had not verified it; verified 2026-09-13, by which
/// time the fan-out had made it larger than the row described.
/// </para>
/// <para>
/// <b>The reading members hand back copies.</b> Returning the live collections would move the race
/// rather than remove it - a caller enumerating <see cref="Controllers"/> while another domain
/// connects gets <see cref="InvalidOperationException"/>, which is the same defect one layer out.
/// </para>
/// </remarks>
public sealed class ConnectionSecurityLog
{
    /// <summary>
    /// Guards every field below. One lock rather than one per collection, because
    /// <see cref="Record"/> writes two of them and they have to agree.
    /// </summary>
    private readonly Lock _gate = new();

    private readonly Dictionary<string, ControllerConnectionSecurity> _byController =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly List<ControllerConnectionSecurity> _inOrderConnected = [];

    private readonly List<AuditError> _errors = [];

    /// <summary>Every controller this run connected to, in the order it first connected.</summary>
    /// <remarks>
    /// <para>
    /// Backed by a list rather than by <see cref="Dictionary{TKey,TValue}.Values"/>, which
    /// guarantees no order at all. It happens to enumerate in insertion order while nothing is
    /// removed, and nothing here removes anything - so the sentence above was true by implementation
    /// accident, and a reader who rendered this collection directly could have had one forest come
    /// back in a different order between two runs. <c>DirectoryWorkDispatch</c> is careful about stable
    /// ordering for the same reason, in the same subsystem.
    /// </para>
    /// <para>
    /// <b>A copy, taken under the lock.</b> Handing back the field would let a caller enumerate it
    /// while another domain is connecting, which throws.
    /// </para>
    /// </remarks>
    public IReadOnlyList<ControllerConnectionSecurity> Controllers
    {
        get
        {
            lock (_gate)
                return [.. _inOrderConnected];
        }
    }

    /// <summary>
    /// The controllers this run could not connect to at all, and why.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what lets the two lists above be believed. Without it, a run in which every
    /// connection failed and a run in which every connection was protected produce the same empty
    /// <see cref="RefusedIntegrity"/>, and a reader has no way to tell "we looked and found
    /// nothing wrong" from "we never got to look" - which is the distinction
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids collapsing, and gate 4
    /// is the build failure that made it get written.
    /// </para>
    /// <para>
    /// A run that reaches capture at all has none of these, because a controller that accepts no
    /// connection ends the run. They exist so that preflight - inventory row A8 - can ask every
    /// controller the question at once and report all the answers rather than the first.
    /// </para>
    /// </remarks>
    public IReadOnlyList<AuditError> Errors
    {
        get
        {
            lock (_gate)
                return [.. _errors];
        }
    }

    /// <summary>
    /// Whether any controller in this run was read over an unprotected connection. What the report
    /// has to disclose.
    /// </summary>
    public bool AnyUnprotected
    {
        get
        {
            lock (_gate)
                return _byController.Values.Any(c => c.Level == ConnectionSecurityLevel.Unprotected);
        }
    }

    /// <summary>
    /// The controllers that declined every rung offering integrity. What the finding is about.
    /// </summary>
    /// <remarks>
    /// Signing is the line, not encryption, because signing is what makes a session safe from
    /// alteration in transit and it is what Microsoft's hardening guidance and the Windows Server
    /// 2025 default are both about. A controller that accepted signing but not sealing is not a
    /// finding.
    /// </remarks>
    public IReadOnlyList<ControllerConnectionSecurity> RefusedIntegrity
    {
        get
        {
            lock (_gate)
            {
                return
                [
                    .. _byController.Values
                        .Where(c => c.Level == ConnectionSecurityLevel.Unprotected)
                        .OrderBy(c => c.DomainController, StringComparer.OrdinalIgnoreCase),
                ];
            }
        }
    }

    /// <summary>
    /// Records the rung a controller answered on. The first answer stands.
    /// </summary>
    /// <param name="domainController">The host.</param>
    /// <param name="level">The rung that answered.</param>
    /// <param name="rungsRefused">How many better rungs were tried and declined.</param>
    public void Record(string domainController, ConnectionSecurityLevel level, int rungsRefused)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainController);
        ArgumentOutOfRangeException.ThrowIfNegative(rungsRefused);

        var host = domainController.Trim();

        // The test and both writes are one step. Split, two threads reaching the same controller
        // both pass the test and both append, and the run reports one controller twice.
        lock (_gate)
        {
            if (_byController.ContainsKey(host))
                return;

            var recorded = new ControllerConnectionSecurity(host, level, rungsRefused);
            _byController[host] = recorded;
            _inOrderConnected.Add(recorded);
        }
    }

    /// <summary>
    /// Records that a controller accepted no connection this run was permitted to offer.
    /// </summary>
    /// <param name="error">Why, naming the controller and the rungs that were tried.</param>
    public void RecordFailure(AuditError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        lock (_gate)
            _errors.Add(error);
    }
}

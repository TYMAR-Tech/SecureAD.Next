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
/// </remarks>
public sealed class ConnectionSecurityLog
{
    private readonly Dictionary<string, ControllerConnectionSecurity> _byController =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly List<AuditError> _errors = [];

    /// <summary>Every controller this run connected to, in the order it first connected.</summary>
    public IReadOnlyCollection<ControllerConnectionSecurity> Controllers => _byController.Values;

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
    public IReadOnlyList<AuditError> Errors => _errors;

    /// <summary>
    /// Whether any controller in this run was read over an unprotected connection. What the report
    /// has to disclose.
    /// </summary>
    public bool AnyUnprotected =>
        _byController.Values.Any(c => c.Level == ConnectionSecurityLevel.Unprotected);

    /// <summary>
    /// The controllers that declined every rung offering integrity. What the finding is about.
    /// </summary>
    /// <remarks>
    /// Signing is the line, not encryption, because signing is what makes a session safe from
    /// alteration in transit and it is what Microsoft's hardening guidance and the Windows Server
    /// 2025 default are both about. A controller that accepted signing but not sealing is not a
    /// finding.
    /// </remarks>
    public IReadOnlyList<ControllerConnectionSecurity> RefusedIntegrity =>
        _byController.Values
            .Where(c => c.Level == ConnectionSecurityLevel.Unprotected)
            .OrderBy(c => c.DomainController, StringComparer.OrdinalIgnoreCase)
            .ToList();

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
        if (_byController.ContainsKey(host))
            return;

        _byController[host] = new ControllerConnectionSecurity(host, level, rungsRefused);
    }

    /// <summary>
    /// Records that a controller accepted no connection this run was permitted to offer.
    /// </summary>
    /// <param name="error">Why, naming the controller and the rungs that were tried.</param>
    public void RecordFailure(AuditError error)
    {
        ArgumentNullException.ThrowIfNull(error);

        _errors.Add(error);
    }
}

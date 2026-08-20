using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Capture;

/// <summary>
/// One naming context, on one domain controller: the whole of what capture reads in one go, and
/// the boundary it never crosses.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row B4, and <c>docs/next/S-9-the-capture-unit.md</c> is the document that says
/// what the search issued for a unit looks like and what was refused.
/// </para>
/// <para>
/// <b>Why a unit is a partition and never a domain.</b> A paged subtree search based at the root
/// of a domain naming context does not stay inside that domain. The controller returns subordinate
/// referrals for the configuration and schema partitions, the DNS zone partitions, and every child
/// domain recursively; if the client chases them, the paged cookie is overwritten inside the LDAP
/// runtime and the search ends after one page reporting success
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased">LDAP
/// paged queries with subordinate referrals are not chased properly</see>, which says outright that
/// there is no resolution). A capture that reads one page of a nine-million-object forest and says
/// nothing went wrong is the one failure this product cannot have. So a unit follows nothing, and
/// the partitions are enumerated deliberately instead.
/// </para>
/// <para>
/// <b>The name.</b> Not a shard. Shard named the parallel fan-out that inventory row B5 defers, and a
/// name for machinery that does not exist teaches a reader something untrue. A future session
/// reinstating fan-out reintroduces the word rather than finding it waiting.
/// </para>
/// </remarks>
/// <param name="NamingContext">
/// The distinguished name of the partition root, exactly as the controller reported it in its
/// RootDSE.
/// </param>
/// <param name="Kind">Which kind of partition this is.</param>
/// <param name="DomainController">
/// The host the unit is read from. One controller per unit, chosen before the run starts, so that
/// under fail-fast a failure names one unit unambiguously.
/// </param>
public sealed record CaptureUnit(string NamingContext, NamingContextKind Kind, string DomainController)
{
    /// <summary>
    /// Creates a unit, refusing one that could not be searched.
    /// </summary>
    /// <remarks>
    /// A <c>Result</c> rather than an exception, because a partition list arriving from a
    /// controller is an input from outside the product and a blank entry in it is an outcome
    /// rather than a defect in this code.
    /// </remarks>
    /// <param name="namingContext">The partition root's distinguished name.</param>
    /// <param name="kind">Which kind of partition it is.</param>
    /// <param name="domainController">The host to read it from.</param>
    public static Result<CaptureUnit> Create(
        string namingContext, NamingContextKind kind, string domainController)
    {
        if (string.IsNullOrWhiteSpace(namingContext))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "CaptureUnitWithoutNamingContext",
                ErrorSeverity.Failed,
                "A capture unit was described without a naming context. There is nothing to "
                + "search, and a unit that searches nothing would report an empty partition "
                + "rather than a missing one.",
                context: null);
        }

        if (string.IsNullOrWhiteSpace(domainController))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "CaptureUnitWithoutDomainController",
                ErrorSeverity.Failed,
                "A capture unit was described without a domain controller to read it from. "
                + $"Naming context: {namingContext}.",
                context: null);
        }

        return new CaptureUnit(namingContext.Trim(), kind, domainController.Trim());
    }

    /// <summary>
    /// Preflight: confirms that <see cref="DomainController"/> actually serves
    /// <see cref="NamingContext"/>, given the partitions that controller named in its own RootDSE.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is checked before the run and not during it.</b> Capture is fail-fast: a unit
    /// that cannot be read ends the run. Discovering at hour two that a controller was never going
    /// to answer for a partition costs the whole capture, and a forest is only readable as it
    /// stands today. Asking every chosen controller, once, before anything is read, costs one round
    /// trip per unit.
    /// </para>
    /// <para>
    /// <b>Who calls it.</b> Inventory row A8 - preflight validation, in branch A - is where this is
    /// invoked, and that row is not yet decided. The check lives here rather than there so that the
    /// obligation cannot fall between two rows: B4 owns whether a unit is well formed, and A8 owns
    /// when the question is asked. A8 not being written yet means the check is not yet called; it
    /// does not mean it is not yet built.
    /// </para>
    /// <para>
    /// <b>The comparison is an exact match, deliberately.</b> Both sides are strings the controller
    /// itself produced - the planned unit's naming context comes from a RootDSE partition list, and
    /// so does the argument. No distinguished name is parsed, so this introduces no second
    /// interpretation of a DN to disagree with <c>DnHelper</c>. Case is ignored because LDAP names
    /// are not case-sensitive.
    /// </para>
    /// </remarks>
    /// <param name="namingContextsServed">
    /// The naming contexts the chosen controller reports serving - the <c>namingContexts</c>
    /// attribute of its RootDSE.
    /// </param>
    public Result<CaptureUnit> ConfirmServedBy(IEnumerable<string> namingContextsServed)
    {
        ArgumentNullException.ThrowIfNull(namingContextsServed);

        var served = namingContextsServed
            .Where(nc => !string.IsNullOrWhiteSpace(nc))
            .Select(nc => nc.Trim())
            .ToList();

        if (served.Count == 0)
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "DomainControllerNamedNoPartitions",
                ErrorSeverity.Failed,
                $"{DomainController} reported no naming contexts, so it cannot be confirmed as "
                + $"serving {NamingContext}. An empty partition list is a failed question, not an "
                + "answer of no.",
                context: null);
        }

        if (!served.Contains(NamingContext, StringComparer.OrdinalIgnoreCase))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "DomainControllerDoesNotServeNamingContext",
                ErrorSeverity.Failed,
                $"{DomainController} does not serve {NamingContext}. It reported: "
                + string.Join(", ", served) + ".",
                context: null);
        }

        return this;
    }
}

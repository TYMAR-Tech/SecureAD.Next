using System.Collections.Frozen;
using SecureAD.Derivation;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// Which of Microsoft's security identifiers this product treats as privileged when it finds one in
/// an account's SID history.
/// </summary>
/// <remarks>
/// <para>
/// <b>The values are Microsoft's; the selection is this product's, and the difference is the whole
/// point of this type.</b> Every identifier below is transcribed from MS-DTYP 2.4.2.4 into
/// <see cref="WellKnownSidCatalog"/> and held against Microsoft by
/// <c>WellKnownSidCatalogMicrosoftAnchorTests</c> - nothing here adds an identifier or a name. But
/// Microsoft does not publish which of them amount to privilege: the Defender for Identity
/// assessment says only that it reports accounts it "profiles to be risky", and that profile is not
/// documented. So this set is a judgement, and it is written out where a reviewer can read it off
/// the page.
/// </para>
/// <para>
/// <b>Why it is a type of its own rather than a field on the rule.</b> It is a table compiled into
/// the assembly: it reads nothing, opens nothing and cannot fail. <c>PrivilegedSidHistory</c> is
/// the opposite - it judges an object and can decline to. Keeping the table beside the judging
/// would mean any exemption granted to the table covered the judging too, which is precisely what
/// gate 4 is watching for. <c>GpoClientSideExtensionCatalog</c> was split out of
/// <c>GpoClientSideExtensions</c> in 2026-08 for the same reason and its remarks record it.
/// </para>
/// <para>
/// <b>Two entries are not administrators and are explained.</b> <c>502</c> (krbtgt) grants nothing
/// by membership; it is here because no documented migration scenario puts a domain's key
/// distribution centre account into another principal's history, so its presence is something an
/// administrator should be told about. Print Operators is the weakest entry - managing printers is
/// not administering a domain - and it is here because a benign migration has no reason to carry
/// it. If it proves noisy against a real forest it comes out of this table, which is a change here
/// rather than to any logic.
/// </para>
/// <para>
/// <b>Deliberately absent:</b> <c>501</c>, <c>513</c>, <c>514</c>, <c>515</c> and <c>545</c> are
/// everyone-groups whose presence says nothing; <c>517</c>, <c>522</c>, <c>526</c>, <c>527</c>,
/// <c>553</c>, <c>571</c> and <c>572</c> are roles this product has no Microsoft basis to call
/// privileged; <c>525</c> (Protected Users) is a protection, and reporting a defence as a defect is
/// how a tool teaches an operator to stop reading it.
/// </para>
/// <para>
/// Reasoned through in docs/layers/judgement/rules/SEC-027-privileged-sid-history.md §5.
/// </para>
/// </remarks>
public static class PrivilegedSidCatalogue
{
    /// <summary>
    /// Relative identifiers that name a privileged principal under whichever domain issued them.
    /// </summary>
    public static readonly FrozenSet<int> PrivilegedRelativeIdentifiers = PrincipalClassificationRegistry.SensitiveHistoryRids;

    /// <summary>
    /// Built-in groups that are privileged, held as whole SIDs rather than relative identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Whole SIDs because that is what Microsoft makes them.</b> <c>S-1-5-32-544</c> is a
    /// well-known SID: the built-in domain identifier is fixed at 32 on every machine, so the value
    /// means Administrators everywhere rather than being counted from an issuing domain. MS-DTYP
    /// lists the built-in aliases separately from the domain-relative table for that reason, and
    /// <see cref="WellKnownSidCatalog"/> transcribes them into a different list.
    /// </para>
    /// <para>
    /// <b>This was got wrong first and the anchor test caught it.</b> All six were originally
    /// relative identifiers, which reads the last value off any SID - so <c>S-1-5-21-…-544</c>, an
    /// ordinary object in a migrated domain, would have been reported as the built-in
    /// Administrators group. Every positive test still passed, because the rule and the tests
    /// shared the mistake. Only the check that goes outside this repository disagreed.
    /// </para>
    /// </remarks>
    public static readonly FrozenSet<string> PrivilegedWellKnownSids = PrincipalClassificationRegistry.SensitiveHistorySids;

    /// <summary>
    /// What Microsoft calls this SID, when this product treats it as privileged.
    /// </summary>
    /// <remarks>
    /// Null when it is not one, so a caller cannot mistake "not privileged" for "privileged but
    /// unnamed". The name is Microsoft's, from <see cref="WellKnownSidCatalog"/>; nothing here
    /// holds a second copy of it.
    /// </remarks>
    /// <param name="sid">A SID in written form.</param>
    public static string? PrivilegedName(string sid)
    {
        if (PrivilegedWellKnownSids.Contains(sid))
            return WellKnownSidCatalog.FindBySid(sid)?.DisplayName;

        // A built-in SID is never read as domain-relative. S-1-5-32 is the built-in domain, so its
        // last value is an alias rather than a principal counted from an issuing domain, and
        // ranking it below would give one number two meanings.
        if (Sid.IsBuiltinDomain(sid))
            return null;

        return Sid.RelativeIdentifier(sid) is { } rid
            && PrivilegedRelativeIdentifiers.Contains(rid)
                ? WellKnownSidCatalog.FindByRid(rid)?.DisplayName
                : null;
    }
}

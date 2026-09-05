using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

/// <summary>
/// Expanding one access control entry's trustee into the principals inside it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Lifted out of SEC-090 on 2026-09-05 because three rules now need it.</b> The scope-walking
/// below is not obvious, it was arrived at by running against a real forest, and a second copy is
/// the one that would be written without it. The DN helpers ended up with three near-identical ways
/// to ask one question by exactly this route.
/// </para>
/// </remarks>
internal static class PrincipalExpansionReading
{
    /// <summary>
    /// Expands a trustee, asking at each scope a principal can be keyed under before concluding it
    /// is absent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A SID is unique within its scope, not within the forest</b>, so the expansion is keyed by
    /// the pair - and which scope a given trustee lives under cannot be read off the trustee.
    /// Measured against <c>ad.lab</c> on 2026-09-03: a domain-relative SID (<c>S-1-5-21-…</c>) is
    /// keyed under the <i>empty</i> scope, because it is already unique across the forest; a
    /// <c>BUILTIN</c> SID such as <c>S-1-5-32-544</c> is keyed under a <i>domain</i>, because that
    /// same SID exists in every domain and means a different group in each.
    /// </para>
    /// <para>
    /// <b>And a BUILTIN trustee carries no domain of its own</b>, because the SID names no single
    /// captured object. What settles it is the object being judged, which is why the subject's
    /// domain is one of the scopes tried.
    /// </para>
    /// <para>
    /// <b>The forest found this and 2,973 green tests did not.</b> The first run against
    /// <c>ad.lab</c> asked only at the trustee's captured domain, so every computer whose list named
    /// <c>SYSTEM</c> or a domain group answered <c>PrincipalNotFound</c>: SEC-090 reported
    /// <i>Indeterminate</i> over half the estate and buried two real findings behind a rule that
    /// looked broken.
    /// </para>
    /// <para>
    /// <b>Asking more than once can only turn "not found" into an answer</b>, never the reverse, so
    /// it cannot manufacture a finding. What survives every scope is a principal this bundle does
    /// not hold - a trustee from a trusted external forest, or one left behind by a deleted object.
    /// </para>
    /// <para>
    /// <b><c>PrincipalDoesNotExist</c> is not an answer either, and stopping on it would be a
    /// defect.</b> That outcome says no object in a fully-read domain carries the identifier, which
    /// is a statement about the <i>scope just asked</i> and not about the trustee. The walk
    /// therefore continues through every scope and returns the last answer, so absence is concluded
    /// only once nowhere is left to ask.
    /// </para>
    /// </remarks>
    /// <param name="expand">The derivation's expansion, keyed by principal and scope.</param>
    /// <param name="trustee">The principal the access control entry names.</param>
    /// <param name="subjectDomain">The domain of the object being judged.</param>
    public static PrincipalExpansion MembersOfTrustee(
        Func<string, string, PrincipalExpansion> expand,
        PermissionTrustee trustee,
        string? subjectDomain)
    {
        ArgumentNullException.ThrowIfNull(expand);
        ArgumentNullException.ThrowIfNull(trustee);

        // Most specific first. Nothing here can produce a wrong match: a domain-relative SID is
        // unique across the forest, so asking under a domain it does not belong to simply answers
        // not found. The only thing an extra scope can do is turn a false absence into an answer.
        var scopes = new List<string>();

        if (!string.IsNullOrEmpty(trustee.DomainFqdn))
            scopes.Add(trustee.DomainFqdn);

        if (!string.IsNullOrEmpty(subjectDomain) && !scopes.Contains(subjectDomain))
            scopes.Add(subjectDomain);

        scopes.Add(string.Empty);

        PrincipalExpansion last = null!;

        foreach (var scope in scopes)
        {
            last = expand(trustee.Sid, scope);

            if (last.Outcome is not (PrincipalExpansionOutcome.PrincipalNotFound
                or PrincipalExpansionOutcome.PrincipalDoesNotExist))
            {
                return last;
            }
        }

        return last;
    }
}

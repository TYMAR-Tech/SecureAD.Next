namespace SecureAD.Evidence;

/// <summary>
/// Why a domain was left out of a run, as a permanent value written into evidence.
/// </summary>
/// <remarks>
/// <b>The two kinds are never merged.</b>
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires a domain an
/// operator took out and a domain the forest named no controller for to be told apart wherever
/// they appear, and a bundle read months later - with no screen and no operator to ask - is the
/// place where losing the difference costs most.
/// </remarks>
public enum ExclusionKind
{
    /// <summary>The operator took the domain out of the run.</summary>
    ByChoice,

    /// <summary>The forest named no writable controller for it, so nothing could read it.</summary>
    ForWantOfCandidates,
}

/// <summary>
/// One domain left out of a run, and everything stated about its leaving.
/// </summary>
/// <remarks>
/// <para>
/// <b>The whole attestation is carried, per
/// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>.</b> An exclusion that
/// governed a run but was not stored with it is a fact about the audit that the audit does not
/// carry, and the first person to need it is an auditor reading the run months later with the
/// operator unavailable and the screen long gone.
/// </para>
/// <para>
/// <b><see cref="Reason"/> is a stable identifier, not a sentence.</b> The wording an operator read
/// may be improved; what the value means may not change, because runs already recorded carry it -
/// the same footing as a rule identifier under <c>docs/decisions/0024-a-rule-identifier-is-permanent.md</c>.
/// </para>
/// <para>
/// <b><see cref="AuthorisedBy"/> is not validated and cannot be.</b> It is a typed string and a
/// statement of accountability, not an identity. Nothing that reads this back may present it as
/// though it had been checked.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition that was left out.</param>
/// <param name="DomainFqdn">
/// The domain's DNS name as the forest declared it, which is what run coverage is keyed by. Carried
/// rather than derived from <paramref name="NamingContext"/>: turning <c>DC=ph,DC=ad,DC=lab</c> into
/// <c>ph.ad.lab</c> by string surgery invents a name nobody published, and is wrong in exactly the
/// forest that renamed a domain.
/// </param>
/// <param name="Kind">Which kind of exclusion this is.</param>
/// <param name="Reason">The stable identifier of the reason chosen from the closed list.</param>
/// <param name="Note">What the operator added in his own words, or null.</param>
/// <param name="RunBy">The signed-in account the run was made under, captured rather than typed.</param>
/// <param name="AuthorisedBy">The person whose decision it was, as typed.</param>
/// <param name="AttestedUtc">When the statement was made.</param>
public sealed record AttestedExclusion(
    string NamingContext,
    string DomainFqdn,
    ExclusionKind Kind,
    string Reason,
    string? Note,
    string RunBy,
    string AuthorisedBy,
    DateTimeOffset AttestedUtc);

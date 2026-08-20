namespace SecureAD.Shell.Services;

/// <summary>
/// Whether a domain is in this run, and if it is not, which kind of exclusion it is.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three states, and deliberately not a boolean.</b> A tick box over this fact would collapse
/// the two exclusions into one empty box, and
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> exists precisely because a
/// domain an operator left out and a domain the forest named no controller for are different
/// events with different remedies. The tick box on the row renders this; it is not this.
/// </para>
/// <para>
/// <b>Both exclusions are attested.</b>
/// <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c> makes the
/// second one an exclusion rather than a gap, so neither leaves a run without a name behind it.
/// </para>
/// </remarks>
internal enum DomainInclusion
{
    /// <summary>The domain is in the run.</summary>
    Included,

    /// <summary>The operator took it out.</summary>
    ExcludedByChoice,

    /// <summary>The forest names no writable controller for it, so there is nothing to read.</summary>
    ExcludedForWantOfCandidates,
}

/// <summary>
/// Why a domain was left out of a run, from the closed list an operator picks from.
/// </summary>
/// <remarks>
/// <para>
/// <b>A closed list is what makes an exclusion answerable later.</b> Per
/// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>, free text alone cannot be
/// counted or compared across runs: twenty runs of prose is twenty things a reader has to
/// interpret. A closed list lets the product answer <i>how many domains were excluded for lack of
/// credentials this year</i>.
/// </para>
/// <para>
/// <b>The meanings are permanent, on the same footing as a rule identifier under
/// <c>0024</c>.</b> The wording in <see cref="ExclusionReasons.Wording"/> may be improved; what a
/// member means may not change, because runs already recorded carry it. That is why
/// <see cref="ExclusionReasons.WireName"/> is separate from the wording and never reads from it.
/// </para>
/// <para>
/// The set grows by record. These three are the situations <c>0049</c> named.
/// </para>
/// </remarks>
internal enum ExclusionReason
{
    /// <summary>The operator does not hold credentials that can read the domain.</summary>
    CredentialsNotHeld,

    /// <summary>The domain is not part of what this audit was asked to cover.</summary>
    OutsideThisAuditsRemit,

    /// <summary>The domain is believed to hold nothing worth reading.</summary>
    BelievedToHoldNothing,
}

/// <summary>
/// The closed reason list, in the words an operator reads and the words a bundle stores.
/// </summary>
/// <remarks>
/// <b>Two vocabularies, kept apart on purpose.</b> <see cref="Wording"/> is for a person and may be
/// reworded; <see cref="WireName"/> is written into evidence and may not. Deriving one from the
/// other - by spacing out the enum name, say - would tie a stored value to a sentence somebody is
/// free to improve, and the improvement would silently rewrite what past runs appear to have said.
/// </remarks>
internal static class ExclusionReasons
{
    /// <summary>Every reason an operator may pick, in the order the dialog offers them.</summary>
    public static IReadOnlyList<ExclusionReason> All { get; } =
    [
        ExclusionReason.CredentialsNotHeld,
        ExclusionReason.OutsideThisAuditsRemit,
        ExclusionReason.BelievedToHoldNothing,
    ];

    /// <summary>How a reason is put to the operator.</summary>
    public static string Wording(ExclusionReason reason) => reason switch
    {
        ExclusionReason.CredentialsNotHeld =>
            "I do not hold credentials that can read this domain.",
        ExclusionReason.OutsideThisAuditsRemit =>
            "This domain is outside what this audit was asked to cover.",
        ExclusionReason.BelievedToHoldNothing =>
            "This domain is believed to hold nothing worth reading.",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    /// <summary>
    /// How a reason is written into a bundle, permanently.
    /// </summary>
    /// <remarks>
    /// Spelled out rather than taken from <see cref="Enum.ToString()"/>, so that renaming a member
    /// is a compile-time choice about code and never an unannounced change to what evidence
    /// already written appears to say.
    /// </remarks>
    public static string WireName(ExclusionReason reason) => reason switch
    {
        ExclusionReason.CredentialsNotHeld => "credentials-not-held",
        ExclusionReason.OutsideThisAuditsRemit => "outside-remit",
        ExclusionReason.BelievedToHoldNothing => "believed-empty",
        _ => throw new ArgumentOutOfRangeException(nameof(reason)),
    };

    /// <summary>How an exclusion's kind is written into a bundle, permanently.</summary>
    /// <remarks>
    /// <c>0063</c> requires the two exclusions be told apart wherever they appear, and a bundle
    /// read months later by somebody with no screen in front of him is exactly where that matters.
    /// </remarks>
    public static string WireName(DomainInclusion inclusion) => inclusion switch
    {
        DomainInclusion.ExcludedByChoice => "by-choice",
        DomainInclusion.ExcludedForWantOfCandidates => "no-candidates",
        _ => throw new ArgumentOutOfRangeException(nameof(inclusion)),
    };
}

/// <summary>
/// What an operator stated when he left a domain out of a run.
/// </summary>
/// <remarks>
/// <para>
/// <b>The whole of this reaches the bundle</b>, per
/// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>. An exclusion that governs
/// a run but is not stored with it is a fact about the audit that the audit does not carry, and the
/// first person to need it is an auditor reading the run months later with the operator
/// unavailable and the screen long gone.
/// </para>
/// <para>
/// <b>It belongs to one run.</b> <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c>
/// refuses to carry one forward or to pre-fill it from the last, so nothing here is persisted
/// outside the bundle it was made for and nothing reads one back to offer it again.
/// </para>
/// <para>
/// <b><see cref="AuthorisedBy"/> is not validated and cannot be.</b> It is a typed string and a
/// statement of accountability, not an identity. Nothing that renders it may present it as though
/// it had been checked.
/// </para>
/// </remarks>
/// <param name="NamingContext">The domain partition that was left out.</param>
/// <param name="DomainFqdn">
/// The domain's DNS name as the forest declared it, which is what a run's coverage is keyed by.
/// Falls back to the naming context only where the forest paired no name with it.
/// </param>
/// <param name="Kind">
/// Which kind of exclusion this is, so that a bundle can tell a domain an operator took out from
/// one the forest named no controller for.
/// </param>
/// <param name="Reason">The reason picked from the closed list.</param>
/// <param name="Note">
/// What the operator added in his own words, or null where he added nothing. The escape that stops
/// the closed list forcing him to pick the nearest wrong answer.
/// </param>
/// <param name="RunBy">
/// The signed-in Windows account, captured rather than typed. A name an operator types for himself
/// is a name he can get wrong.
/// </param>
/// <param name="AuthorisedBy">The person whose decision it was, typed.</param>
/// <param name="MadeUtc">When the statement was made.</param>
internal sealed record ExclusionAttestation(
    string NamingContext,
    string DomainFqdn,
    DomainInclusion Kind,
    ExclusionReason Reason,
    string? Note,
    string RunBy,
    string AuthorisedBy,
    DateTimeOffset MadeUtc);

/// <summary>
/// What the operator supplied in the attestation dialog, before the run stamps the rest.
/// </summary>
/// <remarks>
/// <b>Only the two things he is asked for.</b> The account and the time are not his to give - one
/// is captured and the other is observed - so a dialog that returned them would be a dialog that
/// could get them wrong. It returns what was typed and picked; the view model stamps the rest.
/// </remarks>
/// <param name="Reason">The reason he picked.</param>
/// <param name="Note">What he added in his own words, or null.</param>
/// <param name="AuthorisedBy">The name he gave as the authorising party.</param>
internal sealed record ExclusionStatement(
    ExclusionReason Reason,
    string? Note,
    string AuthorisedBy);

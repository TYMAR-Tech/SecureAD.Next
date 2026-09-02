namespace SecureAD.Evidence.Findings;

/// <summary>
/// What SEC-027 read to reach its conclusion.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every value is kept, not only the ones that fired.</b> The rule ranks a SID history value by
/// its relative identifier, which it can only do for the identifiers Microsoft documents. A value
/// carrying a custom group's identifier from a domain that no longer exists cannot be ranked by
/// anything reading one forest - see the rule document, section 6 - so storing only the matches
/// would show an operator a filtered view of the account he is being told about, and leave him
/// believing the account carries nothing else.
/// </para>
/// <para>
/// <b><c>UnrankedValues</c> is derived rather than stored.</b> It is the values that are not
/// matches, and a stored count would be a second account of a fact already present. Same reasoning
/// as <see cref="KerberosPreauthenticationEvidence.IsDisabled"/>.
/// </para>
/// <para>
/// <b>Why the account's own SID is here.</b> Microsoft: "no two domains in an enterprise share the
/// same domain identifier." Holding it beside the history lets a reader see that the privileged
/// identifier was issued by a <i>different</i> domain, which is the whole of what makes it an
/// escalation rather than a restatement of the account's own privilege. It is nullable because an
/// account whose own SID could not be read still carries the history that was read, and refusing to
/// report that would suppress a true finding over a detail that does not bear on it.
/// </para>
/// </remarks>
/// <param name="ObjectSid">The account's own identifier, or null when it could not be read.</param>
/// <param name="HistoryValues">The values of <c>sIDHistory</c> that were read, in written form.</param>
/// <param name="Matches">The values whose relative identifier this product treats as privileged.</param>
/// <param name="UnreadableValues">How many values were present but could not be decoded.</param>
public sealed record PrivilegedSidHistoryEvidence(
    string? ObjectSid,
    IReadOnlyList<string> HistoryValues,
    IReadOnlyList<PrivilegedSidHistoryMatch> Matches,
    int UnreadableValues) : FindingEvidence
{
    /// <summary>
    /// Whether every value the object carried was read, so this evidence is the whole of what the
    /// account holds.
    /// </summary>
    /// <remarks>
    /// <b>False does not weaken the finding, and must not be read as though it did.</b> A privileged
    /// identifier that was read is carried whether or not a sibling value could be decoded. What
    /// this says is that the account may hold <i>more</i> than is listed - so an operator who
    /// removes what is listed has not necessarily seen everything.
    /// </remarks>
    public bool IsComplete => UnreadableValues == 0;

    /// <summary>
    /// The history values this product could not rank, which is not the same as values it ranked
    /// as harmless.
    /// </summary>
    /// <remarks>
    /// An operator reading a finding needs to know the rule looked at more than it reported on.
    /// These are values whose relative identifier is not one Microsoft documents as privileged -
    /// most often an ordinary account or group of the old domain, whose privilege, if any, lived in
    /// what that domain granted it and left with that domain.
    /// </remarks>
    public IReadOnlyList<string> UnrankedValues =>
    [
        .. HistoryValues.Where(v => !Matches.Any(m => string.Equals(
            m.Sid, v, StringComparison.OrdinalIgnoreCase))),
    ];
}

/// <summary>
/// One value of <c>sIDHistory</c> whose relative identifier names a privileged principal.
/// </summary>
/// <remarks>
/// The name is carried beside the identifier because a SID alone tells an operator nothing, and
/// because it is the Microsoft name from <c>WellKnownSidCatalog</c> rather than a name this product
/// invented. A reader can check it against MS-DTYP 2.4.2.4 without opening this repository.
/// </remarks>
/// <param name="Sid">The history value, in written form.</param>
/// <param name="RelativeIdentifier">Its last sub-authority.</param>
/// <param name="Name">What Microsoft calls that relative identifier.</param>
public sealed record PrivilegedSidHistoryMatch(
    string Sid,
    int RelativeIdentifier,
    string Name);

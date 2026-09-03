namespace SecureAD.Evidence.Findings;

/// <summary>
/// Which of the two rights a confidential attribute needs an access control entry actually carried.
/// </summary>
/// <remarks>
/// <para>
/// <b>Reading a confidential attribute needs both, and the predecessor checked one.</b> Microsoft
/// states it outright: after the read access check, Active Directory checks for confidential
/// attributes, and where <c>READ_PROPERTY</c> is set it <i>also</i> requires <c>CONTROL_ACCESS</c>
/// for the attribute or its property set. The old evaluator's query was
/// <c>(access_mask &amp; 256) != 0</c> and never looked at read at all, so it named principals who
/// cannot retrieve the password - which is the product telling a customer something false.
/// </para>
/// <para>
/// <b>The one-sided cases are kept rather than dropped</b>, because they are different statements.
/// A grant of <c>CONTROL_ACCESS</c> alone is a sensitive permission Microsoft's own tooling hunts
/// for, and reporting it as a fact is honest; asserting that it exposes the password is not.
/// </para>
/// </remarks>
public enum LapsReadRights
{
    /// <summary>
    /// Neither right. The entry matched the attribute but grants no way to read it.
    /// </summary>
    Neither,

    /// <summary>
    /// <c>READ_PROPERTY</c> only. The directory withholds a confidential attribute from this
    /// principal, so it cannot retrieve the password.
    /// </summary>
    ReadPropertyOnly,

    /// <summary>
    /// <c>CONTROL_ACCESS</c> only. Sensitive, and reported as a stated fact rather than a finding,
    /// because on its own it does not yield the password.
    /// </summary>
    ControlAccessOnly,

    /// <summary>
    /// Both. This principal can read the attribute, which is the only state that raises a finding.
    /// </summary>
    Both,
}

/// <summary>
/// How far an access control entry reaches, which is a different question from whether it carried a
/// GUID.
/// </summary>
/// <remarks>
/// <b>An object entry carrying no <c>ObjectType</c> narrows nothing.</b> That is why
/// <c>ObjectPermissions</c> records <c>HasObjectType</c> from <c>ACE_OBJECT_TYPE_PRESENT</c> rather
/// than from whether the GUID is null, and why this evidence carries the distinction forward:
/// reading it wrong reports the wrong population in both directions at once - a narrow per-attribute
/// delegation inflated into control of the whole object, or a blanket grant missed entirely.
/// Microsoft names the blanket grant as the thing to go looking for, because holders of the extended
/// rights permission on an organizational unit "can read confidential attributes, and all the
/// Windows LAPS password attributes are marked as confidential".
/// </remarks>
public enum LapsGrantReach
{
    /// <summary>
    /// The entry names this LAPS attribute's schema GUID, so it grants the right for that attribute
    /// and nothing else.
    /// </summary>
    ThisAttributeOnly,

    /// <summary>
    /// The entry carries no object type at all, so it reaches every attribute on the object -
    /// including this one.
    /// </summary>
    EveryAttribute,
}

/// <summary>
/// One principal on the route from the delegated group down to the broad one.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both, because they answer different questions.</b> The identifier is what stays true when a
/// group is renamed or moved, and is what a later run recognises; the name is the only part an
/// operator can act on. Storing one and deriving the other at display time was measured and
/// refused - see <c>P-128</c> - and the same reasoning is why severity is stored as a word and a
/// rank.
/// </para>
/// <para>
/// <b><see cref="Name"/> is null for a principal this bundle does not hold</b>, which is an honest
/// answer rather than a gap: a group from a trusted forest, or one left behind by a deleted object,
/// has no name here and the identifier is then all there is to show.
/// </para>
/// </remarks>
/// <param name="Sid">The principal's security identifier.</param>
/// <param name="Name">What it is called, or null where nothing in this bundle holds it.</param>
public sealed record PathStep(string Sid, string? Name)
{
    /// <summary>The name where there is one, and the identifier where there is not.</summary>
    public string Display => Name ?? Sid;
}

/// <summary>
/// What SEC-090 rested on: a broad principal that can read a machine's LAPS password, and the route
/// by which it got there.
/// </summary>
/// <remarks>
/// <para>
/// <b>The path is the finding.</b> Naming <i>Authenticated Users</i> as able to read a local
/// administrator password tells an operator nothing actionable when the route runs through six
/// nested groups. <see cref="MembershipPath"/> is what says which link to cut, and P-123 requires it
/// outright. Microsoft's least-privilege guidance describes exactly the situation it exists for -
/// "dozens of nested groups that, when expanded, reveal hundreds, even thousands, of accounts" - and
/// the reason nobody acts on that is that the expansion is never shown.
/// </para>
/// <para>
/// <b>Nothing here judges whether the delegation should exist.</b> The product cannot know which
/// principals an organisation intended, which is the owner's decision recorded as <c>P-123</c>. The
/// only claim this evidence supports is that a principal broad in <i>every</i> organisation is
/// inside the delegated one, and that needs no local knowledge.
/// </para>
/// <para>
/// <b><see cref="InheritedFrom"/> is a fact and not a verdict.</b> A grant inherited from the domain
/// root looks alarming and may be entirely deliberate - the live customer whose configuration
/// prompted <c>P-123</c> delegates attribute read at the domain root on purpose. Reporting where the
/// entry came from lets an operator recognise their own decision; calling it wrong would inherit
/// somebody else's idea of normal.
/// </para>
/// <para>
/// <b><see cref="IsComplete"/> is why an empty result is not reassurance.</b> An expansion that
/// stopped at a budget can find no broad principal while one is still inside, so a finding must be
/// able to say that the walk thinned out. Every member listed really is inside the principal; what
/// may not be said is that nothing else is.
/// </para>
/// </remarks>
/// <param name="TrusteeSid">The principal the access control entry names.</param>
/// <param name="TrusteeName">
/// That principal's name where this bundle holds the object carrying the SID, and null otherwise -
/// which is the ordinary case for a well-known identity or a principal from a trusted forest.
/// </param>
/// <param name="BroadPrincipalSid">
/// The principal found inside it that is broad in every organisation.
/// </param>
/// <param name="BroadPrincipalName">
/// What that principal is called, or null where nothing in this bundle holds it.
/// </param>
/// <param name="MembershipPath">
/// The principals from <paramref name="TrusteeSid"/> down to <paramref name="BroadPrincipalSid"/>,
/// that one included. A direct grant to a broad principal yields a path of one.
/// </param>
/// <param name="Attribute">The LAPS password attribute the entry reaches.</param>
/// <param name="Rights">Which of the two rights a confidential attribute needs the entry carried.</param>
/// <param name="Reach">Whether the entry names this attribute or reaches every attribute.</param>
/// <param name="InheritedFrom">
/// The container the entry was inherited from, or null where it was set on the object itself. Stated
/// as a fact; see the remarks.
/// </param>
/// <param name="ExpansionWasComplete">
/// Whether the walk that found the broad principal reached everything nested inside the trustee.
/// </param>
public sealed record LapsPasswordReaderEvidence(
    string TrusteeSid,
    string? TrusteeName,
    string BroadPrincipalSid,
    string? BroadPrincipalName,
    IReadOnlyList<PathStep> MembershipPath,
    string Attribute,
    LapsReadRights Rights,
    LapsGrantReach Reach,
    string? InheritedFrom,
    bool ExpansionWasComplete) : FindingEvidence
{
    /// <summary>
    /// Whether everything nested inside the trustee was reached, so that finding no <i>further</i>
    /// broad principal is a fact rather than a silence.
    /// </summary>
    public bool IsComplete => ExpansionWasComplete;

    /// <summary>
    /// Whether the principal can actually retrieve the password, which needs both rights.
    /// </summary>
    public bool CanReadThePassword => Rights is LapsReadRights.Both;

    /// <summary>
    /// The route as an operator would read it, naming what can be named.
    /// </summary>
    public string Route => string.Join(" -> ", MembershipPath.Select(s => s.Display));

    /// <summary>
    /// How many nested groups lie between the delegated principal and the broad one. Zero for a
    /// delegation made directly to a broad principal.
    /// </summary>
    public int NestingDepth => Math.Max(0, MembershipPath.Count - 1);
}

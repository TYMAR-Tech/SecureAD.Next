namespace SecureAD.Evidence.Findings;

/// <summary>
/// The right that lets a principal take control of an object's permission list.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three rights, and the test each one passes is the same.</b> Does holding this yield control of
/// the object's access control list? Each of these does, and the reasoning for each is Microsoft's
/// rather than this product's — MS-ADTS 6.1.3 gives the generic mapping, and the two explicit rights
/// are named in the access rights constants.
/// </para>
/// <para>
/// <b><c>GenericWrite</c> is deliberately absent, and that is provable rather than a judgement.</b>
/// <c>GENERIC_WRITE_MAPPING</c> is <c>READ_CONTROL</c>, <c>WRITE_PROPERTY</c> and
/// <c>WRITE_PROPERTY_EXTENDED</c> and nothing else, so it cannot yield control of the list. It is
/// still dangerous in other ways, and what it yields depends on the object's class — which is stage
/// 6's work, not this rule's.
/// </para>
/// </remarks>
public enum ObjectTakeoverRight
{
    /// <summary>
    /// Full Control. <c>GENERIC_ALL_MAPPING</c> includes both <c>RIGHT_WRITE_DAC</c> and
    /// <c>RIGHT_WRITE_OWNER</c>, so it grants the whole of what the other two grant.
    /// </summary>
    GenericAll,

    /// <summary>
    /// <c>WRITE_DAC</c> — the right to modify the object's access control list directly. The
    /// shortest route: the holder rewrites the list, including granting itself anything.
    /// </summary>
    WriteDacl,

    /// <summary>
    /// <c>WRITE_OWNER</c> — the right to become the owner, and so to inherit the rights an owner
    /// holds implicitly.
    /// </summary>
    /// <remarks>
    /// <b>This one is conditional and the other two are not.</b> It reaches control in two steps
    /// rather than one, and the second step depends on the owner's implicit rights surviving. Where
    /// the forest has blocked those rights, this is not takeover-class at all, and a finding
    /// claiming otherwise would be false. See <c>SEC-060</c> §4.
    /// </remarks>
    WriteOwner,
}

/// <summary>
/// What SEC-060 rested on: a principal broad in every organisation that can take control of an
/// object, and the route by which it got there.
/// </summary>
/// <remarks>
/// <para>
/// <b>What "take over" means here, in plain terms.</b> The principal can rewrite the object's
/// permission list — granting itself, or anybody else, full control of that object — and nothing
/// about the object will look unusual afterwards. A permission list shows what was granted. It does
/// not show what the grant is <i>worth</i>.
/// </para>
/// <para>
/// <b>The path is the finding, for the reason <c>P-123</c> gives.</b> Naming <i>Domain Users</i> as
/// able to take over an object tells an operator nothing actionable when the route runs through
/// several nested groups. <see cref="MembershipPath"/> is what says which link to cut.
/// </para>
/// <para>
/// <b>Nothing here says the permission is a mistake.</b> It may be deliberate. This product cannot
/// know which principals an organisation intended to hold access, so the only claim made is that the
/// holder is broad in <i>every</i> organisation — which needs no local knowledge.
/// </para>
/// </remarks>
/// <param name="TrusteeSid">The principal the access control entry names.</param>
/// <param name="TrusteeName">
/// That principal's name where this bundle holds the object carrying the SID, and null otherwise.
/// </param>
/// <param name="BroadPrincipalSid">The principal found inside it that is broad everywhere.</param>
/// <param name="BroadPrincipalName">What that principal is called, or null where nothing holds it.</param>
/// <param name="MembershipPath">
/// The principals from the trustee down to the broad principal, that one included. A grant made
/// directly to a broad principal yields a path of one.
/// </param>
/// <param name="Right">Which takeover-class right the entry effectively carried.</param>
/// <param name="InheritedFrom">
/// The container the entry was inherited from, or null where it was set on the object itself. Stated
/// as a fact and not as a verdict: a grant inherited from the domain root may be entirely deliberate.
/// </param>
/// <param name="ExpansionWasComplete">
/// Whether the walk that found the broad principal reached everything nested inside the trustee.
/// </param>
public sealed record ObjectTakeoverEvidence(
    string TrusteeSid,
    string? TrusteeName,
    string BroadPrincipalSid,
    string? BroadPrincipalName,
    IReadOnlyList<PathStep> MembershipPath,
    ObjectTakeoverRight Right,
    string? InheritedFrom,
    bool ExpansionWasComplete) : FindingEvidence
{
    /// <summary>
    /// Whether everything nested inside the trustee was reached, so that finding no <i>further</i>
    /// broad principal is a fact rather than a silence.
    /// </summary>
    public bool IsComplete => ExpansionWasComplete;

    /// <summary>The route as an operator would read it, naming what can be named.</summary>
    public string Route => string.Join(" -> ", MembershipPath.Select(s => s.Display));

    /// <summary>
    /// How many nested groups lie between the named principal and the broad one. Zero for a grant
    /// made directly to a broad principal.
    /// </summary>
    public int NestingDepth => Math.Max(0, MembershipPath.Count - 1);

    /// <summary>
    /// Whether control is reached by becoming the owner rather than directly, which is the case
    /// that depends on the forest not having blocked an owner's implicit rights.
    /// </summary>
    public bool ThroughOwnership => Right is ObjectTakeoverRight.WriteOwner;
}

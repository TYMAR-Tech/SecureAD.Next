namespace SecureAD.Kernel.Security;

/// <summary>
/// Which objects an access control entry actually controls access to.
/// </summary>
/// <remarks>
/// <para>
/// An entry lives in one object's DACL, and that is not the same as governing that object.
/// <c>INHERIT_ONLY_ACE</c> means the entry <b>does not control access to the object it is attached
/// to</b>; it sits there to be copied to the objects beneath it. MS-DTYP 2.4.4.1.
/// </para>
/// <para>
/// This exists because the classifier was answering without it. Its reasons say things like
/// "hands somebody control of this object", and for an inherit-only entry that sentence is false -
/// the grant is real and it lands somewhere else. Getting it wrong over-reports rather than under-
/// reports, which is the safe direction, but it put two components of one row in disagreement:
/// the Scope column read <i>All descendant objects</i> beside a mark claiming a grant here.
/// Recorded as <c>F-S58-6</c> against <c>S-56</c> R13.
/// </para>
/// </remarks>
public enum EntryReach
{
    /// <summary>
    /// The entry controls access to the object it is attached to. This is the ordinary case and
    /// the reading every entry gets unless <c>INHERIT_ONLY_ACE</c> says otherwise.
    /// </summary>
    ThisObject,

    /// <summary>
    /// <c>INHERIT_ONLY_ACE</c> is set, so the entry grants nothing on the object it is attached to
    /// and everything it says applies to the objects beneath it.
    /// </summary>
    DescendantsOnly,
}

/// <summary>
/// Reads <see cref="EntryReach"/> off the propagation flags the directory stored.
/// </summary>
/// <remarks>
/// The bit lives here rather than at each call site because it was already written down twice -
/// <c>SecurityDescriptorParser</c> and <c>PermissionScope</c> each keep a private copy - and a
/// third would have been the one that drifted.
/// </remarks>
public static class EntryReachReader
{
    /// <summary>
    /// <c>INHERIT_ONLY_ACE</c>, from MS-DTYP 2.4.4.1.
    /// </summary>
    private const byte InheritOnlyAce = 0x08;

    /// <summary>
    /// What the entry governs, given its propagation flags.
    /// </summary>
    /// <param name="propagationFlags">
    /// The entry's <c>NO_PROPAGATE_INHERIT_ACE</c> and <c>INHERIT_ONLY_ACE</c> bits, as
    /// <see cref="SecurityDescriptorParser"/> separated them out of <c>AceFlags</c>.
    /// </param>
    public static EntryReach FromPropagationFlags(byte propagationFlags) =>
        (propagationFlags & InheritOnlyAce) != 0
            ? EntryReach.DescendantsOnly
            : EntryReach.ThisObject;
}

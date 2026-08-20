namespace SecureAD.Kernel.Security;

/// <summary>
/// A single ACE parsed from the DACL of a binary security descriptor.
/// Pure data record — no interpretation of rights or control semantics.
/// </summary>
/// <remarks>
/// <para>
/// <b>The DACL, and only the DACL.</b> Capture never requests the SACL, per
/// <c>docs/decisions/0036-capture-never-requests-the-sacl.md</c>, so nothing here ever describes an
/// audit entry. This summary used to say <i>DACL or SACL</i>, which promised a capability the
/// product does not have and has decided not to acquire.
/// </para>
/// <para>
/// <b>Three members exist to keep what the wire carried rather than a reading of it.</b>
/// <see cref="Ordinal"/> is the stored position, which <c>AceNormalizer</c> sorts away.
/// <see cref="ObjectFlags"/> is the field that decides GUID presence, without which <i>absent</i>
/// and <i>the null GUID</i> collapse together. <see cref="ApplicationData"/> is what a callback ACE
/// carries and what makes a conditional ACE conditional - discarded, an entry that may not apply at
/// all is indistinguishable from one that always does. Required by <c>docs/next/S-56</c> R1.
/// </para>
/// <para>
/// <b><see cref="ApplicationData"/> makes value equality unreliable on this type.</b> A record
/// compares an array by reference, so two ACEs with identical bytes are unequal. Nothing compares
/// <c>ParsedAce</c> today - equality and de-duplication happen on <see cref="CanonicalAce"/>, which
/// is hashed from named fields - and anything that starts to must compare the bytes itself.
/// </para>
/// </remarks>
/// <param name="AceType">ACE type (AccessAllowed, AccessDenied, Object variants, etc.).</param>
/// <param name="AceFlags">Raw ACE flags byte (inheritance, audit flags).</param>
/// <param name="AccessMask">Raw 32-bit access mask.</param>
/// <param name="TrusteeSid">Trustee SID in SDDL string form (e.g., "S-1-5-21-...").</param>
/// <param name="ObjectTypeGuid">ObjectType GUID for object ACEs, null for non-object ACEs. Lowercase 8-4-4-4-12 format.</param>
/// <param name="InheritedObjectTypeGuid">InheritedObjectType GUID for object ACEs, null for non-object ACEs. Lowercase 8-4-4-4-12 format.</param>
/// <param name="IsInherited">True if this ACE was inherited (INHERITED_ACE flag set).</param>
/// <param name="InheritanceFlags">Inheritance flags extracted from AceFlags (CONTAINER_INHERIT, OBJECT_INHERIT).</param>
/// <param name="PropagationFlags">Propagation flags extracted from AceFlags (INHERIT_ONLY, NO_PROPAGATE).</param>
/// <param name="Ordinal">
/// The entry's position in the DACL as the directory stored it, counting from zero.
/// </param>
/// <param name="ObjectFlags">
/// The raw <c>Flags</c> field of an object ACE, which states which GUIDs are present. Zero for
/// non-object ACE types, which have no such field.
/// </param>
/// <param name="ApplicationData">
/// The bytes a callback ACE carries after the trustee SID. Empty for every other ACE type.
/// </param>
public sealed record ParsedAce(
    AceType AceType,
    byte AceFlags,
    int AccessMask,
    string TrusteeSid,
    string? ObjectTypeGuid,
    string? InheritedObjectTypeGuid,
    bool IsInherited,
    byte InheritanceFlags,
    byte PropagationFlags,
    int Ordinal,
    int ObjectFlags,
    byte[] ApplicationData)
{
    /// <summary>ACE_OBJECT_TYPE_PRESENT, from [MS-DTYP] 2.4.4.3.</summary>
    private const int AceObjectTypePresent = 0x01;

    /// <summary>ACE_INHERITED_OBJECT_TYPE_PRESENT, from [MS-DTYP] 2.4.4.3.</summary>
    private const int AceInheritedObjectTypePresent = 0x02;

    /// <summary>
    /// Whether the entry actually carried an <c>ObjectType</c> GUID.
    /// </summary>
    /// <remarks>
    /// <b>Presence is a flag, not a null check.</b> [MS-DTYP] defines it by
    /// <c>ACE_OBJECT_TYPE_PRESENT</c>, and asking whether
    /// <see cref="ObjectTypeGuid"/> is null cannot separate <i>absent</i> from <i>present and equal
    /// to the null GUID</i>. Those mean different things: an object ACE carrying neither GUID has
    /// the same access semantics as its plain counterpart and narrows nothing, whereas a GUID that
    /// is present names what the entry is scoped to. A reader that infers presence from nullity is
    /// guessing. Required by <c>docs/next/S-56</c> R1.
    /// </remarks>
    public bool HasObjectType => (ObjectFlags & AceObjectTypePresent) != 0;

    /// <summary>
    /// Whether the entry actually carried an <c>InheritedObjectType</c> GUID, on the same terms as
    /// <see cref="HasObjectType"/>.
    /// </summary>
    public bool HasInheritedObjectType => (ObjectFlags & AceInheritedObjectTypePresent) != 0;
}

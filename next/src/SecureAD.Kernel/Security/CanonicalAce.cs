namespace SecureAD.Kernel.Security;

/// <summary>
/// A fully normalized, canonical ACE.
/// Produced by <see cref="AceNormalizer"/> from a <see cref="ParsedAce"/>.
/// All fields are deterministic: same raw SD + same canonicalization version = identical CanonicalAce.
/// </summary>
/// <param name="ObjectGuid">GUID of the AD object this ACE belongs to.</param>
/// <param name="AceType">ACE type (AccessAllowed, AccessDenied, Object variants).</param>
/// <param name="TrusteeSid">Trustee SID in SDDL string form.</param>
/// <param name="AccessMask">Normalized 32-bit access mask (generic rights expanded).</param>
/// <param name="ObjectTypeGuid">Normalized ObjectType GUID (lowercase 8-4-4-4-12), or null.</param>
/// <param name="InheritedObjectTypeGuid">Normalized InheritedObjectType GUID (lowercase 8-4-4-4-12), or null.</param>
/// <param name="IsInherited">True if this ACE was inherited.</param>
/// <param name="InheritanceFlags">Inheritance flags (CONTAINER_INHERIT, OBJECT_INHERIT).</param>
/// <param name="PropagationFlags">Propagation flags (INHERIT_ONLY, NO_PROPAGATE).</param>
/// <param name="AceHash">Deterministic SHA-256 hash (lowercase hex) computed from all canonical fields.</param>
/// <param name="CanonicalizationVersion">Version of the normalization logic that produced this ACE.</param>
public sealed record CanonicalAce(
    Guid ObjectGuid,
    AceType AceType,
    string TrusteeSid,
    int AccessMask,
    string? ObjectTypeGuid,
    string? InheritedObjectTypeGuid,
    bool IsInherited,
    byte InheritanceFlags,
    byte PropagationFlags,
    string AceHash,
    int CanonicalizationVersion);

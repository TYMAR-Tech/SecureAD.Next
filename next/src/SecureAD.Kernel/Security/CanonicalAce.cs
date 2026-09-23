namespace SecureAD.Kernel.Security;

/// <summary>
/// A fully normalized, canonical ACE.
/// Produced by <see cref="AceNormalizer"/> from a <see cref="ParsedAce"/>.
/// All fields are deterministic: same raw SD + same canonicalization version = identical CanonicalAce.
/// </summary>
/// <remarks>
/// <b>It names no object, and that is what lets one be stored once.</b> Until canonicalization
/// version 4 this carried the GUID of the object the entry was found on, so one entry inherited by
/// a hundred thousand descendants was a hundred thousand different values - and the production
/// capture of 2026-09-23 stored each distinct entry 294 times as a result. Where an entry was found
/// is a fact about the descriptor holding it, not about the entry, and the bundle records it as a
/// link. See <c>P-272</c>.
/// </remarks>
/// <param name="AceType">ACE type (AccessAllowed, AccessDenied, Object variants).</param>
/// <param name="TrusteeSid">Trustee SID in SDDL string form.</param>
/// <param name="AccessMask">Normalized 32-bit access mask (generic rights expanded).</param>
/// <param name="ObjectTypeGuid">Normalized ObjectType GUID (lowercase 8-4-4-4-12), or null.</param>
/// <param name="InheritedObjectTypeGuid">Normalized InheritedObjectType GUID (lowercase 8-4-4-4-12), or null.</param>
/// <param name="IsInherited">True if this ACE was inherited.</param>
/// <param name="InheritanceFlags">Inheritance flags (CONTAINER_INHERIT, OBJECT_INHERIT).</param>
/// <param name="PropagationFlags">Propagation flags (INHERIT_ONLY, NO_PROPAGATE).</param>
/// <param name="ApplicationData">
/// The callback ACE's condition bytes, empty for every other type.
///
/// <para>
/// <b>Carried because <see cref="AceHash"/> covers it.</b> It has been inside the hash since
/// version 3, where it was added so that two entries granting the same rights under different
/// conditions could not collide - but it was stored nowhere, so an entry row could not reproduce
/// its own hash and two genuinely different conditional entries were identical to read. That was
/// harmless while every entry belonged to one object; it is not once the hash is the key an entry
/// is stored under.
/// </para>
/// </param>
/// <param name="AceHash">Deterministic SHA-256 hash (lowercase hex) computed from all canonical fields.</param>
/// <param name="CanonicalizationVersion">Version of the normalization logic that produced this ACE.</param>
public sealed record CanonicalAce(
    AceType AceType,
    string TrusteeSid,
    int AccessMask,
    string? ObjectTypeGuid,
    string? InheritedObjectTypeGuid,
    bool IsInherited,
    byte InheritanceFlags,
    byte PropagationFlags,
    ReadOnlyMemory<byte> ApplicationData,
    string AceHash,
    int CanonicalizationVersion);

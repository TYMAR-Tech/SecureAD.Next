namespace SecureAD.Kernel.Security;

/// <summary>
/// Result of normalizing all ACEs from a single object's security descriptor.
/// Contains the canonical ACE list, owner/group, DACL metadata, and any errors.
/// </summary>
/// <param name="ObjectGuid">GUID of the AD object.</param>
/// <param name="OwnerSid">Owner SID from the security descriptor, or null.</param>
/// <param name="GroupSid">Group SID from the security descriptor, or null.</param>
/// <param name="DaclState">Whether the DACL is Present, Null, Empty, or Unreadable.</param>
/// <param name="IsDaclProtected">True if SE_DACL_PROTECTED is set.</param>
/// <param name="Aces">Canonically ordered, deduplicated ACEs with deterministic hashes.</param>
/// <param name="Errors">Normalization errors. Empty if normalization succeeded fully.</param>
/// <param name="DaclCompleteness">Whether the DACL yielded every entry its header declared.</param>
/// <param name="DaclWasCanonical">
/// Whether the entries arrived in canonical order, as judged before this type sorted them.
/// </param>
/// <remarks>
/// Both trailing facts are carried rather than recomputed, because neither survives normalisation:
/// <see cref="Aces"/> is sorted, so arrival order is gone, and it is deduplicated and filtered, so
/// its length no longer answers how many entries the descriptor declared. They come from
/// <see cref="ParsedSecurityDescriptor"/> untouched.
/// </remarks>
public sealed record AceNormalizationResult(
    Guid ObjectGuid,
    string? OwnerSid,
    string? GroupSid,
    DaclState DaclState,
    bool IsDaclProtected,
    IReadOnlyList<CanonicalAce> Aces,
    IReadOnlyList<string> Errors,
    DaclCompleteness DaclCompleteness,
    bool DaclWasCanonical);

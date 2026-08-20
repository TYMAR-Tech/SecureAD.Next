namespace SecureAD.Kernel.Security;

/// <summary>
/// Result of parsing a raw binary ntSecurityDescriptor.
/// Contains owner, group, DACL state, protection flag, parsed ACEs, and any parse errors.
/// </summary>
/// <param name="OwnerSid">Owner SID in SDDL string form, or null if absent.</param>
/// <param name="GroupSid">Primary group SID in SDDL string form, or null if absent.</param>
/// <param name="DaclState">Whether the DACL is Present, Null, or Empty.</param>
/// <param name="IsDaclProtected">True if SE_DACL_PROTECTED is set (inheritance blocked).</param>
/// <param name="DaclAces">Parsed ACEs from the DACL. Empty if DACL is Null or Empty.</param>
/// <param name="ControlFlags">Raw 16-bit control flags from the SD header.</param>
/// <param name="Errors">Parse errors encountered. Empty if parsing succeeded fully.</param>
/// <param name="DaclCompleteness">
/// Whether every entry the DACL header declared was actually parsed.
/// </param>
/// <param name="DaclWasCanonical">
/// Whether the entries arrived in canonical order, judged before anything sorted them.
/// </param>
/// <remarks>
/// <para>
/// <b>The last two exist so that a caller can tell what it is missing.</b>
/// <paramref name="DaclCompleteness"/> is the difference between a DACL that was read completely
/// and one that was read in part, which <see cref="DaclState"/> deliberately cannot express because
/// a partly read DACL is genuinely <see cref="DaclState.Present"/>. Required by
/// <c>docs/decisions/0037-an-unreadable-dacl-says-so.md</c>.
/// </para>
/// <para>
/// <paramref name="DaclWasCanonical"/> is the one fact the canonical form destroys.
/// <c>AceNormalizer</c> sorts every DACL, so after normalisation nothing says the directory stored
/// it differently - and an allow placed before a deny grants access that the sorted form denies,
/// because Windows stops at the first match. Required by
/// <c>docs/decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md</c>. Exact order is
/// not carried here: the bundle keeps the raw bytes, and re-parsing recovers it.
/// </para>
/// <para>
/// <b>Neither has a default, deliberately.</b> A default of <c>true</c> for
/// <paramref name="DaclWasCanonical"/> would be a false-safe: any path that forgot to set it would
/// silently claim the DACL arrived in order. Requiring both means the compiler names every site
/// that builds a descriptor, which is the property
/// <c>docs/decisions/0026-one-answer-to-whether-runs-may-be-compared.md</c> buys deliberately
/// elsewhere - a doorway that has not been updated does not build.
/// </para>
/// </remarks>
public sealed record ParsedSecurityDescriptor(
    string? OwnerSid,
    string? GroupSid,
    DaclState DaclState,
    bool IsDaclProtected,
    IReadOnlyList<ParsedAce> DaclAces,
    ushort ControlFlags,
    IReadOnlyList<string> Errors,
    DaclCompleteness DaclCompleteness,
    bool DaclWasCanonical);

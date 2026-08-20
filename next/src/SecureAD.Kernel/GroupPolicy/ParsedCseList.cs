namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// The client-side extensions declared by a GPO's <c>gPCMachineExtensionNames</c> attribute, and
/// whatever could not be read from it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The errors are the point of this type.</b> The parse skips a token it cannot read rather
/// than throwing, which is right - one malformed entry should not cost the whole attribute - but
/// it means a shorter list than the GPO really declared. Handing back only the list would make
/// that indistinguishable from a GPO that genuinely declares fewer extensions, and the caller
/// deciding whether to fetch a GPO's policy files would then skip a GPO whose Registry or Security
/// extension was the unreadable token.
/// </para>
/// <para>
/// The shape matches <see cref="ParsedRegistryPolicy"/> and <see cref="ParsedGppFile"/>: what was
/// read, beside what could not be.
/// </para>
/// </remarks>
/// <param name="Cses">
/// The distinct client-side-extension GUIDs that were read, in the order they appeared. Empty if
/// the attribute was absent, empty, or held nothing readable.
/// </param>
/// <param name="Errors">
/// What could not be read, one entry per unreadable token. Empty when the whole attribute was
/// understood.
/// </param>
public sealed record ParsedCseList(
    IReadOnlyList<Guid> Cses,
    IReadOnlyList<string> Errors);

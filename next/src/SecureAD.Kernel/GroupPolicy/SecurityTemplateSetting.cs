namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// A single name/value setting parsed from a section of a GptTmpl.inf security template.
/// Pure data record — the raw <see cref="Value"/> string is preserved verbatim; callers
/// interpret it per the owning section's semantics (comma list, number, SDDL, etc.).
/// </summary>
/// <param name="Name">The setting name (left-hand side of "Name = Value").</param>
/// <param name="Value">The raw setting value exactly as it appeared (right-hand side), trimmed of surrounding whitespace.</param>
public sealed record SecurityTemplateSetting(
    string Name,
    string Value);

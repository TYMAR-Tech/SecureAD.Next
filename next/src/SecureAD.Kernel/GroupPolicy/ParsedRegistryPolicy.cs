namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Result of parsing a Registry.pol file.
/// Contains the parsed value entries and any errors encountered during parsing.
/// </summary>
/// <param name="Entries">Parsed registry value entries, in file order. Empty if the file held no entries.</param>
/// <param name="Errors">Parse errors encountered. Empty if parsing succeeded fully.</param>
public sealed record ParsedRegistryPolicy(
    IReadOnlyList<RegistryPolicyEntry> Entries,
    IReadOnlyList<string> Errors);

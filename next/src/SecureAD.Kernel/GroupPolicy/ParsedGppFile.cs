namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Result of scanning a Group Policy Preferences XML file (Groups.xml, Services.xml,
/// ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml) for <c>cpassword</c> exposures.
/// </summary>
/// <param name="Findings">
/// Presence-only locators for each non-empty <c>cpassword</c> attribute found. Empty when the file
/// contains no stored credentials.
/// </param>
/// <param name="Errors">Parse errors encountered. Empty if scanning succeeded fully.</param>
public sealed record ParsedGppFile(
    IReadOnlyList<GppPasswordFinding> Findings,
    IReadOnlyList<string> Errors);

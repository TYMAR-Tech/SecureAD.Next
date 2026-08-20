namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// A presence-only locator for a Group Policy Preferences (GPP) <c>cpassword</c> exposure
/// (MS14-025 / CVE-2014-1812). Records <b>that</b> an encrypted password is present and the
/// metadata needed to find and remediate it — never the password value itself.
/// <para>
/// By design this record has no field that holds the <c>cpassword</c> attribute (encrypted or
/// decrypted). The parser tests only whether the attribute is present and non-empty, then
/// discards it. The credential never enters the type system, so it cannot be returned, logged,
/// or persisted. Operators verify natively (e.g. <c>findstr /s /i cpassword \\domain\SYSVOL\...</c>).
/// </para>
/// </summary>
/// <param name="ElementType">
/// The GPP element carrying the password (e.g., "User", "NTService", "Task", "DataSource",
/// "Drive", "Printer"), used to describe what kind of credential is exposed.
/// </param>
/// <param name="AccountName">
/// The account the password is for, when the element exposes it (e.g., the local user name,
/// service "accountName", or drive "userName"). Null when the source file does not name an account.
/// </param>
/// <param name="SourceAttribute">
/// The attribute on the element that names the account (e.g., "userName", "accountName", "runAs"),
/// for provenance. Null when no account attribute was present.
/// </param>
public sealed record GppPasswordFinding(
    string ElementType,
    string? AccountName,
    string? SourceAttribute);

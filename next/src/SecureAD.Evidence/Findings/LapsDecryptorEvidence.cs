namespace SecureAD.Evidence.Findings;

/// <summary>
/// How the <c>ADPasswordEncryptionPrincipal</c> value was written, since Microsoft accepts three
/// forms and only one of them can be matched without asking the directory.
/// </summary>
/// <remarks>
/// <para>
/// Microsoft's
/// <see href="https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings#adpasswordencryptionprincipal">
/// policy settings reference</see> gives the accepted forms as an identifier in string form
/// (<c>S-1-5-21-…-35197</c>), a qualified name (<c>contoso\LAPSAdmins</c>) or a user principal name
/// (<c>lapsadmins@contoso.com</c>), and requires that the principal "must exist and be resolvable by
/// the device".
/// </para>
/// <para>
/// <b>The form is kept because it decides what an unresolved value means.</b> An identifier this
/// bundle cannot place is a principal from somewhere the capture did not read; a name it cannot
/// place may be a typo that stops the policy working altogether. Those are different things to tell
/// an operator, and collapsing them into "unresolved" would lose the difference.
/// </para>
/// </remarks>
public enum LapsDecryptorForm
{
    /// <summary>A security identifier in string form, which needs no lookup to interpret.</summary>
    SecurityIdentifier,

    /// <summary>
    /// A qualified name, <c>DOMAIN\name</c>, which only the directory can turn into an identifier.
    /// </summary>
    QualifiedName,

    /// <summary>
    /// A user principal name, <c>name@domain</c>, which likewise needs the directory.
    /// </summary>
    UserPrincipalName,
}

/// <summary>
/// What SEC-093 rested on: a Group Policy Object whose authorized LAPS password decryptor is, or
/// contains, a principal broad in every organisation.
/// </summary>
/// <remarks>
/// <para>
/// <b>The subject is the policy and never a machine, and that is a refusal rather than a gap.</b>
/// Microsoft states that the principal authorized to decrypt "can't be changed after a password is
/// encrypted", so a password already in the directory was encrypted against whatever the policy
/// named at the moment it was written - a value the directory does not record. Naming the machines
/// affected would therefore assert something about the past that no evidence establishes, which is
/// what <c>docs/decisions/0086</c> puts out of bounds. The owner settled it on 2026-09-03.
/// </para>
/// <para>
/// <b>Nested membership is the rule, not an edge of it.</b> Windows LAPS encrypts against exactly
/// one principal, and Microsoft's documented answer to needing more than one is to "create a wrapper
/// group that has all the relevant security principals as members". So the supported configuration
/// is a group, and what matters is what ended up inside it - which is why
/// <see cref="MembershipPath"/> carries the route and not just the endpoints.
/// </para>
/// <para>
/// <b>Correcting the policy does not undo the exposure</b>, for the same reason the subject is the
/// policy: every password already stored stays decryptable by the old principal until it is
/// rotated. Every finding says so, because an operator who fixes the setting and stops has not
/// finished.
/// </para>
/// </remarks>
/// <param name="PolicyDisplayName">
/// The name an administrator knows the policy by, or null where the policy carried none. The
/// distinguished name is a GUID and is unusable in a report.
/// </param>
/// <param name="ConfiguredValue">
/// The <c>ADPasswordEncryptionPrincipal</c> value exactly as the policy states it, kept verbatim so
/// an operator can find the setting they have to change.
/// </param>
/// <param name="Form">How that value was written.</param>
/// <param name="DecryptorSid">
/// The identifier the value resolved to, or null where it could not be resolved.
/// </param>
/// <param name="DecryptorName">What the decryptor is called, where this bundle can say.</param>
/// <param name="BroadPrincipalSid">
/// The broad principal that can decrypt, or null on a finding that could not resolve the decryptor
/// at all.
/// </param>
/// <param name="BroadPrincipalName">What that principal is called.</param>
/// <param name="MembershipPath">
/// The route from the configured decryptor down to the broad principal. A single step where the
/// decryptor is itself broad.
/// </param>
/// <param name="ExpansionWasComplete">
/// Whether the walk reached everything nested inside the decryptor.
/// </param>
public sealed record LapsDecryptorEvidence(
    string? PolicyDisplayName,
    string ConfiguredValue,
    LapsDecryptorForm Form,
    string? DecryptorSid,
    string? DecryptorName,
    string? BroadPrincipalSid,
    string? BroadPrincipalName,
    IReadOnlyList<PathStep> MembershipPath,
    bool ExpansionWasComplete) : FindingEvidence
{
    /// <summary>
    /// Whether the decryptor was resolved and its membership walked to the end, so that finding no
    /// broad principal would be a fact rather than a silence.
    /// </summary>
    public bool IsComplete => DecryptorSid is not null && ExpansionWasComplete;

    /// <summary>
    /// Whether a broad principal was actually found, as against the decryptor being unresolvable.
    /// </summary>
    /// <remarks>
    /// <b>The two are separate findings about separate problems.</b> A broad decryptor means the
    /// password is protected against too many people. An unresolvable one means Microsoft's
    /// documented behaviour applies - "a policy processing failure occurs and the managed account's
    /// password isn't backed up" - so no password is being stored at all. Reporting the second as
    /// the first would send an operator to fix the wrong thing.
    /// </remarks>
    public bool BroadPrincipalFound => BroadPrincipalSid is not null;

    /// <summary>The route as an operator would read it, naming what can be named.</summary>
    public string Route => string.Join(" -> ", MembershipPath.Select(s => s.Display));

    /// <summary>
    /// How many nested groups lie between the configured decryptor and the broad principal. Zero
    /// where the policy names a broad principal outright.
    /// </summary>
    public int NestingDepth => Math.Max(0, MembershipPath.Count - 1);
}

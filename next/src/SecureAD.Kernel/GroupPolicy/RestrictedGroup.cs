namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// A Restricted Groups entry parsed from the [Group Membership] section of a GptTmpl.inf
/// security template. Combines the "__Members" and "__Memberof" lines for a single principal.
/// </summary>
/// <param name="GroupName">
/// The principal the entry applies to (group or account). The security-template "*" SID prefix,
/// when present, is stripped so the value is a bare SID (e.g., "S-1-5-32-544") or a name.
/// </param>
/// <param name="Members">
/// Principals declared as members of <paramref name="GroupName"/> (from the "__Members" line).
/// Empty if no such line existed. "*" prefixes are stripped.
/// </param>
/// <param name="MemberOf">
/// Groups that <paramref name="GroupName"/> is declared a member of (from the "__Memberof" line).
/// Empty if no such line existed. "*" prefixes are stripped.
/// </param>
public sealed record RestrictedGroup(
    string GroupName,
    IReadOnlyList<string> Members,
    IReadOnlyList<string> MemberOf);

using System.Globalization;

namespace SecureAD.Kernel.Security;

/// <summary>
/// What a group's <c>groupType</c> says: its scope, and whether it can hold permissions at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>The two halves are not the same question and are worded separately.</b> Scope decides where a
/// group may be used and what it may contain; <see cref="IsSecurityGroup"/> decides whether it can
/// appear in an access control list. A distribution group named <i>Domain Admins Mail</i> holding
/// no permission at all is a different object from the security group beside it, and a viewer that
/// showed only <i>Universal</i> would not tell them apart.
/// </para>
/// <para>
/// <b>The value arrives negative.</b> The security bit is <c>0x80000000</c> in a signed 32-bit
/// field, so an ordinary global security group is stored as <c>-2147483646</c>. Microsoft's own
/// search examples use <c>-2147483648</c> for the flag. A reader parsing this as unsigned rejects
/// every security group in the forest and reports them all as unreadable; one parsing it as signed
/// and then testing the bit arithmetically is what this does.
/// </para>
/// <para>
/// Transcribed from <c>learn.microsoft.com/windows/win32/adschema/a-grouptype</c> on 2026-08-18 and
/// asserted bit by bit by <c>GroupTypeWordingTests</c>.
/// </para>
/// </remarks>
/// <param name="Value">The value as the directory holds it.</param>
/// <param name="Scope">
/// The group's scope in words, or null when no scope bit is set - which is a malformed group rather
/// than a group with no scope.
/// </param>
/// <param name="IsSecurityGroup">
/// Whether the group can hold permissions. False means it is a distribution group and appears in no
/// access control list.
/// </param>
/// <param name="IsSystemGroup">Whether the directory created the group rather than a person.</param>
public sealed record GroupTypeWording(
    int Value, string? Scope, bool IsSecurityGroup, bool IsSystemGroup)
{
    private const int SystemCreated = 0x00000001;
    private const int Global = 0x00000002;
    private const int DomainLocal = 0x00000004;
    private const int Universal = 0x00000008;
    private const int SecurityEnabled = unchecked((int)0x80000000);

    /// <summary>
    /// The whole value in one sentence, as a screen shows it.
    /// </summary>
    /// <remarks>
    /// Says <i>distribution</i> out loud rather than leaving it to be inferred from the absence of
    /// the word <i>security</i>. An operator scanning a list of groups reads what is there.
    /// </remarks>
    public string Worded =>
        (Scope is null ? "Group of no scope this build recognises" : Scope)
        + (IsSecurityGroup ? " security group" : " distribution group")
        + (IsSystemGroup ? ", created by the directory" : string.Empty);

    /// <summary>
    /// Reads a stored <c>groupType</c>, or null when the text is not one.
    /// </summary>
    /// <param name="stored">The value as the bundle holds it.</param>
    public static GroupTypeWording? Of(string? stored)
    {
        if (!int.TryParse(stored, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value))
            return null;

        return new GroupTypeWording(
            value,
            ScopeOf(value),
            (value & SecurityEnabled) != 0,
            (value & SystemCreated) != 0);
    }

    /// <summary>
    /// The scope bits, of which exactly one is set on a well-formed group.
    /// </summary>
    /// <remarks>
    /// Null rather than a guess when none is set or more than one is. A group claiming two scopes
    /// is not a thing Active Directory produces, and picking the first would hide that the object
    /// is malformed.
    /// </remarks>
    private static string? ScopeOf(int value) =>
        (value & (Global | DomainLocal | Universal)) switch
        {
            Global => "Global",
            DomainLocal => "Domain local",
            Universal => "Universal",
            _ => null,
        };
}

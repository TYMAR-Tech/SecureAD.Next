namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Result of parsing a GptTmpl.inf security template.
/// Holds every section losslessly as raw name/value settings, plus typed accessors for the
/// two security-relevant sections ([Privilege Rights] and [Group Membership]). Sections not
/// given a typed accessor remain available through <see cref="GetSection"/>.
/// </summary>
/// <param name="Sections">
/// All parsed sections keyed by section name (case-insensitive), each a list of settings in file order.
/// </param>
/// <param name="Errors">Parse errors encountered. Empty if parsing succeeded fully.</param>
public sealed record ParsedSecurityTemplate(
    IReadOnlyDictionary<string, IReadOnlyList<SecurityTemplateSetting>> Sections,
    IReadOnlyList<string> Errors)
{
    private const string PrivilegeRightsSection = "Privilege Rights";
    private const string GroupMembershipSection = "Group Membership";
    private const string MembersSuffix = "__Members";
    private const string MemberOfSuffix = "__Memberof";

    /// <summary>
    /// Returns the raw settings of a section by name (case-insensitive), or an empty list if absent.
    /// </summary>
    /// <param name="sectionName">The section name without brackets (e.g., "System Access").</param>
    public IReadOnlyList<SecurityTemplateSetting> GetSection(string sectionName)
    {
        ArgumentNullException.ThrowIfNull(sectionName);
        return Sections.TryGetValue(sectionName, out var settings) ? settings : [];
    }

    /// <summary>
    /// Interprets the [Privilege Rights] section as a map from privilege constant
    /// (e.g., "SeDebugPrivilege") to the trustees granted it. The security-template "*" SID
    /// prefix is stripped from each trustee. Returns an empty map if the section is absent.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<string>> GetPrivilegeRights()
    {
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var setting in GetSection(PrivilegeRightsSection))
        {
            result[setting.Name] = SplitTrusteeList(setting.Value);
        }

        return result;
    }

    /// <summary>
    /// Interprets the [Group Membership] section as Restricted Groups entries, combining the
    /// "__Members" and "__Memberof" lines for each principal. "*" SID prefixes are stripped.
    /// Returns an empty list if the section is absent.
    /// </summary>
    public IReadOnlyList<RestrictedGroup> GetGroupMemberships()
    {
        var section = GetSection(GroupMembershipSection);
        if (section.Count == 0)
        {
            return [];
        }

        // Preserve first-seen order of principals for deterministic output.
        var order = new List<string>();
        var members = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var memberOf = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var setting in section)
        {
            string groupName;
            bool isMembers;

            if (setting.Name.EndsWith(MembersSuffix, StringComparison.OrdinalIgnoreCase))
            {
                groupName = setting.Name[..^MembersSuffix.Length];
                isMembers = true;
            }
            else if (setting.Name.EndsWith(MemberOfSuffix, StringComparison.OrdinalIgnoreCase))
            {
                groupName = setting.Name[..^MemberOfSuffix.Length];
                isMembers = false;
            }
            else
            {
                continue; // unrecognized line shape — left in the raw section only
            }

            groupName = StripStar(groupName.Trim());

            if (!members.ContainsKey(groupName))
            {
                order.Add(groupName);
                members[groupName] = [];
                memberOf[groupName] = [];
            }

            var values = SplitTrusteeList(setting.Value);
            (isMembers ? members[groupName] : memberOf[groupName]).AddRange(values);
        }

        var result = new List<RestrictedGroup>(order.Count);
        foreach (var groupName in order)
        {
            result.Add(new RestrictedGroup(groupName, members[groupName], memberOf[groupName]));
        }

        return result;
    }

    /// <summary>
    /// Splits a comma-separated trustee list, trimming whitespace, dropping empty entries,
    /// and stripping the security-template "*" SID prefix from each entry.
    /// </summary>
    private static IReadOnlyList<string> SplitTrusteeList(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new List<string>(parts.Length);
        foreach (var part in parts)
        {
            result.Add(StripStar(part));
        }

        return result;
    }

    private static string StripStar(string value) =>
        value.StartsWith('*') ? value[1..] : value;
}

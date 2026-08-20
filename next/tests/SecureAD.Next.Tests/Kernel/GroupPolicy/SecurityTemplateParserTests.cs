using System.Text;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public class SecurityTemplateParserTests
{
    // A representative GptTmpl.inf body used across several tests.
    private const string SampleTemplate =
        "[Unicode]\r\n" +
        "Unicode=yes\r\n" +
        "[System Access]\r\n" +
        "MinimumPasswordLength = 14\r\n" +
        "LockoutBadCount = 5\r\n" +
        "[Privilege Rights]\r\n" +
        "SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-1-2-3-1105\r\n" +
        "SeBackupPrivilege = *S-1-5-32-551\r\n" +
        "[Group Membership]\r\n" +
        "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1106,*S-1-5-21-1-2-3-1107\r\n" +
        "*S-1-5-21-1-2-3-1108__Memberof = *S-1-5-32-544\r\n" +
        "[Version]\r\n" +
        "signature=\"$CHICAGO$\"\r\n" +
        "Revision=1\r\n";

    // --- Encoding handling ---

    [Fact]
    public void WhenUtf16LeWithBom_ThenParsesSections()
    {
        var bytes = ToUtf16LeWithBom(SampleTemplate);

        var result = SecurityTemplateParser.ParseTemplateFile(bytes);

        Assert.Empty(result.Errors);
        Assert.True(result.Sections.ContainsKey("System Access"));
        Assert.True(result.Sections.ContainsKey("Privilege Rights"));
    }

    [Fact]
    public void WhenUtf8NoBom_ThenParsesSections()
    {
        var bytes = Encoding.UTF8.GetBytes(SampleTemplate);

        var result = SecurityTemplateParser.ParseTemplateFile(bytes);

        Assert.Empty(result.Errors);
        Assert.True(result.Sections.ContainsKey("Privilege Rights"));
    }

    [Fact]
    public void WhenUtf8WithBom_ThenBomStripped()
    {
        var preamble = Encoding.UTF8.GetPreamble();
        var body = Encoding.UTF8.GetBytes(SampleTemplate);
        var bytes = new byte[preamble.Length + body.Length];
        preamble.CopyTo(bytes, 0);
        body.CopyTo(bytes, preamble.Length);

        var result = SecurityTemplateParser.ParseTemplateFile(bytes);

        // First section name must not carry a stray BOM character.
        Assert.True(result.Sections.ContainsKey("Unicode"));
    }

    // --- Generic section parsing ---

    [Fact]
    public void WhenSystemAccessSection_ThenRawSettingsPreserved()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var section = result.GetSection("System Access");
        Assert.Equal(2, section.Count);
        Assert.Equal("MinimumPasswordLength", section[0].Name);
        Assert.Equal("14", section[0].Value);
        Assert.Equal("LockoutBadCount", section[1].Name);
        Assert.Equal("5", section[1].Value);
    }

    [Fact]
    public void WhenSectionNameQueriedCaseInsensitively_ThenFound()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        Assert.NotEmpty(result.GetSection("system access"));
    }

    [Fact]
    public void WhenSectionAbsent_ThenGetSectionReturnsEmpty()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        Assert.Empty(result.GetSection("Nonexistent"));
    }

    [Fact]
    public void WhenValueContainsEquals_ThenOnlyFirstEqualsSplits()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var version = result.GetSection("Version");
        var signature = Assert.Single(version, s => s.Name == "signature");
        Assert.Equal("\"$CHICAGO$\"", signature.Value);
    }

    // --- Privilege Rights accessor ---

    [Fact]
    public void WhenPrivilegeRights_ThenTrusteesSplitAndStarStripped()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var privileges = result.GetPrivilegeRights();
        Assert.Equal(["S-1-5-32-544", "S-1-5-21-1-2-3-1105"], privileges["SeDebugPrivilege"]);
        Assert.Equal(["S-1-5-32-551"], privileges["SeBackupPrivilege"]);
    }

    [Fact]
    public void WhenPrivilegeRightsQueriedCaseInsensitively_ThenFound()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var privileges = result.GetPrivilegeRights();
        Assert.True(privileges.ContainsKey("sedebugprivilege"));
    }

    [Fact]
    public void WhenNoPrivilegeRightsSection_ThenEmptyMap()
    {
        var result = SecurityTemplateParser.ParseTemplateFile("[System Access]\r\nMinimumPasswordLength = 8\r\n");

        Assert.Empty(result.GetPrivilegeRights());
    }

    // --- Group Membership accessor ---

    [Fact]
    public void WhenGroupMembers_ThenMembersParsedAndStarStripped()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var groups = result.GetGroupMemberships();
        var admins = Assert.Single(groups, g => g.GroupName == "S-1-5-32-544");
        Assert.Equal(["S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-1107"], admins.Members);
        Assert.Empty(admins.MemberOf);
    }

    [Fact]
    public void WhenGroupMemberOf_ThenMemberOfParsed()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(SampleTemplate);

        var groups = result.GetGroupMemberships();
        var account = Assert.Single(groups, g => g.GroupName == "S-1-5-21-1-2-3-1108");
        Assert.Equal(["S-1-5-32-544"], account.MemberOf);
        Assert.Empty(account.Members);
    }

    [Fact]
    public void WhenSamePrincipalHasMembersAndMemberOf_ThenCombinedIntoOneEntry()
    {
        var template =
            "[Group Membership]\r\n" +
            "*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1106\r\n" +
            "*S-1-5-32-544__Memberof = *S-1-5-32-545\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        var group = Assert.Single(result.GetGroupMemberships());
        Assert.Equal("S-1-5-32-544", group.GroupName);
        Assert.Equal(["S-1-5-21-1-2-3-1106"], group.Members);
        Assert.Equal(["S-1-5-32-545"], group.MemberOf);
    }

    [Fact]
    public void WhenEmptyMembersList_ThenGroupHasNoMembers()
    {
        var template =
            "[Group Membership]\r\n" +
            "*S-1-5-32-544__Members =\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        var group = Assert.Single(result.GetGroupMemberships());
        Assert.Empty(group.Members);
    }

    // --- Comments, blanks, and resilience ---

    [Fact]
    public void WhenCommentsAndBlankLines_ThenIgnored()
    {
        var template =
            "; this is a comment\r\n" +
            "\r\n" +
            "[Privilege Rights]\r\n" +
            "; another comment\r\n" +
            "SeDebugPrivilege = *S-1-5-32-544\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        Assert.Empty(result.Errors);
        Assert.Single(result.GetSection("Privilege Rights"));
    }

    [Fact]
    public void WhenSettingBeforeSection_ThenRecordsError()
    {
        var template = "Orphan = value\r\n[System Access]\r\nMinimumPasswordLength = 8\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        Assert.Contains(result.Errors, e => e.Contains("before any section header"));
    }

    [Fact]
    public void WhenMalformedSectionHeader_ThenRecordsError()
    {
        var template = "[Unterminated\r\nMinimumPasswordLength = 8\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        Assert.Contains(result.Errors, e => e.Contains("malformed section header"));
    }

    [Fact]
    public void WhenDuplicateSectionHeaders_ThenSettingsMerged()
    {
        var template =
            "[Privilege Rights]\r\n" +
            "SeDebugPrivilege = *S-1-5-32-544\r\n" +
            "[Privilege Rights]\r\n" +
            "SeBackupPrivilege = *S-1-5-32-551\r\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        Assert.Equal(2, result.GetSection("Privilege Rights").Count);
    }

    [Fact]
    public void WhenLfOnlyLineEndings_ThenParsed()
    {
        var template = "[Privilege Rights]\nSeDebugPrivilege = *S-1-5-32-544\n";

        var result = SecurityTemplateParser.ParseTemplateFile(template);

        Assert.Single(result.GetSection("Privilege Rights"));
    }

    [Fact]
    public void WhenEmptyInput_ThenNoSectionsNoErrors()
    {
        var result = SecurityTemplateParser.ParseTemplateFile(string.Empty);

        Assert.Empty(result.Sections);
        Assert.Empty(result.Errors);
    }

    // =====================================================================
    //  Helpers
    // =====================================================================

    private static byte[] ToUtf16LeWithBom(string text)
    {
        var preamble = Encoding.Unicode.GetPreamble(); // FF FE
        var body = Encoding.Unicode.GetBytes(text);
        var bytes = new byte[preamble.Length + body.Length];
        preamble.CopyTo(bytes, 0);
        body.CopyTo(bytes, preamble.Length);
        return bytes;
    }
}

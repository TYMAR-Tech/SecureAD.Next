using System.Reflection;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public class GroupPolicyPreferenceParserTests
{
    // Realistic GPP file fragments. The cpassword values below are arbitrary non-empty tokens —
    // the parser only tests presence, never decrypts, so their content is irrelevant.
    private const string GroupsXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
          <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator (built-in)" image="2" changed="2013-01-01 00:00:00" uid="{abc}">
            <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Administrator (built-in)"/>
          </User>
        </Groups>
        """;

    private const string ServicesXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <NTServices clsid="{2CFB484A-4E96-4b5d-A0B6-093D2F91E6AE}">
          <NTService clsid="{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}" name="MyService" image="0" changed="2013-01-01 00:00:00" uid="{def}">
            <Properties startupType="NOCHANGE" serviceName="MyService" timeout="30" accountName="DOMAIN\svc_app" cpassword="someEncryptedBlobValue=="/>
          </NTService>
        </NTServices>
        """;

    private const string ScheduledTasksXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
          <Task clsid="{2DEECB1C-E3D1-4d3b-8CF2-F6E3D6E2C4F9}" name="DailyJob" image="0" changed="2013-01-01 00:00:00" uid="{ghi}">
            <Properties action="C" name="DailyJob" runAs="DOMAIN\taskrunner" cpassword="taskCpasswordBlob==" logonType="password"/>
          </Task>
        </ScheduledTasks>
        """;

    private const string DataSourcesXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <DataSources clsid="{380going}">
          <DataSource clsid="{5C209626-D820-4d69-8D50-1FED0AD3A0B9}" name="MyDSN" image="0" changed="2013-01-01 00:00:00" uid="{jkl}">
            <Properties action="U" userName="dsnuser" cpassword="dsnCpassword==" dsn="MyDSN" driver="SQL Server"/>
          </DataSource>
        </DataSources>
        """;

    private const string DrivesXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
          <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="H:" image="1" changed="2013-01-01 00:00:00" uid="{mno}">
            <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="mapuser" cpassword="driveCpassword==" path="\\server\share" letter="H"/>
          </Drive>
        </Drives>
        """;

    private const string PrintersXml =
        """
        <?xml version="1.0" encoding="utf-8"?>
        <Printers clsid="{1F577D12-3D1B-471e-A1B7-060317597B9C}">
          <SharedPrinter clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}" name="\\srv\printer" image="0" changed="2013-01-01 00:00:00" uid="{pqr}">
            <Properties action="U" path="\\srv\printer" username="printuser" cpassword="printerCpassword=="/>
          </SharedPrinter>
        </Printers>
        """;

    // --- Detection across all six GPP file types ---

    [Theory]
    [InlineData(nameof(GroupsXml), "User", "Administrator (built-in)")]
    [InlineData(nameof(ServicesXml), "NTService", "DOMAIN\\svc_app")]
    [InlineData(nameof(ScheduledTasksXml), "Task", "DOMAIN\\taskrunner")]
    [InlineData(nameof(DataSourcesXml), "DataSource", "dsnuser")]
    [InlineData(nameof(DrivesXml), "Drive", "mapuser")]
    [InlineData(nameof(PrintersXml), "SharedPrinter", "printuser")]
    public void WhenCpasswordPresent_ThenFindingWithAccountAndElement(string sampleName, string expectedElement, string expectedAccount)
    {
        var xml = SampleByName(sampleName);

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        Assert.Empty(result.Errors);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(expectedElement, finding.ElementType);
        Assert.Equal(expectedAccount, finding.AccountName);
    }

    // --- Empty / absent cpassword ---

    [Fact]
    public void WhenCpasswordEmpty_ThenNoFinding()
    {
        // GPP writes cpassword="" after MS14-025 remediation removes the stored password.
        var xml =
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{x}" name="svc"><Properties action="U" userName="svc" cpassword=""/></User>
            </Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void WhenNoCpasswordAttribute_ThenNoFinding()
    {
        var xml =
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{x}" name="svc"><Properties action="U" userName="svc"/></User>
            </Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public void WhenMultipleUsersWithCpassword_ThenOneFindingEach()
    {
        var xml =
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{a}" name="a"><Properties userName="a" cpassword="blobA=="/></User>
              <User clsid="{b}" name="b"><Properties userName="b" cpassword="blobB=="/></User>
            </Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        Assert.Equal(2, result.Findings.Count);
    }

    // --- Presence-only guarantee (the security property) ---

    [Fact]
    public void WhenCpasswordPresent_ThenValueNeverAppearsInResult()
    {
        const string secret = "UNIQUEcpasswordBlobThatMustNotLeak123==";
        var xml =
            $$"""
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{x}" name="svc"><Properties userName="svc" cpassword="{{secret}}"/></User>
            </Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        // The cpassword value must not appear in ANY public property of ANY finding.
        var finding = Assert.Single(result.Findings);
        foreach (var prop in typeof(GppPasswordFinding).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            var value = prop.GetValue(finding) as string;
            Assert.True(value is null || !value.Contains(secret),
                $"cpassword value leaked into GppPasswordFinding.{prop.Name}");
        }
    }

    [Fact]
    public void WhenFindingType_ThenHasNoPasswordProperty()
    {
        // Structural guarantee: the record exposes no member that could hold the credential.
        var propNames = typeof(GppPasswordFinding)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name.ToLowerInvariant())
            .ToList();

        Assert.DoesNotContain("cpassword", propNames);
        Assert.DoesNotContain("password", propNames);
    }

    // --- Hardening / resilience ---

    [Fact]
    public void WhenDtdExternalEntity_ThenParsesWithoutResolvingEntity()
    {
        // XXE attempt: a DTD with an external entity. Hardened settings (DtdProcessing.Prohibit,
        // XmlResolver=null) must reject the DTD rather than fetch the file — surfaced as an error,
        // never an entity expansion.
        var xml =
            """
            <?xml version="1.0"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
            <Groups><User><Properties userName="&xxe;" cpassword="blob=="/></User></Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        Assert.NotEmpty(result.Errors);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void WhenMalformedXml_ThenReturnsErrorNotThrow()
    {
        var result = GroupPolicyPreferenceParser.ParsePreferenceFile("<Groups><User unclosed");

        Assert.NotEmpty(result.Errors);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void WhenEmptyInput_ThenNoFindingsNoErrors()
    {
        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(ReadOnlySpan<byte>.Empty);

        Assert.Empty(result.Findings);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void WhenCpasswordButNoAccountAttribute_ThenFindingWithNullAccount()
    {
        var xml =
            """
            <?xml version="1.0" encoding="utf-8"?>
            <Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
              <User clsid="{x}" name="svc"><Properties action="U" cpassword="blob=="/></User>
            </Groups>
            """;

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(xml);

        var finding = Assert.Single(result.Findings);
        Assert.Null(finding.AccountName);
        Assert.Null(finding.SourceAttribute);
    }

    [Fact]
    public void WhenUtf8Bom_ThenParsed()
    {
        var preamble = System.Text.Encoding.UTF8.GetPreamble();
        var body = System.Text.Encoding.UTF8.GetBytes(GroupsXml);
        var bytes = new byte[preamble.Length + body.Length];
        preamble.CopyTo(bytes, 0);
        body.CopyTo(bytes, preamble.Length);

        var result = GroupPolicyPreferenceParser.ParsePreferenceFile(bytes);

        Assert.Single(result.Findings);
    }

    // --- Helpers ---

    private static string SampleByName(string name) => name switch
    {
        nameof(GroupsXml) => GroupsXml,
        nameof(ServicesXml) => ServicesXml,
        nameof(ScheduledTasksXml) => ScheduledTasksXml,
        nameof(DataSourcesXml) => DataSourcesXml,
        nameof(DrivesXml) => DrivesXml,
        nameof(PrintersXml) => PrintersXml,
        _ => throw new ArgumentOutOfRangeException(nameof(name), name, "Unknown sample"),
    };
}

using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Sysvol;

/// <summary>
/// Reading the Group Policy files on SYSVOL: inventory row B14.
///
/// <para>
/// <b>Every test here that matters is about a share saying no.</b> This is the first read in the
/// product that is allowed to fail without failing the run, per <c>docs/decisions/0044</c>, and the
/// whole risk of that decision is that a refusal turns into a silence: a policy nobody could open
/// producing the same evidence as a policy that configures nothing. So the fixtures deny things,
/// and the assertions are about what the bundle then says.
/// </para>
/// </summary>
public sealed class SysvolCaptureTests : IDisposable
{
    private static readonly Guid PolicyGuid = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SecondPolicyGuid = new("22222222-2222-2222-2222-222222222222");

    private const string PolicyPath =
        @"\\contoso.com\SysVol\contoso.com\Policies\{11111111-1111-1111-1111-111111111111}";

    private const string SecondPolicyPath =
        @"\\contoso.com\SysVol\contoso.com\Policies\{22222222-2222-2222-2222-222222222222}";

    private const string TemplatePath = @"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

    private readonly string _root = TempDirectories.Create("sysvol");

    private static readonly DateTimeOffset Started = new(2026, 8, 26, 9, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A minimal self-relative security descriptor with an owner, a group and an empty DACL. What
    /// it grants does not matter here; that it is stored against the right path does.
    /// </summary>
    private static byte[] ADescriptor() =>
    [
        0x01, 0x00, 0x04, 0x80,
        0x14, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x2C, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// <summary>
    /// The failure the session exists to make visible. A policy folder the run may not open is
    /// reported as unreadable, with what the share said, rather than as a policy with no settings.
    /// </summary>
    [Fact]
    public async Task APolicyFolderThatIsRefusedIsReportedRatherThanLookingEmpty()
    {
        var reader = new InMemorySysvolFileReader()
            .Denying(PolicyPath, string.Empty);

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        var policy = Assert.Single(coverage.Policies);

        Assert.Equal(GpoReadOutcome.Unreadable, policy.Outcome);
        Assert.Equal(SysvolReadOutcome.NotRead, coverage.Outcome);
        Assert.Contains("not allowed", policy.Reason);
    }

    /// <summary>
    /// The state that made a new decision necessary: one policy read, another refused, and a
    /// bundle sealed with both facts in it.
    /// </summary>
    [Fact]
    public async Task OnePolicyRefusedOutOfTwoLeavesTheOtherReadAndSaysWhichWasMissed()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .Denying(SecondPolicyPath, string.Empty);

        var coverage = await ReadAsync(
            reader,
            Inventory(
                OnePolicy(),
                GpoTarget.Of(SecondPolicyGuid, "Workstation Lockdown", SecondPolicyPath)));

        Assert.Equal(SysvolReadOutcome.PartiallyRead, coverage.Outcome);
        Assert.Equal(2, coverage.PoliciesDeclared);
        Assert.Equal(1, coverage.PoliciesRead);
        Assert.Equal("Workstation Lockdown", Assert.Single(coverage.UnreadablePolicies).DisplayName);
    }

    /// <summary>
    /// A refusal below the policy's root is a partial read, not a whole one and not a failed one -
    /// which is why the per-policy outcome has three members.
    /// </summary>
    /// <remarks>
    /// Every other path in this fixture has a descriptor, deliberately. Written without them the
    /// test still passed when the refusal was ignored entirely, because paths with no descriptor
    /// were being recorded as having vanished - so it was green for a reason that had nothing to do
    /// with what it is named for. Mutation-tested in both directions after the fix.
    /// </remarks>
    [Fact]
    public async Task APolicyWhoseScriptsFolderIsRefusedIsReadOnlyInPart()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Scripts\logon.bat", Bytes("echo hello"))
            .Denying(PolicyPath, @"Machine\Scripts");

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(GpoReadOutcome.PartiallyRead, Assert.Single(coverage.Policies).Outcome);
    }

    /// <summary>
    /// <c>docs/decisions/0043</c>: a path whose permissions could not be read gets a positive row,
    /// because no rows in <c>ace</c> otherwise means "this path grants nothing".
    /// </summary>
    [Fact]
    public async Task APathWhosePermissionsAreRefusedGetsARowSayingSo()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Scripts", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Scripts\logon.bat", Bytes("echo hello"))
            .Denying(PolicyPath, @"Machine\Scripts\logon.bat");

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(
            [@"Machine\Scripts\logon.bat"],
            Query(bundle, "SELECT relative_path FROM unreadable_sysvol_descriptor"));
    }

    /// <summary>
    /// The permissions on the policy folder itself, which is what SEC-082 is about: who can rewrite
    /// what every machine in the domain applies.
    /// </summary>
    [Fact]
    public async Task ThePolicyFoldersOwnPermissionsAreStored()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor());

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(
            [""],
            Query(bundle, "SELECT relative_path FROM sysvol_path_security_descriptor"));
    }

    /// <summary>
    /// The privileges a policy grants, out of its security template. SEC-064 reads these, and until
    /// this session nothing opened the file at all.
    /// </summary>
    [Fact]
    public async Task ThePrivilegesAPolicyGrantsAreStored()
    {
        var template = """
            [Privilege Rights]
            SeDebugPrivilege = *S-1-5-32-545
            """;

        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(PolicyPath, TemplatePath, TemplateBytes(template));

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(
            ["Privilege Rights|SeDebugPrivilege|*S-1-5-32-545"],
            Query(
                bundle,
                "SELECT section || '|' || name || '|' || value FROM gpo_security_setting"));
    }

    /// <summary>
    /// Restricted Groups, which SEC-065 reads. The direction is stored because the two are
    /// opposites: one grants administrative rights on every machine, the other receives them.
    /// </summary>
    [Fact]
    public async Task AGroupMembershipAPolicyImposesIsStoredWithItsDirection()
    {
        var template = """
            [Group Membership]
            *S-1-5-32-544__Members = *S-1-5-21-1-2-3-1000
            """;

        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(PolicyPath, TemplatePath, TemplateBytes(template));

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        // The parser strips the file format's leading asterisk, so what is stored is the plain
        // identifier a rule can join on.
        Assert.Equal(
            ["S-1-5-32-544|Member|S-1-5-21-1-2-3-1000"],
            Query(
                bundle,
                "SELECT group_name || '|' || relationship || '|' || principal "
                + "FROM gpo_restricted_group"));
    }

    /// <summary>
    /// A file that was opened and could not be understood produces an error row. Without it, a
    /// template that failed to parse and a policy that assigns no privileges are the same evidence.
    /// </summary>
    [Fact]
    public async Task AFileThatCouldNotBeParsedIsRecordedRatherThanReadAsEmpty()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(PolicyPath, @"Machine\Registry.pol", Bytes("this is not a policy file"));

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.NotEmpty(Query(bundle, "SELECT message FROM gpo_file_error"));
    }

    /// <summary>
    /// A policy the directory declared whose folder is not on the share. The policy object outlived
    /// its files, which is a fact about the customer's forest and not a failure of this run - but it
    /// is still a policy nothing was read from.
    /// </summary>
    [Fact]
    public async Task APolicyWithNoFolderOnTheShareIsReportedUnreadable()
    {
        var coverage = await ReadAsync(new InMemorySysvolFileReader(), Inventory(OnePolicy()));

        var policy = Assert.Single(coverage.Policies);

        Assert.Equal(GpoReadOutcome.Unreadable, policy.Outcome);
        Assert.Contains("not on the SYSVOL share", policy.Reason);
    }

    /// <summary>
    /// A policy read in full has nothing to caveat, and the run says so plainly. Without this the
    /// suite would only prove the record can report failure.
    /// </summary>
    [Fact]
    public async Task APolicyReadInFullIsReportedAsRead()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor());

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(GpoReadOutcome.Read, Assert.Single(coverage.Policies).Outcome);
        Assert.True(coverage.AllDeclaredPoliciesAreComplete);
    }

    /// <summary>
    /// An operator who stopped the run has discovered nothing about his policies. Recording a
    /// cancelled read as unreadable policies would put a finding in front of him that says more
    /// than he knows.
    /// </summary>
    [Fact]
    public async Task ACancelledReadIsNotReportedAsUnreadablePolicies()
    {
        using var writer = BundleWriter.Create(Directory.CreateDirectory(_root).FullName, Started);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        var capture = new SysvolCapture(new InMemorySysvolFileReader(), writer);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => capture.ReadAsync(Inventory(OnePolicy()), cancelled.Token));
    }

    private static GpoTarget OnePolicy() =>
        GpoTarget.Of(PolicyGuid, "Default Domain Policy", PolicyPath);

    /// <summary>
    /// Builds the inventory the way a run does - by observing captured directory objects - so these
    /// tests exercise the path that actually produces the denominator.
    /// </summary>
    private static GpoInventory Inventory(params GpoTarget[] targets)
    {
        var inventory = new GpoInventory();

        foreach (var target in targets)
        {
            inventory.Observe(
                CapturedObject.Create(
                    $"CN={{{target.GpoGuid}}},CN=Policies,CN=System,DC=contoso,DC=com",
                    [
                        Attribute("objectClass", "top", "container", "groupPolicyContainer"),
                        Attribute("displayName", target.DisplayName),
                        Attribute("gPCFileSysPath", target.FileSysPath),
                    ]),
                target.GpoGuid);
        }

        return inventory;
    }

    private static AttributeValues Attribute(string name, params string[] values) =>
        new(name, values, AttributeCompleteness.Complete, NextRange: null);

    /// <summary>
    /// A policy whose attribute values arrive as bytes rather than as strings, which is how a
    /// directory controller commonly returns them.
    /// </summary>
    /// <remarks>
    /// <b>Every other test here builds values as strings, and that is why this went unseen.</b>
    /// <c>AttributeValues.Values</c> is <c>IReadOnlyList&lt;object&gt;</c> and
    /// <c>LdapEntryReader</c> documents each value as "a string or a byte[] apiece" - which is why
    /// <c>LdapEntryReader.AsText</c> exists at all. A run against a real forest produced no policies,
    /// no coverage and no error, and the tests stayed green because the test and the code shared
    /// one assumption about the shape of a value.
    /// </remarks>
    private static AttributeValues BytesAttribute(string name, params string[] values) =>
        new(
            name,
            [.. values.Select(v => (object)System.Text.Encoding.UTF8.GetBytes(v))],
            AttributeCompleteness.Complete,
            NextRange: null);

    /// <summary>
    /// A policy is recognised when the directory returns its attributes as bytes.
    /// </summary>
    /// <remarks>
    /// <b>Measured against <c>ad.lab</c> on 2026-09-03:</b> a sealed bundle held twelve
    /// <c>groupPolicyContainer</c> objects each carrying a valid <c>gPCFileSysPath</c>, and yet
    /// <c>gpo_registry_setting</c>, <c>sysvol_gpo_coverage</c> and <c>gpo_file_error</c> were all
    /// empty and the run log carried no SYSVOL line. Nothing was recognised as a policy, so SYSVOL
    /// was handed an empty list and had nothing to fail at - which is why the coverage record that
    /// <c>docs/decisions/0044</c> relies on to prevent exactly this silence never fired.
    /// </remarks>
    [Fact]
    public void APolicyWhoseValuesArriveAsBytesIsStillRecognised()
    {
        var inventory = new GpoInventory();

        inventory.Observe(
            CapturedObject.Create(
                $"CN={{{PolicyGuid}}},CN=Policies,CN=System,DC=contoso,DC=com",
                [
                    BytesAttribute("objectClass", "top", "container", "groupPolicyContainer"),
                    BytesAttribute("displayName", "Default Domain Policy"),
                    BytesAttribute("gPCFileSysPath", PolicyPath),
                ]),
            PolicyGuid);

        var policy = Assert.Single(inventory.Policies);

        Assert.Equal(PolicyGuid, policy.GpoGuid);
        Assert.Equal("Default Domain Policy", policy.DisplayName);
        Assert.Equal(PolicyPath, policy.FileSysPath);
    }

    private async Task<SysvolCoverage> ReadAsync(ISysvolFileReader reader, GpoInventory inventory)
    {
        using var writer = BundleWriter.Create(Directory.CreateDirectory(_root).FullName, Started);

        return await new SysvolCapture(reader, writer).ReadAsync(inventory, CancellationToken.None);
    }

    /// <summary>Runs a SYSVOL capture and seals the bundle, returning its directory.</summary>
    private async Task<string> CaptureAsync(ISysvolFileReader reader, GpoInventory inventory)
    {
        var directory = Directory.CreateDirectory(_root).FullName;

        using var writer = BundleWriter.Create(directory, Started);

        var coverage = await new SysvolCapture(reader, writer)
            .ReadAsync(inventory, CancellationToken.None);

        writer.Complete(
            RunCoverage.Of(
                CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [
                    ForestPartitionCoverage.Read(
                        "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read(
                        "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
                ],
                coverage),
            Started.AddMinutes(4));

        return directory;
    }

    private static List<string> Query(string bundleDirectory, string sql)
    {
        using var connection = new SqliteConnection(
            $"Data Source={BundleLayout.EvidencePath(bundleDirectory)};Mode=ReadOnly");
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = sql;

        using var rows = command.ExecuteReader();

        var values = new List<string>();
        while (rows.Read())
        {
            values.Add(rows.IsDBNull(0) ? "(null)" : rows.GetString(0));
        }

        return values;
    }

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    /// <summary>
    /// A security template as Windows writes one: UTF-16 with a byte-order mark. The mark matters -
    /// the parser reads a file without one as UTF-8, which is what a hand-made fixture gets wrong.
    /// </summary>
    private static byte[] TemplateBytes(string text) =>
        [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(text)];

    public void Dispose()
    {
        // Left on disk deliberately: a failed run's evidence is worth reading, and the path is
        // random so nothing collides. It is not left there forever - the directory belongs to this
        // run's folder, which survives until the next test run starts and then goes with it. So the
        // evidence is readable for exactly as long as anyone would want it.
        GC.SuppressFinalize(this);
    }
}

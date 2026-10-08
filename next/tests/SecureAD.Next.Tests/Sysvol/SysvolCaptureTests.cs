using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Capture;
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
    /// A file that was opened and could not be understood leaves the policy explicitly incomplete.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This asserted only that an error row existed until 2026-09-13, and that is why it never
    /// caught anything.</b> The row was always written; what was missing was the mark against the
    /// policy's coverage, so a truncated <c>Machine\Registry.pol</c> yielded no settings and the
    /// policy was still reported <c>Read</c> and complete. <c>SEC-093</c> then read an absent LAPS
    /// decryptor setting as an assessed, finding-free policy. That is <c>CAP-002</c>, and this test
    /// passed throughout it.
    /// </para>
    /// <para>
    /// The outcome is what is asserted now. An error row is a diagnostic; coverage is the claim a
    /// customer acts on, and nothing reads <c>gpo_file_error</c> back.
    /// </para>
    /// <para>
    /// <b>Every folder and the file itself are given permissions deliberately, and mutation testing
    /// is what forced it.</b> Without them the unreadable permissions were a second gap, so the
    /// policy came out <c>PartiallyRead</c> whether the parse failure was marked or not - the
    /// outcome assertion passed against a capture with the fix removed, and only the reason text
    /// caught it. A fixture with more than one thing wrong cannot prove which one the check saw.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AFileThatCouldNotBeParsedLeavesThePolicyExplicitlyIncomplete()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Registry.pol", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Registry.pol", Bytes("this is not a policy file"));

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        var policy = Assert.Single(coverage.Policies);

        Assert.Equal(GpoReadOutcome.PartiallyRead, policy.Outcome);
        Assert.Contains(@"Machine\Registry.pol", policy.Reason, StringComparison.Ordinal);
        Assert.Contains("could not be understood", policy.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// The diagnostics survive alongside the coverage mark.
    /// </summary>
    /// <remarks>
    /// The coverage mark says the policy is incomplete; the error rows say what the parser choked
    /// on. Downgrading coverage must not cost the detail, because a fix that traded one for the
    /// other would be answering a false-clean claim with a claim that explains nothing.
    /// </remarks>
    [Fact]
    public async Task AFileThatCouldNotBeParsedStillRecordsWhatTheParserSaid()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Registry.pol", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Registry.pol", Bytes("this is not a policy file"));

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.NotEmpty(Query(bundle, "SELECT message FROM gpo_file_error"));
    }

    /// <summary>
    /// A file enumeration listed, that then will not open, leaves the policy explicitly incomplete.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>CAP-003</c>.</b> Enumeration establishes the file is there. A later read returning
    /// nothing is therefore not the same as a policy that simply has no <c>GptTmpl.inf</c> - the
    /// share said the file existed and then would not produce it, which is a gap in the evidence
    /// and used to leave coverage complete.
    /// </para>
    /// <para>
    /// <b>Every folder on the way down, and the file itself, is given a readable descriptor, and
    /// mutation testing is what forced it.</b> The policy folder alone was not enough: enumeration
    /// walks the ancestors, and a folder without a descriptor is a second gap, so the policy came
    /// out <c>PartiallyRead</c> whether the vanished file was marked or not. That keeps this a
    /// <c>PartiallyRead</c> case rather than an <c>Unreadable</c> one, and makes the vanished file
    /// the only thing that can produce the outcome.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AListedFileThatWillNotOpenLeavesThePolicyExplicitlyIncomplete()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Preferences", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Preferences\Groups", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Preferences\Groups\Groups.xml", ADescriptor())
            .WithListedButUnopenableFile(PolicyPath, @"Machine\Preferences\Groups\Groups.xml");

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()), scanGppPasswords: true);

        var policy = Assert.Single(coverage.Policies);

        Assert.Equal(GpoReadOutcome.PartiallyRead, policy.Outcome);
        Assert.Contains("Groups.xml", policy.Reason, StringComparison.Ordinal);
        Assert.Contains("could not be opened", policy.Reason, StringComparison.Ordinal);
    }

    /// <summary>
    /// A well-known file a policy simply does not have is still an answer, not a gap.
    /// </summary>
    /// <remarks>
    /// <b>The negative control for the test above, and the reason the distinction exists at all.</b>
    /// A policy with no <c>GptTmpl.inf</c> assigns no user rights - that is a complete answer. If
    /// absence were read as a gap everywhere, every ordinary policy in a customer's forest would
    /// report as incomplete and the caveat would stop meaning anything.
    /// </remarks>
    [Fact]
    public async Task AWellKnownFileAPolicyDoesNotHaveIsNotAGap()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor());

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(GpoReadOutcome.Read, Assert.Single(coverage.Policies).Outcome);
    }

    [Fact]
    public async Task GppPasswordScanningIsSkippedAndRecordedAsNotRequestedByDefault()
    {
        var path = @"Machine\Preferences\Groups\Groups.xml";
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(
                PolicyPath,
                path,
                Bytes("<Groups><User><Properties userName=\"legacy\" cpassword=\"secret\"/></User></Groups>"))
            .WithDescriptor(PolicyPath, path, ADescriptor());

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(["0"], Query(bundle, "SELECT COUNT(*) FROM gpo_stored_credential"));
        Assert.Equal(
            ["NotRequested|"],
            Query(
                bundle,
                "SELECT gpp_password_scan_outcome || '|' || COALESCE(gpp_password_scan_reason, '') "
                + "FROM sysvol_gpo_coverage"));
    }

    [Fact]
    public async Task RequestedGppPasswordScanningStoresOnlyOccurrenceMetadataAndCompleteCoverage()
    {
        var path = @"Machine\Preferences\Groups\Groups.xml";
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(
                PolicyPath,
                path,
                Bytes("<Groups><User><Properties userName=\"legacy\" cpassword=\"secret\"/></User></Groups>"))
            .WithDescriptor(PolicyPath, path, ADescriptor());

        var bundle = await CaptureAsync(
            reader, Inventory(OnePolicy()), scanGppPasswords: true);

        Assert.Equal(
            [$"{path}|User|legacy|userName"],
            Query(
                bundle,
                "SELECT relative_path || '|' || element_type || '|' || account_name || '|' "
                + "|| source_attribute FROM gpo_stored_credential"));
        Assert.Equal(
            ["Read|"],
            Query(
                bundle,
                "SELECT gpp_password_scan_outcome || '|' || COALESCE(gpp_password_scan_reason, '') "
                + "FROM sysvol_gpo_coverage"));
    }

    [Fact]
    public async Task RequestedGppPasswordScanningRecordsParseFailureRatherThanLookingClean()
    {
        var path = @"Machine\Preferences\Groups\Groups.xml";
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithFile(PolicyPath, path, Bytes("<Groups><User>"))
            .WithDescriptor(PolicyPath, path, ADescriptor());

        var coverage = await ReadAsync(
            reader, Inventory(OnePolicy()), scanGppPasswords: true);

        var policy = Assert.Single(coverage.Policies);
        Assert.Equal(GppPasswordScanOutcome.PartiallyRead, policy.GppPasswordScanOutcome);
        Assert.Contains("Groups.xml", policy.GppPasswordScanReason, StringComparison.Ordinal);
    }

    /// <summary>
    /// An XML file under a scripts folder does not destroy the capture.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>CAP-001</c> and <c>P-172</c>, and the cost of it was the whole night's work.</b> The
    /// preference scan enumerates <c>*.xml</c> across the entire policy folder, so it reaches
    /// <c>Machine\Scripts</c>; the script scan then enumerates everything under the script folders
    /// and reaches the same file again. Both captured its descriptor, and
    /// <c>sysvol_path_security_descriptor</c> is keyed <c>(gpo_guid, relative_path)</c> - so the
    /// second insert threw, and nothing caught it. <c>SysvolCapture</c> has no <c>catch</c>,
    /// <c>CaptureRun</c> has two and both are for cancellation, and <c>CaptureSession</c> has none,
    /// so the exception unwound a run that had already read every domain and had not yet sealed.
    /// </para>
    /// <para>
    /// <c>settings.xml</c> under <c>Machine\Scripts</c> is an ordinary layout rather than a
    /// contrivance, which is what made this worth a P1.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AnXmlFileUnderAScriptsFolderDoesNotDestroyTheCapture()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Scripts", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Scripts\settings.xml", Bytes("<Groups/>"))
            .WithDescriptor(PolicyPath, @"Machine\Scripts\settings.xml", ADescriptor());

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()), scanGppPasswords: true);

        var only = Assert.Single(coverage.Policies);
        Assert.True(only.Outcome == GpoReadOutcome.Read, only.Reason);
    }

    /// <summary>
    /// The doubly-reached file's permissions are stored once, not twice.
    /// </summary>
    /// <remarks>
    /// The run surviving is not on its own proof the defect is gone - a fix that swallowed the
    /// second write would also survive. This asserts the bundle holds exactly one row for the path,
    /// which is what the key was always meant to guarantee and what the second acquisition broke.
    /// </remarks>
    [Fact]
    public async Task AFileReachedByBothScansIsStoredOnce()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Scripts", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Scripts\settings.xml", Bytes("<Groups/>"))
            .WithDescriptor(PolicyPath, @"Machine\Scripts\settings.xml", ADescriptor());

        var bundle = await CaptureAsync(reader, Inventory(OnePolicy()), scanGppPasswords: true);

        Assert.Equal(
            ["1"],
            Query(
                bundle,
                "SELECT COUNT(*) FROM sysvol_path_security_descriptor "
                + "WHERE relative_path = 'Machine\\Scripts\\settings.xml'"));
    }

    /// <summary>
    /// A scripts-folder XML whose contents read and whose permissions are refused.
    /// </summary>
    /// <remarks>
    /// <b>The case the review asked for by name</b>, because it is where the two scans disagree
    /// about what they found. The preference scan opens the file and is refused its descriptor; the
    /// script scan is refused the same descriptor again. The refusal is recorded once, the policy is
    /// explicitly partial, and the run still reaches an outcome.
    /// </remarks>
    [Fact]
    public async Task AScriptsFolderXmlWhoseDescriptorIsRefusedIsRecordedOnceAndSaysSo()
    {
        var reader = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, string.Empty, ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Scripts", ADescriptor())
            .WithFile(PolicyPath, @"Machine\Scripts\settings.xml", Bytes("<Groups/>"))
            .Denying(PolicyPath, @"Machine\Scripts\settings.xml");

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()), scanGppPasswords: true);

        Assert.Equal(GpoReadOutcome.PartiallyRead, Assert.Single(coverage.Policies).Outcome);
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

        var capture = new SysvolCapture(new InMemorySysvolFileReader(), writer, RunLog.Discarded, TimeProvider.System);

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => capture.ReadAsync(Inventory(OnePolicy()), cancelled.Token));
    }

    [Fact]
    public async Task ATimedOutEnumerationMarksOnlyItsPolicyIncomplete()
    {
        var files = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor())
            .WithDescriptor(SecondPolicyPath, "", ADescriptor());
        var reader = new TimedOutReader(files, "directories", "*");

        var coverage = await ReadAsync(reader, Inventory(OnePolicy(),
            GpoTarget.Of(SecondPolicyGuid, "Second policy", SecondPolicyPath)));

        Assert.Equal([GpoReadOutcome.PartiallyRead, GpoReadOutcome.Read],
            coverage.Policies.Select(policy => policy.Outcome));
    }

    [Fact]
    public async Task NoFurtherAcquisitionRunsForAPolicyWhoseEnumerationTimedOut()
    {
        var reader = new TimedOutReader(new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor()), "directories", "*");

        await ReadAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(["acl:", "directories:*"], reader.Calls.Select(call => call.Operation + ":" + call.Path));
    }

    [Fact]
    public async Task CompletedRootEvidenceSurvivesAnEnumerationTimeoutInASealedBundle()
    {
        var reader = new TimedOutReader(new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor()), "directories", "*");

        var directory = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal([PolicyGuid.ToString("D") + "|PartiallyRead|"], Query(directory,
            "SELECT c.gpo_guid || '|' || c.outcome || '|' || d.relative_path "
            + "FROM sysvol_gpo_coverage c JOIN sysvol_path_security_descriptor d ON c.gpo_guid = d.gpo_guid"));
    }

    [Fact]
    public async Task CompletedFileContentsSurviveTheSubsequentAclTimeout()
    {
        var files = new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor())
            .WithDescriptor(PolicyPath, "Machine", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Microsoft", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Microsoft\Windows NT", ADescriptor())
            .WithDescriptor(PolicyPath, @"Machine\Microsoft\Windows NT\SecEdit", ADescriptor())
            .WithDescriptor(PolicyPath, TemplatePath, ADescriptor())
            .WithFile(PolicyPath, TemplatePath, TemplateBytes("[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-545"));
        var reader = new TimedOutReader(files, "acl", TemplatePath);

        var directory = await CaptureAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(["SeDebugPrivilege|*S-1-5-32-545"], Query(directory,
            "SELECT name || '|' || value FROM gpo_security_setting"));
    }

    [Fact]
    public async Task ARootTimeoutIsUnreadableRatherThanAnEmptySuccessfulPolicy()
    {
        var reader = new TimedOutReader(new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor()), "acl", "");

        var coverage = await ReadAsync(reader, Inventory(OnePolicy()));

        Assert.Equal(GpoReadOutcome.Unreadable, Assert.Single(coverage.Policies).Outcome);
    }

    [Fact]
    public async Task ADatabaseConstraintFailureEscapesThePolicyTimeoutBoundary()
    {
        using var writer = BundleWriter.Create(Directory.CreateDirectory(_root).FullName, Started);
        var descriptor = ADescriptor();
        writer.WriteSysvolSecurityDescriptor(PolicyGuid, "", descriptor,
            AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(descriptor)));
        var reader = new InMemorySysvolFileReader().WithDescriptor(PolicyPath, "", descriptor);
        var capture = new SysvolCapture(reader, writer, RunLog.Discarded, TimeProvider.System);

        await Assert.ThrowsAsync<SqliteException>(() => capture.ReadAsync(Inventory(OnePolicy()), CancellationToken.None));
    }

    [Fact]
    public async Task PolicyProgressCountsAccountForTimeoutsWithoutCallingThemCompleteReads()
    {
        using var writer = BundleWriter.Create(Directory.CreateDirectory(_root).FullName, Started);
        var reader = new TimedOutReader(new InMemorySysvolFileReader()
            .WithDescriptor(PolicyPath, "", ADescriptor())
            .WithDescriptor(SecondPolicyPath, "", ADescriptor()), "directories", "*");
        var log = new RecordingRunLog();

        await new SysvolCapture(reader, writer, log, TimeProvider.System).ReadAsync(Inventory(OnePolicy(),
            GpoTarget.Of(SecondPolicyGuid, "Second policy", SecondPolicyPath)), CancellationToken.None);

        Assert.Equal(["1|2|PartiallyRead", "2|2|Read"], log.Saying("SYSVOL policy accounted for")
            .Select(row => RecordingRunLog.Value(row, "policiesCompleted") + "|"
                + RecordingRunLog.Value(row, "policiesTotal") + "|" + RecordingRunLog.Value(row, "outcome")));
    }

    private sealed class TimedOutReader(ISysvolFileReader inner, string operation, string path) : ISysvolFileReader
    {
        internal List<(Guid Gpo, string Operation, string Path)> Calls { get; } = [];

        public Task<Result<byte[]?>> ReadFileAsync(GpoTarget target, string relativePath, CancellationToken cancellationToken) =>
            ReadAsync(target, "file", relativePath, () => inner.ReadFileAsync(target, relativePath, cancellationToken));

        public Task<Result<byte[]?>> ReadSecurityDescriptorAsync(GpoTarget target, string relativePath, CancellationToken cancellationToken) =>
            ReadAsync(target, "acl", relativePath, () => inner.ReadSecurityDescriptorAsync(target, relativePath, cancellationToken));

        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(GpoTarget target, string searchPattern, CancellationToken cancellationToken) =>
            ReadAsync(target, "files", searchPattern, () => inner.EnumerateRelativeFilesAsync(target, searchPattern, cancellationToken));

        public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(GpoTarget target, CancellationToken cancellationToken) =>
            ReadAsync(target, "directories", "*", () => inner.EnumerateRelativeDirectoriesAsync(target, cancellationToken));

        private Task<Result<T>> ReadAsync<T>(GpoTarget target, string requestedOperation, string requestedPath, Func<Task<Result<T>>> read)
        {
            Calls.Add((target.GpoGuid, requestedOperation, requestedPath));
            return target.GpoGuid == PolicyGuid && requestedOperation == operation && requestedPath == path
                ? Task.FromResult(Result<T>.Failure(AuditError.Create(ErrorCategory.Capture,
                    "SysvolOperationTimedOut", ErrorSeverity.Failed,
                    $"Synthetic timeout at {target.FileSysPath}\\{requestedPath}; remaining policy operations were not attempted.", target.FileSysPath)))
                : read();
        }
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

    private async Task<SysvolCoverage> ReadAsync(
        ISysvolFileReader reader,
        GpoInventory inventory,
        bool? scanGppPasswords = null)
    {
        using var writer = BundleWriter.Create(Directory.CreateDirectory(_root).FullName, Started);

        var capture = scanGppPasswords is { } scan
            ? new SysvolCapture(
                reader, writer, RunLog.Discarded, TimeProvider.System, new CaptureOptions(scan))
            : new SysvolCapture(reader, writer, RunLog.Discarded, TimeProvider.System);

        return await capture
            .ReadAsync(inventory, CancellationToken.None);
    }

    /// <summary>Runs a SYSVOL capture and seals the bundle, returning its directory.</summary>
    private async Task<string> CaptureAsync(
        ISysvolFileReader reader,
        GpoInventory inventory,
        bool? scanGppPasswords = null)
    {
        var directory = Directory.CreateDirectory(_root).FullName;

        using var writer = BundleWriter.Create(directory, Started);

        var capture = scanGppPasswords is { } scan
            ? new SysvolCapture(
                reader, writer, RunLog.Discarded, TimeProvider.System, new CaptureOptions(scan))
            : new SysvolCapture(reader, writer, RunLog.Discarded, TimeProvider.System);

        var coverage = await capture
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

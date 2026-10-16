using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    private const string LapsRoot = "DC=ad,DC=lab";
    private const string LapsDn = "CN=FS01,OU=Servers," + LapsRoot;
    private static DateTimeOffset LapsStarted => new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(null)]
    [InlineData("unreadable")]
    [InlineData("4294967296")]
    public void P248SavedLapsKeepsUnknownAccountState(string? rawAccount)
    {
        var directory = CreateLapsRun(account: null, rawAccount: rawAccount);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Equal(LapsAttributes.AccountState.Unknown, Assert.Single(page.Value.Computers).AccountState);
    }

    [Theory]
    [InlineData(null, LapsTimestampReading.Absent)]
    [InlineData("not a date", LapsTimestampReading.Unreadable)]
    [InlineData("0", LapsTimestampReading.Unreadable)]
    [InlineData("133700000000000000", LapsTimestampReading.Present)]
    public void P248SavedLapsPreservesTimestampReading(string? raw, LapsTimestampReading expected)
    {
        var directory = CreateLapsRun(modern: raw);
        using var source = new BundleAssetSource();

        var row = Assert.Single(source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null).Value.Computers);

        Assert.Equal((raw, expected), (row.WindowsLaps.Raw, row.WindowsLaps.Reading));
    }

    [Fact]
    public void P248SavedLapsReadsTheRecordedInterpretationWithoutReclassification()
    {
        var directory = CreateLapsRun();
        // Deliberately distinguish the recorded interpretation from what today's raw-value classifiers
        // would produce. This is synthetic, resealed evidence of passive readback, not tamper resistance.
        MutateControlRun(directory, """
            UPDATE laps_inventory SET management='LegacyLaps', result=json_set(result,
                '$.Management','LegacyLaps', '$.Capability.Kind','Unknown', '$.Capability.Basis','OperatingSystemName',
                '$.AccountState','Unknown', '$.DomainController.PrimaryGroupIsDomainController',json('true'),
                '$.WindowsLaps.Reading','Unreadable', '$.WindowsLaps.ExpiresUtc',NULL)
            """);
        using var source = new BundleAssetSource();

        var row = Assert.Single(source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null).Value.Computers);

        Assert.Equal((LapsManagement.LegacyLaps, LapsCapabilityKind.Unknown, LapsCapabilityBasis.OperatingSystemName,
            LapsAttributes.AccountState.Unknown, true, LapsTimestampReading.Unreadable, (DateTimeOffset?)null),
            (row.Management, row.Capability.Kind, row.Capability.Basis, row.AccountState,
             row.DomainController.PrimaryGroupIsDomainController, row.WindowsLaps.Reading, row.WindowsLaps.ExpiresUtc));
    }

    [Fact]
    public void P248SavedLapsRetainsOriginalSupportingValues()
    {
        var directory = CreateLapsRun(legacy: "unreadable");
        using var source = new BundleAssetSource();

        var row = Assert.Single(source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null).Value.Computers);

        Assert.Equal((LapsDn, "ad.lab", "Windows Server 2022 Datacenter", "10.0 (20348)", "4096", "133700000000000000", "unreadable"),
            (row.DistinguishedName, row.DomainFqdn, row.OperatingSystem, row.OperatingSystemVersion,
             row.UserAccountControl, row.WindowsLaps.Raw, row.LegacyLaps.Raw));
    }

    [Theory]
    [InlineData("CN=FS01,OU=Servers,DC=ad,DC=lab", ListingScope.Base, 1)]
    [InlineData("DC=ad,DC=lab", ListingScope.OneLevel, 1)]
    [InlineData("DC=ad,DC=lab", ListingScope.Subtree, 2)]
    public void P248SavedLapsRespectsListingScope(string dn, ListingScope scope, int expected)
    {
        var directory = LapsBundle.BuildMany([
            (LapsDn, "Windows Server 2022", "10.0 (20348)", "133700000000000000", null, 4096u),
            ("CN=Other," + LapsRoot, "Windows Server 2022", "10.0 (20348)", "133700000000000000", null, 4096u)], LapsStarted);
        SavedLapsTestRun.Judge(directory);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(dn, scope, "", null), null).Value;

        Assert.Equal((expected, expected), (page.Total, page.Computers.Count));
    }

    [Fact]
    public void P248SavedLapsEscapesScopeWildcards()
    {
        var directory = LapsBundle.BuildMany([
            ("CN=A,OU=_%!," + LapsRoot, "Windows Server 2022", "10.0 (20348)", "133700000000000000", null, 4096u),
            ("CN=B,OU=Other!," + LapsRoot, "Windows Server 2022", "10.0 (20348)", "133700000000000000", null, 4096u)], LapsStarted);
        SavedLapsTestRun.Judge(directory);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new("OU=_%!," + LapsRoot, ListingScope.Subtree, "", null), null).Value;

        Assert.Equal("A", Assert.Single(page.Computers).Name);
    }

    [Fact]
    public void P248SavedLapsCountsTheWholeScopeRatherThanThePage()
    {
        var directory = LapsBundle.BuildMany(Enumerable.Range(0, 103).Select(index =>
            ($"CN=PC{index:D3},OU=Servers,{LapsRoot}", (string?)"Windows Server 2022", (string?)"10.0 (20348)",
             (string?)"133700000000000000", (string?)null, 4096u)).ToArray(), LapsStarted);
        SavedLapsTestRun.Judge(directory);
        using var source = new BundleAssetSource();

        var query = new LapsQuery(LapsRoot, ListingScope.Subtree, "", null);
        var first = source.ListLapsComputers(directory, query, null).Value;
        var second = source.ListLapsComputers(directory, query, Assert.IsType<LapsPageMark>(first.Next)).Value;

        Assert.Equal((100, 3, 103, 103, 103),
            (first.Computers.Count, second.Computers.Count, first.Total, second.Total, second.CountOf(LapsManagement.WindowsLaps)));
    }

    [Fact]
    public void P248SavedLapsDoesNotDecodeAnotherPage()
    {
        var directory = CreateLapsRun();
        MutateControlRun(directory, """
            INSERT INTO laps_inventory VALUES ('CN=Other,DC=ad,DC=lab','Other','DC=ad,DC=lab','lab,ad,Other','NotManaged','ad.lab','not json');
            UPDATE laps_inventory_product SET computer_count=2
            """);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsDn, ListingScope.Base, "", null), null).Value;

        Assert.Equal(LapsDn, Assert.Single(page.Computers).DistinguishedName);
    }

    [Fact]
    public void P248SavedLapsRefusesCaptureOnlyInsteadOfCalculatingInventory()
    {
        var directory = CreateLapsEvidence();
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Equal("This run has no saved LAPS inventory.", page.Error?.Description);
    }

    [Fact]
    public void P248SavedLapsCompletedEmptyInventoryIsARealAnswer()
    {
        var directory = LapsBundle.BuildMany([], LapsStarted);
        SavedLapsTestRun.Judge(directory);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Equal((true, 0, 0), (page.IsSuccess, page.Value.Total, page.Value.Computers.Count));
    }

    [Theory]
    [InlineData("DELETE FROM laps_inventory_product", "This run has no saved LAPS inventory.")]
    [InlineData("UPDATE laps_inventory_product SET state='Writing'", "incomplete or invalid")]
    [InlineData("UPDATE laps_inventory_product SET generation_id='different'", "incomplete or invalid")]
    [InlineData("UPDATE judgement SET schema_version=39", "schema version 39")]
    public void P248SavedLapsRefusesAnUnavailableProduct(string sql, string message)
    {
        var directory = CreateLapsRun();
        MutateControlRun(directory, sql);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Contains(message, page.Error?.Description ?? "", StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("result='not json'")]
    [InlineData("management='NotManaged'")]
    public void P248SavedLapsRefusesInvalidRequestedRows(string assignment)
    {
        var directory = CreateLapsRun();
        MutateControlRun(directory, "UPDATE laps_inventory SET " + assignment);
        using var source = new BundleAssetSource();

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Equal("Shell.SavedResultsInvalidEvidence", page.Error?.Code);
    }

    [Fact]
    public void P248SavedLapsSharesProtectedFilesAcrossReads()
    {
        var directory = CreateLapsRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        var second = source.ListLapsComputers(directory, new(LapsDn, ListingScope.Base, "", null), null);
        source.ReadObjectAttributes(directory, LapsDn);

        Assert.Equal((1, 1L, 1L, 0L),
            (second.Value.Computers.Count, counts.EvidenceVerifications, counts.JudgementVerifications, counts.AnalyticalReads));
        Assert.Equal((0L, 0L, 0L), (counts.FactsVerifications, counts.PermissionProofVerifications, counts.PathProofVerifications));
    }

    [Fact]
    public void P248SavedLapsVerifiesAgainAfterClosing()
    {
        var directory = CreateLapsRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);
        source.CloseRun();
        source.SelectRun(directory);

        var page = source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null);

        Assert.Equal((1, 0L, 2L), (page.Value.Computers.Count, counts.EvidenceVerifications, counts.JudgementVerifications));
        Assert.Equal(2L, counts.NavigationVerifications);
        Assert.Equal(0L, counts.FactsVerifications);
    }

    [Fact]
    public void P248SavedLapsHonorsCancellation()
    {
        var directory = CreateLapsRun();
        using var session = new OpenedRunResults(directory);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();

        Assert.Throws<OperationCanceledException>(() => session.ReadLapsComputers(new(LapsRoot, ListingScope.Subtree, "", null), null, stopping.Token));
    }

    [Fact]
    public void P248SavedLapsDoesNotPublishAnUnfinishedProduct()
    {
        var directory = CreateLapsEvidence();
        using var writer = JudgementWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            null, LapsStarted, LapsStarted);
        using (var connection = new SqliteConnection($"Data Source={TestSealing.PendingJudgementPath(directory)};Pooling=False"))
        {
            connection.Open();
            TestSealing.AttachJudgementParts(connection, directory, writer.GenerationId, staged: true);
            using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO laps_inventory_product VALUES (1, $generation, 'Writing', NULL)";
            command.Parameters.AddWithValue("$generation", writer.GenerationId.ToString("D"));
            command.ExecuteNonQuery();
        }

        Assert.Throws<InvalidDataException>(() => writer.Complete(LapsStarted));
    }

    [Theory]
    [InlineData(null, "Account state unknown")]
    [InlineData(516, "Domain controller; account state unknown")]
    public void P248SavedLapsShowsUnknownRatherThanDisabled(int? group, string expected)
    {
        var directory = CreateLapsRun(account: null, primaryGroup: group);
        using var source = new BundleAssetSource();

        var row = new LapsComputerViewModel(Assert.Single(source.ListLapsComputers(directory, new(LapsRoot, ListingScope.Subtree, "", null), null).Value.Computers));

        Assert.Equal(expected, row.NotJudgedBecause);
    }

    private static string CreateLapsRun(uint? account = 4096, string? modern = "133700000000000000", string? legacy = null,
        string? rawAccount = null, int? primaryGroup = null)
    {
        var directory = CreateLapsEvidence(account, modern, legacy, rawAccount, primaryGroup);
        SavedLapsTestRun.Judge(directory);
        return directory;
    }

    private static string CreateLapsEvidence(uint? account = 4096, string? modern = "133700000000000000", string? legacy = null,
        string? rawAccount = null, int? primaryGroup = null) =>
        LapsBundle.Build(LapsDn, ["top", "computer"], "Windows Server 2022 Datacenter", "10.0 (20348)",
            modern, legacy, account, false, true, LapsStarted, primaryGroup, accountControlText: rawAccount);
}

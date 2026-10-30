using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("user", 0x00400200u, false)]
    [InlineData("user", 0x00400202u, true)]
    [InlineData("computer", 0x00401000u, false)]
    [InlineData("computer", 0x00401002u, true)]
    public void Sec022SelectedFlagsAreBoundAndDoNotRewriteSavedResults(string objectClass, uint control, bool disabled)
    {
        var directory = Sec022SettingRun(objectClass, control);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            var selected = source.ReadSelectedFinding(directory, row.Reference!.Value, false);
            Assert.True(selected.IsSuccess, selected.Error?.Description);
            Assert.Equal(0L, counts.Heavy);
            foreach (var attempt in new[] { 1, 2 })
            {
                var read = source.ReadAccountSetting(directory, row.Reference.Value);
                Assert.True(read.IsSuccess, read.Error?.Description);
                var setting = read.Value;
                Assert.Equal(row.Reference.Value, setting.Reference);
                Assert.Equal(row.ObjectGuid, setting.ObjectGuid);
                Assert.Equal(row.Subject, setting.Subject);
                Assert.Equal(row.DistinguishedName, setting.DistinguishedName);
                Assert.Equal(control, setting.AccountControl.UserAccountControl);
                Assert.Equal(disabled, setting.AccountControl.IsDisabled);
                Assert.True(setting.HasReportedSetting);
                Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                    counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
            }
            Assert.Equal(row, source.ReadSelectedFinding(directory, row.Reference.Value, false).Value);
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("text")]
    [InlineData("negative")]
    [InlineData("too-large")]
    [InlineData("fraction")]
    [InlineData("flag-clear")]
    public void Sec022UnreadableSavedFlagsAreExplicitRefusalsNotEnabledAccounts(string defect)
    {
        var directory = Sec022SettingRun("user", 0x00400200);
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_user_account_control",
            "text" => "UPDATE finding_user_account_control SET user_account_control='unreadable'",
            "negative" => "UPDATE finding_user_account_control SET user_account_control=-1",
            "too-large" => "UPDATE finding_user_account_control SET user_account_control=4294967296",
            "fraction" => "UPDATE finding_user_account_control SET user_account_control=4194816.5",
            _ => "UPDATE finding_user_account_control SET user_account_control=512",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        Assert.True(source.ReadSelectedFinding(directory, row.Reference!.Value, false).IsSuccess);
        var read = source.ReadAccountSetting(directory, row.Reference.Value);
        Assert.False(read.IsSuccess);
        Assert.Contains("saved account setting", read.Error.Description, StringComparison.Ordinal);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("zero")]
    [InlineData("missing")]
    public void Sec022SelectedSettingRejectsInvalidReferences(string defect)
    {
        var directory = Sec022SettingRun("user", 0x00400200);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var reference = row.Reference!.Value;
        var invalid = defect switch
        {
            "generation" => reference with { GenerationId = Guid.NewGuid() },
            "zero" => reference with { FindingId = 0 },
            _ => reference with { FindingId = long.MaxValue },
        };
        Assert.False(source.ReadAccountSetting(directory, invalid).IsSuccess);
    }

    [Fact]
    public void Sec022SettingRejectsUnsupportedRulesEvenWithTheSameFlag()
    {
        var otherDirectory = Sec022SettingRun("user", 0x00400220, savedRuleId: "SEC-999");
        using var other = new BundleAssetSource();
        var otherRow = Assert.Single(other.ReadFindingsList(otherDirectory, FindingsQuery.Everything()).Value.Findings);
        Assert.Equal("SEC-999", otherRow.RuleId);
        var otherRead = other.ReadAccountSetting(otherDirectory, otherRow.Reference!.Value);
        Assert.False(otherRead.IsSuccess);
        Assert.Contains("saved account setting", otherRead.Error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void Sec022SettingLookupUsesFindingIdentityRatherThanNameOrFirstRow()
    {
        var names = new[] { "CN=First,DC=ad,DC=lab", "CN=Second,DC=ad,DC=lab" };
        var directory = LapsBundle.BuildMany([
            (names[0], null, null, null, null, 0x00401000u),
            (names[1], null, null, null, null, 0x00401002u),
        ], DateTimeOffset.UnixEpoch);
        var rule = new NoKerberosPreauthentication();
        using (var evidence = BundleReader.Open(directory).Value)
        {
            var findings = names.Select(dn => Assert.Single(rule.Judge(evidence.ReadObjectAttributes(dn)!).Findings)
                with { PrincipalName = "Same display name" }).ToArray();
            WriteFindingsFixture(directory, findings);
        }
        using var source = new BundleAssetSource();
        var first = source.ReadFindingsList(directory, FindingsQuery.Everything() with { PageSize = 1 }).Value;
        var second = source.ReadFindingsList(directory, FindingsQuery.Everything()
            .ResumingAfter(first.Next!.Value) with { PageSize = 1 }).Value;
        var firstRow = Assert.Single(first.Findings);
        var secondRow = Assert.Single(second.Findings);
        Assert.Equal(firstRow.PrincipalName, secondRow.PrincipalName);
        var firstSetting = source.ReadAccountSetting(directory, firstRow.Reference!.Value).Value;
        var secondSetting = source.ReadAccountSetting(directory, secondRow.Reference!.Value).Value;
        Assert.False(firstSetting.AccountControl.IsDisabled);
        Assert.True(secondSetting.AccountControl.IsDisabled);
        Assert.Equal(firstRow.Reference.Value, firstSetting.Reference);
        Assert.Equal(secondRow.Reference.Value, secondSetting.Reference);
        Assert.Equal(firstRow.ObjectGuid, firstSetting.ObjectGuid);
        Assert.Equal(secondRow.ObjectGuid, secondSetting.ObjectGuid);
    }

    private static string Sec022SettingRun(string objectClass, uint control, string? savedRuleId = null)
        => AccountSettingRun(objectClass, control, new NoKerberosPreauthentication(), savedRuleId);

    private static string AccountSettingRun(string objectClass, uint control, IObjectRule rule, string? savedRuleId = null)
    {
        const string dn = "CN=Captured account,DC=ad,DC=lab";
        var classes = objectClass == "computer" ? new[] { "top", "user", "computer" } : ["top", "person", "user"];
        var directory = LapsBundle.Build(dn, classes, null, null, null, null, control, false, true, DateTimeOffset.UnixEpoch);
        using var evidence = BundleReader.Open(directory).Value;
        var captured = evidence.ReadObjectAttributes(dn)!;
        var definition = rule.Definition with { Id = savedRuleId ?? rule.Definition.Id };
        var finding = Assert.Single(rule.Judge(captured).Findings) with { RuleId = definition.Id };
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!;
        using var writer = JudgementWriter.Create(directory, seal.Hash, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        writer.Write(RuleExecution.Judged(definition, 1, 0, [finding]));
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }
}

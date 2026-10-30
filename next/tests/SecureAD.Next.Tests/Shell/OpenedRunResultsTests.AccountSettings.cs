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
    [MemberData(nameof(AccountSettingDetailTests.States), MemberType = typeof(AccountSettingDetailTests))]
    public void AccountSettingReadbackKeepsEachRuleFlagStateAndBinding(
        string ruleId, uint flag, string label, Severity severity, string objectClass, bool disabled)
    {
        var control = flag | (objectClass == "computer" ? 0x1000u : 0x200u) | (disabled ? 2u : 0);
        var directory = AccountSettingRun(objectClass, control, AccountSettingRule(ruleId));
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            foreach (var attempt in new[] { 1, 2 })
            {
                var read = source.ReadAccountSetting(directory, row.Reference!.Value);
                Assert.True(read.IsSuccess, read.Error?.Description);
                Assert.Equal(row.Reference.Value, read.Value.Reference);
                Assert.Equal(ruleId, read.Value.RuleId);
                Assert.Equal(row.ObjectGuid, read.Value.ObjectGuid);
                Assert.Equal(row.Subject, read.Value.Subject);
                Assert.Equal(row.DistinguishedName, read.Value.DistinguishedName);
                Assert.Equal(control, read.Value.AccountControl.UserAccountControl);
                Assert.Equal(disabled, read.Value.AccountControl.IsDisabled);
                Assert.Equal(label, read.Value.SettingName);
                Assert.True(read.Value.HasReportedSetting);
                Assert.Equal(severity, row.Severity);
            }
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    public static IEnumerable<object[]> InvalidAccountSettingInputs()
    {
        foreach (var rule in new[] { ("SEC-028", 0x20u), ("SEC-029", 0x80u), ("SEC-033", 0x200000u) })
            foreach (var defect in new[] { "missing", "text", "negative", "too-large", "fraction", "another-flag" })
                yield return [rule.Item1, rule.Item2, defect];
    }

    [Theory]
    [MemberData(nameof(InvalidAccountSettingInputs))]
    public void AccountSettingReadbackRefusesMissingMalformedOrWrongFlags(string ruleId, uint flag, string defect)
    {
        var directory = AccountSettingRun("user", flag | 0x200u, AccountSettingRule(ruleId));
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_user_account_control",
            "text" => "UPDATE finding_user_account_control SET user_account_control='unreadable'",
            "negative" => "UPDATE finding_user_account_control SET user_account_control=-1",
            "too-large" => "UPDATE finding_user_account_control SET user_account_control=4294967296",
            "fraction" => "UPDATE finding_user_account_control SET user_account_control=4194816.5",
            _ => "UPDATE finding_user_account_control SET user_account_control=4194816",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadAccountSetting(directory, row.Reference!.Value);
        Assert.False(read.IsSuccess);
        Assert.Contains("saved account setting", read.Error.Description, StringComparison.Ordinal);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    [Fact]
    public void SeveralSavedOptionsKeepTheirIndependentFindingsAndExactSelectedAnswers()
    {
        const uint control = 0x006002a0;
        const string dn = "CN=Several captured options,DC=ad,DC=lab";
        var directory = LapsBundle.Build(dn, ["top", "person", "user"], null, null, null, null,
            control, false, true, DateTimeOffset.UnixEpoch);
        using (var evidence = BundleReader.Open(directory).Value)
        {
            var captured = evidence.ReadObjectAttributes(dn)!;
            var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!;
            using var writer = JudgementWriter.Create(directory, seal.Hash, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
            foreach (var rule in new IObjectRule[]
            {
                new NoKerberosPreauthentication(), new PasswordNotRequired(), new ReversiblePasswordEncryption(), new DesEncryptionOnly(),
            })
                writer.Write(RuleExecution.Judged(rule.Definition, 1, 0, [Assert.Single(rule.Judge(captured).Findings)]));
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        var page = source.ReadFindingsList(directory, FindingsQuery.Everything() with { PageSize = 2 }).Value;
        var later = source.ReadFindingsList(directory, FindingsQuery.Everything().ResumingAfter(page.Next!.Value)
            with { PageSize = 2 }).Value;
        var rows = page.Findings.Concat(later.Findings).ToArray();
        Assert.Equal(new[] { "SEC-022", "SEC-028", "SEC-029", "SEC-033" }, rows.Select(row => row.RuleId));
        Assert.Equal(4, rows.Select(row => row.Reference).Distinct().Count());
        Assert.Single(rows.Select(row => row.ObjectGuid).Distinct());
        Assert.Null(later.Next);
        foreach (var row in rows)
        {
            var read = source.ReadAccountSetting(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.Equal(row.Reference.Value, read.Value.Reference);
            Assert.Equal(row.RuleId, read.Value.RuleId);
            Assert.Equal(row.ObjectGuid, read.Value.ObjectGuid);
            Assert.Equal(control, read.Value.AccountControl.UserAccountControl);
            Assert.True(read.Value.HasReportedSetting);
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    private static IObjectRule AccountSettingRule(string ruleId) => ruleId switch
    {
        "SEC-028" => new PasswordNotRequired(),
        "SEC-029" => new ReversiblePasswordEncryption(),
        "SEC-033" => new DesEncryptionOnly(),
        _ => throw new ArgumentOutOfRangeException(nameof(ruleId)),
    };
}

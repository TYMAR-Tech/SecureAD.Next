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
    [MemberData(nameof(DelegationSettingDetailTests.States), MemberType = typeof(DelegationSettingDetailTests))]
    public void DelegationReadbackUsesOnlyTheBoundSavedHeader(
        string ruleId, string objectClass, bool computerClass, bool disabled)
    {
        var directory = DelegationSettingRun(objectClass, disabled);
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
                Assert.Equal("Unconstrained delegation", read.Value.SettingName);
                Assert.Equal(disabled, read.Value.AccountControl.IsDisabled);
                Assert.Equal(computerClass, read.Value.Delegation!.IsComputer);
                Assert.Equal(new(false, false, false), read.Value.Delegation.ControllerSignals);
                Assert.True(read.Value.HasExpectedContext);
                Assert.Equal(Severity.High, row.Severity);
                Assert.Equal(objectClass, row.ObjectClass);
            }
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public void DelegationReadbackPreservesStoredIndicatorsWithoutReplayingExclusions(int mask)
    {
        var directory = DelegationSettingRun("computer", false, mask);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadAccountSetting(directory, row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(new((mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0), read.Value.Delegation!.ControllerSignals);
        Assert.Equal("SEC-011", read.Value.RuleId);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    public static IEnumerable<object[]> InvalidDelegationInputs()
    {
        foreach (var objectClass in new[] { "user", "computer" })
            foreach (var defect in new[] { "missing", "uac-text", "uac-negative", "uac-too-large", "uac-fraction", "flag-clear", "wrong-kind" })
                yield return [objectClass, defect];
        foreach (var column in new[] { "is_computer", "server_trust_account_bit", "primary_group_is_domain_controller", "under_domain_controllers_ou" })
            foreach (var value in new[] { "2", "'unreadable'" })
                yield return ["computer", column + "=" + value];
    }

    [Theory]
    [MemberData(nameof(InvalidDelegationInputs))]
    public void DelegationReadbackRefusesMissingMalformedAndMismatchedHeaders(string objectClass, string defect)
    {
        var directory = DelegationSettingRun(objectClass, false);
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_unconstrained_delegation",
            "uac-text" => "UPDATE finding_unconstrained_delegation SET user_account_control='unreadable'",
            "uac-negative" => "UPDATE finding_unconstrained_delegation SET user_account_control=-1",
            "uac-too-large" => "UPDATE finding_unconstrained_delegation SET user_account_control=4294967296",
            "uac-fraction" => "UPDATE finding_unconstrained_delegation SET user_account_control=524802.5",
            "flag-clear" => "UPDATE finding_unconstrained_delegation SET user_account_control=512",
            "wrong-kind" => "UPDATE finding_unconstrained_delegation SET is_computer=" + (objectClass == "computer" ? "0" : "1"),
            _ => "UPDATE finding_unconstrained_delegation SET " + defect,
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadAccountSetting(directory, row.Reference!.Value);
        Assert.False(read.IsSuccess);
        Assert.Contains("saved account setting", read.Error.Description, StringComparison.Ordinal);
        Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
    }

    [Fact]
    public void DelegationCannotBorrowAFlatFlagHeaderWhenItsOwnHeaderIsMissing()
    {
        var directory = DelegationSettingRun("computer", false);
        ChangeCoverageProof(directory, """
            INSERT INTO finding_user_account_control(finding_id,user_account_control)
                SELECT finding_id,user_account_control FROM finding_unconstrained_delegation;
            DELETE FROM finding_unconstrained_delegation
            """);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        Assert.False(source.ReadAccountSetting(directory, row.Reference!.Value).IsSuccess);
    }

    [Fact]
    public void SeveralDelegationFindingsKeepExactSelectedIdentityAndIndependentState()
    {
        var names = new[] { "CN=First,DC=ad,DC=lab", "CN=Second,DC=ad,DC=lab" };
        var directory = LapsBundle.BuildMany([
            (names[0], null, null, null, null, 0x00081000u),
            (names[1], null, null, null, null, 0x00081002u),
        ], DateTimeOffset.UnixEpoch);
        using (var captured = BundleReader.Open(directory).Value)
        {
            var findings = names.Select((dn, index) =>
            {
                var identity = captured.ReadObjectAttributes(dn)!;
                return new Finding("SEC-011", 1, Severity.High, new(FindingSubjectKind.Account, dn),
                    identity.ObjectGuid!.Value, dn, "ad.lab", "computer", "Saved delegation observation",
                    EvidenceCompleteness.Complete, new UnconstrainedDelegationEvidence(
                        index == 0 ? 0x00081000u : 0x00081002u, true, new(false, false, false)))
                { PrincipalName = "Same display name" };
            }).ToArray();
            WriteFindingsFixture(directory, findings);
        }
        using var source = new BundleAssetSource();
        var first = source.ReadFindingsList(directory, FindingsQuery.Everything() with { PageSize = 1 }).Value;
        var second = source.ReadFindingsList(directory, FindingsQuery.Everything().ResumingAfter(first.Next!.Value)
            with { PageSize = 1 }).Value;
        var firstRow = Assert.Single(first.Findings);
        var secondRow = Assert.Single(second.Findings);
        Assert.Equal(firstRow.PrincipalName, secondRow.PrincipalName);
        var firstSetting = source.ReadAccountSetting(directory, firstRow.Reference!.Value).Value;
        var secondSetting = source.ReadAccountSetting(directory, secondRow.Reference!.Value).Value;
        Assert.Equal(firstRow.Reference.Value, firstSetting.Reference);
        Assert.Equal(secondRow.Reference.Value, secondSetting.Reference);
        Assert.Equal(firstRow.ObjectGuid, firstSetting.ObjectGuid);
        Assert.Equal(secondRow.ObjectGuid, secondSetting.ObjectGuid);
        Assert.False(firstSetting.AccountControl.IsDisabled);
        Assert.True(secondSetting.AccountControl.IsDisabled);
        Assert.Null(second.Next);
    }

    private static string DelegationSettingRun(string objectClass, bool disabled, int mask = 0)
    {
        var computer = objectClass != "user";
        var control = 0x00080000u | (computer ? ((mask & 1) != 0 ? 0x2000u : 0x1000u) : 0x200u) | (disabled ? 2u : 0);
        var dn = (mask & 4) != 0 ? "CN=Captured,OU=Domain Controllers,DC=ad,DC=lab" : "CN=Captured,OU=Accounts,DC=ad,DC=lab";
        IReadOnlyList<string> classes = objectClass switch
        {
            "user" => ["top", "person", "user"],
            "computer" => ["top", "person", "user", "computer"],
            "msDS-ManagedServiceAccount" => ["top", "person", "user", "computer", "msDS-ManagedServiceAccount"],
            _ => ["top", "person", "user", "computer", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"],
        };
        var directory = LapsBundle.Build(dn, classes, null, null, null, null, control, false, true, DateTimeOffset.UnixEpoch,
            primaryGroupId: (mask & 2) != 0 ? 516 : computer ? 515 : 513);
        using var captured = BundleReader.Open(directory).Value;
        var identity = captured.ReadObjectAttributes(dn)!;
        IObjectRule rule = computer ? new UnconstrainedDelegationOnNonDomainController() : new UnconstrainedDelegationOnAccount();
        var signals = new DomainControllerSignals((mask & 1) != 0, (mask & 2) != 0, (mask & 4) != 0);
        // These retained positives deliberately include indicators the current producer would suppress;
        // selected readback must preserve the stored answer rather than replay that exclusion.
        var finding = new Finding(rule.Definition.Id, 1, Severity.High, new(FindingSubjectKind.Account, "captured account"),
            identity.ObjectGuid!.Value, dn, "ad.lab", objectClass, "Original recorded delegation description",
            EvidenceCompleteness.Complete, new UnconstrainedDelegationEvidence(control, computer, signals));
        var seal = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!;
        using var writer = JudgementWriter.Create(directory, seal.Hash, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        writer.Write(RuleExecution.Judged(rule.Definition, 1, 0, [finding]));
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }
}

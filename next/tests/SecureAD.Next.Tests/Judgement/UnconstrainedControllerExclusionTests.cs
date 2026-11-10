using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class UnconstrainedControllerExclusionTests
{
    private const string Root = "DC=contoso,DC=com";
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;
    private static readonly string[] Kinds =
        ["user", "computer", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"];

    public static IEnumerable<object[]> WritableClues() =>
        Kinds.SelectMany(kind => Enumerable.Range(0, 4).Select(clue => new object[] { kind, clue }));

    [Theory]
    [MemberData(nameof(WritableClues))]
    public void WritableCluesCannotSuppressAFlaggedAccountOrMoveItsRule(string kind, int clue)
    {
        var group = clue switch { 1 or 3 => 516, 2 => 521, _ => kind == "user" ? 513 : 515 };
        var subject = Subject(kind, RiskControl(kind), group, clue is 0 or 3);
        var result = Rule(kind).Judge(subject);
        Assert.True(result.IsComplete);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(kind == "user" ? "SEC-010" : "SEC-011", finding.RuleId);
        Assert.Equal((Severity.High, subject.ObjectGuid, kind),
            (finding.Severity, finding.ObjectGuid, finding.ObjectClass));
        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(finding.Evidence);
        Assert.Equal(RiskControl(kind), evidence.UserAccountControl);
        Assert.Equal(kind != "user", evidence.IsComputer);
        Assert.Equal(DomainControllerSignals.Of(subject), evidence.DomainController);
        Assert.True(evidence.DomainController.SignalsDisagree);
        Assert.Empty((kind == "user"
            ? new UnconstrainedDelegationOnNonDomainController().Judge(subject)
            : new UnconstrainedDelegationOnAccount().Judge(subject)).Findings);
    }

    [Theory]
    [InlineData(0x00082000u, 516, true)]
    [InlineData(0x00082000u, 516, false)]
    [InlineData(0x00082000u, 515, false)]
    [InlineData(0x04081000u, 521, true)]
    [InlineData(0x04081000u, 521, false)]
    [InlineData(0x04081000u, 515, false)]
    public void PublishedControllerRoleFlagsRemainExcludedWithoutRequiringWritableClues(
        uint control, int group, bool underOu)
    {
        var subject = Subject("computer", control, group, underOu);
        var result = new UnconstrainedDelegationOnNonDomainController().Judge(subject);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Empty(result.InputsNotCaptured);
    }

    [Theory]
    [InlineData(0x00082000u, 513, false)]
    [InlineData(0x00082000u, 513, true)]
    [InlineData(0x00082000u, 516, false)]
    [InlineData(0x00082000u, 516, true)]
    [InlineData(0x04081000u, 513, false)]
    [InlineData(0x04081000u, 513, true)]
    [InlineData(0x04081000u, 521, false)]
    [InlineData(0x04081000u, 521, true)]
    public void AControllerFlagCannotTurnCapturedUserClassIntoAController(uint control, int group, bool underOu)
    {
        var subject = Subject("user", control, group, underOu);
        var result = new UnconstrainedDelegationOnAccount().Judge(subject);
        Assert.True(result.IsComplete);
        var finding = Assert.Single(result.Findings);
        Assert.Equal("SEC-010", finding.RuleId);
        Assert.False(Assert.IsType<UnconstrainedDelegationEvidence>(finding.Evidence).IsComputer);
    }

    [Theory]
    [InlineData("user", true)]
    [InlineData("user", false)]
    [InlineData("computer", true)]
    [InlineData("computer", false)]
    public void AnUnreadableRequiredPrimaryGroupIsUnassessedRatherThanFalse(string kind, bool enabled)
    {
        var subject = Subject(kind, enabled ? RiskControl(kind) : 0x200u, 513,
            primaryGroupText: "not a RID");
        var result = Rule(kind).Judge(subject);
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Equal(new[] { "primaryGroupID" }, result.InputsNotCaptured);
        Assert.Empty(result.Unresolved);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("msDS-ManagedServiceAccount")]
    [InlineData("msDS-GroupManagedServiceAccount")]
    public void AReadableDisabledSettingRemainsACompleteNegative(string kind)
    {
        var subject = Subject(kind, kind == "user" ? 0x200u : 0x1000u, 516, true);
        var result = Rule(kind).Judge(subject);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Empty(result.InputsNotCaptured);
    }

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    public void CorrectedExclusionsHaveTheirOwnCalculationVersion(string kind) =>
        Assert.Equal(2, Rule(kind).Definition.Version);

    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    public void SavedExecutionPreservesFlaggedCluesControllerExclusionsAndUnassessedInputs(string kind)
    {
        var subjects = new[]
        {
            Subject(kind, RiskControl(kind), kind == "user" ? 513 : 515, true, name: "OU clue"),
            Subject(kind, RiskControl(kind), 516, name: "Group clue"),
            Subject("computer", 0x00082000, 516, name: "Writable controller"),
            Subject("computer", 0x04081000, 521, name: "Read-only controller"),
            Subject(kind, RiskControl(kind), 513, primaryGroupText: "not a RID", name: "Unreadable group"),
            Subject(kind, RiskControl(kind), 513, true, name: "Unidentified flagged") with { ObjectGuid = null },
            Subject(kind, kind == "user" ? 0x200u : 0x1000u, 516, true, name: "Disabled setting"),
        };
        var directory = TempDirectories.Create("unconstrained-controller-exclusion");
        var coverage = new PartitionCoverage(Root, NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, subjects.Length, 1, [], false);
        using (var writer = BundleWriter.Create(directory, When))
        {
            writer.WriteCoverage(coverage);
            foreach (var subject in subjects)
            {
                var attributes = subject.Attributes.Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName,
                    StoredAttributeCompleteness.Complete,
                    attribute.Values.Select(value => EvidenceValue.OfText(value.Text!)).ToArray())).ToArray();
                writer.WriteObject(new(coverage, subject.DistinguishedName, subject.ObjectGuid, attributes, When));
            }
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
                SysvolCoverage.Of([])), When.AddMinutes(1));
        }
        var original = SelfMembershipDiscoveryTests.Hash(directory);
        var judged = JudgingRun.Judge(directory, [Rule(kind)], When, When,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal(JudgementRunState.CompletedDegraded, judged.Value);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.Read();
        var execution = Assert.Single(saved.RulesRun);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(5, execution.ObjectsJudged);
        Assert.Equal(2, execution.ObjectsNotJudged);
        Assert.Equal(2, execution.MissingInputs.Count);
        Assert.Contains(new MissingInput("primaryGroupID", 1), execution.MissingInputs);
        Assert.Contains(new MissingInput("objectGUID", 1), execution.MissingInputs);
        Assert.Equal(subjects.Take(2).Select(subject => subject.ObjectGuid).Order(),
            saved.Findings.Select(finding => (Guid?)finding.ObjectGuid).Order());
        foreach (var finding in saved.Findings)
        {
            Assert.Equal(2, finding.RuleVersion);
            var proof = Assert.IsType<UnconstrainedDelegationEvidence>(finding.Evidence);
            Assert.True(proof.DomainController.SignalsDisagree);
            var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(finding.DistinguishedName)).Value.Findings);
            Assert.Equal(reader.Description.GenerationId, row.Reference!.Value.GenerationId);
            var selected = reader.ReadAccountSetting(row.Reference.Value);
            Assert.True(selected.IsSuccess, selected.Error?.Description);
            Assert.Equal(row.Reference.Value, selected.Value.Reference);
            Assert.Equal(finding.ObjectGuid, selected.Value.ObjectGuid);
            Assert.Equal(proof.UserAccountControl, selected.Value.AccountControl.UserAccountControl);
            Assert.Equal(new SavedDelegationContext(proof.IsComputer, proof.DomainController), selected.Value.Delegation);
        }
        Assert.Equal(original, SelfMembershipDiscoveryTests.Hash(directory));
    }

    private static IObjectRule Rule(string kind) => kind == "user"
        ? new UnconstrainedDelegationOnAccount() : new UnconstrainedDelegationOnNonDomainController();

    private static uint RiskControl(string kind) => 0x00080000u | (kind == "user" ? 0x200u : 0x1000u);

    private static ObjectAttributes Subject(string kind, uint control, int group, bool underOu = false,
        string? primaryGroupText = null, string name = "SyntheticScout05")
    {
        string[] classes = kind == "user" ? ["top", "user"]
            : kind == "computer" ? ["top", "user", "computer"] : ["top", "user", "computer", kind];
        return new($"CN={name},OU={(underOu ? "Domain Controllers" : "Accounts")}," + Root,
            Guid.NewGuid(), When, EvidenceCompleteness.Complete,
        [
            new("objectClass", AttributeCardinality.MultiValued,
                classes.Select((value, ordinal) => new AttributeValue(ordinal, value, null)).ToArray()),
            new("sAMAccountName", AttributeCardinality.SingleValued, [new(0, name, null)]),
            new("userAccountControl", AttributeCardinality.SingleValued, [new(0, control.ToString(CultureInfo.InvariantCulture), null)]),
            new("primaryGroupID", AttributeCardinality.SingleValued, [new(0, primaryGroupText ?? group.ToString(CultureInfo.InvariantCulture), null)]),
        ], "contoso.com");
    }
}

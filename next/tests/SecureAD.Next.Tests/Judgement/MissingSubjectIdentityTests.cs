using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MissingSubjectIdentityTests
{
    private static readonly string[] RuleIds = ["SEC-010", "SEC-011", "SEC-022", "SEC-027", "SEC-028", "SEC-029", "SEC-033"];
    private static readonly Guid KnownGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;
    private const string Root = "DC=contoso,DC=com";

    public static IEnumerable<object[]> Rules() => RuleIds.Select(id => new object[] { id });
    public static IEnumerable<object[]> InvalidIdentities() =>
        RuleIds.SelectMany(id => new[] { new object[] { id, false }, new object[] { id, true } });
    public static IEnumerable<object[]> MalformedControls() =>
        InvalidIdentities().Where(row => (string)row[0] != "SEC-027");
    public static IEnumerable<object[]> Exclusions() =>
        new[] { "other-class", "domain-controller", "trust-account" }
            .SelectMany(kind => new[] { new object[] { kind, false }, new object[] { kind, true } });

    [Theory]
    [MemberData(nameof(InvalidIdentities))]
    public void PositiveWithUnusableIdentityIsExplicitlyNotJudged(string id, bool allZero)
    {
        var (rule, _, _) = Case(id);
        var result = rule.Judge(Subject(id, true, allZero ? Guid.Empty : null));
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Equal(new[] { "objectGUID" }, result.InputsNotCaptured);
        Assert.Empty(result.Unresolved);
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void AValidPositiveKeepsItsOriginalFindingIdentityAndClassification(string id)
    {
        var (rule, _, _) = Case(id);
        var subject = Subject(id, true, KnownGuid);
        var result = rule.Judge(subject);
        Assert.True(result.IsComplete);
        var finding = Assert.Single(result.Findings);
        Assert.Equal((id, rule.Definition.Version, rule.Definition.Severity, KnownGuid),
            (finding.RuleId, finding.RuleVersion, finding.Severity, finding.ObjectGuid));
        Assert.Equal(new FindingSubject(FindingSubjectKind.Account, "SyntheticScout02"), finding.Subject);
        Assert.Equal(subject.DistinguishedName, finding.DistinguishedName);
        Assert.Equal("contoso.com", finding.DomainFqdn);
    }

    [Theory]
    [MemberData(nameof(InvalidIdentities))]
    public void ATrueNegativeDoesNotRequireAFindingIdentity(string id, bool allZero)
    {
        var (rule, _, _) = Case(id);
        var result = rule.Judge(Subject(id, false, allZero ? Guid.Empty : null));
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Empty(result.InputsNotCaptured);
        Assert.Empty(result.Unresolved);
    }

    [Theory]
    [MemberData(nameof(Exclusions))]
    public void AnExistingExclusionDoesNotBecomeAnIdentityGap(string kind, bool allZero)
    {
        var id = kind switch { "other-class" => "SEC-010", "domain-controller" => "SEC-011", _ => "SEC-028" };
        var (rule, _, flag) = Case(id);
        var classes = kind == "other-class" ? "computer" : null;
        var control = flag | 0x200u | (kind == "domain-controller" ? 0x2000u : kind == "trust-account" ? 0x800u : 0u);
        var subject = Subject(id, true, allZero ? Guid.Empty : null, classes, control.ToString(CultureInfo.InvariantCulture));
        var result = rule.Judge(subject);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Empty(result.InputsNotCaptured);
    }

    [Theory]
    [MemberData(nameof(MalformedControls))]
    public void AnUnusableIdentityDoesNotHideAnUnreadableRuleInput(string id, bool allZero)
    {
        var (rule, _, _) = Case(id);
        var result = rule.Judge(Subject(id, true, allZero ? Guid.Empty : null, controlText: "not a number"));
        Assert.False(result.IsComplete);
        Assert.Empty(result.Findings);
        Assert.Equal(new[] { "userAccountControl" }, result.InputsNotCaptured);
    }

    [Theory]
    [MemberData(nameof(Rules))]
    public void SavedExecutionRetainsTheRealFindingAndReportsBothIdentityGaps(string id)
    {
        var directory = TempDirectories.Create("missing-subject-identity");
        var coverage = new PartitionCoverage(Root, NamingContextKind.Domain, "dc.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 5, 1, [], false);
        using (var writer = BundleWriter.Create(directory, When))
        {
            writer.WriteCoverage(coverage);
            Write("Valid positive", KnownGuid, true);
            Write("Missing identity", null, true);
            Write("Empty identity", Guid.Empty, true);
            Write("True negative", Guid.NewGuid(), false);
            writer.WriteObject(new(coverage, "OU=Not applicable," + Root, null,
                [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("organizationalUnit")])], When));
            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                [DomainCoverage.Read("contoso.com")],
                [ForestPartitionCoverage.Read("CN=Configuration," + Root, NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema)],
                SysvolCoverage.Of([])), When.AddMinutes(1));

            void Write(string name, Guid? guid, bool positive)
            {
                var attributes = Values(id, positive).Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName,
                    StoredAttributeCompleteness.Complete, attribute.Values.Select(value => value.Text is { } text
                        ? EvidenceValue.OfText(text) : EvidenceValue.OfBytes(value.Bytes!)).ToArray())).ToArray();
                writer.WriteObject(new(coverage, "CN=" + name + "," + Root, guid, attributes, When));
            }
        }
        var original = SelfMembershipDiscoveryTests.Hash(directory);
        var (rule, _, _) = Case(id);
        var judged = JudgingRun.Judge(directory, [rule], When, When, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal(JudgementRunState.CompletedDegraded, judged.Value);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.Read();
        Assert.False(saved.EveryRuleReachedEveryVerdict);
        var execution = Assert.Single(saved.RulesRun);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Equal(2, execution.ObjectsJudged);
        Assert.Equal(2, execution.ObjectsNotJudged);
        Assert.Equal(1, execution.ObjectsNotApplicable);
        Assert.Equal(new MissingInput("objectGUID", 2), Assert.Single(execution.MissingInputs));
        Assert.Equal(KnownGuid, Assert.Single(saved.Findings).ObjectGuid);
        Assert.Equal(original, SelfMembershipDiscoveryTests.Hash(directory));
    }

    private static (IObjectRule Rule, string Class, uint Flag) Case(string id) => id switch
    {
        "SEC-010" => (new UnconstrainedDelegationOnAccount(), "user", UnconstrainedDelegation.TrustedForDelegation),
        "SEC-011" => (new UnconstrainedDelegationOnNonDomainController(), "computer", UnconstrainedDelegation.TrustedForDelegation),
        "SEC-022" => (new NoKerberosPreauthentication(), "user", NoKerberosPreauthentication.DontRequirePreauth),
        "SEC-027" => (new PrivilegedSidHistory(), "user", 0u),
        "SEC-028" => (new PasswordNotRequired(), "user", PasswordNotRequired.PasswordNotRequiredFlag),
        "SEC-029" => (new ReversiblePasswordEncryption(), "user", ReversiblePasswordEncryption.ReversibleEncryption),
        "SEC-033" => (new DesEncryptionOnly(), "user", DesEncryptionOnly.DesKeyOnly),
        _ => throw new ArgumentOutOfRangeException(nameof(id)),
    };

    private static ObjectAttributes Subject(string id, bool positive, Guid? guid, string? objectClass = null, string? controlText = null) =>
        new("CN=SyntheticScout02," + Root, guid, When, EvidenceCompleteness.Complete,
            Values(id, positive, objectClass, controlText), "contoso.com");

    private static ObjectAttribute[] Values(string id, bool positive, string? objectClass = null, string? controlText = null)
    {
        var (_, normalClass, flag) = Case(id);
        var kind = objectClass ?? normalClass;
        var control = controlText ?? (0x200u | (positive ? flag : 0u)).ToString(CultureInfo.InvariantCulture);
        return
        [
            Text("objectClass", AttributeCardinality.MultiValued, kind == "computer" ? ["top", "user", "computer"] : ["top", kind]),
            Text("sAMAccountName", AttributeCardinality.SingleValued, ["SyntheticScout02"]),
            Text("userAccountControl", AttributeCardinality.SingleValued, [control]),
            Text("primaryGroupID", AttributeCardinality.SingleValued, [kind == "computer" ? "515" : "513"]),
            new("objectSid", AttributeCardinality.SingleValued, [new(0, null, Sid.ToBytes("S-1-5-21-1-2-3-1100"))]),
            new("sIDHistory", AttributeCardinality.MultiValued, id == "SEC-027" && positive
                ? [new(0, null, Sid.ToBytes("S-1-5-21-1-2-3-512"))] : []),
        ];
    }

    private static ObjectAttribute Text(string name, AttributeCardinality cardinality, string[] values) =>
        new(name, cardinality, values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
}

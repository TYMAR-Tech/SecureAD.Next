using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using Xunit;
using Fixture = SecureAD.Next.Tests.Judgement.ServiceAccountRuleTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ConstrainedDelegationReadTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void OriginalOccurrencesArePagedWithoutChangingExactValuesOrWholeFindingCompleteness(int count)
    {
        var evidence = Evidence(count);
        var selected = Selected(evidence);
        var values = new List<string>();
        DelegationConfigurationMark? mark = null;
        do
        {
            var page = Project(evidence, selected, mark);
            Assert.True(page.Context.Matches(selected));
            Assert.True(page.Context.EvidenceIsComplete);
            Assert.Empty(page.Context.DescribeLimitations());
            Assert.True(page.IsExpectedPage(mark?.Offset ?? 0));
            Assert.Equal(Math.Min(50, count - values.Count), page.Services.Count);
            values.AddRange(page.Services);
            mark = page.Next;
            if (mark is { } next)
            {
                Assert.Equal(selected.Reference!.Value.GenerationId, next.GenerationId);
                Assert.Equal(selected.Reference.Value.FindingId, next.FindingId);
                Assert.Equal(evidence.Resource.ObjectGuid, next.ResourceGuid);
                Assert.Equal(values.Count, next.Offset);
            }
        } while (mark is not null);
        Assert.Equal(evidence.Services.Select(value => value.ConfiguredService), values);
        if (count > 1) Assert.Equal(values[0], values[1]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ResourceRelevanceIsReadAsSavedWithoutReclassifyingOrReconstructingOriginalAttributes(bool established)
    {
        var evidence = Evidence(2, established);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Account"]!["Attributes"]![0]!["Values"]![0]!["Bytes"] = "not a base64 snapshot";
        json["Resource"]!["Attributes"]![0]!["Values"]![0]!["Bytes"] = new string('x', 160_000);
        var page = Project(json.ToJsonString(), evidence, Selected(evidence));
        Assert.Equal(established, page.Context.EstablishedTier0);
        Assert.Equal(evidence.Account.ObjectGuid, page.Context.Account.ObjectGuid);
        Assert.Equal(evidence.Resource.DistinguishedName, page.Context.Resource.DistinguishedName);
        Assert.Equal(evidence.Services.Select(value => value.ConfiguredService), page.Services);
    }

    [Theory]
    [InlineData("ServiceResourceUnresolved", DelegationConfigurationInputLimitations.UnresolvedService, "could not be matched")]
    [InlineData("ServiceResourceAmbiguous", DelegationConfigurationInputLimitations.AmbiguousService, "no destination is guessed")]
    [InlineData("ResourceRelevanceUnassessed", DelegationConfigurationInputLimitations.UnassessedResource, "some other configured destinations")]
    [InlineData("CaptureIncomplete", DelegationConfigurationInputLimitations.CaptureIncomplete, "supported matches shown here remain findings")]
    [InlineData("ConfiguredServiceUnsupported", DelegationConfigurationInputLimitations.Other, "Additional saved evidence limitations")]
    public void KnownPositivesRetainTheirOwnSavedLimitations(string reason, DelegationConfigurationInputLimitations expected, string wording)
    {
        var evidence = Evidence(1) with { Limitations = [reason], InputsComplete = reason != "CaptureIncomplete" };
        var page = Project(evidence, Selected(evidence));
        Assert.Equal(expected, page.Context.Limitations);
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Single(page.Services);
        Assert.Contains(wording, Assert.Single(page.Context.DescribeLimitations()), StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceAndSourceCompletenessRemainQualifiedIndependentlyOfLoadedServicePages()
    {
        var evidence = Evidence(51) with
        {
            Resource = Evidence(1).Resource with { Completeness = EvidenceCompleteness.MayBeMissingConfidentialValues },
        };
        evidence = evidence with
        {
            Scope = evidence.Scope with { ResourceGuid = evidence.Resource.ObjectGuid, TargetDn = evidence.Resource.DistinguishedName,
                Limitations = ["MembershipIncomplete"] },
        };
        var page = Project(evidence, Selected(evidence));
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Equal(DelegationConfigurationInputLimitations.Other, page.Context.Limitations);
        Assert.Contains("Additional saved evidence limitations", Assert.Single(page.Context.DescribeLimitations()), StringComparison.Ordinal);
        Assert.NotNull(page.Next);
    }

    public static IEnumerable<object[]> InvalidFacts()
    {
        const string differentGuid = "\"00000000-0000-0000-0000-000000000001\"";
        yield return ["ConfigurationKind", "\"ResourceBased\""];
        yield return ["EvidenceSeal", "\"wrong captured source\""];
        yield return ["DerivationGenerationId", differentGuid];
        yield return ["DerivationSeal", "\"wrong derivation source\""];
        yield return ["PolicyVersion", "2"];
        yield return ["DescriptorParserVersion", "-1"];
        yield return ["Account.ObjectGuid", differentGuid];
        yield return ["Account.DistinguishedName", "\"CN=Another account,DC=contoso,DC=com\""];
        yield return ["Account.DomainFqdn", "\"another.example\""];
        yield return ["Account.ObjectClass", "\"computer\""];
        yield return ["Account.Completeness", "\"not a saved completeness\""];
        yield return ["Account.CapturedUtc", "\"not a capture time\""];
        yield return ["Account.Attributes", "null"];
        yield return ["Resource.ObjectGuid", differentGuid];
        yield return ["Resource.DistinguishedName", "\"CN=Another resource,DC=contoso,DC=com\""];
        yield return ["Scope.GenerationId", differentGuid];
        yield return ["Scope.ResourceGuid", differentGuid];
        yield return ["Scope.TargetDn", "\"CN=Another resource,DC=contoso,DC=com\""];
        yield return ["Scope.Fingerprint", "\"not a saved fingerprint\""];
        yield return ["Scope.EstablishedTier0", "\"true\""];
        yield return ["Scope.ClassificationBases", "[]"];
        yield return ["Scope.AnchorDns", "[]"];
        yield return ["Scope.Limitations", "[\"\"]"];
        yield return ["Services", "[]"];
        yield return ["Grants", "[{}]"];
        yield return ["InputsComplete", "false"];
        yield return ["IsComplete", "false"];
    }

    [Theory]
    [MemberData(nameof(InvalidFacts))]
    public void MissingMalformedOrMismatchedSavedFactsAreRefused(string path, string replacement)
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        var names = path.Split('.');
        var parent = names.Take(names.Length - 1).Aggregate(json, (node, name) => node[name]!);
        parent[names[^1]] = JsonNode.Parse(replacement);
        var error = Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, Selected(evidence)));
        Assert.Equal(SavedDelegationConfiguration.ConstrainedInvalidDetails, error.Message);
    }

    [Theory]
    [InlineData("ConfiguredService", "\"LDAP/unmatched.contoso.com\"")]
    [InlineData("RegisteredService", "\"LDAP/resource.contoso.com:636/another-instance\"")]
    [InlineData("ConfigurationOrdinal", "-1")]
    [InlineData("ConfigurationOrdinal", "2147483648")]
    [InlineData("RegistrationOrdinal", "1.25")]
    public void ARequestedServicePageCannotInventAnOccurrence(string property, string replacement)
    {
        var evidence = Evidence(51);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Services"]![50]![property] = JsonNode.Parse(replacement);
        var first = Project(json.ToJsonString(), evidence, Selected(evidence));
        Assert.Equal(50, first.Services.Count);
        var error = Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, Selected(evidence), first.Next));
        Assert.Equal(SavedDelegationConfiguration.ConstrainedInvalidDetails, error.Message);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("trailing-comma")]
    [InlineData("missing-comma")]
    [InlineData("bad-escape")]
    [InlineData("unescaped-control")]
    [InlineData("too-deep")]
    public void InvalidJsonOrMissingRequiredMembersCannotBecomeAnEmptySuccessfulAssessment(string defect)
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        json = defect switch
        {
            "missing" => json.Replace("\"InputsComplete\":true,", "", StringComparison.Ordinal),
            "duplicate" => json.Insert(1, "\"InputsComplete\":true,"),
            "truncated" => json[..^1],
            "trailing-comma" => json.Insert(json.Length - 1, ","),
            "missing-comma" => json.Replace(",\"IsComplete\"", "\"IsComplete\"", StringComparison.Ordinal),
            "bad-escape" => json.Replace("CN=Delegating account", "CN=Delegating\\q account", StringComparison.Ordinal),
            "unescaped-control" => json.Replace("CN=Delegating account", "CN=Delegating\naccount", StringComparison.Ordinal),
            "too-deep" => json.Replace("\"Attributes\":[", "\"Attributes\":[" + new string('[', 65)
                + "0" + new string(']', 65) + ",", StringComparison.Ordinal),
            _ => json + "{}",
        };
        Assert.Throws<InvalidDataException>(() => Project(json, evidence, Selected(evidence)));
    }

    [Fact]
    public void CancellationInterruptsSkippingAnUnrequestedLargeSnapshot()
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Account"]!["Attributes"]![0]!["Values"]![0]!["Text"] = new string('x', 160_000);
        using var cancel = new CancellationTokenSource();
        using var stream = new CancellingStream(Encoding.UTF8.GetBytes(json.ToJsonString()), cancel);
        Assert.Throws<OperationCanceledException>(() => DelegationConfigurationProjection.Read(stream, Selected(evidence),
            Description(evidence), evidence.DerivationSeal, null, cancel.Token));
    }

    internal static DelegationConfigurationEvidence Evidence(int count, bool established = true)
    {
        const string root = "DC=contoso,DC=com";
        var account = new DelegationConfigurationAccount(Guid.NewGuid(), "CN=Delegating account," + root, "contoso.com", "user",
            DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete,
            [new("objectClass", AttributeCardinality.MultiValued, [new(0, "user", null)])]);
        var resource = account with { ObjectGuid = Guid.NewGuid(), DistinguishedName = "CN=Registered resource," + root,
            ObjectClass = "computer" };
        var generation = Guid.NewGuid();
        var scope = new DelegationResourceScope(generation, resource.ObjectGuid, resource.DistinguishedName, new string('a', 64),
            established, established ? ["DomainController"] : [], ["CN=Established Tier 0," + root], established ? [] : [42], []);
        var services = Enumerable.Range(0, count).Select(index =>
        {
            var value = $"LDAP/resource.contoso.com:389/instance-{(index == 1 ? 0 : index):D3}";
            return new DelegationServiceOccurrence(index, value, index, value.ToUpperInvariant());
        }).ToArray();
        return new(DelegationConfigurationKind.Constrained, new string('b', 64), Guid.NewGuid(), new string('c', 64),
            DelegationConfigurationRules.PolicyVersion, SecureAD.Kernel.Security.SecurityDescriptorParser.Version,
            account, resource, scope, services, [], true, []);
    }

    internal static Finding Finding(DelegationConfigurationEvidence evidence) => new("SEC-012", 1, Severity.High,
        new(FindingSubjectKind.Account, DelegationConfigurationRules.Key(evidence.Account.ObjectGuid, evidence.Resource.ObjectGuid)),
        evidence.Account.ObjectGuid, evidence.Account.DistinguishedName, evidence.Account.DomainFqdn, evidence.Account.ObjectClass,
        "Original full saved explanation must not be used to recover facts.", EvidenceCompleteness.Complete, evidence)
        { PrincipalName = "delegating account" };

    internal static FindingListItem Selected(DelegationConfigurationEvidence evidence) =>
        FindingListItem.FromFinding(Finding(evidence)) with { Reference = new(evidence.Scope.GenerationId, 17) };

    internal static SavedDelegationConfiguration Project(DelegationConfigurationEvidence evidence, FindingListItem selected,
        DelegationConfigurationMark? after = null) =>
        Project(JsonSerializer.Serialize(evidence, ProofSerialization.Options), evidence, selected, after);

    private static SavedDelegationConfiguration Project(string json, DelegationConfigurationEvidence evidence, FindingListItem selected,
        DelegationConfigurationMark? after = null)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        return DelegationConfigurationProjection.Read(stream, selected, Description(evidence), evidence.DerivationSeal, after, CancellationToken.None);
    }

    private static JudgementDescription Description(DelegationConfigurationEvidence evidence) => new(evidence.EvidenceSeal,
        evidence.Scope.GenerationId, evidence.DerivationGenerationId, JudgementRunState.Completed,
        DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);

    internal static string PublishedRun(int count)
    {
        var names = Enumerable.Range(0, count).Select(index => $"LDAP/service.contoso.com:389/instance-{index:D3}").ToArray();
        const string accountDn = "CN=Delegating account,DC=contoso,DC=com";
        const string resourceDn = "CN=Narrow fixture administrator,DC=contoso,DC=com";
        var front = Fixture.With(Fixture.Account(dn: accountDn, sid: "S-1-5-21-1-2-3-1100", spns: []),
            DelegationConfigurationRules.ConstrainedAttribute, names.Select(EvidenceValue.OfText).ToArray());
        var back = Fixture.With(Fixture.Account(dn: resourceDn, sid: "S-1-5-21-1-2-3-500", spns: names),
            DelegationConfigurationRules.ConstrainedAttribute, []);
        back = Fixture.With(back, DelegationConfigurationRules.ResourceAttribute, []);
        var directory = Fixture.Capture([front, back]);
        Derive(directory);
        var result = JudgingRun.Judge(directory, [new ConstrainedDelegationToRelevantService()], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    internal sealed class CancellingStream(byte[] bytes, CancellationTokenSource cancel) : MemoryStream(bytes)
    {
        private int _reads;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (++_reads == 2) cancel.Cancel();
            return base.Read(buffer, offset, Math.Min(count, 4096));
        }
        public override int Read(Span<byte> buffer)
        {
            if (++_reads == 2) cancel.Cancel();
            return base.Read(buffer[..Math.Min(buffer.Length, 4096)]);
        }
    }
}

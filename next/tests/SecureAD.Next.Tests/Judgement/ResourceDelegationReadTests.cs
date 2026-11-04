using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Fixture = SecureAD.Next.Tests.Judgement.ServiceAccountRuleTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ResourceDelegationReadTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void SavedHoldersArePagedWithoutMembersDescriptorReplayOrChangingResourceGrain(int count)
    {
        var evidence = Evidence(count);
        var selected = Selected(evidence);
        var all = new List<string>();
        DelegationConfigurationMark? mark = null;
        do
        {
            var page = Project(evidence, selected, mark);
            Assert.True(page.Context.Matches(selected));
            Assert.True(page.Context.IsResourceBased);
            Assert.Equal(page.Context.Account, page.Context.Resource);
            Assert.False(page.Context.HasNullDacl);
            Assert.True(page.Context.EvidenceIsComplete);
            Assert.Empty(page.Services);
            Assert.Equal(Math.Min(50, count - all.Count), page.Holders.Count);
            Assert.All(page.Holders, holder => Assert.Null(holder.Name));
            all.AddRange(page.Holders.Select(holder => holder.Sid));
            mark = page.Next;
            if (mark is { } next)
            {
                Assert.Equal(all.Count, next.Offset);
                Assert.Equal(selected.Reference!.Value.GenerationId, next.GenerationId);
                Assert.Equal(selected.Reference.Value.FindingId, next.FindingId);
                Assert.Equal(evidence.Resource.ObjectGuid, next.ResourceGuid);
            }
        } while (mark is not null);
        Assert.Equal(evidence.Grants.Select(grant => grant.TrusteeSid), all);
        Assert.Equal(evidence.Resource.ObjectGuid.ToString("D"), selected.Subject.Key);
        Assert.Equal(Severity.High, selected.Severity);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NullDaclIsSavedConfigurationNotAnInventedExplicitEveryoneEntry(bool complete)
    {
        var evidence = Evidence(0, nullDacl: true) with
        {
            InputsComplete = complete,
            Limitations = complete ? [] : ["CaptureIncomplete"],
        };
        var page = Project(evidence, Selected(evidence));
        Assert.True(page.Context.HasNullDacl);
        Assert.True(page.Context.IsResourceBased);
        Assert.Equal(complete, page.Context.EvidenceIsComplete);
        Assert.Empty(page.Holders);
        Assert.Empty(page.Services);
        Assert.Null(page.Next);
        Assert.True(page.IsExpectedPage(0));
        Assert.False(page.IsExpectedPage(50));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SavedResourceRoleAndUnrequestedSnapshotsDoNotTriggerReanalysis(bool established)
    {
        var evidence = Evidence(1, established: established);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Account"]!["Attributes"]![0]!["Values"]![0]!["Bytes"] = "not a base64 snapshot";
        json["Resource"]!["Attributes"]![0]!["Values"]![0]!["Bytes"] = new string('x', 160_000);
        var page = Project(json.ToJsonString(), evidence, Selected(evidence));
        Assert.Equal(established, page.Context.EstablishedTier0);
        Assert.Equal(evidence.Resource.DistinguishedName, page.Context.Resource.DistinguishedName);
        Assert.Single(page.Holders);
    }

    [Fact]
    public void AHolderWithManyOriginalGrantOccurrencesDoesNotBecomeThousandsOfFindingsOrMembers()
    {
        var evidence = Evidence(1) with
        {
            Grants = [new("S-1-5-21-1-2-3-2100", Enumerable.Range(0, 20_000).ToArray(), false)],
        };
        var page = Project(evidence, Selected(evidence));
        Assert.Equal("S-1-5-21-1-2-3-2100", Assert.Single(page.Holders).Sid);
        Assert.Null(page.Next);
        Assert.Equal(evidence.Resource.ObjectGuid.ToString("D"), page.Context.Subject.Key);
    }

    [Theory]
    [InlineData("CaptureIncomplete", DelegationConfigurationInputLimitations.CaptureIncomplete, "supported grants shown here remain findings")]
    [InlineData("ResourceDescriptorIncomplete", DelegationConfigurationInputLimitations.ConfigurationUnassessed, "Some RBCD configuration could not be assessed")]
    [InlineData("ResourceDelegationEntryUnsupported", DelegationConfigurationInputLimitations.ConfigurationUnassessed, "unassessed entries are not treated as a clean configuration")]
    [InlineData("StoredGenericRightUnsupported", DelegationConfigurationInputLimitations.ConfigurationUnassessed, "Supported saved grants remain listed")]
    [InlineData("OtherRequesterDenyMembershipUnassessed", DelegationConfigurationInputLimitations.Other, "Additional saved evidence limitations")]
    [InlineData("AccountSourceIncomplete", DelegationConfigurationInputLimitations.Other, "not a complete delegation assessment")]
    public void PositiveSavedGrantsKeepTheirOwnLimitationsWithoutInventingRequesterAuthorization(
        string reason, DelegationConfigurationInputLimitations expected, string wording)
    {
        var evidence = Evidence(1) with { Limitations = [reason], InputsComplete = reason != "CaptureIncomplete" };
        var page = Project(evidence, Selected(evidence));
        Assert.False(page.Context.EvidenceIsComplete);
        Assert.Equal(expected, page.Context.Limitations);
        Assert.Contains(wording, Assert.Single(page.Context.DescribeLimitations()), StringComparison.Ordinal);
        Assert.Single(page.Holders);
    }

    public static IEnumerable<object[]> InvalidFacts()
    {
        const string differentGuid = "\"00000000-0000-0000-0000-000000000001\"";
        yield return ["ConfigurationKind", "\"Constrained\""];
        yield return ["EvidenceSeal", "\"different captured source\""];
        yield return ["DerivationGenerationId", differentGuid];
        yield return ["DerivationSeal", "\"different derivation source\""];
        yield return ["PolicyVersion", "2"];
        yield return ["DescriptorParserVersion", "-1"];
        yield return ["Account.ObjectGuid", differentGuid];
        yield return ["Account.DistinguishedName", "\"CN=Another account,DC=contoso,DC=com\""];
        yield return ["Account.DomainFqdn", "\"another.example\""];
        yield return ["Account.ObjectClass", "\"user\""];
        yield return ["Resource.ObjectGuid", differentGuid];
        yield return ["Resource.DomainFqdn", "\"another.example\""];
        yield return ["Resource.ObjectClass", "\"user\""];
        yield return ["Scope.GenerationId", differentGuid];
        yield return ["Scope.ResourceGuid", differentGuid];
        yield return ["Scope.TargetDn", "\"CN=Another resource,DC=contoso,DC=com\""];
        yield return ["Scope.Fingerprint", "\"invalid fingerprint\""];
        yield return ["Scope.EstablishedTier0", "\"true\""];
        yield return ["Scope.ClassificationBases", "[]"];
        yield return ["Scope.AnchorDns", "[]"];
        yield return ["Services", "[{}]"];
        yield return ["Grants", "[]"];
        yield return ["InputsComplete", "false"];
        yield return ["IsComplete", "false"];
    }

    [Theory]
    [MemberData(nameof(InvalidFacts))]
    public void MalformedMisboundOrWrongFamilyFactsAreRefusedInsteadOfFallingBackToProse(string path, string replacement)
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        var names = path.Split('.');
        var parent = names.Take(names.Length - 1).Aggregate(json, (node, name) => node[name]!);
        parent[names[^1]] = JsonNode.Parse(replacement);
        var error = Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, Selected(evidence)));
        Assert.Equal(SavedDelegationConfiguration.ResourceInvalidDetails, error.Message);
    }

    [Theory]
    [InlineData("TrusteeSid", "\"not a SID\"")]
    [InlineData("TrusteeSid", "\"S-1-3-0\"")]
    [InlineData("EntryOrdinals", "[]")]
    [InlineData("EntryOrdinals", "[-1]")]
    [InlineData("EntryOrdinals", "[2147483648]")]
    [InlineData("EntryOrdinals", "[1.5]")]
    [InlineData("EntryOrdinals", "[0,0]")]
    [InlineData("EntryOrdinals", "[2,1]")]
    [InlineData("NullDacl", "\"false\"")]
    [InlineData("NullDacl", "true")]
    public void InvalidSavedGrantMeaningOrOccurrencesCannotBecomeAHolder(string property, string replacement)
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Grants"]![0]![property] = JsonNode.Parse(replacement);
        Assert.Equal(SavedDelegationConfiguration.ResourceInvalidDetails,
            Assert.Throws<InvalidDataException>(() => Project(json.ToJsonString(), evidence, Selected(evidence))).Message);
    }

    [Theory]
    [InlineData("ordinary-holder")]
    [InlineData("with-entry")]
    [InlineData("mixed-grants")]
    public void NullDaclCannotBeRelabelledAsAnOrdinaryGrantOrMixedWithNamedEntries(string defect)
    {
        var evidence = Evidence(0, nullDacl: true);
        evidence = defect switch
        {
            "ordinary-holder" => evidence with { Grants = [evidence.Grants[0] with { TrusteeSid = "S-1-5-21-1-2-3-1100" }] },
            "with-entry" => evidence with { Grants = [evidence.Grants[0] with { EntryOrdinals = [0] }] },
            _ => evidence with { Grants = [.. evidence.Grants, new("S-1-5-21-1-2-3-1100", [0], false)] },
        };
        Assert.Throws<InvalidDataException>(() => Project(evidence, Selected(evidence)));
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("duplicate")]
    public void ResourceProjectionRequiresOneCompleteSavedJsonObject(string defect)
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        json = defect switch
        {
            "truncated" => json[..^1],
            "trailing" => json + "{}",
            _ => json.Insert(1, "\"InputsComplete\":true,"),
        };
        Assert.Equal(SavedDelegationConfiguration.ResourceInvalidDetails,
            Assert.Throws<InvalidDataException>(() => Project(json, evidence, Selected(evidence))).Message);
    }

    [Fact]
    public void CancellationInterruptsSkippingTheResourcesUnrequestedDescriptorSnapshot()
    {
        var evidence = Evidence(1);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Resource"]!["Attributes"]![0]!["Values"]![0]!["Text"] = new string('x', 160_000);
        using var cancel = new CancellationTokenSource();
        using var stream = new ConstrainedDelegationReadTests.CancellingStream(
            Encoding.UTF8.GetBytes(json.ToJsonString()), cancel);
        var description = new JudgementDescription(evidence.EvidenceSeal, evidence.Scope.GenerationId, evidence.DerivationGenerationId,
            JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        Assert.Throws<OperationCanceledException>(() => DelegationConfigurationProjection.Read(
            stream, Selected(evidence), description, evidence.DerivationSeal, null, cancel.Token));
    }

    internal static DelegationConfigurationEvidence Evidence(int count, bool nullDacl = false, bool established = true)
    {
        var basis = ConstrainedDelegationReadTests.Evidence(0, established);
        var resource = basis.Resource;
        var grants = nullDacl ? [new ResourceDelegationGrant("S-1-1-0", [], true)]
            : Enumerable.Range(0, count).Select(index => new ResourceDelegationGrant($"S-1-5-21-1-2-3-{1100 + index}", [index], false)).ToArray();
        return basis with { ConfigurationKind = DelegationConfigurationKind.ResourceBased, Account = resource,
            Resource = resource, Services = [], Grants = grants };
    }

    internal static Finding Finding(DelegationConfigurationEvidence evidence) => new("SEC-013", 1, Severity.High,
        new(FindingSubjectKind.Account, evidence.Resource.ObjectGuid.ToString("D")), evidence.Resource.ObjectGuid,
        evidence.Resource.DistinguishedName, evidence.Resource.DomainFqdn, evidence.Resource.ObjectClass,
        "Original raw RBCD descriptor/holder prose must not be used to recover facts.", EvidenceCompleteness.Complete, evidence)
        { PrincipalName = "resource account" };

    internal static FindingListItem Selected(DelegationConfigurationEvidence evidence) =>
        FindingListItem.FromFinding(Finding(evidence)) with { Reference = new(evidence.Scope.GenerationId, 17) };

    internal static SavedDelegationConfiguration Project(DelegationConfigurationEvidence evidence, FindingListItem selected,
        DelegationConfigurationMark? after = null) =>
        Project(JsonSerializer.Serialize(evidence, ProofSerialization.Options), evidence, selected, after);

    private static SavedDelegationConfiguration Project(string json, DelegationConfigurationEvidence evidence, FindingListItem selected,
        DelegationConfigurationMark? after = null)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(json));
        var description = new JudgementDescription(evidence.EvidenceSeal, evidence.Scope.GenerationId, evidence.DerivationGenerationId,
            JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        return DelegationConfigurationProjection.Read(stream, selected, description, evidence.DerivationSeal, after, CancellationToken.None);
    }

    internal static string PublishedRun(int count = 1, bool nullDacl = false, bool ambiguousName = false)
    {
        var sids = Enumerable.Range(0, count).Select(index => $"S-1-5-21-1-2-3-{1100 + index}").ToArray();
        var descriptor = nullDacl
            ? new RawSecurityDescriptor(ControlFlags.SelfRelative, null, null, null, null)
            : new RawSecurityDescriptor(ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent, null, null, null, GrantAcl(sids));
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        var resource = Fixture.Account(dn: "CN=Narrow fixture administrator,DC=contoso,DC=com",
            sid: "S-1-5-21-1-2-3-500", spns: []);
        resource = Fixture.With(resource, DelegationConfigurationRules.ConstrainedAttribute, []);
        resource = Fixture.With(resource, DelegationConfigurationRules.ResourceAttribute, [EvidenceValue.OfBytes(bytes)]);
        var sources = new List<Fixture.Source> { resource };
        if (count > 0) sources.Add(Fixture.Account(dn: "CN=Captured delegation holder,DC=contoso,DC=com", sid: sids[0], spns: []));
        if (ambiguousName) sources.Add(Fixture.Account(dn: "CN=Another captured holder,DC=contoso,DC=com", sid: sids[0], spns: []));
        var directory = Fixture.Capture(sources);
        Derive(directory);
        var judged = JudgingRun.Judge(directory, [new ResourceBasedDelegationOnRelevantResource()], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static RawAcl GrantAcl(IEnumerable<string> sids)
    {
        var acl = new RawAcl(2, 0);
        foreach (var sid in sids)
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x100,
                new System.Security.Principal.SecurityIdentifier(sid), false, null));
        return acl;
    }
}

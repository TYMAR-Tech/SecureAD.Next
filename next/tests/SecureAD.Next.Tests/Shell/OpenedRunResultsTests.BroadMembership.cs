using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using Fixtures = SecureAD.Next.Tests.Judgement.BroadAdministrativeGroupMembershipTests;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("SEC-061", false)]
    [InlineData("SEC-061", true)]
    [InlineData("SEC-062", false)]
    [InlineData("SEC-062", true)]
    public void BroadMembershipReadsOnlySelectedSavedSourcesLinksValuesAndGaps(string rule, bool partial)
    {
        var directory = BroadDetailsRun(rule, partial);
        BroadGroupMembershipEvidence original;
        using (var reader = JudgementReader.Open(directory).Value)
            original = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var answer = source.ReadBroadMembershipSources(directory, row.Reference!.Value, null);
            Assert.True(answer.IsSuccess, answer.Error?.Description);
            Assert.True(answer.Value.Context.Matches(row));
            Assert.True(answer.Value.IsExpectedPage(null));
            Assert.Equal(original.TargetGuid, answer.Value.Context.Target.ObjectGuid);
            Assert.Equal(original.BroadSources.Select(value => (value.Sid, value.SidScope, value.Name)),
                answer.Value.Rows.Select(value => (value.Value.Sid, value.Value.SidScope, value.Value.Name)));
            Assert.Equal(original.IsComplete, answer.Value.Context.IsComplete);
            Assert.Equal(original.InputsComplete, answer.Value.Context.InputsComplete);
            Assert.Equal(original.Limitations.Count, answer.Value.Context.LimitationCount);
            var links = new List<SavedBroadMembershipLink>();
            BroadMembershipMark? mark = null;
            do
            {
                var page = source.ReadBroadMembershipLinks(directory, row.Reference.Value, mark);
                Assert.True(page.IsSuccess, page.Error?.Description); Assert.True(page.Value.IsExpectedPage(mark));
                Assert.InRange(page.Value.Rows.Count, 1, 50);
                links.AddRange(page.Value.Rows.Select(value => value.Value)); mark = page.Value.Next;
            } while (mark is not null);
            Assert.Equal(original.Links.Select(value => (value.GroupGuid, value.MemberGuid, value.MemberReferenceGuid, (long)value.Witnesses.Count)),
                links.Select(value => (value.ContainingGroup.ObjectGuid, value.Member.ObjectGuid, value.RecordedThrough.ObjectGuid, value.WitnessCount)));
            var selected = links.First(value => value.WitnessCount > 50);
            var values = new List<SavedBroadMembershipWitness>(); mark = null;
            do
            {
                var page = source.ReadBroadMembershipValues(directory, row.Reference.Value, selected.Position, mark);
                Assert.True(page.IsSuccess, page.Error?.Description); Assert.True(page.Value.IsExpectedPage(mark));
                Assert.InRange(page.Value.Rows.Count, 1, 50);
                Assert.Equal(selected, page.Value.SelectedLink);
                values.AddRange(page.Value.Rows.Select(value => value.Value)); mark = page.Value.Next;
            } while (mark is not null);
            Assert.Equal(original.Links[(int)selected.Position].Witnesses.Select(value => (value.SourceObjectGuid, value.Attribute, value.Ordinal, value.Value)),
                values.Select(value => (value.Source.ObjectGuid, value.Attribute, value.OriginalOrdinal, value.Value)));
            var gaps = source.ReadBroadMembershipLimitations(directory, row.Reference.Value, null);
            Assert.True(gaps.IsSuccess, gaps.Error?.Description); Assert.True(gaps.Value.IsExpectedPage(null));
            Assert.Equal(original.Limitations, gaps.Value.Rows.Select(value => value.Value));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("target")]
    [InlineData("kind")]
    [InlineData("offset")]
    [InlineData("beyond")]
    [InlineData("link")]
    public void BroadMembershipRejectsUnboundCrossLevelAndCrossRelationshipContinuations(string defect)
    {
        var directory = BroadDetailsRun("SEC-062");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var candidates = new List<SavedBroadMembershipLink>();
        BroadMembershipMark? continuation = null;
        do
        {
            var links = source.ReadBroadMembershipLinks(directory, reference, continuation).Value;
            candidates.AddRange(links.Rows.Select(value => value.Value)); continuation = links.Next;
        } while (continuation is not null);
        var selected = Assert.Single(candidates, value => value.WitnessCount > 50);
        var first = source.ReadBroadMembershipValues(directory, reference, selected.Position, null).Value;
        var mark = first.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() }, "finding" => mark with { FindingId = mark.FindingId + 1 },
            "target" => mark with { TargetGuid = Guid.NewGuid() }, "kind" => mark with { Kind = BroadMembershipPageKind.Links },
            "offset" => mark with { Offset = 51 }, "beyond" => mark with { Offset = 1000 },
            _ => mark with { LinkPosition = selected.Position + 1 },
        };
        Assert.False(source.ReadBroadMembershipValues(directory, reference, selected.Position, mark).IsSuccess);
    }

    [Theory]
    [InlineData("target")]
    [InlineData("kind")]
    [InlineData("generation")]
    [InlineData("policy")]
    [InlineData("complete")]
    [InlineData("missing")]
    public void BroadMembershipRefusesMissingOrInconsistentSavedHeaders(string field)
    {
        var directory = BroadDetailsRun("SEC-061", true);
        var sql = field switch
        {
            "target" => "UPDATE finding_broad_group_membership SET proof=json_set(proof,'$.TargetGuid','00000000-0000-0000-0000-000000000001')",
            "kind" => "UPDATE finding_broad_group_membership SET proof=json_set(proof,'$.TargetKind','AdministrativeGroup')",
            "generation" => "UPDATE finding_broad_group_membership SET proof=json_set(proof,'$.DerivationGenerationId','00000000-0000-0000-0000-000000000001')",
            "policy" => "UPDATE finding_broad_group_membership SET proof=json_set(proof,'$.PolicyVersion',999)",
            "complete" => "UPDATE finding_broad_group_membership SET proof=json_set(proof,'$.IsComplete',json('true'))",
            _ => "DELETE FROM finding_broad_group_membership",
        };
        ChangeCoverageProof(directory, sql);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        Assert.False(source.ReadBroadMembershipSources(directory, reference, null).IsSuccess);
    }

    [Theory]
    [InlineData("SEC-061")]
    [InlineData("SEC-062")]
    public void BroadMembershipKeepsForeignReferencesSeparateFromResolvedMembers(string rule)
    {
        var directory = BroadDetailsRun(rule, foreign: true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var page = source.ReadBroadMembershipLinks(directory, reference, null);
        Assert.True(page.IsSuccess, page.Error?.Description);
        var link = Assert.Single(page.Value.Rows).Value;
        Assert.Equal("child.contoso.com", link.Member.DomainFqdn);
        Assert.Equal("contoso.com", link.ContainingGroup.DomainFqdn);
        Assert.Equal("foreignSecurityPrincipal", link.RecordedThrough.ObjectClass);
        Assert.NotEqual(link.Member.ObjectGuid, link.RecordedThrough.ObjectGuid);
        Assert.Equal(link.Member.Sid, link.RecordedThrough.Sid);
        var values = source.ReadBroadMembershipValues(directory, reference, link.Position, null).Value;
        Assert.Equal(link.RecordedThrough.DistinguishedName, Assert.Single(values.Rows).Value.Value);
    }

    [Theory]
    [InlineData("SEC-061")]
    [InlineData("SEC-062")]
    public void BroadMembershipSkipsUnopenedOriginalPayloadsButRefusesThemWhenRequested(string rule)
    {
        var directory = BroadDetailsRun(rule);
        ChangeCoverageProof(directory, """
            UPDATE finding_broad_group_membership SET proof=json_set(proof,
                '$.Principals[0].Values',json('[{"Unopened":"identity attributes"}]'),
                '$.Links[0].Witnesses[0].Value','unopened original payload')
            """);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        Assert.True(source.ReadBroadMembershipSources(directory, reference, null).IsSuccess);
        var links = source.ReadBroadMembershipLinks(directory, reference, null);
        Assert.True(links.IsSuccess, links.Error?.Description);
        Assert.False(source.ReadBroadMembershipValues(directory, reference, 0, null).IsSuccess);
    }

    [Theory]
    [InlineData("SEC-061")]
    [InlineData("SEC-062")]
    public void BroadMembershipKeepsConfigurationSpecialIdentityAndMemberOfSourceWithoutInventingADomain(string rule)
    {
        var directory = BroadDetailsRun(rule, configuration: true);
        BroadGroupMembershipEvidence original;
        using (var reader = JudgementReader.Open(directory).Value)
            original = Assert.IsType<BroadGroupMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadBroadMembershipSources(directory, reference, null).Value;
        Assert.Equal("S-1-5-11", Assert.Single(read.Rows).Value.Sid);
        Assert.Null(read.Rows[0].Value.SidScope);
        var link = Assert.Single(source.ReadBroadMembershipLinks(directory, reference, null).Value.Rows).Value;
        Assert.Equal(original.Principals.Single(identity => identity.ObjectGuid == link.Member.ObjectGuid).DomainFqdn, link.Member.DomainFqdn);
        Assert.Equal("CN=Configuration,DC=contoso,DC=com", link.Member.NamingContext);
        var values = source.ReadBroadMembershipValues(directory, reference, link.Position, null).Value;
        var memberOf = Assert.Single(values.Rows, row => row.Value.Attribute == "memberOf").Value;
        Assert.Equal(link.RecordedThrough.ObjectGuid, memberOf.Source.ObjectGuid);
        Assert.Equal(link.ContainingGroup.DistinguishedName, memberOf.Value);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BroadMembershipRejectsAnotherSelectedGenerationOrMissingFinding(bool generation)
    {
        var directory = BroadDetailsRun("SEC-061");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = long.MaxValue };
        Assert.False(source.ReadBroadMembershipSources(directory, reference, null).IsSuccess);
        Assert.False(source.ReadBroadMembershipLinks(directory, reference, null).IsSuccess);
        Assert.False(source.ReadBroadMembershipValues(directory, reference, 0, null).IsSuccess);
        Assert.False(source.ReadBroadMembershipLimitations(directory, reference, null).IsSuccess);
    }

    private static string BroadDetailsRun(string rule, bool partial = false, bool foreign = false, bool configuration = false)
    {
        const string root = "DC=contoso,DC=com";
        const string domainSid = "S-1-5-21-1-2-3";
        var target = "CN=Renamed target,CN=Builtin," + root;
        var wide = configuration ? "CN=Authenticated users,CN=WellKnown Security Principals,CN=Configuration," + root
            : "CN=Broad group," + (foreign ? "DC=child," : "") + root;
        var broadSid = (foreign ? "S-1-5-21-4-5-6" : domainSid) + "-513";
        var bridges = Enumerable.Range(0, 57).Select(index => "CN=Bridge " + index + "," + root).ToArray();
        var reference = "CN=Foreign broad,CN=ForeignSecurityPrincipals," + root;
        var members = configuration ? new[] { wide } : foreign ? new[] { reference }
            : bridges.Concat(Enumerable.Range(0, 56).Select(index => index % 2 == 0 ? bridges[0] : bridges[0].ToUpperInvariant())).ToArray();
        if (partial) members = [.. members, "CN=Uncaptured," + root];
        var sources = new List<Fixtures.Source> { Fixtures.Group(target, "S-1-5-32-" + (rule == "SEC-061" ? "554" : "544"), -2147483643, members) };
        if (configuration) sources.Add(Fixtures.Stub(wide, "S-1-5-11") with { MemberOf = [target] });
        else sources.Add(Fixtures.Group(wide, broadSid, -2147483646));
        if (!configuration)
        {
            if (foreign) sources.Add(Fixtures.Stub(reference, broadSid));
            else sources.AddRange(bridges.Select((dn, index) => Fixtures.Group(dn, domainSid + "-" + (1200 + index), -2147483646, [wide])));
        }
        var directory = Fixtures.Capture(sources);
        Derive(directory);
        var judged = JudgingRun.Judge(directory, [RuleCatalogue.All.Single(value => value.Definition.Id == rule)],
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }
}

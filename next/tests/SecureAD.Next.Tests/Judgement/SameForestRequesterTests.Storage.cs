using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class SameForestRequesterTests
{
    [Fact]
    public void SameForestProofRetainsEveryOriginalEntryLinkAndGeneration()
    {
        using var reader = Open(Prepared("nested"));
        var assessment = Assessment(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        var original = Assert.Single(sources.Bundle.ReadPermissions(Target)!.Entries);
        var evidence = Assert.Single(assessment.Evidence);
        Assert.Equal(Tier0PathCalculation.Fingerprint(original), Tier0PathCalculation.Fingerprint(evidence.Entry));
        var links = evidence.Membership!.Links;
        Assert.Equal(new[] { (Actor, Global), (Global, Universal), (Universal, Local) },
            links.Select(link => (link.Member.DistinguishedName, link.Group.DistinguishedName)));
        foreach (var link in links)
        {
            var member = sources.Bundle.ReadObjectAttributes(link.Member.DistinguishedName)!;
            var group = sources.Bundle.ReadObjectAttributes(link.Group.DistinguishedName)!;
            Assert.Equal(Tier0Target.From(member, link.Member.NamingContext), link.Member);
            Assert.Equal(Tier0Target.From(group, link.Group.NamingContext), link.Group);
            Assert.Equal(group.CapturedUtc, link.CapturedUtc);
            Assert.Contains(group.Find("member")!.Values, value => value.Ordinal == link.Witness.Ordinal && value.Stored == link.Witness.Value);
            Assert.Equal(Tier0PathCalculation.Fingerprint(new
            {
                Member = Tier0PathCalculation.Fingerprint(member), Group = Tier0PathCalculation.Fingerprint(group),
            }), link.SourceFingerprint);
        }
        Assert.Equal(Tier0PathCalculation.Fingerprint(sources.Bundle.ReadScope().Value), assessment.ResourceContext!.ScopeFingerprint);
        Assert.Equal((reader.Description.GenerationId, reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal),
            (assessment.GenerationId, assessment.DerivationGenerationId, assessment.EvidenceSeal));
        var permission = Assert.Single(assessment.Permissions);
        Assert.Equal(Tier0PathCalculation.Fingerprint(reader.ReadControlEdge(Target, permission.Id)), permission.Fingerprint);
    }

    [Theory]
    [InlineData("$.ResourceContext.ResourceDomain.DomainFqdn", "'contoso.com'")]
    [InlineData("$.ResourceContext.ScopeFingerprint", "'invalid'")]
    [InlineData("$.ResourceContext.ReadDomains", "json('[\"branch.example\"]')")]
    [InlineData("$.Evidence[0].Membership.Links[1].GroupType", "-2147483646")]
    [InlineData("$.Evidence[0].Membership.Links[2].Group.DomainFqdn", "'contoso.com'")]
    [InlineData("$.Evidence[0].Membership.Links[0].Witness.Ordinal", "-1")]
    [InlineData("$.Steps[1].MembershipWitness.Value", "'CN=Wrong,DC=branch,DC=example'")]
    [InlineData("$.EvidenceSeal", "'changed'")]
    public void SameForestSavedReadRefusesBrokenResourceOrMembershipBindings(string path, string value)
    {
        var directory = Prepared("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.Requesters[0].Assessment" + path[1..], value);
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadPathRiskPage(Actor, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None));
    }

    [Fact]
    public void SameForestPassiveReadKeepsTheSavedScopeWithoutReplayingAnalysis()
    {
        var directory = Prepared("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.Requesters[0].Assessment.ResourceContext.ScopeFingerprint",
            "'" + new string('f', 64) + "'");
        using var reader = Open(directory);
        var before = Snapshot(directory);
        var question = Assert.Single(reader.ReadPathRiskPage(Actor, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        Assert.Equal(new string('f', 64), question.Requester!.ResourceContext!.ScopeFingerprint);
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void SameForestResourceAndGroupInputsAreReusedWithinTheirGeneration()
    {
        using var reader = Open(Prepared("nested"));
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(value => value.Identity.DistinguishedName,
            value => value.Identity, StringComparer.OrdinalIgnoreCase);
        var context = RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None)!;
        var resource = context.Resource(identities[Target]);
        var route = context.Read(Actor, Local, true);
        Assert.Equal(3, route.Links.Count);
        Assert.Same(resource, context.Resource(identities[RootB]));
        Assert.Same(route, context.Read(Actor, Local, true));
        Assert.Same(context, RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None));
    }

    [Fact]
    public void SameForestSubjectSidMustBelongToItsDeclaredDomain()
    {
        using var reader = Open(Prepared("nested"));
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(value => value.Identity.DistinguishedName,
            value => value.Identity, StringComparer.OrdinalIgnoreCase);
        var context = RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None)!;
        Assert.True(context.InResourceForest(identities[Actor], identities[Target]));
        Assert.False(context.InResourceForest(identities[Actor] with { Sid = SidB + "-1100" }, identities[Target]));
    }

    [Fact]
    public void SameForestChangeDoesNotExpandTheObtainedMembershipContext()
    {
        using var reader = Open(Prepared("nested"));
        using var sources = ControlProofVerification.OpenSources(reader);
        var request = new RequesterDaclRequest(Actor, Target);
        var captured = Assessment(reader);
        var member = new OwnAccountMembershipAssessment(new(Actor, Global), reader.Description.GenerationId,
            reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal, captured.Requester,
            captured.Steps[0].To, null!, ControlEvaluationState.Established, OwnAccountMembershipBasis.ExistingMembership,
            [], [captured.Steps[0].MembershipWitness!], [], []);
        var identities = captured.Steps.SelectMany(step => new[] { step.From, step.To })
            .Append(captured.ResourceContext!.ResourceDomain)
            .Append(Tier0Target.From(sources.Bundle.ReadObjectAttributes(RootA)!, RootA))
            .Distinct().ToDictionary(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var context = RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None);
        var assessment = RequesterDaclEvaluator.Assess(request, reader.ReadPathInputs(), reader.Description, identities,
            sources.Bundle.ReadObjectAttributes, sources.Bundle.ReadPermissions(Target), sources.ReadNamingContexts().Value,
            reader.ReadControlEdges(Target, null, null, true, 0).Edges, A, CancellationToken.None, member, context, TargetPermissionReference.EntryMatches);
        Assert.Equal(ControlEvaluationState.Unknown, assessment.Authorization);
        Assert.Contains(RequesterDaclIssue.ResourceContextUnsupported, assessment.Issues);
        Assert.Null(assessment.ResourceContext);
    }

    private static string[] Snapshot(string directory) => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
}

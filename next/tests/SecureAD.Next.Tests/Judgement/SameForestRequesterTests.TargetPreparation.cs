using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Judgement;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class SameForestRequesterTests
{
    [Theory]
    [InlineData("nested")]
    [InlineData("global")]
    [InlineData("universal")]
    [InlineData("builtin")]
    [InlineData("history")]
    [InlineData("excluded")]
    [InlineData("cycle")]
    public void BatchedTargetPreparationPreservesSameForestAndResourceScopedProofs(string variant)
    {
        using var reader = Open(Prepared(variant, automatic: false));
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, reader.BundleDirectory, reader.Description.GenerationId);
        using var sources = ControlProofVerification.OpenSources(reader);
        var inputs = reader.ReadPathInputs();
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        var memberships = RequesterMembershipContext.Create(sources, identities, inputs, CancellationToken.None);
        RequesterDaclProofs.Question[] questions =
        [
            new(new(Actor, Target), null), new(new(Other, RootA), null), new(new(Other, Target), null),
            new(new(Actor, RootA), null), new(new(Actor, Target), null),
        ];
        var expected = questions.Select(question => Assert.Single(TargetPermissionReference.Create(connection, reader.Description,
            sources, identities, inputs, [question.Request], CancellationToken.None, null, memberships, currentSourceFingerprints: true))).ToArray();

        var actual = RequesterBatchEvaluation.Create(connection, reader.Description, sources, identities, inputs, questions,
            CancellationToken.None, memberships);

        Assert.Equal(JsonSerializer.Serialize(expected, ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
        Assert.Equal(questions.Length, actual.Count);
        Assert.Equal(expected[0].Assessment.ResourceContext, actual[0].Assessment.ResourceContext);
    }
}

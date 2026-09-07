using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SelfMembershipCoverageTests
{
    [Fact]
    public void EmptyExplicitProductDoesNotClaimAutomaticDiscovery()
    {
        var directory = ExplicitBundle();
        using var reader = JudgementReader.Open(directory).Value!;
        var summary = reader.ReadSelfMembershipSummary();
        Assert.NotNull(summary);
        Assert.Equal(SelfMembershipDiscoveryMode.ExplicitRequests, summary.Discovery.Mode);
        Assert.Equal("ExplicitRequestsOnly", summary.Verdict);
        Assert.False(summary.Discovery.InputScanCompleted);
        Assert.Null(summary.Discovery.Budget);
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Equal(reader.Description.GenerationId, summary.GenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, summary.EvidenceSeal);
        var selected = reader.ReadSelfMembershipAssessments(SelfMembershipDiscoveryTests.TargetDn, null);
        Assert.True(selected.ProductWasDerived);
        Assert.Equal(summary.GenerationId, selected.Summary!.GenerationId);
        Assert.Equal(summary.Verdict, selected.Summary.Verdict);
    }

    [Theory]
    [InlineData("missing-record")]
    [InlineData("orphan-record")]
    [InlineData("null")]
    [InlineData("malformed")]
    [InlineData("missing-field")]
    [InlineData("bad-version")]
    [InlineData("bad-mode")]
    [InlineData("negative-work")]
    [InlineData("null-limitations")]
    [InlineData("invalid-limitation")]
    [InlineData("invented-completion")]
    [InlineData("invented-budget")]
    public void MalformedCoverageFailsSummarySelectedReadAndShellAdapter(string mutation)
    {
        var directory = ExplicitBundle();
        Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            if (mutation is "missing-record" or "orphan-record")
            {
                command.CommandText = mutation == "missing-record"
                    ? "DELETE FROM self_membership_discovery" : "DELETE FROM self_membership_product";
            }
            else
            {
                command.CommandText = "SELECT coverage_json FROM self_membership_discovery";
                var json = JsonNode.Parse((string)command.ExecuteScalar()!)!.AsObject();
                switch (mutation)
                {
                    case "missing-field": json.Remove("PairsDiscovered"); break;
                    case "bad-version": json["Version"] = 99; break;
                    case "bad-mode": json["Mode"] = 99; break;
                    case "negative-work": json["ObjectsVisited"] = -1; break;
                    case "null-limitations": json["Limitations"] = null; break;
                    case "invalid-limitation": json["Limitations"] = JsonNode.Parse("[{\"Reason\":999,\"TargetDn\":null,\"PermissionOrdinal\":null,\"TrusteeSid\":null,\"MemberDn\":null}]"); break;
                    case "invented-completion": json["InputScanCompleted"] = true; break;
                    case "invented-budget": json["Budget"] = JsonNode.Parse("{\"Objects\":1,\"PermissionEntries\":1,\"MembershipValues\":1,\"Pairs\":1}"); break;
                }
                command.CommandText = "UPDATE self_membership_discovery SET coverage_json=$json";
                command.Parameters.AddWithValue("$json", mutation == "null" ? "null" : mutation == "malformed" ? "{" : json.ToJsonString());
            }
            command.ExecuteNonQuery();
        });
        using var reader = JudgementReader.Open(directory).Value!;
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipSummary());
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(SelfMembershipDiscoveryTests.TargetDn, null));
        Assert.Throws<InvalidDataException>(() => reader.ReadSelfMembershipAssessments(null, SelfMembershipDiscoveryTests.UserDn));
        using var source = new BundleAssetSource();
        Assert.False(source.ReadSelfMembershipAssessments(directory, SelfMembershipDiscoveryTests.TargetDn, null).IsSuccess);
    }

    internal static string ExplicitBundle()
    {
        var directory = SelfMembershipDiscoveryTests.Bundle();
        var judged = JudgingRun.Judge(directory, [], [], SelfMembershipBudget.Default,
            SelfMembershipDiscoveryTests.Started, SelfMembershipDiscoveryTests.Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    internal static void Mutate(string directory, Action<SqliteConnection> mutate)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value!;
        var path = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
        {
            connection.Open();
            mutate(connection);
        }
        BundleSealing.Seal(path, BundleLayout.AnalysisGenerationSealPath(directory, generation.Kind, generation.GenerationId));
    }
}

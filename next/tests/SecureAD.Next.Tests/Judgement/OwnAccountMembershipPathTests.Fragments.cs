using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void MissingPathFragmentCannotPublishOverThePreviousJudgement()
    {
        var directory = PrepareRisk(RiskCapture());
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        var evidence = BundleSealing.HashFile(BundleLayout.EvidencePath(directory));
        var corrupt = new RemoveFragmentAtPublication(directory);

        var error = Record.Exception(() => JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.SupportedCapturedQuestions,
            Started, Started, corrupt, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null));

        Assert.True(corrupt.Removed);
        Assert.IsType<InvalidDataException>(error);
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.Equal(evidence, BundleSealing.HashFile(BundleLayout.EvidencePath(directory)));
        using var reader = Open(directory);
        Assert.Equal(3, reader.ReadPathRequesterRisks(UserDn, CancellationToken.None).Assessments.Count);
    }

    private sealed class RemoveFragmentAtPublication(string directory) : IProgress<JudgingRun.JudgingProgress>
    {
        internal bool Removed { get; private set; }

        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase != JudgingPhase.PublishingJudgement || Removed) return;
            var path = TestSealing.PendingJudgementPath(directory);
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString());
            connection.Open();
            TestSealing.AttachJudgementParts(connection, directory, Guid.Empty, staged: true);
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM path_proof_chunk WHERE rowid=(SELECT MIN(rowid) FROM path_proof_chunk)";
            Assert.Equal(1, command.ExecuteNonQuery());
            Removed = true;
        }
    }
}

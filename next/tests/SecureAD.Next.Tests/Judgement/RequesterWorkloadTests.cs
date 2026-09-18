using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Measure;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class RequesterWorkloadTests(RequesterWorkloadTests.Workloads workloads) : IClassFixture<RequesterWorkloadTests.Workloads>
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BothModesKeepTheRequestedPhysicalShape(bool separate)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(workloads.Bundle(separate)),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*),COUNT(DISTINCT domain_fqdn),(SELECT COUNT(*) FROM ace),(SELECT COUNT(*) FROM member_value) FROM captured_object";
        using var rows = command.ExecuteReader();
        Assert.True(rows.Read());
        Assert.Equal(200L, rows.GetInt64(0));
        Assert.Equal(2L, rows.GetInt64(1));
        Assert.Equal(3400L, rows.GetInt64(2));
        Assert.Equal(12L, rows.GetInt64(3));
    }

    [Theory]
    [InlineData(false, "SelfMembership", 0)]
    [InlineData(false, "WriteMembers", 0)]
    [InlineData(true, "SelfMembership", 4)]
    [InlineData(true, "WriteMembers", 4)]
    public void CombinedProofsRetainUnknownAnswersAndSeparateEstablishedAnswers(bool separate, string kind, int established)
    {
        var answers = workloads.Header(separate).GetProperty("MembershipDacls").EnumerateArray()
            .Select(p => p.GetProperty("Assessment"))
            .Where(p => p.GetProperty("Request").GetProperty("PermissionKind").GetString() == kind).ToArray();
        var positive = answers.Where(p => p.GetProperty("Authorization").GetString() == "Established").ToArray();
        var unknown = answers.Where(p => p.GetProperty("Authorization").GetString() == "Unknown").ToArray();
        Assert.Equal(established, positive.Length);
        Assert.Equal(4, unknown.Length);
        Assert.Equal(established + 4, answers.Length);
        Assert.All(positive, p =>
        {
            var dacl = p.GetProperty("Dacl");
            Assert.Equal("Established", dacl.GetProperty("Authorization").GetString());
            Assert.EndsWith("-516", dacl.GetProperty("Target").GetProperty("Sid").GetString());
            Assert.NotEmpty(dacl.GetProperty("Permissions").EnumerateArray());
            Assert.NotEmpty(p.GetProperty("Steps").EnumerateArray());
        });
        Assert.All(unknown, p => Assert.Equal("Unknown", p.GetProperty("Dacl").GetProperty("Authorization").GetString()));
    }

    [Theory]
    [InlineData("Requesters", "Authorization")]
    [InlineData("OwnAccounts", "Obtainability")]
    public void OtherFamiliesStillSaveEstablishedAnswers(string family, string verdict)
    {
        var answers = workloads.Header(true).GetProperty(family).EnumerateArray()
            .Select(p => p.GetProperty("Assessment")).ToArray();
        Assert.NotEmpty(answers);
        Assert.Contains(answers, p => p.GetProperty(verdict).GetString() == "Established");
    }

    public sealed class Workloads
    {
        private readonly string _root = Path.Combine(AppContext.BaseDirectory, "p242-workload-checks", Guid.NewGuid().ToString("N"));
        private readonly Dictionary<bool, string> _bundles = [];
        private readonly Dictionary<bool, JsonElement> _headers = [];
        private static readonly DateTimeOffset When = new(2026, 9, 17, 0, 0, 0, TimeSpan.Zero);

        public string Bundle(bool separate)
        {
            if (_bundles.TryGetValue(separate, out var existing)) return existing;
            Directory.CreateDirectory(_root);
            var build = Path.Combine(_root, "correctness-build.json");
            if (!File.Exists(build))
                File.WriteAllText(build, JsonSerializer.Serialize(new
                {
                    Purpose = "Offline correctness fixture, not a scale measurement",
                    TestAssembly = typeof(RequesterWorkloadTests).Assembly.Location,
                    Sha256 = BundleSealing.HashFile(typeof(RequesterWorkloadTests).Assembly.Location),
                }));
            var output = Path.Combine(_root, separate ? "separate" : "legacy");
            string[] args = [output, "200", "3400", "2", "4", "2", .. separate ? new[] { "separate-combined-target" } : Array.Empty<string>()];
            Assert.Equal(0, RequesterWorkload.Run(args, build));
            var bundle = Path.Combine(output, "bundle");
            _bundles.Add(separate, bundle);
            return bundle;
        }

        public JsonElement Header(bool separate)
        {
            if (_headers.TryGetValue(separate, out var existing)) return existing;
            var bundle = Bundle(separate);
            var log = new Log();
            var derived = Stage2aRun.Derive(bundle, ExpansionBudget.Bulk, When, Stage2aRun.Unwatched, log, CancellationToken.None);
            Assert.True(derived.IsSuccess, derived.Error?.Description);
            var judged = JudgingRun.JudgeAudit(bundle, [], PathRequesterPolicy.SupportedCapturedQuestions,
                When, When, JudgingRun.NobodyIsWatching, log, CancellationToken.None, null);
            Assert.True(judged.IsSuccess, judged.Error?.Description);
            var generation = AnalysisStoreLifecycle.Resolve(bundle, AnalysisStoreKind.Judgement).Value.GenerationId;
            var output = Path.GetDirectoryName(bundle)!;
            RequesterMeasurement.ProofCounts(BundleLayout.AnalysisGenerationDataPath(bundle, AnalysisStoreKind.Judgement, generation), output);
            using var json = JsonDocument.Parse(File.ReadAllText(Path.Combine(output, "saved-proof-header.json")));
            var header = json.RootElement.Clone();
            _headers.Add(separate, header);
            return header;
        }

        private sealed class Log : IRunLog
        {
            public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail) { }
            public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) { }
        }
    }
}

using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Measure;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class RequesterMeasurementTests
{
    [Theory]
    [InlineData(0, 1, 1, 1, true)]
    [InlineData(1, 0, 1, 1, true)]
    [InlineData(1, 1, 0, 1, true)]
    [InlineData(1, 1, 1, 0, true)]
    [InlineData(1, 1, 1, 1, false)]
    public void SelectedCountsCannotReplaceActualMatchingThreeFamilyWork(int requester, int own, int combined, int post, bool match)
    {
        Assert.False(new RequesterMeasurement.WorkCounts(requester, own, combined, post, 0, match).AllFamiliesExercised);
    }

    [Fact]
    public void AnExecutedPostMembershipCheckCountsEvenWhenItRefusesPermission()
    {
        Assert.True(new RequesterMeasurement.WorkCounts(1, 1, 1, 1, 0, true).AllFamiliesExercised);
    }

    [Fact]
    public void ASealedInputIsCopiedWithoutChangingTheOriginal()
    {
        var (source, output) = Evidence();
        var original = BundleSealing.HashFile(BundleLayout.EvidencePath(source));
        var copy = RequesterMeasurement.CopyEvidence(source, output);

        Assert.Equal(original, BundleSealing.HashFile(BundleLayout.EvidencePath(copy)));
        Assert.Equal(original, BundleSealing.HashFile(BundleLayout.EvidencePath(source)));
    }

    [Fact]
    public void UncheckpointedOriginalsAreRefusedRatherThanRewritten()
    {
        var (source, output) = Evidence();
        File.WriteAllText(BundleLayout.EvidencePath(source) + "-wal", "retained pending bytes");

        var error = Assert.Throws<InvalidDataException>(() => RequesterMeasurement.CopyEvidence(source, output));
        Assert.Contains("nonempty source WAL", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMismatchingSealCannotSupplyMeasurementEvidence()
    {
        var (source, output) = Evidence();
        File.AppendAllText(BundleLayout.EvidencePath(source), "unsealed change");

        var error = Assert.Throws<InvalidDataException>(() => RequesterMeasurement.CopyEvidence(source, output));
        Assert.Contains("seal does not match", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void StoredIdentitiesAreComparedNotJustFamilyCounts()
    {
        var (database, output) = Proofs("CN=Other,DC=example", false, false);

        var error = Assert.Throws<InvalidDataException>(() => RequesterMeasurement.ProofCounts(database, output));
        Assert.Contains("question identities", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASavedProofCannotBorrowAnotherGeneration()
    {
        var (database, output) = Proofs("CN=User,DC=example", true, false);

        var error = Assert.Throws<InvalidDataException>(() => RequesterMeasurement.ProofCounts(database, output));
        Assert.Contains("another generation", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateSavedAssessmentsAreNotHiddenBySetComparison()
    {
        var (database, output) = Proofs("CN=User,DC=example", false, true);

        var error = Assert.Throws<InvalidDataException>(() => RequesterMeasurement.ProofCounts(database, output));
        Assert.Contains("Duplicate saved assessment", error.Message, StringComparison.Ordinal);
    }

    private static (string Source, string Output) Evidence()
    {
        var root = Fresh();
        var source = Path.Combine(root, "source");
        var output = Path.Combine(root, "output");
        Directory.CreateDirectory(source); Directory.CreateDirectory(output);
        File.WriteAllText(BundleLayout.EvidencePath(source), "immutable fixture bytes");
        BundleSealing.Seal(BundleLayout.EvidencePath(source), BundleLayout.SealPath(source));
        return (source, output);
    }

    private static (string Database, string Output) Proofs(string storedRequester, bool wrongGeneration, bool duplicate)
    {
        var root = Fresh();
        var database = Path.Combine(root, "proofs.db");
        var generation = Guid.NewGuid();
        var proof = new { Assessment = new { GenerationId = wrongGeneration ? Guid.NewGuid() : generation,
            Request = new { RequesterDn = storedRequester, TargetDn = "CN=Core,DC=example" } } };
        var header = new
        {
            Generation = generation,
            Selection = new { Candidates = new[] { new { Family = "RequesterDacl", RequesterDn = "CN=User,DC=example", TargetDn = "CN=Core,DC=example" } } },
            Requesters = duplicate ? new[] { proof, proof } : [proof], OwnAccounts = Array.Empty<object>(), MembershipDacls = Array.Empty<object>(),
        };
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE tier0_path_calculation(id INTEGER,proof TEXT); INSERT INTO tier0_path_calculation VALUES(1,$proof)";
        command.Parameters.AddWithValue("$proof", JsonSerializer.Serialize(header));
        command.ExecuteNonQuery();
        return (database, root);
    }

    private static string Fresh()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "p242-runner-checks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}

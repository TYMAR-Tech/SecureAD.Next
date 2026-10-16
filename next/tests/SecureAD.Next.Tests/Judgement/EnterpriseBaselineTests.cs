using System.Security.Cryptography;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Measure;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class EnterpriseBaselineTests
{
    private static readonly string[] ProductFiles = ["evidence.current.json", "evidence.db", "evidence.db.seal"];

    [Theory]
    [InlineData("changed")]
    [InlineData("missing")]
    [InlineData("escape")]
    public void BuildProvenanceRefusesChangedMissingOrForeignInputs(string defect)
    {
        var root = Fresh();
        File.WriteAllText(Path.Combine(root, "input.cs"), "recorded input");
        var fingerprint = new EnterpriseFingerprint("input.cs",
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(root, "input.cs")))));
        switch (defect)
        {
            case "changed": File.AppendAllText(Path.Combine(root, "input.cs"), "changed"); break;
            case "missing": File.Delete(Path.Combine(root, "input.cs")); break;
            case "escape":
                root = Directory.CreateDirectory(Path.Combine(root, "child")).FullName;
                fingerprint = fingerprint with { Path = "..\\input.cs" };
                break;
        }

        var error = Assert.Throws<InvalidDataException>(() => EnterpriseBaseline.VerifyFingerprint(root, fingerprint));
        Assert.Contains(defect switch { "changed" => "changed", "missing" => "missing", _ => "escapes" }, error.Message);
    }

    [Fact]
    public void MatchingSourceBytesHaveAWorkingPositiveProvenanceControl()
    {
        var root = Fresh();
        var path = Path.Combine(root, "input.cs");
        File.WriteAllText(path, "recorded input");
        EnterpriseBaseline.VerifyFingerprint(root,
            new("input.cs", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExistingFilesAndDirectoriesAreNeverReusedAsMeasurementOutput(bool file)
    {
        var root = Fresh();
        var output = Path.Combine(root, "retained");
        if (file) File.WriteAllText(output, "retained original");
        else { Directory.CreateDirectory(output); File.WriteAllText(Path.Combine(output, "original"), "retained original"); }

        Assert.Throws<IOException>(() => EnterpriseBaseline.CreateOutput(output));
        Assert.Equal("retained original", File.ReadAllText(file ? output : Path.Combine(output, "original")));
    }

    [Theory]
    [InlineData(16, 343, 795, 7, 343, 5)]
    [InlineData(17, 342, 795, 7, 343, 5)]
    [InlineData(17, 343, 794, 7, 343, 5)]
    [InlineData(17, 343, 795, 6, 343, 5)]
    [InlineData(17, 343, 795, 7, 342, 5)]
    [InlineData(17, 343, 795, 7, 343, 4)]
    public void EveryIndependentCapturedCounterMustMatch(int version, long objects, long members,
        long positions, long links, long partitions) =>
        Assert.Throws<InvalidDataException>(() => EnterpriseBaseline.RequireControlCounts(
            new(version, objects, members, positions, links, partitions)));

    [Fact]
    public void CurrentWriterPreservesTheControlRecipeAndOriginalOccurrences()
    {
        var run = Fresh();
        EnterpriseControlWorkload.Write(run, CancellationToken.None);
        var counts = EnterpriseBaseline.InspectCaptured(run);

        Assert.Equal(new EnterpriseCapturedCounts(17, 343, 795, 7, 343, 5), counts);
        EnterpriseBaseline.RequireControlCounts(counts);
    }

    [Fact]
    public void MutableAnnotationsAndSqliteSidecarsAreNotRetainedInputFingerprints()
    {
        var root = Fresh();
        var evidence = BundleLayout.EvidencePath(root);
        File.WriteAllText(evidence, "immutable bytes");
        BundleSealing.Seal(evidence, BundleLayout.SealPath(root));
        File.WriteAllText(BundleLayout.CaptureManifestPath(root), "publication snapshot");
        foreach (var name in new[] { "annotations.db", "evidence.db-wal", "evidence.db-shm" })
            File.WriteAllText(Path.Combine(root, name), "mutable or transient bytes");

        var fingerprints = EnterpriseBaseline.FingerprintProducts(root);

        Assert.Equal(ProductFiles, fingerprints.Select(file => file.Path));
        Assert.All(fingerprints, file => Assert.Equal(new FileInfo(Path.Combine(root, file.Path)).Length, file.Bytes));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ObservationRequiresRealVerificationSamplesAndHonestStageCompletion(bool fails)
    {
        var root = Fresh();
        var path = BundleLayout.EvidencePath(root);
        File.WriteAllText(path, "immutable control bytes");
        BundleSealing.Seal(path, BundleLayout.SealPath(root));
        using var stopping = new CancellationTokenSource();
        using var observation = new EnterpriseBaselineObservation(root, 32L * 1024 * 1024 * 1024, stopping);
        if (fails)
            Assert.Throws<InvalidDataException>(() => observation.Measure<int>("selected",
                () => throw new InvalidDataException("deliberate control failure")));
        else
            Assert.Equal(7, observation.Measure("selected", () => 7));
        Assert.True(BundleSealing.Verify(root).MayBeOpened);
        observation.Dispose();

        Assert.Equal(!fails, Assert.Single(observation.Stages).Succeeded);
        Assert.Equal(1L, observation.Verifications.Values.Sum());
        Assert.True(observation.ResourceSamples > 0);
        var events = File.ReadLines(Path.Combine(root, "observations.jsonl"))
            .Select(line => { using var document = JsonDocument.Parse(line); return document.RootElement.GetProperty("Event").GetString(); })
            .ToArray();
        Assert.Contains("resource-sample", events);
        Assert.Contains("store-verification-attempt", events);
    }

    private static string Fresh()
    {
        var path = Path.Combine(Path.GetTempPath(), "er-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(path);
        return path;
    }
}

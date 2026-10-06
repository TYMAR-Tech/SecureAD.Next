using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class Tier0PathFingerprintTests
{
    [Theory]
    [InlineData(PathInputAvailability.NotProduced)]
    [InlineData(PathInputAvailability.RequiredInputsUnavailable)]
    [InlineData(PathInputAvailability.Recorded)]
    public void CompletePathInputsRetainTheirExistingFingerprint(PathInputAvailability availability)
        => MatchesExisting(Inputs(availability));

    [Theory]
    [InlineData("classifications")]
    [InlineData("relations")]
    [InlineData("permission-witness")]
    [InlineData("requester-source")]
    public void IndividuallyFingerprintedProofsRetainTheirExistingBytes(string shape)
    {
        var inputs = Inputs(PathInputAvailability.Recorded);
        switch (shape)
        {
            case "classifications":
                MatchesExisting(inputs.Classifications.ToArray());
                break;
            case "relations":
                MatchesExisting(inputs.AdmissionRelationships.ToArray());
                break;
            case "permission-witness":
                MatchesExisting(inputs.Classifications[0].Supports[0].Evidence[1]);
                break;
            case "requester-source":
                MatchesExisting(new
                {
                    inputs.Input,
                    Target = inputs.FixedTargets[0],
                    Membership = inputs.Classifications,
                    Permission = inputs.AdmissionRelationships[1],
                    Occurrences = inputs.PermissionIds,
                    Missing = (string?)null,
                });
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(shape));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("\\\"\n\t\u00e9\u6f22\ud83d\udd12<>+")]
    public void ScalarFingerprintsRetainEscapingAndNull(string? value) => MatchesExisting(value);

    [Fact]
    public void ValuesLargerThanTheSerializerBufferKeepTheirCompleteBytes()
    {
        var text = new string('x', 40_000) + "\u00e9\u6f22\ud83d\udd12\\\"\r\n";
        MatchesExisting(new
        {
            Values = new string?[] { text, null, text },
            Bytes = new byte[] { 0, 10, 13, 127, 128, 255 },
        });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FingerprintingDoesNotAllocateWholeDocumentCopies(bool permissionIds)
    {
        if (permissionIds)
        {
            var inputs = Inputs(PathInputAvailability.Recorded);
            AssertBounded(inputs with { PermissionIds = Enumerable.Repeat(1_234_567_890L, 800_000).ToList() }, inputs);
            return;
        }
        var text = new string('a', 2_048);
        var values = Enumerable.Repeat(text, 4_096).ToArray();
        AssertBounded(values, new[] { text });
    }

    private static void AssertBounded<T>(T value, T warmup)
    {
        var expected = ExistingFingerprint(value);
        _ = Tier0PathCalculation.Fingerprint(warmup);

        var before = GC.GetAllocatedBytesForCurrentThread();
        var actual = Tier0PathCalculation.Fingerprint(value);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.Equal(expected, actual);
        Assert.True(allocated < 1_048_576,
            $"Hashing over 8 MiB of JSON allocated {allocated:N0} bytes; document-sized copies must not return.");
    }

    [Fact]
    public void SerializationFailureStillEscapesAsTheOriginalFailure()
    {
        var failure = new InvalidOperationException("The proof could not be read.");

        var actual = Assert.Throws<InvalidOperationException>(
            () => Tier0PathCalculation.Fingerprint(new BrokenProof(failure)));

        Assert.Same(failure, actual);
    }

    private sealed class BrokenProof(InvalidOperationException failure)
    {
        public string Evidence => throw failure;
    }

    private static void MatchesExisting<T>(T value)
        => Assert.Equal(ExistingFingerprint(value), Tier0PathCalculation.Fingerprint(value));

    private static string ExistingFingerprint<T>(T value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(value, ProofSerialization.Options))));

    private static PathInputs Inputs(PathInputAvailability availability)
    {
        const string domain = "DC=contoso,DC=com";
        var generation = Guid.Parse("980b899d-61a0-47b2-a386-ae8e7d0167ed");
        var coverage = new Tier0Coverage(false, false, false,
            Tier0Limitations.InputIncomplete | Tier0Limitations.ControlQualificationUnsupported
            | Tier0Limitations.ProcessingIncomplete);
        if (availability != PathInputAvailability.Recorded)
            return new(generation, availability, null, coverage, [], [], [], [], [], null);

        var binding = new Tier0InputBinding(new string('a', 64),
            Guid.Parse("c2743064-aeab-4d65-b571-7f6a4727f3bd"), new string('b', 64),
            PrincipalClassificationRegistry.Version, 2, 2, domain, "CN=Configuration," + domain);
        var root = new Tier0Target(Guid.Parse("9211b313-1bca-4872-aa70-fdbe3bf8bb32"),
            domain, domain, "contoso.com", null, null);
        var group = new Tier0Target(Guid.Parse("b7d6e50b-b095-4c6a-9540-477086d36b25"),
            "CN=Administrators,CN=Builtin," + domain, domain, "contoso.com", "S-1-5-32-544", "contoso.com");
        var member = new Tier0Target(Guid.Parse("5e608171-a683-4719-9caf-dfba531aee99"),
            "CN=Jos\u00e9\\, Admin,OU=Privileged Users," + domain, domain, "contoso.com",
            "S-1-5-21-1-2-3-1100", null);
        var witness = new Tier0Evidence(group, "member", 17, member.DistinguishedName);
        var support = new Tier0Support(Tier0Basis.EffectiveMembership, group,
            [witness, witness with { Ordinal = 23 }, witness]);
        var classification = new Tier0Classification(binding, member, [support, support], coverage);
        var relations = new[]
        {
            Tier0RelevanceRelation.FromMembership(classification, 0),
            Tier0RelevanceRelation.FromCapturedPermission(binding, member, group, ControlCapability.CanWriteDacl,
                new(group.DistinguishedName, 17, member.Sid!), ControlUncertainty.HolderUnresolved),
        };
        return new(generation, availability, binding, coverage, [root, group], [classification, classification],
            relations, [11, 7, 11, long.MaxValue],
            [
                new(new(Tier0DiscoveryReason.DescriptorIncomplete, group.DistinguishedName, 17, member.Sid),
                    PathUncertaintyCause.CapturedEvidenceIncomplete, PathSubjectScope.RecordedTrustee,
                    PathTargetScope.Object, group),
                new(new(Tier0DiscoveryReason.UnsupportedRoute, null, null, null),
                    PathUncertaintyCause.AnalysisUnsupported, PathSubjectScope.UnknownWithinForest,
                    PathTargetScope.Forest, null),
            ],
            new(generation, binding.EvidenceSeal, 1, 3, 2, 1,
                new(1, SelfMembershipDiscoveryMode.Automatic, false, false, null, 0, 0, 0, 0,
                    [new(SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured, null, null, null, null)])));
    }
}

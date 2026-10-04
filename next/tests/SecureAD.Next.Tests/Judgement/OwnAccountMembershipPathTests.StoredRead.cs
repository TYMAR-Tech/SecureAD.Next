using System.Text.Json;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("Requesters", PathRequesterFamily.RequesterDacl)]
    [InlineData("OwnAccounts", PathRequesterFamily.OwnAccountMembership)]
    [InlineData("MembershipDacls", PathRequesterFamily.MembershipDacl)]
    public void P248AllPathReadersUseSavedAnswersWithoutReplaying(string family, PathRequesterFamily kind)
    {
        var directory = CoveragePrepared();
        string pathJson;
        string coverageJson;
        using (var original = Open(directory))
        {
            pathJson = JsonSerializer.Serialize(PathProofVerification.ReadPath(original, UserDn));
            var coverage = PathProofVerification.ReadCoverage(original);
            Assert.Equal(1, coverage.Families.Single(value => value.Family == kind).StoredAssessments);
            coverageJson = JsonSerializer.Serialize(coverage);
        }
        // This resealed, test-only marker changes no saved answer, but a source replay must reject it.
        PathProofVerification.AlterRequesterProof(directory, "$." + family + "[0].SourceFingerprint", "'" + new string('f', 64) + "'");
        using var reader = Open(directory);

        var path = reader.ReadTier0Path(UserDn);
        var coverageRead = reader.ReadPathRequesterCoverage();
        var together = reader.ReadTier0PathWithCoverage(UserDn);

        Assert.Equal(new[] { pathJson, coverageJson, pathJson, coverageJson }, new[]
        {
            JsonSerializer.Serialize(path), JsonSerializer.Serialize(coverageRead),
            JsonSerializer.Serialize(together.Path), JsonSerializer.Serialize(together.Coverage),
        });
        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Theory]
    [InlineData("$.Requesters[0].Assessment.GenerationId")]
    [InlineData("$.OwnAccounts[0].Assessment.GenerationId")]
    [InlineData("$.MembershipDacls[0].Assessment.Membership.GenerationId")]
    public void P248CoverageRefusesAnAssessmentFromAnotherGeneration(string path)
    {
        var directory = CoveragePrepared();
        PathProofVerification.AlterRequesterProof(directory, path, "'11111111-1111-1111-1111-111111111111'");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadPathRequesterCoverage());
    }

    [Fact]
    public void P248StoredCoverageDoesNotPromoteUnavailableInputs()
    {
        var directory = Capture();
        JudgeCoverage(directory);
        using var reader = Open(directory);

        var coverage = reader.ReadPathRequesterCoverage();

        Assert.Equal((PathRequesterCoverageState.InputsUnavailable, 0, PathInputAvailability.RequiredInputsUnavailable),
            (coverage.Verdict, coverage.Families.Sum(value => value.StoredAssessments), coverage.Inputs.Availability));
    }
}

using System.Collections.Immutable;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsDirectoryWmiAssessmentTests
{
    [Theory]
    [InlineData(4096u, true)]
    [InlineData(8192u, false)]
    [InlineData(67112960u, false)]
    public void LapsDirectoryAssessmentUsesOneCorrelatedFilterWithoutErasingEitherOriginalOutcome(uint flags, bool matches)
    {
        var result = Read(flags);
        var projection = result.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal);
        Assert.False(projection.IsObservedWmiResult);
        Assert.Equal(GpoDirectoryWmiAssessment.Assumption, projection.Assumption);
        Assert.Null(projection.Reason);
        Assert.Null(projection.UnresolvedCondition);
        var assessment = Assert.Single(projection.UsedAssessments);
        Assert.Equal(matches ? GpoDirectoryWmiState.MatchesRecordedPlatform : GpoDirectoryWmiState.DoesNotMatchRecordedPlatform, assessment.State);
        Assert.Equal(matches ? GroupB : null, projection.Value!.Principal);
        Assert.Equal(matches ? LapsConfiguredValueState.PolicyValue : LapsConfiguredValueState.DocumentedDefault, projection.Value.State);
        Assert.All(result.RegistryPolicies, policy =>
        {
            Assert.Equal(assessment.Condition, policy.Applicability.DirectoryAssessment.Condition);
            Assert.Equal(GpoApplicabilityState.Unknown, policy.Applicability.State);
        });
        var condition = assessment.Condition!.Value;
        var positive = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [condition] = true });
        var negative = result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [condition] = false });
        Assert.Equal(GroupB, positive.Principal);
        Assert.Equal(LapsConfiguredValueState.DocumentedDefault, negative.State);
        Assert.IsType<LapsSettingBranch>(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].Decision);
        Assert.Equal(3, result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].DecisionNodeCount);
        Assert.False(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].IsDefiniteForComputer);
        Assert.True(result.HasOpenPolicyScope);
    }

    [Fact]
    public void LapsDirectoryAssessmentCombinesDifferentSupportedFiltersWithoutChangingTheHigherAlternative()
    {
        var definitions = new Dictionary<int, string>
        {
            [1] = GpoDirectoryWmiAssessmentTests.Wrapper("SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.0.%'"),
            [2] = GpoDirectoryWmiAssessmentTests.Wrapper("SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3"),
        };
        var directory = LapsPrecedenceRun.Build(
            [new(1, [TextValue(Principal, GroupA)], Filter: 1), new(2, [TextValue(Principal, GroupB)], Filter: 2)],
            filterDefinitions: definitions, computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), accountControl: 8192);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var projection = result.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal);
        Assert.Equal(GroupA, projection.Value!.Principal);
        Assert.Equal(2, projection.UsedAssessments.Length);
        Assert.Contains(projection.UsedAssessments, value => value.State == GpoDirectoryWmiState.DoesNotMatchRecordedPlatform);
        var both = projection.UsedAssessments.ToDictionary(value => value.Condition!.Value, _ => true);
        Assert.Equal(GroupB, result.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, both).Principal);
        Assert.Null(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].UniformOrderedProjectionValue);
    }

    [Fact]
    public void LapsDirectoryAssessmentMissingPlatformKeepsTheRequiredFilterAndAnExplicitReason()
    {
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])]);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var result = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var projection = result.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal);
        Assert.Null(projection.Value);
        Assert.NotNull(projection.UnresolvedCondition);
        Assert.NotNull(projection.Reason);
        Assert.Empty(projection.UsedAssessments);
        Assert.IsType<LapsSettingBranch>(result.Settings[LapsPolicySetting.ADPasswordEncryptionPrincipal].Decision);
    }

    [Theory]
    [InlineData("seal")]
    [InlineData("computer")]
    [InlineData("condition")]
    public void LapsDirectoryAssessmentRefusesForeignBoundSupportEvenWithUsablePlatformInformation(string defect)
    {
        var result = Read(4096);
        var policies = result.RegistryPolicies.ToArray();
        var first = policies[0];
        var assessment = first.Applicability.DirectoryAssessment;
        assessment = defect switch
        {
            "seal" => assessment with { EvidenceSeal = "another seal" },
            "computer" => assessment with { Computer = assessment.Computer with { ObjectId = assessment.Computer.ObjectId + 1 } },
            "condition" => assessment with { Condition = assessment.Condition!.Value with { FilterObjectId = assessment.Condition.Value.FilterObjectId + 1 } },
            _ => throw new ArgumentOutOfRangeException(nameof(defect)),
        };
        policies[0] = first with { Applicability = first.Applicability with { DirectoryAssessment = assessment } };
        result = result with { RegistryPolicies = policies.ToImmutableArray() };
        Assert.Throws<InvalidDataException>(() => result.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal));
    }

    [Fact]
    public void LapsDirectoryAssessmentRefusesContradictoryAnswersForOneSharedCapturedFilter()
    {
        var result = Read(4096);
        var policies = result.RegistryPolicies.ToArray();
        var first = policies[0];
        Assert.Equal(first.Applicability.DirectoryAssessment.Condition, policies[1].Applicability.DirectoryAssessment.Condition);
        var assessment = first.Applicability.DirectoryAssessment with { State = GpoDirectoryWmiState.DoesNotMatchRecordedPlatform };
        policies[0] = first with { Applicability = first.Applicability with { DirectoryAssessment = assessment } };
        result = result with { RegistryPolicies = policies.ToImmutableArray() };
        Assert.Throws<InvalidDataException>(() => result.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal));
    }

    private static LapsConfiguredPolicy Read(uint flags)
    {
        var directory = LapsPrecedenceRun.Build(
            [new(1, [TextValue(Principal, GroupA)]), new(2, [TextValue(Principal, GroupB)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), accountControl: flags);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        return reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
    }
}

using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void SavedPathAdapterReadsTheRecordedOwnAccountRoute()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.NotEmpty(PresentationQuestions(section));
        Assert.Equal("Not requested", section.Result);
    }

    [Theory]
    [InlineData("SW", OwnAccountMembershipPermissionKind.SelfMembership, "Self-Membership")]
    [InlineData("WP", OwnAccountMembershipPermissionKind.WriteMembers, "Write members")]
    public void SavedPathCombinedDisplayKeepsTheSelectedMembershipMechanism(string right, OwnAccountMembershipPermissionKind kind, string expected)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{UserSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = kind }]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains(PresentationQuestions(section).SelectMany(value => value.Entries),
            value => value.Value.Contains("Relevant permission: " + expected, StringComparison.Ordinal));
    }

    [Fact]
    public void SavedPathCombinedDisplayRetainsTheSavedAuthorizationAssumption()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains(PresentationQuestions(section).SelectMany(value => value.RecordDetails),
            value => value.Label == "Saved membership-followed-by-permission assumptions" && value.Value == MembershipDaclAssessment.Context);
    }

    [Fact]
    public void SavedPathAdapterReadsAConcreteRequesterPermissionWithoutTransferringIdentity()
    {
        var directory = Capture(coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        Judge(directory, [], [new(UserDn, CoreDn)]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains("not to act as that object", PresentationSteps(section)[^1].Description);
        Assert.Contains(PresentationQuestions(section).SelectMany(value => value.RecordDetails),
            value => value.Label == "Requester distinguished name" && value.Value == UserDn);
    }

    [Fact]
    public void SavedPathAdapterKeepsTheOriginalPermissionInsteadOfMultiplyingHolderCounts()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var first = source.ReadSavedTier0Path(directory, UserDn).Value!;
        var group = Enum.GetValues<PathRiskVerdict>().First(value => first.Page.Counts.For(value) > 0);
        var saved = source.ReadSavedTier0Path(directory, UserDn, group, null).Value!;
        using var reader = Open(directory);
        var original = reader.ReadControlEdges(TargetDn, null, null, true, 0);

        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(original.Edges.Single(edge => edge.Id == saved.Page.Questions[0].Steps[0].PermissionId)),
            System.Text.Json.JsonSerializer.Serialize(Assert.Single(saved.Permissions)));
    }

    [Fact]
    public void SavedPathAdapterKeepsReadbackPassive()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var before = Snapshot(directory);
        source.ReadSavedTier0Path(directory, UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void SavedPathAdapterRefusesChangedDerivationInsteadOfReadingAnOldResult()
    {
        var directory = Prepared();
        Derive(directory);
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void SavedPathAdapterRefusesAlteredStoredProof()
    {
        var directory = Prepared();
        Mutate(directory, "DELETE FROM tier0_path_calculation");
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);

        Assert.Equal("Shell.SavedPathInvalidEvidence", result.Error?.Code);
    }

    [Theory]
    [InlineData(AnalysisStoreKind.Judgement, false)]
    [InlineData(AnalysisStoreKind.Judgement, true)]
    [InlineData(AnalysisStoreKind.Derivation, false)]
    [InlineData(AnalysisStoreKind.Derivation, true)]
    public void SavedPathAdapterWithholdsEarlierResultsWhileAnUnpublishedAttemptExists(AnalysisStoreKind kind, bool manifest)
    {
        var directory = Prepared();
        File.WriteAllText(UnpublishedPath(directory, kind, manifest), "retained unfinished attempt");
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);

        Assert.Equal("Shell.SavedPathUnfinished", result.Error?.Code);
    }

    [Fact]
    public void SavedPathAdapterMissingGenerationIsNoSavedResult()
    {
        var directory = Capture();
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);

        Assert.Equal((true, (SavedTier0Path?)null), (result.IsSuccess, result.Value));
    }

    [Fact]
    public void SavedPathAdapterDoesNotCallACorruptManifestAnAbsentResult()
    {
        var directory = Prepared();
        File.WriteAllText(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement), "invalid manifest");
        using var source = new BundleAssetSource();
        var result = source.ReadSavedTier0Path(directory, UserDn);

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void SavedPathDisplayKeepsUnknownMembershipAndAddReadinessSeparate()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains("Captured membership: unresolved", PresentationQuestions(section)[0].Membership);
        Assert.Contains("Prerequisites for adding this account to the group: unresolved", PresentationQuestions(section)[0].Membership);
    }

    private static string UnpublishedPath(string directory, AnalysisStoreKind kind, bool manifest)
    {
        if (manifest) return AnalysisStoreLifecycle.ManifestPath(directory, kind) + ".partial";
        if (kind == AnalysisStoreKind.Derivation) return AnalysisStoreLifecycle.StagingPath(directory, kind);
        var generation = Guid.NewGuid();
        AnalysisStoreLifecycle.BeginAttempt(directory, kind, generation);
        return BundleLayout.AnalysisGenerationDataPath(directory, kind, generation);
    }

    [Fact]
    public void SavedPathQuestionsKeepUnknownReadinessAsANamedSavedAnswer()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains(PresentationQuestions(section).SelectMany(value => value.RecordDetails),
            value => value.Label == "Ordinary Add readiness" && value.Value == "Unknown");
    }

    private static SavedTier0PathSectionViewModel Presentation(BundleAssetSource source, string directory)
    {
        var section = new SavedTier0PathSectionViewModel(new(ObjectSectionCatalog.SavedTier0Path, "Tier 0 findings and routes", []));
        section.ConfigureAsync(UserDn, (group, after, _) => Task.FromResult(source.ReadSavedTier0Path(directory, UserDn, group, after)));
        section.Read();
        foreach (var group in section.Groups) group.IsExpanded = true;
        return section;
    }

    private static IReadOnlyList<SavedPathQuestionViewModel> PresentationQuestions(SavedTier0PathSectionViewModel section) =>
        section.Groups.SelectMany(group => group.Questions).ToArray();

    private static IReadOnlyList<SavedPathStepViewModel> PresentationSteps(SavedTier0PathSectionViewModel section) =>
        PresentationQuestions(section).SelectMany(question => question.Steps).ToArray();
}

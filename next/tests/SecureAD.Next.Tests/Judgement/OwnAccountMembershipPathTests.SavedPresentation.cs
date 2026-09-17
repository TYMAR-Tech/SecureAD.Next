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

        Assert.Equal("Supported route recorded", section.Result);
    }

    [Theory]
    [InlineData("SW", OwnAccountMembershipPermissionKind.SelfMembership, "Self-Membership validated write")]
    [InlineData("WP", OwnAccountMembershipPermissionKind.WriteMembers, "ordinary Write Members")]
    public void SavedPathCombinedDisplayKeepsTheSelectedMembershipMechanism(string right, OwnAccountMembershipPermissionKind kind, string expected)
    {
        var directory = Capture($"O:SYG:SYD:(OA;;{right};{MemberGuid};;{UserSid})", membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn) { PermissionKind = kind }]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains("Saved own-account membership proof (" + expected + ")", section.Steps[0].Evidence);
    }

    [Fact]
    public void SavedPathCombinedDisplayRetainsTheSavedAuthorizationAssumption()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        JudgeMembershipDacl(directory, [new(UserDn, TargetDn, CoreDn)]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains(MembershipDaclAssessment.Context, section.Steps[^1].Evidence);
    }

    [Fact]
    public void SavedPathAdapterReadsAConcreteRequesterPermissionWithoutTransferringIdentity()
    {
        var directory = Capture(coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
        Derive(directory);
        Judge(directory, [], [new(UserDn, CoreDn)]);
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains("Saved concrete requester authorization and ordered permission evidence:", section.Steps[^1].Evidence);
    }

    [Fact]
    public void SavedPathAdapterKeepsTheOriginalPermissionInsteadOfMultiplyingHolderCounts()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var saved = source.ReadSavedTier0Path(directory, UserDn).Value!;
        using var reader = Open(directory);
        var original = reader.ReadControlEdges(TargetDn, null, null, true, 0);

        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(original.Edges.Single(edge => edge.Id == saved.Path.Steps[0].PermissionId)),
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

        Assert.Contains("Unknown current membership and unknown ordinary Add readiness remain unknown.", section.Steps[0].Evidence);
    }

    private static string UnpublishedPath(string directory, AnalysisStoreKind kind, bool manifest) => manifest
        ? AnalysisStoreLifecycle.ManifestPath(directory, kind) + ".partial"
        : AnalysisStoreLifecycle.StagingPath(directory, kind);

    [Fact]
    public void SavedPathQuestionsKeepUnknownReadinessAsANamedSavedAnswer()
    {
        var directory = Prepared();
        using var source = new BundleAssetSource();
        var section = Presentation(source, directory);

        Assert.Contains("\"Readiness\": \"Unknown\"", section.SavedQuestions);
    }

    private static SavedTier0PathSectionViewModel Presentation(BundleAssetSource source, string directory)
    {
        var section = new SavedTier0PathSectionViewModel(new(ObjectSectionCatalog.SavedTier0Path, "Saved Tier 0 path", []));
        section.Configure(UserDn, () => source.ReadSavedTier0Path(directory, UserDn));
        section.Read();
        return section;
    }
}

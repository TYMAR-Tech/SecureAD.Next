using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed class MemberAttributionPresentationTests
{
    [Theory]
    [InlineData(UserDn, false)]
    [InlineData(TargetDn, true)]
    public void BothDirectionsPresentStoredMembersAndThePartialWarning(string dn, bool byHolder)
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        using var source = new BundleAssetSource();
        var section = Open(source, reader.BundleDirectory, dn, byHolder);
        Assert.Equal((1, true, true), (section.MemberPanel.Rows.Count,
            section.MemberPanel.Status.Contains("These are not total effective-membership counts.", StringComparison.Ordinal),
            section.MemberPanel.Counting.Contains("do not add control-edge counts", StringComparison.Ordinal)));
    }

    [Fact]
    public void ReverseOwnerChangeRemainsUnknownAndUncounted()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;0x000F01FF;;;{TargetSid})"));
        var value = Assert.Single(reader.ReadPermissionsThroughMembership(UserSid, null, true, 0).Permissions,
            permission => permission.Capability == nameof(ControlCapability.CanBecomeOwnerAndRewriteDacl));
        Assert.Equal((ControlEvaluationState.Unknown, false), (value.PermissionState, value.IsCounted));
    }

    [Fact]
    public void ReverseSupportingPermissionKeepsItsFullControlCountLabel()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;0x000F01FF;;;{TargetSid})"));
        using var source = new BundleAssetSource();
        var section = Open(source, reader.BundleDirectory, UserDn, false);
        Assert.Contains(section.ThroughMembership, row => row.Capability.Contains("Included in full-control count — not counted again", StringComparison.Ordinal));
    }

    [Fact]
    public void ReverseUnknownSummaryCannotBorrowEstablishmentFromMembership()
    {
        var value = new MemberPermissionReference(1, TargetSid, null, UserDn, "HasFullControl", ControlExpectedness.Unknown,
            false, MemberAttributionState.Established, MemberAttributionState.Established, "CapturedGroupRouteUsable")
            { PermissionState = ControlEvaluationState.Unknown };
        var row = new ControlEdgesSectionViewModel.MemberPermissionRowViewModel(value);
        Assert.Contains("Unknown; Not counted", row.Capability, StringComparison.Ordinal);
    }

    [Fact]
    public void MemberPagingLeavesTheSourcePermissionCountUnchanged()
    {
        using var reader = MemberAttributionTests.Prepare(PagedBundle());
        using var source = new BundleAssetSource();
        var section = Open(source, reader.BundleDirectory, UserDn, false);
        var counts = section.Counts;
        section.MemberPanel.NextPageCommand.Execute(null);
        Assert.Equal((counts, 3, "Showing 3 stored members"), (section.Counts, section.MemberPanel.Rows.Count, section.MemberPanel.Showing));
    }

    [Fact]
    public void MemberDetailRejectsAGenerationChangeAndClearsOldRows()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        var panel = new MemberAttributionPanelViewModel();
        var detail = reader.ReadMemberAttribution(TargetSid, null, UserDn);
        panel.Show(Result<MemberAttributionDetail>.Success(detail), detail.GenerationId);
        panel.Show(Result<MemberAttributionDetail>.Success(detail), Guid.NewGuid());
        Assert.Equal((0, true), (panel.Rows.Count, panel.Status.Contains("not an empty result", StringComparison.Ordinal)));
    }

    [Fact]
    public void NoBudgetIsNotPresentedAsAnEmptyGroup()
    {
        var panel = new MemberAttributionPanelViewModel();
        panel.Show(Result<MemberAttributionDetail>.Success(new(false, null, []) { GenerationId = Guid.Empty }), Guid.Empty);
        Assert.Equal("Member expansion did not run. No expansion budget was approved. Group-held permissions remain visible and counted as before.", panel.Status);
    }

    [Fact]
    public void ReverseSectionRetainsTheMembershipOnlyCaveat()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        using var source = new BundleAssetSource();
        var section = Open(source, reader.BundleDirectory, UserDn, false);
        Assert.Equal(("Permissions through group membership", "Captured security-group membership", true),
            (section.ThroughMembershipHeading, Assert.Single(section.ThroughMembership).Membership,
             section.MemberPanel.Caveat.Contains("No directory operation was performed.", StringComparison.Ordinal)));
    }

    [Fact]
    public void CorruptMemberEvidenceDoesNotRemoveValidHolderPermissions()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        var directory = reader.BundleDirectory;
        reader.Dispose();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM member_attribution_member";
            command.ExecuteNonQuery();
        });
        using var source = new BundleAssetSource();
        var section = Open(source, directory, UserDn, false);
        Assert.Equal((1, 0, true), (section.Rows.Count, section.MemberPanel.Rows.Count,
            section.MemberPanel.Status.Contains("not an empty result", StringComparison.Ordinal)));
    }

    internal static ControlEdgesSectionViewModel Open(BundleAssetSource source, string directory, string dn, bool byHolder)
    {
        var screen = new AssetsViewModel(source);
        screen.Show(directory, false);
        var attributes = Assert.IsType<ObjectAttributes>(source.ReadObjectAttributes(directory, dn).Value);
        var objectClass = Assert.IsType<string>(attributes.Find("objectClass")?.Values.Last().Text);
        screen.OpenObject(new(new(dn, dn, attributes.ObjectGuid, objectClass, "DC=contoso,DC=com")));
        var opened = Assert.IsType<ObjectViewModel>(screen.Opened);
        opened.Show(ObjectSectionCatalog.ControlEdges);
        var section = Assert.IsType<ControlEdgesSectionViewModel>(opened.Selected);
        section.ByHolder = byHolder;
        return section;
    }

    private static string PagedBundle() => Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})",
        members: Enumerable.Range(0, 103).Select(UserName).ToArray(), writeAdditional: (writer, coverage) =>
        {
            foreach (var index in Enumerable.Range(1, 102))
                writer.WriteObject(new(coverage, UserName(index), Guid.NewGuid(),
                [
                    new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("user")]),
                    new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(SecureAD.Kernel.Security.Sid.ToBytes($"S-1-5-21-1-2-3-{5000 + index}")!)]),
                    new("primaryGroupID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("513")]),
                ], Started));
        });
}

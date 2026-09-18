using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    private const string UnrelatedMemberRight = "77777777-1111-2222-3333-444444444444";
    private const string DistributionHistorySid = "S-1-5-21-1-2-3-1999";
    private const string PagingSubjectSid = "S-1-5-21-1-2-3-9999";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CorrectionSavedPathReadsPermissionBeyondDisplayPage(bool fullControl)
    {
        var directory = PagingCapture(fullControl);
        Derive(directory);
        Judge(directory, []);
        using var source = new BundleAssetSource();

        var saved = source.ReadSavedTier0Path(directory, UserDn);

        Assert.True(saved.IsSuccess, saved.Error?.Description);
        Assert.Equal(PagingSubjectSid, saved.Value!.Permissions.Single().HolderSid);
    }

    [Fact]
    public void CorrectionExactPermissionRejectsAnotherTarget()
    {
        var (directory, id) = ExactPermissionInput();
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdge(CoreDn, id));
    }

    [Theory]
    [InlineData("UPDATE control_product SET completed=0")]
    [InlineData("UPDATE control_product SET engine_version=-1")]
    public void CorrectionExactPermissionRequiresACompletedCurrentProduct(string sql)
    {
        var (directory, id) = ExactPermissionInput();
        Mutate(directory, sql);
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdge(TargetDn, id));
    }

    [Fact]
    public void CorrectionExactPermissionRetainsFullControlValidation()
    {
        var (directory, id) = ExactPermissionInput();
        Mutate(directory, "DELETE FROM full_control_manifest");
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadEdge(reader, TargetDn, id));
    }

    [Fact]
    public void CorrectionExactPermissionRetainsOwnershipValidation()
    {
        var (directory, id) = ExactPermissionInput();
        Mutate(directory, "UPDATE control_object SET principal_sid='S-1-5-21-1-2-3-1998'");
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadEdge(reader, TargetDn, id));
    }

    [Theory]
    [InlineData("UPDATE control_edge SET generation='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE control_edge SET derivation_generation='99999999-9999-9999-9999-999999999999'")]
    public void CorrectionExactPermissionRejectsOtherGenerations(string sql)
    {
        var (directory, id) = ExactPermissionInput();
        Mutate(directory, sql);
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdge(TargetDn, id));
    }

    [Fact]
    public void CorrectionExactPermissionRejectsMissingSupports()
    {
        var (directory, id) = ExactPermissionInput();
        Mutate(directory, "DELETE FROM control_ace");
        using var reader = Open(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdge(TargetDn, id));
    }

    [Fact]
    public void CorrectionRequesterHistoryDenyCannotBeExcludedAsDistributionMembership()
    {
        var directory = HistoryCapture(DistributionHistorySid, "O:SYG:SYD:",
            $"O:SYG:SYD:(D;;WD;;;{DistributionHistorySid})(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory, [], [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void CorrectionRequesterHistoryDenyDoesNotProduceReachablePath()
    {
        var directory = HistoryCapture(DistributionHistorySid, "O:SYG:SYD:",
            $"O:SYG:SYD:(D;;WD;;;{DistributionHistorySid})(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory, [], [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void CorrectionUnrelatedDistributionDenyStillAllowsDirectPermission()
    {
        var directory = HistoryCapture("S-1-5-21-1-2-3-1998", "O:SYG:SYD:",
            $"O:SYG:SYD:(D;;WD;;;{DistributionHistorySid})(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory, [], [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Established, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Theory]
    [InlineData("SW", OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData("WP", OwnAccountMembershipPermissionKind.WriteMembers)]
    public void CorrectionRequesterHistoryDenyKeepsMembershipUnknown(string right, OwnAccountMembershipPermissionKind kind)
    {
        var directory = HistoryCapture(DistributionHistorySid,
            $"O:SYG:SYD:(OD;;{right};{MemberGuid};;{DistributionHistorySid})(OA;;{right};{MemberGuid};;{UserSid})", "O:SYG:SYD:");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn) { PermissionKind = kind }]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Obtainability);
    }

    [Fact]
    public void CorrectionMemberNamedExtendedRightDoesNotAuthorizeAnAdd()
    {
        var directory = MemberCollisionCapture();
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Obtainability);
    }

    [Fact]
    public void CorrectionMemberNamedExtendedRightDoesNotProduceReachablePath()
    {
        var directory = MemberCollisionCapture();
        Derive(directory);
        Judge(directory, [WriteMembersRequest()]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    private (string Directory, long Id) ExactPermissionInput()
    {
        var directory = Prepared();
        using var reader = Open(directory);
        return (directory, reader.ReadTier0Path(UserDn).Steps[0].PermissionId!.Value);
    }

    private string PagingCapture(bool fullControl)
    {
        var rights = fullControl ? "0xF01FF" : "WD";
        var grants = string.Concat(Enumerable.Range(3000, 249).Select(rid => $"(A;;{rights};;;S-1-5-21-1-2-3-{rid})"));
        return Capture("O:SYG:SYD:", userSid: PagingSubjectSid, membershipTail: false,
            coreDescriptor: $"O:SYG:SYD:{grants}(A;;WD;;;{PagingSubjectSid})",
            additional: (writer, coverage) =>
            {
                foreach (var rid in Enumerable.Range(3000, 249))
                    Write(writer, coverage, $"CN=Grant{rid},DC=contoso,DC=com", ["top", "user"],
                        $"S-1-5-21-1-2-3-{rid}", [], "O:SYG:SYD:");
            });
    }

    private string HistoryCapture(string historySid, string groupDescriptor, string coreDescriptor) => Capture(groupDescriptor,
        coreDescriptor: coreDescriptor,
        userAttributes: [.. Account("512", "513"), Binary("sIDHistory", Sid.ToBytes(historySid)!)],
        additional: (writer, coverage) => Write(writer, coverage, "CN=Distribution,DC=contoso,DC=com",
            ["top", "group"], DistributionHistorySid, [Text("groupType", "2")], "O:SYG:SYD:"));

    private string MemberCollisionCapture() => Capture($"O:SYG:SYD:(OA;;WP;{UnrelatedMemberRight};;{UserSid})",
        additional: (writer, _) =>
        {
            var configuration = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
                "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 1, 1, [], false);
            writer.WriteCoverage(configuration);
            Write(writer, configuration, "CN=member,CN=Extended-Rights,CN=Configuration,DC=contoso,DC=com",
                ["top", "controlAccessRight"], null,
                [Text("cn", "member"), Text("rightsGuid", UnrelatedMemberRight), Text("validAccesses", "256")], null);
        });
}

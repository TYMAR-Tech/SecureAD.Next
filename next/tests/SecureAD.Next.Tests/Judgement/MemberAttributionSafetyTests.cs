using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MemberAttributionSafetyTests
{
    [Fact]
    public void UnresolvedHolderCannotBecomeCompleteReverseSilence()
    {
        const string missing = "S-1-5-21-9-8-7-1100";
        using var reader = MemberAttributionTests.Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{missing})"));
        Assert.Equal((false, "HolderIdentityUnresolved"), (reader.ReadPermissionsThroughMembership(UserSid, null, true, 0).IsComplete,
            Assert.Single(reader.ReadMemberAttribution(missing, null, UserDn).Expansion!.Limitations.Where(reason => reason == "HolderIdentityUnresolved"))));
    }

    [Fact]
    public void DisabledMembersRemainVisibleWithTheirSourceRoute()
    {
        const string member = "CN=Account,DC=contoso,DC=com";
        var directory = Bundle(users: 0, members: [member], sddl: $"O:SYG:SYD:(A;;WD;;;{TargetSid})",
            writeAdditional: (writer, coverage) => writer.WriteObject(new(coverage, member, Guid.NewGuid(),
            [
                Text("objectClass", "user"),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(UserSid)!)]),
                Text("primaryGroupID", "513"), Text("userAccountControl", "514"),
            ], Started)));
        using var reader = MemberAttributionTests.Prepare(directory);
        var expansion = reader.ReadMemberAttribution(TargetSid, null, TargetDn).Expansion!;
        Assert.Equal((1, 1, "514"), (expansion.ResolvedMemberCount, expansion.Routes.Count,
            Assert.Single(expansion.Members).Source!.Find("userAccountControl")!.OnlyValue!.Text));
    }

    [Fact]
    public void ExplicitDeletionEvidenceIsDifferentFromMissingDeletionEvidence()
    {
        var deleted = ControlEdgeDeriverTests.Subject with
        {
            Attributes = [new("isDeleted", SecureAD.Kernel.Capture.AttributeCardinality.SingleValued, [new(0, "TRUE", null)])],
        };
        Assert.True(new MemberAttributionMember(deleted.DistinguishedName, deleted, MemberAttributionState.Established).IsDeleted);
    }

    [Fact]
    public void AmbiguousHolderSidDoesNotBecomeACompleteMemberTotal()
    {
        using var reader = MemberAttributionTests.Prepare(Bundle(users: 103, userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        Assert.False(reader.ReadMemberAttribution(TargetSid, null, UserDn).IsComplete);
    }

    [Theory]
    [InlineData(0, 1, 1)]
    [InlineData(1, 0, 1)]
    [InlineData(1, 1, 0)]
    [InlineData(-1, 1, 1)]
    public void InvalidBudgetIsRejectedBeforeAnyBundleAccess(long nodes, long links, long records)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => JudgingRun.JudgeWithMemberAttribution("not-a-bundle", [],
            new(nodes, links, records, TimeSpan.FromSeconds(1)), Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None));
    }

    [Fact]
    public void RerunningSameWorkBudgetKeepsTheSameMemberPrefixAndLinks()
    {
        var directory = Bundle(users: 5, userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        using var first = MemberAttributionTests.Prepare(directory, new(3, 100, 100, TimeSpan.FromMinutes(1)));
        var before = first.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        first.Dispose();
        var result = JudgingRun.JudgeWithMemberAttribution(directory, [], new(3, 100, 100, TimeSpan.FromMinutes(1)),
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var second = FullControlStorageTests.Open(directory);
        var after = second.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal(before.Links, after.Links);
    }

    private static EvidenceAttribute Text(string name, string value) => new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);
}

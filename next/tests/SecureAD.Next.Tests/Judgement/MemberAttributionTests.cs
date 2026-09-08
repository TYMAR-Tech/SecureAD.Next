using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;
using System.Text.Json;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class MemberAttributionTests
{
    private const string NestedDn = "CN=Nested,DC=contoso,DC=com";
    private const string LongerDn = "CN=Longer,DC=contoso,DC=com";

    [Fact]
    public void GroupHeldPermissionRetainsItsMemberWithoutAddingAHolderEdge()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        var result = JudgingRun.JudgeWithMemberAttribution(directory, [], new(100, 100, 1000, TimeSpan.FromMinutes(1)),
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = FullControlStorageTests.Open(directory);
        var detail = reader.ReadMemberAttribution(TargetSid, null, UserDn);
        var page = reader.ReadControlEdges(UserDn, null, null, true, 0);
        Assert.Equal((1, 1L), (detail.Expansion!.ResolvedMemberCount, page.ExpectedCount + page.UnknownCount + page.UnexpectedCount));
    }

    [Fact]
    public void LongerIndependentInitialMembershipIsRetained()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [UserDn, LongerDn],
            writeAdditional: (writer, coverage) =>
            {
                Write(writer, coverage, LongerDn, "S-1-5-21-1-2-3-3100", "group", -2147483646, [NestedDn]);
                Write(writer, coverage, NestedDn, "S-1-5-21-1-2-3-3101", "group", -2147483646, [UserDn]);
            });
        using var reader = Prepare(directory);
        var expansion = reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal(new[] { NestedDn, TargetDn }.Order(), expansion.Routes.Where(route => route.Member == UserDn).Select(route => route.InitialGroup).Order());
    }

    [Fact]
    public void PrimaryGroupMembershipSurvivesWithoutMemberBacklinks()
    {
        var primaryUser = "CN=Primary,DC=contoso,DC=com";
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", membership: false,
            writeAdditional: (writer, coverage) => Write(writer, coverage, primaryUser, "S-1-5-21-1-2-3-3200", "user", null, [],
                new EvidenceAttribute("primaryGroupID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(TargetSid.Split('-')[^1])])));
        using var reader = Prepare(directory);
        Assert.Contains(reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!.Links,
            link => link.Member == primaryUser && link.Attribute == "primaryGroupID");
    }

    [Theory]
    [InlineData(-2147483646L, MemberAttributionState.Established)]
    [InlineData(2L, MemberAttributionState.NotEstablished)]
    [InlineData(null, MemberAttributionState.Unknown)]
    public void SecurityAndDistributionAndMissingTypesRemainDifferent(long? type, MemberAttributionState expected)
    {
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", groupType: type));
        Assert.Equal(expected, Assert.Single(reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!.Members).State);
    }

    [Fact]
    public void CycleRetainsItsLinksWithoutCountingTheRootAsItsOwnMember()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [NestedDn],
            writeAdditional: (writer, coverage) => Write(writer, coverage, NestedDn, "S-1-5-21-1-2-3-3101", "group", -2147483646, [TargetDn, UserDn]));
        using var reader = Prepare(directory);
        var expansion = reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal((2, 3, false), (expansion.ResolvedMemberCount, expansion.Links.Count, expansion.Members.Any(member => member.Identity == TargetDn)));
    }

    [Fact]
    public void UnresolvedDnKeepsTheGroupAndCapturedSourceAttribute()
    {
        const string missing = "CN=Missing,DC=foreign,DC=example";
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [UserDn, missing]));
        var expansion = reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal((1, TargetDn, "member", false), (expansion.UnresolvedMemberCount,
            expansion.Links.Single(link => link.Member == missing).SourceDn,
            expansion.Links.Single(link => link.Member == missing).Attribute, expansion.IsComplete));
    }

    [Fact]
    public void ForeignStubIsNotCountedAsAResolvedUnderlyingPrincipal()
    {
        const string foreign = "CN=Foreign,DC=contoso,DC=com";
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [foreign],
            writeAdditional: (writer, coverage) => Write(writer, coverage, foreign, "S-1-5-21-7-8-9-1100", "foreignSecurityPrincipal", null, []));
        using var reader = Prepare(directory);
        var expansion = reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal((0, 1), (expansion.ResolvedMemberCount, expansion.UnresolvedMemberCount));
    }

    [Theory]
    [InlineData(2, 100, 1000, MemberAttributionStop.NodeBudgetExceeded)]
    [InlineData(100, 1, 1000, MemberAttributionStop.LinkBudgetExceeded)]
    [InlineData(100, 100, 4, MemberAttributionStop.StorageBudgetExceeded)]
    public void WorkBudgetRetainsTheDiscoveredPrefix(long nodes, long links, long records, MemberAttributionStop expected)
    {
        using var reader = Prepare(Bundle(users: 3, userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"), new(nodes, links, records, TimeSpan.FromMinutes(1)));
        var expansion = reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!;
        Assert.Equal((expected, 1, false), (expansion.Stop, expansion.ResolvedMemberCount, expansion.IsComplete));
    }

    [Fact]
    public void ElapsedBudgetRetainsAnExplicitTimedStop()
    {
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"), new(100, 100, 1000, TimeSpan.FromTicks(1)));
        Assert.Equal(MemberAttributionStop.TimeBudgetExceeded, reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!.Stop);
    }

    [Fact]
    public void ReverseReadbackDoesNotManufactureNamedHolderEdges()
    {
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", sddl: "O:SYG:SYD:"));
        Assert.Equal((0, TargetSid), (reader.ReadControlEdges(null, UserSid, null, true, 0).Edges.Count,
            Assert.Single(reader.ReadPermissionsThroughMembership(UserSid, null, true, 0).Permissions).HolderSid));
    }

    [Fact]
    public void FullControlSupportsAndMembersDoNotMultiplyTheSummaryCount()
    {
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;0x000F01FF;;;{TargetSid})"));
        var page = reader.ReadControlEdges(UserDn, null, null, true, 0);
        Assert.Equal((1L, 1, 1), (page.ExpectedCount + page.UnknownCount + page.UnexpectedCount,
            reader.ReadMemberAttribution(TargetSid, null, UserDn).Expansion!.ResolvedMemberCount,
            reader.ReadPermissionsThroughMembership(UserSid, null, true, 0).Permissions.Count(permission => permission.IsCounted)));
    }

    [Fact]
    public void ExpansionDoesNotEnableRequesterDiscovery()
    {
        using var reader = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        Assert.Equal("NotStarted", reader.ReadSelfMembershipSummary()!.Verdict);
    }

    [Fact]
    public void CurrentHostEntryPointStoresNotRunInsteadOfAnEmptyExpansion()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        var result = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = FullControlStorageTests.Open(directory);
        Assert.False(reader.ReadMemberAttribution(TargetSid, null, UserDn).WasRun);
    }

    [Fact]
    public void ReopeningStoredExpansionDoesNotRecomputeItsTimedResult()
    {
        using var reader = Prepare(Bundle(users: 3, userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"), new(2, 100, 1000, TimeSpan.FromMinutes(1)));
        var before = JsonSerializer.Serialize(reader.ReadMemberAttribution(TargetSid, null, UserDn));
        using var reopened = FullControlStorageTests.Open(reader.BundleDirectory);
        Assert.Equal(before, JsonSerializer.Serialize(reopened.ReadMemberAttribution(TargetSid, null, UserDn)));
    }

    [Theory]
    [InlineData("DELETE FROM member_attribution_product")]
    [InlineData("DELETE FROM member_attribution_member")]
    [InlineData("DELETE FROM member_attribution_context")]
    [InlineData("DELETE FROM member_attribution_permission")]
    [InlineData("UPDATE member_attribution_root SET proof='{}'")]
    [InlineData("UPDATE member_attribution_member SET sid='S-1-1-0'")]
    [InlineData("UPDATE member_attribution_product SET root_count=0")]
    public void CorruptMemberProofIsRefusedWithoutChangingHolderCounts(string mutation)
    {
        using var prepared = Prepare(Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})"));
        var directory = prepared.BundleDirectory;
        prepared.Dispose();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA foreign_keys=OFF; " + mutation;
            command.ExecuteNonQuery();
        });
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadMemberAttribution(TargetSid, null, UserDn));
    }

    internal static JudgementReader Prepare(string directory, MemberAttributionBudget? budget = null)
    {
        Derive(directory);
        var result = JudgingRun.JudgeWithMemberAttribution(directory, [], budget ?? new(10000, 10000, 100000, TimeSpan.FromMinutes(1)),
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return FullControlStorageTests.Open(directory);
    }

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string sid, string kind,
        long? groupType, string[] members, params EvidenceAttribute[] extra)
    {
        writer.WriteObject(new(coverage, dn, Guid.NewGuid(),
        [
            new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(kind)]),
            new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]),
            new("groupType", StoredAttributeCompleteness.Complete, groupType is { } type ? [EvidenceValue.OfText(type.ToString(System.Globalization.CultureInfo.InvariantCulture))] : []),
            new("member", StoredAttributeCompleteness.Complete, members.Select(EvidenceValue.OfText).ToArray()),
            .. extra,
        ], Started));
    }
}

using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GroupMembershipTotalsTests
{
    [Fact]
    public void TotalsCountCapturedObjectsOnceIncludingDistributionGroupsAndNonPrincipals()
    {
        var totals = Graph(
            Group("Root", "Alice", "Nested", "alice"),
            Group("Nested", "Alice", "Bob", "Contact") with { Attributes =
                [.. Group("Nested", "Alice", "Bob", "Contact").Attributes, Attribute("groupType", "2")] },
            Object("Alice", "user"), Object("Bob", "computer"), Object("Contact", "contact"));
        Assert.Equal(new(4, 0, 0, GroupMembershipLimitations.None), totals["Root"]);
        Assert.Equal(3, totals["Nested"].KnownMembers);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TotalsExcludeTheStartingGroupAndTerminateThroughOverlappingCycles(bool selfOnly)
    {
        var objects = selfOnly ? new[] { Group("A", "A") }
            : new[] { Group("A", "A", "B"), Group("B", "A", "C"), Group("C", "B", "User"), Object("User", "user") };
        var totals = Graph(objects);
        Assert.Equal(selfOnly ? 0 : 3, totals["A"].KnownMembers);
        if (!selfOnly) Assert.All(totals.Values, total => Assert.Equal(3, total.KnownMembers));
        Assert.All(totals.Values, total => Assert.Equal(GroupMembershipLimitations.None, total.Limitations));
    }

    [Fact]
    public void TotalsKeepSameSidGroupsInDifferentDomainsSeparate()
    {
        var first = "CN=Administrators,CN=Builtin,DC=one";
        var second = "CN=Administrators,CN=Builtin,DC=two";
        ObjectAttributes Scoped(string dn, string member) => Group(dn, member) with
            { Attributes = [.. Group(dn, member).Attributes, Attribute("objectSid", "S-1-5-32-544")] };
        var totals = Graph(Group("Root", first, second), Scoped(first, "Alice"), Scoped(second, "Bob"),
            Object("Alice", "user"), Object("Bob", "user"));
        Assert.Equal(4, totals["Root"].KnownMembers);
        Assert.Equal(1, totals[first].KnownMembers);
        Assert.Equal(1, totals[second].KnownMembers);
    }

    [Theory]
    [InlineData("memberOf", "Root")]
    [InlineData("primaryGroupID", "513")]
    public void TotalsDoNotAddMemberOfOrPrimaryGroupRelationships(string attribute, string value)
    {
        var root = Group("Root") with { Attributes = [.. Group("Root").Attributes, Attribute("objectSid", "S-1-5-21-1-2-3-513")] };
        var user = Object("Alice", "user") with { Attributes =
            [.. Object("Alice", "user").Attributes, Attribute(attribute, value), Attribute("objectSid", "S-1-5-21-1-2-3-1100")] };
        Assert.Equal(new(0, 0, 0, GroupMembershipLimitations.None), Graph(root, user)["Root"]);
    }

    [Fact]
    public void TotalsKeepUniqueMissingReferencesSeparateAndPropagateNestedGaps()
    {
        var totals = Graph(Group("Root", "Nested", "Missing"), Group("Nested", "missing", "Other"));
        Assert.Equal(new(1, 2, 0, GroupMembershipLimitations.UnresolvedReferences), totals["Root"]);
        Assert.Equal(new(0, 2, 0, GroupMembershipLimitations.UnresolvedReferences), totals["Nested"]);
    }

    [Fact]
    public void TotalsCountOriginalUnreadableValuesOncePerReachedGroup()
    {
        var nested = Group("Nested") with { Attributes =
            [Attribute("objectClass", "group"), new("member", AttributeCardinality.MultiValued,
                [new(0, null, [1]), new(1, "", null)])] };
        var totals = Graph(Group("Root", "Nested", "NESTED"), nested);
        Assert.Equal(new(1, 0, 2, GroupMembershipLimitations.UnreadableReferences), totals["Root"]);
    }

    [Theory]
    [InlineData(GroupMembershipLimitations.SourceLimited)]
    [InlineData(GroupMembershipLimitations.ForeignPrincipal)]
    [InlineData(GroupMembershipLimitations.ObjectClassNotRecorded)]
    public void TotalsRetainLimitationsOnReachedObjects(GroupMembershipLimitations limitation)
    {
        var member = limitation switch
        {
            GroupMembershipLimitations.SourceLimited => Group("Nested") with { Completeness = EvidenceCompleteness.MayBeMissingConfidentialValues },
            GroupMembershipLimitations.ForeignPrincipal => Object("Nested", "foreignSecurityPrincipal"),
            _ => Object("Nested", "user") with { Attributes = [] },
        };
        Assert.Equal(new(1, 0, 0, limitation), Graph(Group("Root", "Nested"), member)["Root"]);
    }

    [Fact]
    public void TotalsDistinguishMissingMemberAttributeFromRecordedEmptyValues()
    {
        var missing = Group("Missing") with { Attributes = [Attribute("objectClass", "group")] };
        var totals = Graph(Group("Empty"), missing);
        Assert.Equal(GroupMembershipLimitations.SourceLimited, totals["Missing"].Limitations);
        Assert.Equal(GroupMembershipLimitations.None, totals["Empty"].Limitations);
    }

    [Fact]
    public void TotalsRetainCaptureShortfallEvenForAnEmptyGroup()
    {
        var graph = new GroupMembershipTotals();
        graph.Add(Group("Root"));
        var total = Assert.Single(graph.Calculate(false, CancellationToken.None)).Total;
        Assert.Equal(new(0, 0, 0, GroupMembershipLimitations.CaptureIncomplete), total);
        Assert.Equal("Incomplete", total.Verdict);
        Assert.Equal("Recorded", Assert.Single(graph.Calculate(true, CancellationToken.None)).Total.Verdict);
    }

    [Fact]
    public void TotalsRefuseAmbiguousCapturedNames()
    {
        var graph = new GroupMembershipTotals();
        graph.Add(Group("Root"));
        Assert.Throws<InvalidDataException>(() => graph.Add(Group("root")));
    }

    [Fact]
    public void TotalsObserveCancellationBeforePublishingAnAnswer()
    {
        var graph = new GroupMembershipTotals();
        graph.Add(Group("Root", "Missing"));
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => graph.Calculate(true, stop.Token).ToArray());
    }

    private static Dictionary<string, GroupMembershipTotal> Graph(params ObjectAttributes[] objects)
    {
        var graph = new GroupMembershipTotals();
        foreach (var source in objects.Reverse()) graph.Add(source);
        return graph.Calculate(true, CancellationToken.None).ToDictionary(row => row.DistinguishedName, row => row.Total);
    }

    private static ObjectAttributes Group(string name, params string[] members) => Object(name, "group") with
        { Attributes = [Attribute("objectClass", "group"), Attribute("member", members)] };
    private static ObjectAttributes Object(string name, string kind) => new(name, Guid.NewGuid(),
        DateTimeOffset.UnixEpoch, EvidenceCompleteness.Complete, [Attribute("objectClass", kind)], null);
    private static ObjectAttribute Attribute(string name, params string[] values) => new(name, AttributeCardinality.MultiValued,
        values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
}

using System.Text.Json;
using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed partial class PrincipalExpansionTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompactExpansionCreatesNoPathBodiesUntilASelectedPathIsRead(bool qualified)
    {
        using var reader = DerivationReader.Open(Store(edges: [(0, 1), (1, 2)])).Value;
        using var counts = new CapturedMembershipPreparationTests.Counts(reader.Description.GenerationId);
        var result = qualified ? reader.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None)
            : reader.MembersOf(Readers, Scope);
        Assert.Equal(new[] { Staff, Alice }, result.Members!.Select(member => member.Sid));
        Assert.Equal(new[] { 2, 3 }, result.Members.Select(member => member.PathFromRoot.Count));
        Assert.Equal((2L, 0L), (counts.For("membership.compact_paths"), counts.For("membership.materialized_paths")));
        Assert.Equal(new[] { Readers, Staff, Alice }, result.Members[1].PathFromRoot);
        Assert.Equal(new[] { Readers, Staff, Alice }, result.Members[1].PathFromRoot);
        Assert.Equal(1L, counts.For("membership.materialized_paths"));
    }

    [Fact]
    public void CompactParentPathsRetainDeepChainsWithoutADepthLimit()
    {
        const int count = 48;
        var edges = Enumerable.Range(0, count - 1).Select(index => (index, index + 1)).ToArray();
        using var reader = DerivationReader.Open(Store(edges, principalCount: count)).Value;
        using var counts = new CapturedMembershipPreparationTests.Counts(reader.Description.GenerationId);
        var result = reader.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None);
        Assert.Equal(count - 1, result.Members!.Count);
        Assert.Equal(count, result.Members[^1].PathFromRoot.Count);
        Assert.Equal(0L, counts.For("membership.materialized_paths"));
        string[] expected = [Readers, Staff, Alice, DomainUsers,
            .. Enumerable.Range(4, count - 4).Select(index => $"S-1-5-21-9-9-9-{2000 + index}")];
        Assert.Equal(expected, result.Members[^1].PathFromRoot);
        Assert.Equal(1L, counts.For("membership.materialized_paths"));
    }

    [Fact]
    public void CompactPathsKeepCyclesAndTheFirstSupportedRouteDeterministic()
    {
        using var reader = DerivationReader.Open(Store(edges: [(0, 1), (1, 0), (0, 2), (1, 2)])).Value;
        var result = reader.MembersOf(Readers, Scope, (_, _) => true, CancellationToken.None);
        Assert.Equal(new[] { Staff, Alice }, result.Members!.Select(member => member.Sid));
        Assert.Equal(new[] { Readers, Alice }, result.Members[1].PathFromRoot);
        Assert.Equal(2, result.Members.Select(member => member.Sid).Distinct().Count());
    }

    [Fact]
    public void LazyPathValuesRemainOwnedAfterAnotherWalkAndReaderDisposal()
    {
        var reader = DerivationReader.Open(Store(edges: [(0, 1), (1, 2)])).Value;
        var original = reader.MembersOf(Readers, Scope);
        reader.MembersOf(Staff, Scope);
        reader.Dispose();
        Assert.Equal(new[] { Readers, Staff, Alice }, original.Members![1].PathFromRoot);
        Assert.Equal(JsonSerializer.Serialize(new[] { Readers, Staff, Alice }),
            JsonSerializer.Serialize(original.Members[1].PathFromRoot));
    }
}

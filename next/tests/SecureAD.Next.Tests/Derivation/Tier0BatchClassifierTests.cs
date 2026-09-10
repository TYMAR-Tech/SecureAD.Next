using System.Collections;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class Tier0BatchClassifierTests
{
    [Fact]
    public void BatchPreservesSingleObjectProofAndTargetOrder()
    {
        var evidence = new Tier0TestEvidence();
        var member = evidence.Principal("Member", "S-1-5-21-1-2-3-1200", "user");
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512", "group",
            Tier0TestEvidence.Attribute("groupType", "-2147483646"), Tier0TestEvidence.Attribute("member", member.DistinguishedName));
        var ordinary = evidence.Principal("Ordinary", "S-1-5-21-1-2-3-1300", "user");
        var targets = new[] { evidence.Target(ordinary), evidence.Target(root), evidence.Target(member) };
        var input = evidence.Input(root, member, ordinary);
        var routes = new Dictionary<Tier0Target, MembershipRouteSummary> { [evidence.Target(member)] = evidence.Routes(member, root) };
        var expected = targets.Select(target => Tier0Classifier.Qualify(evidence.Binding, target, input, routes.GetValueOrDefault(target))).ToArray();
        var actual = Tier0Classifier.QualifyMany(evidence.Binding, targets, input, target => routes.GetValueOrDefault(target));
        Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(actual.Classifications));
    }

    [Fact]
    public void BatchIndexesTheCapturedPopulationOnce()
    {
        var evidence = new Tier0TestEvidence();
        var first = evidence.Principal("First", "S-1-5-21-1-2-3-512");
        var second = evidence.Principal("Second", "S-1-5-21-1-2-3-520");
        var source = new CountedObjects(evidence.Input(first, second).Objects);
        var input = new CapturedMembershipInput(evidence.Generation, true, source);
        Tier0Classifier.QualifyMany(evidence.Binding, [evidence.Target(first), evidence.Target(second)], input, routes: null);
        Assert.Equal(1, source.Enumerations);
    }

    [Fact]
    public void BatchRetainsDuplicateSidAmbiguity()
    {
        var evidence = new Tier0TestEvidence();
        var first = evidence.Principal("First", "S-1-5-21-1-2-3-512");
        var second = evidence.Principal("Second", "S-1-5-21-1-2-3-512");
        var actual = Tier0Classifier.QualifyMany(evidence.Binding, [evidence.Target(first), evidence.Target(second)], evidence.Input(first, second), routes: null);
        Assert.All(actual.Classifications, result => Assert.Equal(Tier0State.Unknown, result.State));
    }

    [Fact]
    public void ASourceGenerationMismatchIsNotIndexedOrClassifiedAsSafe()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        var actual = Tier0Classifier.QualifyMany(evidence.Binding, [evidence.Target(root)],
            evidence.Input(root) with { DerivationGenerationId = Guid.NewGuid() }, routes: null);
        Assert.True(Assert.Single(actual.Classifications).Coverage.Limitations.HasFlag(Tier0Limitations.SourceMismatch));
        Assert.True(actual.Coverage.Limitations.HasFlag(Tier0Limitations.SourceMismatch));
    }

    [Fact]
    public void AnEmptyBatchUnderASourceMismatchIsNotReportedAsComplete()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");

        var actual = Tier0Classifier.QualifyMany(evidence.Binding, [],
            evidence.Input(root) with { DerivationGenerationId = Guid.NewGuid() }, routes: null);

        Assert.Empty(actual.Classifications);
        Assert.False(actual.Coverage.IsComplete);
    }

    [Fact]
    public void AnEmptyBatchOfANonEmptyInputIsComplete()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");

        var actual = Tier0Classifier.QualifyMany(evidence.Binding, [], evidence.Input(root), routes: null);

        Assert.Empty(actual.Classifications);
        Assert.True(actual.Coverage.IsComplete);
    }

    [Fact]
    public void CancellationDoesNotReturnAPartialBatchAsCompleted()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        using var cancellation = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => Tier0Classifier.QualifyMany(evidence.Binding,
            [evidence.Target(root)], evidence.Input(root), _ => { cancellation.Cancel(); return null; }, cancellation.Token));
    }

    private sealed class CountedObjects(IReadOnlyList<ObjectAttributes> source) : IReadOnlyList<ObjectAttributes>
    {
        internal int Enumerations { get; private set; }
        public int Count => source.Count;
        public ObjectAttributes this[int index] => source[index];
        public IEnumerator<ObjectAttributes> GetEnumerator()
        {
            Enumerations++;
            return source.GetEnumerator();
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

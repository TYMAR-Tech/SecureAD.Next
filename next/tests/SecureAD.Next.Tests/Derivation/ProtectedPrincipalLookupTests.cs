using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class ProtectedPrincipalLookupTests
{
    private const string Sid = "S-1-5-32-544";

    [Theory]
    [InlineData(null, 1)]
    [InlineData("", 2)]
    [InlineData("FIRST.EXAMPLE", 3)]
    [InlineData("second.example", 4)]
    [InlineData("missing.example", null)]
    public void LookupKeepsNullEmptyAndDomainScopesDistinct(string? scope, int? expected)
    {
        var product = Product(Fact(1, null), Fact(2, ""), Fact(3, "first.example"), Fact(4, "second.example"));

        Assert.Equal(expected, product.Lookup(Sid, scope)?.SidId);
    }

    [Fact]
    public void LookupKeepsSidComparisonOrdinal()
    {
        var product = Product(Fact(1, null));

        Assert.Null(product.Lookup("s-1-5-32-544", null));
    }

    [Fact]
    public void LookupKeepsTheFirstFactForAnEquivalentKey()
    {
        var first = Fact(1, "FIRST.EXAMPLE");
        var product = Product(first, Fact(2, "first.example"));

        Assert.Same(first, product.Lookup(Sid, "first.example"));
    }

    [Fact]
    public void ReplacingPrincipalsOnARecordCopyReplacesItsIndex()
    {
        var product = Product(Fact(1, null));
        product.Lookup(Sid, null);
        var replacement = Fact(2, null);

        var copy = product with { Principals = new[] { replacement } };

        Assert.Same(replacement, copy.Lookup(Sid, null));
    }

    [Fact]
    public void ReplacingPrincipalsOnACopyDoesNotChangeTheOriginal()
    {
        var original = Fact(1, null);
        var product = Product(original);
        var copy = product with { Principals = new[] { Fact(2, null) } };
        copy.Lookup(Sid, null);

        Assert.Same(original, product.Lookup(Sid, null));
    }

    [Fact]
    public void MetadataOnlyCopyKeepsTheIndexedSnapshot()
    {
        var product = Product(Fact(1, null));

        var copy = product with { StatedLimits = ProtectionUnknownReason.MembershipEvidenceIncomplete };

        Assert.Same(product.Principals, copy.Principals);
    }

    [Fact]
    public void CallerCannotChangeTheSnapshotThroughTheOriginalArray()
    {
        var original = Fact(1, null);
        var source = new[] { original };
        var product = Product(source);

        source[0] = Fact(2, null);

        Assert.Same(original, Assert.Single(product.Principals));
    }

    [Fact]
    public void JsonRoundTripRebuildsTheIndex()
    {
        var product = Product(Fact(1, "first.example"), Fact(2, null));

        var restored = JsonSerializer.Deserialize<StoredProtectedPrincipalDerivation>(JsonSerializer.Serialize(product))!;

        Assert.Equal(1, restored.Lookup(Sid, "FIRST.EXAMPLE")?.SidId);
    }

    [Fact]
    public void MissingSidDoesNotReturnAnotherPrincipal()
    {
        var product = Product(Fact(1, null));

        Assert.Null(product.Lookup("S-1-5-32-545", null));
    }

    private static StoredProtectedPrincipalDerivation Product(params StoredProtectedPrincipalFact[] facts) =>
        new(1, new AdminSdExclusionMask([], HeuristicReadOutcome.DefaultedByAbsence, null),
            [], facts, ProtectionUnknownReason.None);

    private static StoredProtectedPrincipalFact Fact(int id, string? scope) =>
        new(id, Sid, scope, ProtectedPrincipalEvaluation.NotProtected, null,
            ProtectionUnknownReason.None, [], OwnerAcceptance.NotAccepted);
}

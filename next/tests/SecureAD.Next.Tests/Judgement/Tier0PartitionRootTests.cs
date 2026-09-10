using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Covers naming-context roots as Tier-0 seeds, per decision 0117.
/// </summary>
/// <remarks>
/// A partition root holds no SID, so no controller route can reach it. Without this basis a
/// replication grant on a domain root - which is every credential in the domain - would be recorded
/// as not assessed automatically, in every forest, permanently.
/// </remarks>
public sealed class Tier0PartitionRootTests
{
    [Theory]
    [InlineData("domainDNS")]
    [InlineData("configuration")]
    [InlineData("dMD")]
    public void ACapturedPartitionHeadQualifiesWithoutHoldingASid(string objectClass)
    {
        var evidence = new Tier0TestEvidence();
        var root = Root(evidence, "CN=Partition,DC=contoso,DC=com", objectClass);
        var result = Tier0Classifier.Qualify(evidence.Binding,
            Tier0Target.From(root, root.DistinguishedName), evidence.Input(root), routes: null);
        Assert.Equal((Tier0State.Established, Tier0Basis.PartitionRoot),
            (result.State, result.Supports.Single().Basis));
    }

    /// <summary>
    /// The negative control. An ordinary container inside a partition is not its head, and would
    /// otherwise admit most of the directory.
    /// </summary>
    [Fact]
    public void AnObjectInsideAPartitionIsNotItsHead()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("Ordinary", "S-1-5-21-1-2-3-1500", "user");
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        Assert.Equal(Tier0State.Unknown, result.State);
    }

    [Fact]
    public void AHeadWhoseClassDisagreesWithItsContextIsUnverifiedRatherThanASeed()
    {
        var evidence = new Tier0TestEvidence();
        var root = Root(evidence, "CN=Pretender,DC=contoso,DC=com", "container");
        var result = Tier0Classifier.Qualify(evidence.Binding,
            Tier0Target.From(root, root.DistinguishedName), evidence.Input(root), routes: null);
        Assert.Equal((Tier0State.Unknown, true),
            (result.State, result.Coverage.Limitations.HasFlag(Tier0Limitations.IdentityUnverified)));
    }

    [Fact]
    public void TheQualifyingWitnessNamesTheCapturedClass()
    {
        var evidence = new Tier0TestEvidence();
        var root = Root(evidence, "CN=Configuration,DC=contoso,DC=com", "configuration");
        var result = Tier0Classifier.Qualify(evidence.Binding,
            Tier0Target.From(root, root.DistinguishedName), evidence.Input(root), routes: null);
        Assert.Contains(result.Supports.Single().Evidence,
            item => item.Attribute == "objectClass" && item.Value == "configuration");
    }

    /// <summary>
    /// A domain root is both a partition head and, through its own SID, an ordinary captured
    /// identity. The bases stay separate rather than one masking the other.
    /// </summary>
    [Fact]
    public void ADomainHeadQualifiesOnItsOwnBasisWithoutSuppressingOthers()
    {
        var evidence = new Tier0TestEvidence();
        var result = Tier0Classifier.Qualify(evidence.Binding,
            Tier0Target.From(evidence.Domain, evidence.Domain.DistinguishedName), evidence.Input(), routes: null);
        Assert.Contains(result.Supports, support => support.Basis == Tier0Basis.PartitionRoot);
    }

    private static ObjectAttributes Root(Tier0TestEvidence evidence, string dn, string objectClass) =>
        new(dn, Guid.NewGuid(), DateTimeOffset.UnixEpoch, default,
            [Tier0TestEvidence.Attribute("objectClass", "top", objectClass)], "contoso.com");
}

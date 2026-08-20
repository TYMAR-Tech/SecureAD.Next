using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F9 - how much of the forest a run actually read, and the verdict that follows.
///
/// <para>
/// Per <c>0027</c> a partially read domain counts as failed. There is no third state between read
/// and not read, because a domain read in part is a hole of unknown shape, and a hole is what
/// makes a later comparison understate change while looking confident.
/// </para>
/// </summary>
public sealed class RunCoverageTests
{
    private static readonly CoverageId Declared =
        CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com"]);

    [Fact]
    public void ARunThatReadEveryDomainIsComplete()
    {
        var coverage = RunCoverage.Of(Declared,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
        ], BothForestPartitions, NoPolicies);

        Assert.True(coverage.AllDeclaredUnitsAreComplete);
        Assert.Empty(coverage.IncompleteDomains);
    }

    [Fact]
    public void ADomainThatWasNotReadAtAllMakesTheRunIncomplete()
    {
        var coverage = RunCoverage.Of(Declared,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.NotRead("eu.contoso.com", "No controller answered."),
        ], BothForestPartitions, NoPolicies);

        Assert.False(coverage.AllDeclaredUnitsAreComplete);
        Assert.Equal(["eu.contoso.com"], coverage.IncompleteDomains);
    }

    /// <summary>
    /// The owner's ruling of 2026-08-12, and the one most likely to be softened later by someone
    /// who reasons that most of a domain is better than none of it.
    /// </summary>
    [Fact]
    public void ADomainReadOnlyInPartCountsAsFailed()
    {
        var coverage = RunCoverage.Of(Declared,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.PartiallyRead("eu.contoso.com", "The controller stopped answering."),
        ], BothForestPartitions, NoPolicies);

        Assert.False(
            coverage.AllDeclaredUnitsAreComplete,
            "0027 rules that a partially read domain counts as failed. A run holding a hole of "
            + "unknown shape must not be usable as a baseline.");
        Assert.Equal(["eu.contoso.com"], coverage.IncompleteDomains);
    }

    /// <summary>
    /// A refusal has to name the domain and say what happened to it, or the operator is told his
    /// run is unusable and not told what to fix.
    /// </summary>
    [Fact]
    public void AnIncompleteDomainCarriesTheReasonItWasIncomplete()
    {
        var coverage = RunCoverage.Of(Declared,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.NotRead("eu.contoso.com", "No controller answered."),
        ], BothForestPartitions, NoPolicies);

        var domain = coverage.Domains.Single(d => d.DomainFqdn == "eu.contoso.com");

        Assert.Equal("No controller answered.", domain.Reason);
    }

    /// <summary>
    /// A domain read in full has nothing to explain, and a reason attached to it would be a
    /// sentence with no subject.
    /// </summary>
    [Fact]
    public void ADomainReadInFullCarriesNoReason()
    {
        Assert.Null(DomainCoverage.Read("contoso.com").Reason);
    }

    /// <summary>
    /// The declared set comes from the forest and the read outcomes come from capture. If capture
    /// reports on a domain nobody declared, the two disagree about what the forest is, and
    /// deciding which to believe is not this component's business.
    /// </summary>
    [Fact]
    public void ReportingOnADomainThatWasNeverDeclaredIsRefused()
    {
        Assert.Throws<ArgumentException>(() => RunCoverage.Of(Declared,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
            DomainCoverage.Read("us.contoso.com"),
        ], BothForestPartitions, NoPolicies));
    }

    /// <summary>
    /// The dangerous direction. A declared domain with no outcome at all is a domain nobody looked
    /// at, and treating silence as success is the defect this product exists to stop.
    /// </summary>
    [Fact]
    public void ADeclaredDomainWithNoOutcomeIsRefused()
    {
        Assert.Throws<ArgumentException>(
            () => RunCoverage.Of(Declared, [DomainCoverage.Read("contoso.com")], BothForestPartitions, NoPolicies));
    }

    [Fact]
    public void ANullDeclarationIsRefused()
    {
        Assert.Throws<ArgumentNullException>(
            () => RunCoverage.Of(null!, [DomainCoverage.Read("contoso.com")], BothForestPartitions, NoPolicies));
    }

    [Fact]
    public void ANullOutcomeListIsRefused()
    {
        Assert.Throws<ArgumentNullException>(
            () => RunCoverage.Of(Declared, null!, BothForestPartitions, NoPolicies));
    }

    /// <summary>
    /// The forest-wide half of the same rule, per <c>0035</c>. The configuration and schema
    /// partitions belong to no domain, so before they had a home a run that never read one still
    /// reported every domain as covered - and per <c>0014</c> an unread schema partition is the
    /// failure that stops any permission being resolved at all.
    /// </summary>
    [Fact]
    public void AForestPartitionThatWasNotReadMakesTheRunIncomplete()
    {
        var coverage = RunCoverage.Of(
            Declared,
            [DomainCoverage.Read("contoso.com"), DomainCoverage.Read("eu.contoso.com")],
            [
                ForestPartitionCoverage.Read(ConfigurationDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.NotRead(SchemaDn, NamingContextKind.Schema, "The controller refused it."),
            ],
            NoPolicies);

        Assert.False(
            coverage.AllDeclaredUnitsAreComplete,
            "Every domain was read, so a run that only counted domains would report this as "
            + "complete. The schema partition was not read and the run is not usable.");
        Assert.Equal(["Schema"], coverage.UnreadForestPartitions);
        Assert.Empty(coverage.IncompleteDomains);
    }

    /// <summary>
    /// The dangerous direction again, one level up. A forest-wide partition with no outcome is a
    /// partition nobody looked at, and unlike a domain there is no discovery step to notice it
    /// missing - every forest has exactly one of each, so the denominator is known here.
    /// </summary>
    [Theory]
    [InlineData(NamingContextKind.Configuration)]
    [InlineData(NamingContextKind.Schema)]
    public void AForestPartitionWithNoOutcomeIsRefused(NamingContextKind omitted)
    {
        var reported = BothForestPartitions.Where(p => p.Kind != omitted).ToArray();

        Assert.Throws<ArgumentException>(() => RunCoverage.Of(
            Declared,
            [DomainCoverage.Read("contoso.com"), DomainCoverage.Read("eu.contoso.com")],
            reported,
            NoPolicies));
    }

    /// <summary>
    /// A domain partition has a domain to be reported against. Accepting one here would describe
    /// one naming context in two coverage models, which is the disagreement <c>0035</c> ended.
    /// </summary>
    [Fact]
    public void ADomainPartitionIsNotAForestWideFact()
    {
        Assert.Throws<ArgumentException>(
            () => ForestPartitionCoverage.Read("DC=contoso,DC=com", NamingContextKind.Domain));
    }

    /// <summary>A forest-wide partition that was read has nothing to explain.</summary>
    [Fact]
    public void AForestPartitionReadInFullCarriesNoReason()
    {
        Assert.Null(
            ForestPartitionCoverage.Read(SchemaDn, NamingContextKind.Schema).Reason);
    }

    private const string ConfigurationDn = "CN=Configuration,DC=contoso,DC=com";

    private const string SchemaDn = "CN=Schema,CN=Configuration,DC=contoso,DC=com";

    /// <summary>
    /// Both forest-wide partitions read, which is the ordinary case a test not about them wants.
    /// </summary>
    private static readonly ForestPartitionCoverage[] BothForestPartitions =
    [
        ForestPartitionCoverage.Read(ConfigurationDn, NamingContextKind.Configuration),
        ForestPartitionCoverage.Read(SchemaDn, NamingContextKind.Schema),
    ];

    /// <summary>
    /// A forest that declared no Group Policy at all, which is what a test not about SYSVOL wants.
    /// </summary>
    /// <remarks>
    /// Empty rather than absent. Per <c>0044</c> the SYSVOL record is required and has no overload
    /// that omits it, because a run that never attempted the share must not pass as one that had
    /// nothing to report.
    /// </remarks>
    private static readonly SysvolCoverage NoPolicies = SysvolCoverage.Of([]);

    /// <summary>
    /// Every outcome must be reachable, or the vocabulary is describing states nothing produces -
    /// which is the failure that stopped this session twice.
    /// </summary>
    [Fact]
    public void EveryReadOutcomeIsProducible()
    {
        Assert.Equal(DomainReadOutcome.Read, DomainCoverage.Read("a.com").Outcome);
        Assert.Equal(DomainReadOutcome.PartiallyRead, DomainCoverage.PartiallyRead("a.com", "why").Outcome);
        Assert.Equal(DomainReadOutcome.NotRead, DomainCoverage.NotRead("a.com", "why").Outcome);
        Assert.Equal(
            DomainReadOutcome.ExcludedByChoice,
            DomainCoverage.Excluded("a.com", ExclusionKind.ByChoice, "why").Outcome);
        Assert.Equal(
            DomainReadOutcome.ExcludedForWantOfCandidates,
            DomainCoverage.Excluded("a.com", ExclusionKind.ForWantOfCandidates, "why").Outcome);
        Assert.Equal(5, Enum.GetValues<DomainReadOutcome>().Length);
    }

    /// <summary>
    /// A domain left out by choice never records the same outcome as one nothing could reach.
    /// </summary>
    /// <remarks>
    /// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> holds the distinction
    /// wherever either appears, and names the run's own record of what it covered explicitly. A
    /// reader of coverage must tell them apart without going back to another table, so the cause
    /// lives in the outcome rather than in the reason text.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainNeverRecordsTheSameOutcomeAsAnUnreachableOne()
    {
        var byChoice = DomainCoverage.Excluded("a.com", ExclusionKind.ByChoice, "why");
        var noCandidates = DomainCoverage.Excluded(
            "a.com", ExclusionKind.ForWantOfCandidates, "why");
        var unreachable = DomainCoverage.NotRead("a.com", "why");

        Assert.NotEqual(byChoice.Outcome, unreachable.Outcome);
        Assert.NotEqual(noCandidates.Outcome, unreachable.Outcome);
        Assert.NotEqual(byChoice.Outcome, noCandidates.Outcome);
    }

    /// <summary>
    /// An excluded domain is not counted as covered.
    /// </summary>
    /// <remarks>
    /// A run that left a domain out did not read the whole forest, and a bundle claiming otherwise
    /// would be <c>F-S28-1</c> arriving by the front door.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainDoesNotCountAsCovered()
    {
        var coverage = RunCoverage.Of(
            CoverageId.ForDomains("example.com", ["a.com"]),
            [DomainCoverage.Excluded("a.com", ExclusionKind.ByChoice, "outside remit")],
            BothForestPartitions,
            NoPolicies);

        Assert.False(coverage.AllDeclaredUnitsAreComplete);
        Assert.Single(coverage.IncompleteDomains);
    }

    /// <summary>
    /// An incomplete domain that could not say why would produce a refusal message with a blank
    /// where its cause belongs.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnIncompleteDomainWithoutAReasonIsRefused(string reason)
    {
        Assert.Throws<ArgumentException>(() => DomainCoverage.NotRead("a.com", reason));
        Assert.Throws<ArgumentException>(() => DomainCoverage.PartiallyRead("a.com", reason));
    }
}

using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F2 - the run's evidence identity. Coverage answers <i>same evidence</i>: which domains the
/// forest reported when the run started.
///
/// <para>
/// It is kept apart from <see cref="ProfileId"/> because the two are not recoverable the same way.
/// A profile is a pure function of the forest name and can be recomputed for a bundle whose
/// metadata is missing; a coverage identity can only be read back from where the run recorded it.
/// Folding them together would force a half-populated value at exactly the sites that recompute
/// the profile, which is how a wrong key comes to group runs that must not be compared.
/// </para>
/// <para>
/// The predecessor also hashed a list of operator-chosen OU exclusions. There is no such list:
/// <c>0017</c> removed operator-configurable exclusion and capture reads the whole forest.
/// <see cref="NothingCarriesExclusionsAnyMore"/> holds that.
/// </para>
/// </summary>
public sealed class CoverageIdTests
{
    private static readonly string[] TwoDomains = ["contoso.com", "eu.contoso.com"];

    [Fact]
    public void TheSameDomainsAlwaysProduceTheSameCoverage()
    {
        Assert.Equal(
            CoverageId.ForDomains("contoso.com", TwoDomains).Value,
            CoverageId.ForDomains("contoso.com", TwoDomains).Value);
    }

    /// <summary>
    /// A forest that gained or lost a domain is a different evidence set, and that difference is
    /// what <c>0027</c> state 6 reports as a qualified comparison. If it did not change the value,
    /// the state could never fire.
    /// </summary>
    [Fact]
    public void AddingADomainChangesTheCoverage()
    {
        Assert.NotEqual(
            CoverageId.ForDomains("contoso.com", TwoDomains).Value,
            CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com", "us.contoso.com"]).Value);
    }

    /// <summary>
    /// The order domains come back from discovery is not a fact about the forest, so it must not
    /// reach the identity. Two runs of an unchanged forest that enumerated its domains in a
    /// different order are the same evidence.
    /// </summary>
    [Fact]
    public void TheOrderDomainsWereDiscoveredInDoesNotMatter()
    {
        Assert.Equal(
            CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com"]).Value,
            CoverageId.ForDomains("contoso.com", ["eu.contoso.com", "contoso.com"]).Value);
    }

    [Fact]
    public void CaseDoesNotChangeTheCoverage()
    {
        Assert.Equal(
            CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com"]).Value,
            CoverageId.ForDomains("CONTOSO.com", ["Contoso.COM", "EU.Contoso.com"]).Value);
    }

    /// <summary>
    /// A domain named twice by discovery is one domain. Left in, it would make a run incomparable
    /// with an identical one that happened not to repeat itself.
    /// </summary>
    [Fact]
    public void ADomainNamedTwiceCountsOnce()
    {
        Assert.Equal(
            CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com"]).Value,
            CoverageId.ForDomains("contoso.com", ["contoso.com", "eu.contoso.com", "contoso.com"]).Value);
    }

    /// <summary>
    /// The forest is part of the evidence identity as well as of the profile. Two different
    /// forests could in principle report domain sets that normalise alike, and a bundle copied in
    /// by hand is exactly the case <c>0025</c> keeps the forest key for.
    /// </summary>
    [Fact]
    public void TheForestIsPartOfTheCoverage()
    {
        Assert.NotEqual(
            CoverageId.ForDomains("contoso.com", ["shared.example"]).Value,
            CoverageId.ForDomains("fabrikam.com", ["shared.example"]).Value);
    }

    /// <summary>
    /// The set that was hashed is kept, so a refusal can name the domains rather than showing an
    /// operator two hashes that differ.
    ///
    /// <para>
    /// Asserted through <c>RunCoverage</c> because the list itself is internal: gate 4 forbids a
    /// public collection on a type that cannot say whether it looked, and rather than widen that
    /// gate's allowlist for a new reason, the list stays inside the assembly and callers read it
    /// from the type that carries <c>IsComplete</c> beside it.
    /// </para>
    /// </summary>
    [Fact]
    public void TheDomainsAreKeptNormalisedSoARefusalCanNameThem()
    {
        var coverage = CoverageId.ForDomains("contoso.com", ["EU.Contoso.com", "contoso.COM"]);

        var read = RunCoverage.Of(coverage,
        [
            DomainCoverage.Read("contoso.com"),
            DomainCoverage.Read("eu.contoso.com"),
        ], BothForestPartitions, SysvolCoverage.Of([]));

        Assert.Equal(
            ["contoso.com", "eu.contoso.com"],
            read.Domains.Select(d => d.DomainFqdn));
    }

    /// <summary>
    /// Both forest-wide partitions read. This test is about domain normalisation, so the
    /// forest-wide half is the ordinary case.
    /// </summary>
    private static readonly ForestPartitionCoverage[] BothForestPartitions =
    [
        ForestPartitionCoverage.Read(
            "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
        ForestPartitionCoverage.Read(
            "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
    ];

    [Fact]
    public void TheValueIsSixteenLowercaseHexCharacters()
    {
        var value = CoverageId.ForDomains("contoso.com", TwoDomains).Value;

        Assert.Equal(16, value.Length);
        Assert.All(value, c => Assert.True(
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
            $"'{c}' is not lowercase hex."));
    }

    /// <summary>
    /// A run that declared no domains assessed nothing, and an identity for it would be a key that
    /// silently groups every such run together as comparable.
    /// </summary>
    [Fact]
    public void ARunThatDeclaredNoDomainsIsRefused()
    {
        Assert.Throws<ArgumentException>(() => CoverageId.ForDomains("contoso.com", []));
    }

    [Fact]
    public void ADomainThatIsBlankIsRefused()
    {
        Assert.Throws<ArgumentException>(
            () => CoverageId.ForDomains("contoso.com", ["contoso.com", "  "]));
    }

    [Fact]
    public void ANullDomainListIsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => CoverageId.ForDomains("contoso.com", null!));
    }

    /// <summary>
    /// The predecessor's coverage identity hashed operator-chosen OU exclusions alongside the
    /// domains, and decision <c>0025</c> and the first draft of <c>0026</c> were both reasoned on
    /// the attestation ladder that governed them. <c>0017</c> had already removed all of it.
    ///
    /// <para>
    /// This is asserted by reflection rather than trusted, in the manner the predecessor's own
    /// <c>ProfileIdTests</c> used to prove a deleted factory stayed deleted. A member reappearing
    /// here would mean the exclusion model had come back without a decision behind it.
    /// </para>
    /// </summary>
    [Fact]
    public void NothingCarriesExclusionsAnyMore()
    {
        var offenders = typeof(CoverageId)
            .GetMembers()
            .Select(m => m.Name)
            .Where(n => n.Contains("Exclu", StringComparison.OrdinalIgnoreCase)
                || n.Contains("Attest", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            $"CoverageId names {string.Join(", ", offenders)}. Capture reads the whole forest per "
            + "0017, so there is nothing to exclude and nothing to attest.");
    }
}

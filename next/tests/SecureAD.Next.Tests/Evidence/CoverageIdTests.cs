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
/// <c>0052</c> reads everything below a domain whole, so there is nothing smaller than a domain to
/// leave out. A whole domain can be left out, and
/// <see cref="LeavingOutADifferentDomainIsDifferentEvidence"/> holds that it reaches the identity.
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
    /// The owner's question, as a test: a three domain forest audited with different domains left
    /// out produces one group per combination, and two runs of the same combination land together.
    ///
    /// <para>
    /// Written from his own example - <c>ad</c>, <c>ba</c> and <c>sf</c>. Group one is all three,
    /// group two is <c>ad</c> and <c>ba</c>, group three is <c>ad</c> and <c>sf</c>. The second
    /// assertion is the one that matters most: a later run of group two must join that group rather
    /// than start a fourth, or every run would sit alone and nothing would ever be comparable.
    /// </para>
    /// </summary>
    [Fact]
    public void RunsGroupByWhichDomainsTheyCovered()
    {
        string[] forest = ["ad.lab", "ba.ad.lab", "sf.ad.lab"];

        var allThree = CoverageId.ForDomains("ad.lab", forest).Value;
        var adAndBa = CoverageId.ForDomainsExcluding("ad.lab", forest, ["sf.ad.lab"]).Value;
        var adAndSf = CoverageId.ForDomainsExcluding("ad.lab", forest, ["ba.ad.lab"]).Value;

        Assert.Equal(
            3,
            new[] { allThree, adAndBa, adAndSf }.Distinct(StringComparer.Ordinal).Count());

        var adAndBaAWeekLater =
            CoverageId.ForDomainsExcluding("ad.lab", forest, ["sf.ad.lab"]).Value;

        Assert.Equal(adAndBa, adAndBaAWeekLater);
    }

    /// <summary>
    /// Two runs of one forest that left out <i>different</i> domains are not the same evidence.
    ///
    /// <para>
    /// This test replaced <c>NothingCarriesExclusionsAnyMore</c> on 2026-08-21, which asserted by
    /// reflection that <c>CoverageId</c> named nothing to do with exclusion, on the authority of
    /// <c>0017</c> - capture reads the whole forest, so there is nothing to exclude. <c>0052</c>
    /// reintroduced whole-domain exclusion and <c>CoverageId</c>'s own remarks recorded the gap,
    /// but the guard was never re-anchored. It therefore passed for as long as the product could
    /// not produce an exclusion, and would have failed the build the moment the fix <c>0052</c>
    /// requires was written - a check holding the product to a premise that had been withdrawn.
    /// </para>
    /// <para>
    /// The case it now covers is the one an operator hits: an eight domain forest audited twice,
    /// each run leaving out a different domain. Before the fix both declared all eight, hashed
    /// alike, and were offered as comparable.
    /// </para>
    /// </summary>
    [Fact]
    public void LeavingOutADifferentDomainIsDifferentEvidence()
    {
        var withoutEu = CoverageId.ForDomainsExcluding(
            "contoso.com", ["contoso.com", "eu.contoso.com", "us.contoso.com"], ["eu.contoso.com"]);

        var withoutUs = CoverageId.ForDomainsExcluding(
            "contoso.com", ["contoso.com", "eu.contoso.com", "us.contoso.com"], ["us.contoso.com"]);

        Assert.NotEqual(withoutEu.Value, withoutUs.Value);
    }

    /// <summary>
    /// A run that left a domain out is not the same evidence as one that read the whole forest,
    /// even though both declared the same domains. This is the pairing <c>0052</c> names.
    /// </summary>
    [Fact]
    public void LeavingADomainOutIsNotTheSameAsReadingTheWholeForest()
    {
        Assert.NotEqual(
            CoverageId.ForDomains("contoso.com", TwoDomains).Value,
            CoverageId.ForDomainsExcluding("contoso.com", TwoDomains, ["eu.contoso.com"]).Value);
    }

    /// <summary>
    /// A forest that genuinely has two domains, and a three domain forest with one left out, cover
    /// the same ground and are still not the same evidence. Hashing only the remainder would merge
    /// them, and a comparison across the pair would read a whole domain's absence as no change.
    /// </summary>
    [Fact]
    public void AForestThatShrankIsNotAForestWithADomainLeftOut()
    {
        Assert.NotEqual(
            CoverageId.ForDomains("contoso.com", TwoDomains).Value,
            CoverageId.ForDomainsExcluding(
                "contoso.com",
                ["contoso.com", "eu.contoso.com", "us.contoso.com"],
                ["us.contoso.com"]).Value);
    }

    /// <summary>
    /// The order and case exclusions arrive in are not facts about the forest, for the same reason
    /// they are not for the declared set.
    /// </summary>
    [Fact]
    public void TheOrderAndCaseOfExclusionsDoesNotMatter()
    {
        var domains = new[] { "contoso.com", "eu.contoso.com", "us.contoso.com" };

        Assert.Equal(
            CoverageId.ForDomainsExcluding(
                "contoso.com", domains, ["eu.contoso.com", "us.contoso.com"]).Value,
            CoverageId.ForDomainsExcluding(
                "contoso.com", domains, ["US.Contoso.com", "EU.CONTOSO.COM"]).Value);
    }

    /// <summary>
    /// Excluding nothing is the whole-forest case, so it must not differ from asking for it
    /// directly. Were these to diverge, every run would carry an identity that depended on which
    /// factory its caller happened to use.
    /// </summary>
    [Fact]
    public void ExcludingNothingIsTheWholeForest()
    {
        Assert.Equal(
            CoverageId.ForDomains("contoso.com", TwoDomains).Value,
            CoverageId.ForDomainsExcluding("contoso.com", TwoDomains, []).Value);
    }

    /// <summary>
    /// A run cannot leave out a domain the forest never reported. Ignoring it would produce an
    /// identity that silently matches a run of different scope, which is the one failure this type
    /// exists to prevent.
    /// </summary>
    [Fact]
    public void ExcludingADomainTheForestDidNotDeclareIsRefused()
    {
        Assert.Throws<ArgumentException>(
            () => CoverageId.ForDomainsExcluding(
                "contoso.com", TwoDomains, ["us.contoso.com"]));
    }

    [Fact]
    public void ABlankExclusionIsRefused()
    {
        Assert.Throws<ArgumentException>(
            () => CoverageId.ForDomainsExcluding("contoso.com", TwoDomains, ["  "]));
    }

    [Fact]
    public void ANullExclusionListIsRefused()
    {
        Assert.Throws<ArgumentNullException>(
            () => CoverageId.ForDomainsExcluding("contoso.com", TwoDomains, null!));
    }
}

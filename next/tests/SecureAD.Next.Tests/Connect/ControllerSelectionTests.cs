using SecureAD.Audit.Connect;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Choosing which controller each domain is read from, and ordering the rest as that domain's
/// failover list.
///
/// <para>
/// Every one of these runs without a directory, which is the point of keeping the ranking apart
/// from the reads that feed it. What is exercised here is the order of the rules, because that
/// order is the whole of the behaviour: a rule applied in the wrong place still produces exactly
/// one host name, and nothing about the answer says it was the wrong one.
/// </para>
/// </summary>
public sealed class ControllerSelectionTests
{
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Schema = "CN=Schema," + Configuration;
    private const string Sites = "CN=Sites," + Configuration;
    private const string Root = "DC=example,DC=com";
    private const string Other = "DC=other,DC=example,DC=com";

    /// <summary>
    /// A wide-area read of a large domain is the difference between an audit that finishes in an
    /// evening and one that does not, so site beats every other consideration.
    /// </summary>
    [Fact]
    public async Task AControllerInTheOperatorSiteIsPinnedOverALexicallyEarlierOne()
    {
        var selection = await SelectAsync(
            operatorSite: "Oslo",
            controllers: [("DC1", "London"), ("DC2", "Oslo")]);

        Assert.Equal("dc2.example.com", Domain(selection).PinnedController);
        Assert.True(Domain(selection).IsInOperatorSite);
    }

    /// <summary>
    /// The reason the FSMO rule exists: the PDC emulator carries password changes, lockouts and
    /// time for the whole domain, and an hours-long read is the worst thing to point at it.
    /// </summary>
    [Fact]
    public async Task AnEstablishedRoleHolderIsRankedBelowAControllerHoldingNoRole()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London"), ("DC2", "London")],
            pdcEmulator: "DC1",
            establishPdc: true);

        Assert.Equal("dc2.example.com", Domain(selection).PinnedController);
    }

    /// <summary>
    /// Site outranks role. A role holder nearby is still a better answer than a wide-area read.
    /// </summary>
    [Fact]
    public async Task SiteOutranksHoldingARole()
    {
        var selection = await SelectAsync(
            operatorSite: "Oslo",
            controllers: [("DC1", "London"), ("DC2", "Oslo")],
            pdcEmulator: "DC2",
            establishPdc: true);

        Assert.Equal("dc2.example.com", Domain(selection).PinnedController);
    }

    /// <summary>
    /// Lexical order last, so the same candidate set always produces the same choice and two runs a
    /// week apart pick the same controller unless the forest changed.
    /// </summary>
    [Fact]
    public async Task EqualCandidatesAreOrderedLexicallyByHostName()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC3", "London"), ("DC1", "London"), ("DC2", "London")]);

        Assert.Equal("dc1.example.com", Domain(selection).PinnedController);
        Assert.Equal(["dc2.example.com", "dc3.example.com"], Domain(selection).Failover);
    }

    /// <summary>
    /// A machine matching no subnet has no site preference, and ranking falls back to lexical order
    /// rather than treating every controller as local.
    /// </summary>
    [Fact]
    public async Task ARunWithNoSiteHasNoSitePreference()
    {
        var selection = await SelectAsync(
            operatorSite: null,
            controllers: [("DC2", "Oslo"), ("DC1", "London")]);

        Assert.Equal("dc1.example.com", Domain(selection).PinnedController);
        Assert.False(Domain(selection).IsInOperatorSite);
        Assert.Null(selection.Value!.OperatorSite);
    }

    /// <summary>
    /// The failover list is what <c>0040</c> walks when a read fails. It is the rest of the ranked
    /// candidates, so the second choice is the best of what is left rather than the next name.
    /// </summary>
    [Fact]
    public async Task TheFailoverListIsTheRestOfTheRankingInOrder()
    {
        var selection = await SelectAsync(
            operatorSite: "Oslo",
            controllers: [("DC1", "London"), ("DC2", "Oslo"), ("DC3", "London")]);

        Assert.Equal("dc2.example.com", Domain(selection).PinnedController);
        Assert.Equal(["dc1.example.com", "dc3.example.com"], Domain(selection).Failover);
    }

    /// <summary>
    /// An operator naming a controller gets that controller, and the ranking still supplies the
    /// order of what to fall back to.
    /// </summary>
    [Fact]
    public async Task AnOverrideIsObeyedAndTheRestRemainAsFailover()
    {
        var selection = await SelectAsync(
            operatorSite: "Oslo",
            controllers: [("DC1", "London"), ("DC2", "Oslo")],
            overrides: new Dictionary<string, string> { [Root] = "dc1.example.com" });

        Assert.Equal("dc1.example.com", Domain(selection).PinnedController);
        Assert.True(Domain(selection).WasOverridden);
        Assert.Equal(["dc2.example.com"], Domain(selection).Failover);
    }

    /// <summary>
    /// The predecessor fell back silently, so a mistyped host name produced a successful run against
    /// a controller the operator did not name, with nothing recording the substitution.
    /// </summary>
    [Fact]
    public async Task AnOverrideThatIsNotACandidateStopsTheRun()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            overrides: new Dictionary<string, string> { [Root] = "dc9.example.com" });

        Assert.False(selection.IsSuccess);
        Assert.Equal("Capture.OverriddenControllerIsNotACandidate", selection.Error!.Code);
    }

    /// <summary>
    /// And it never quietly becomes the automatic choice instead. The run stops holding no selection
    /// at all, and the refusal names both what was asked for and what it would otherwise have
    /// chosen, so the substitution that did not happen is visible in the words.
    /// </summary>
    [Fact]
    public async Task AnOverrideThatIsNotACandidateNeverFallsBack()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            overrides: new Dictionary<string, string> { [Root] = "dc9.example.com" });

        Assert.Throws<InvalidOperationException>(() => selection.Value);
        Assert.Contains("dc9.example.com", selection.Error!.Description);
        Assert.Contains("dc1.example.com", selection.Error!.Description);
    }

    /// <summary>
    /// A domain the forest names no writable controller for is a fact about the forest, not a fault
    /// of the run. It is recorded and left for an attestation rather than planned against.
    /// </summary>
    [Fact]
    public async Task ADomainWithNoCandidatesIsRecordedRatherThanPlannedAgainst()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            domains: [Root, "DC=orphan,DC=example,DC=com"]);

        Assert.Equal("DC=orphan,DC=example,DC=com", Assert.Single(selection.Value!.DomainsWithNoCandidates));
        Assert.Equal(Root, Assert.Single(selection.Value!.Domains).NamingContext);
        Assert.False(selection.Value!.IsComplete);
    }

    /// <summary>
    /// The failure this exists to prevent, stated as a property of the answer: a domain ranked
    /// without knowing which of its controllers is the PDC emulator may well have pinned it, and the
    /// selection says so rather than presenting the choice as fully informed.
    /// </summary>
    [Fact]
    public async Task ADomainRankedWithoutItsPdcEmulatorIsNotComplete()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")]);

        Assert.False(Domain(selection).IsComplete);
        Assert.False(selection.Value!.IsComplete);
    }

    /// <summary>
    /// And a domain ranked on every input says that too, so the two are distinguishable.
    /// </summary>
    [Fact]
    public async Task ADomainRankedOnEveryInputIsComplete()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            pdcEmulator: "DC1",
            establishPdc: true);

        Assert.True(Domain(selection).IsComplete);
        Assert.True(selection.Value!.IsComplete);
    }

    /// <summary>
    /// A controller that does not hold a writable replica of the domain is not a candidate for it,
    /// which is what keeps a read-only controller out without any capability probe.
    /// </summary>
    [Fact]
    public async Task OnlyControllersHoldingTheDomainAreCandidates()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            otherDomainControllers: [("DC2", "London")]);

        Assert.Equal("dc1.example.com", Domain(selection).PinnedController);
        Assert.Empty(Domain(selection).Failover);
    }

    /// <summary>
    /// Two domains are never read from the same machine, because a controller holds a writable
    /// replica of exactly one domain and that is the whole of the eligibility test.
    /// </summary>
    /// <remarks>
    /// This is what lets preflight ask several domains at once: the rule
    /// <c>SerializedDirectoryAccessGateTests</c> holds is that no controller sees two requests at
    /// once, and domains on disjoint controllers cannot breach it. That gate says in its own words
    /// that it cannot prove this, and that the obligation belongs to whatever assigns controllers
    /// to naming contexts. This is that proof.
    /// </remarks>
    [Fact]
    public async Task TwoDomainsAreNeverPinnedToTheSameController()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            otherDomainControllers: [("DC2", "London")],
            domains: [Root, Other]);

        var pinned = selection.Value!.Domains.Select(domain => domain.PinnedController).ToList();

        Assert.Equal(["dc1.example.com", "dc2.example.com"], pinned.Order());
        Assert.Equal(pinned.Count, pinned.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    /// <summary>
    /// The control for the test above, and the reason a caller may not treat disjoint controllers
    /// as guaranteed: selection pins whatever the forest says holds the domain, so a controller
    /// declaring two domains is pinned for both.
    /// </summary>
    /// <remarks>
    /// Active Directory does not produce this, which is why the test above passes against every
    /// real forest. It is asserted rather than assumed because the difference matters to anything
    /// running domains concurrently: the disjointness is a property of the input, not a rule this
    /// code enforces, so a dispatcher must not rely on selection to keep two requests off one
    /// machine.
    /// </remarks>
    [Fact]
    public async Task AControllerDeclaringTwoDomainsIsPinnedForBoth()
    {
        var selection = await SelectAsync(
            operatorSite: "London",
            controllers: [("DC1", "London")],
            domains: [Root, Other],
            alsoHeldByFirstController: Other);

        var pinned = selection.Value!.Domains.Select(domain => domain.PinnedController).ToList();

        Assert.Equal(["dc1.example.com", "dc1.example.com"], pinned);
    }

    private static DomainSelection Domain(Result<ControllerSelection> selection) =>
        Assert.Single(selection.Value!.Domains);

    private static string SettingsDn(string host, string site) =>
        "CN=NTDS Settings,CN=" + host + ",CN=Servers,CN=" + site + "," + Sites;

    private static async Task<Result<ControllerSelection>> SelectAsync(
        string? operatorSite,
        (string Host, string Site)[] controllers,
        string? pdcEmulator = null,
        bool establishPdc = false,
        IReadOnlyDictionary<string, string>? overrides = null,
        string[]? domains = null,
        (string Host, string Site)[]? otherDomainControllers = null,
        string? alsoHeldByFirstController = null)
    {
        var model = new ControllerModel();
        model.AddObject(Schema);
        model.AddObject("CN=Partitions," + Configuration);
        model.AddObject(
            Root,
            pdcEmulator is null
                ? []
                : [("fSMORoleOwner", (object[])[SettingsDn(
                    pdcEmulator,
                    controllers.Single(c => c.Host == pdcEmulator).Site)])]);

        for (var i = 0; i < controllers.Length; i++)
        {
            var (host, site) = controllers[i];

            AddController(
                model,
                host,
                site,
                i == 0 && alsoHeldByFirstController is not null
                    ? [Root, alsoHeldByFirstController]
                    : [Root]);
        }

        foreach (var (host, site) in otherDomainControllers ?? [])
        {
            AddController(model, host, site, [Other]);
        }

        using var channel = model.Connections().Connect("dc1.example.com").Value!;

        var topology = await ForestTopology.ReadAsync(
            channel, Configuration, CancellationToken.None);

        var roles = await ForestRoles.ReadAsync(
            channel, Configuration, Schema, topology.Value!, [Root], CancellationToken.None);

        var withPdc = establishPdc
            ? roles.Value!.With(await ForestRoles.EstablishPdcEmulatorAsync(
                channel, Root, topology.Value!, CancellationToken.None))
            : roles.Value!;

        return ControllerSelection.For(
            topology.Value!,
            withPdc,
            operatorSite,
            domains ?? [Root],
            overrides ?? new Dictionary<string, string>());
    }

    private static void AddController(
        ControllerModel model, string host, string site, string[] namingContexts)
    {
        model.AddObject(
            "CN=" + host + ",CN=Servers,CN=" + site + "," + Sites,
            ("dNSHostName", [host.ToLowerInvariant() + ".example.com"]));
        model.AddObject(
            SettingsDn(host, site),
            ("msDS-hasMasterNCs", namingContexts));
    }
}

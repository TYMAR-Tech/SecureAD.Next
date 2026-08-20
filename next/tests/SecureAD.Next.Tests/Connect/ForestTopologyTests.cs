using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Reading the forest's physical topology - every controller, its site, and the domains it holds a
/// writable replica of - from one connection to the configuration partition.
///
/// <para>
/// Before this, a domain was read from whichever machine DNS returned for the domain's name. There
/// was no candidate list, no site affinity, and no way to tell a read-only controller from a
/// writable one, which is what
/// <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c> exists to
/// replace.
/// </para>
/// </summary>
public sealed class ForestTopologyTests
{
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Sites = "CN=Sites," + Configuration;
    private const string Subnets = "CN=Subnets," + Sites;

    [Fact]
    public async Task EveryWritableControllerTheForestDeclaresIsACandidate()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        AddDomainController(controller, "DC2", "Oslo", "DC=example,DC=com");

        var topology = await ReadAsync(controller);

        Assert.True(topology.IsSuccess);
        Assert.Equal(
            ["dc1.example.com", "dc2.example.com"],
            topology.Value!.Controllers.Select(c => c.HostName).OrderBy(h => h, StringComparer.Ordinal));
    }

    /// <summary>
    /// The site is not an attribute of a controller. It is the great-grandparent container of the
    /// controller's own settings object, so the depth of the walk is the whole of the answer -
    /// counting wrong yields a plausible-looking wrong site rather than an error.
    /// </summary>
    [Fact]
    public async Task AControllerSiteIsTheGreatGrandparentOfItsSettingsObject()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");

        var topology = await ReadAsync(controller);

        Assert.Equal("London", Assert.Single(topology.Value!.Controllers).Site);
    }

    /// <summary>
    /// A read-only controller declares its domains in <c>msDS-hasFullReplicaNCs</c>, never in
    /// <c>msDS-hasMasterNCs</c>. Reading only the latter means it cannot enter a candidate list,
    /// so there is no capability probe to forget to run.
    /// </summary>
    [Fact]
    public async Task AReadOnlyControllerIsNeverACandidate()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        AddServer(controller, "RODC1", "Branch");
        controller.AddObject(
            SettingsDn("RODC1", "Branch"),
            ("msDS-hasFullReplicaNCs", ["DC=example,DC=com"]));

        var topology = await ReadAsync(controller);

        Assert.Equal("dc1.example.com", Assert.Single(topology.Value!.Controllers).HostName);
    }

    /// <summary>
    /// A controller the forest names but gives no host name for cannot be connected to. Dropping it
    /// silently would shorten a candidate list with nothing recording why, which is the absence
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids being read as a fact.
    /// </summary>
    [Fact]
    public async Task AControllerWithNoHostNameIsRecordedRatherThanDropped()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        controller.AddObject(
            SettingsDn("DC2", "London"),
            ("msDS-hasMasterNCs", ["DC=example,DC=com"]));

        var topology = await ReadAsync(controller);

        Assert.Equal("dc1.example.com", Assert.Single(topology.Value!.Controllers).HostName);
        Assert.Equal(
            SettingsDn("DC2", "London"),
            Assert.Single(topology.Value!.ControllersWithNoHostName));
    }

    /// <summary>
    /// Every domain a controller holds writably is kept, because a controller is a candidate for
    /// each of them separately. A global catalogue holding one domain and the forest root is one
    /// machine on two candidate lists.
    /// </summary>
    [Fact]
    public async Task AControllerHoldingSeveralDomainsIsACandidateForEach()
    {
        var controller = new ControllerModel();
        AddDomainController(
            controller, "DC1", "London", "DC=example,DC=com", "DC=east,DC=example,DC=com");

        var topology = await ReadAsync(controller);

        Assert.Equal(
            ["DC=east,DC=example,DC=com", "DC=example,DC=com"],
            Assert.Single(topology.Value!.Controllers)
                .WritableNamingContexts.OrderBy(n => n, StringComparer.Ordinal));
    }

    [Fact]
    public async Task SubnetsAreReadWithTheSiteEachBelongsTo()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        AddSubnet(controller, "10.20.0.0/16", "London");
        AddSubnet(controller, "10.30.0.0/16", "Oslo");

        var topology = await ReadAsync(controller);

        Assert.Equal(
            [("10.20.0.0/16", "London"), ("10.30.0.0/16", "Oslo")],
            topology.Value!.Subnets
                .Select(s => (s.Prefix, s.Site))
                .OrderBy(s => s.Prefix, StringComparer.Ordinal));
    }

    /// <summary>
    /// A forest may declare a range and never assign it. It cannot contribute a site preference,
    /// and it is not a fault of the run.
    /// </summary>
    [Fact]
    public async Task ASubnetWithNoSiteIsLeftOutRatherThanFailingTheRead()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        controller.AddObject("CN=10.40.0.0/16," + Subnets);

        var topology = await ReadAsync(controller);

        Assert.True(topology.IsSuccess);
        Assert.Empty(topology.Value!.Subnets);
    }

    /// <summary>
    /// A forest with more controllers than one page holds must yield all of them. A read that
    /// stopped at the first page would shorten every candidate list in a large forest, which is
    /// exactly where a chosen controller matters most.
    /// </summary>
    [Fact]
    public async Task EveryPageOfControllersIsRead()
    {
        var controller = new ControllerModel();

        for (var i = 0; i < ServerLimits.PageSize + 25; i++)
        {
            AddDomainController(controller, "DC" + i, "London", "DC=example,DC=com");
        }

        var topology = await ReadAsync(controller);

        Assert.Equal(ServerLimits.PageSize + 25, topology.Value!.Controllers.Count);
    }

    /// <summary>
    /// A controller that answers without the paging control has not said whether there is more to
    /// send. Treating that as the end is how part of a forest becomes the whole of it.
    /// </summary>
    [Fact]
    public async Task AnAnswerThatCannotSayItWasTheLastOneIsRefused()
    {
        var controller = new ControllerModel { AnswerWithoutThePagingControl = true };
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");

        var topology = await ReadAsync(controller);

        Assert.False(topology.IsSuccess);
        Assert.Equal("Capture.SiteTopologyCouldNotBeRead", topology.Error!.Code);
    }

    /// <summary>
    /// A sites container naming no writable controller at all cannot be right - the controller that
    /// answered is itself one - so it is refused rather than planned against.
    /// </summary>
    [Fact]
    public async Task AForestDeclaringNoWritableControllerIsRefused()
    {
        var topology = await ReadAsync(new ControllerModel());

        Assert.False(topology.IsSuccess);
        Assert.Equal("Capture.ForestDeclaredNoDomainControllers", topology.Error!.Code);
    }

    [Fact]
    public async Task ASitesContainerThatCannotBeReadStopsThePlan()
    {
        var controller = new ControllerModel();
        AddDomainController(controller, "DC1", "London", "DC=example,DC=com");
        controller.RefusesToRead.Add(Sites);

        var topology = await ReadAsync(controller);

        Assert.False(topology.IsSuccess);
        Assert.Equal("Capture.SiteTopologyCouldNotBeRead", topology.Error!.Code);
    }

    private static string SettingsDn(string host, string site) =>
        "CN=NTDS Settings,CN=" + host + ",CN=Servers,CN=" + site + "," + Sites;

    private static void AddServer(ControllerModel controller, string host, string site) =>
        controller.AddObject(
            "CN=" + host + ",CN=Servers,CN=" + site + "," + Sites,
            ("dNSHostName", [host.ToLowerInvariant() + ".example.com"]));

    private static void AddSubnet(ControllerModel controller, string prefix, string site) =>
        controller.AddObject(
            "CN=" + prefix + "," + Subnets,
            ("siteObject", ["CN=" + site + "," + Sites]));

    private static void AddDomainController(
        ControllerModel controller, string host, string site, params string[] namingContexts)
    {
        AddServer(controller, host, site);
        controller.AddObject(
            SettingsDn(host, site),
            ("msDS-hasMasterNCs", namingContexts.Cast<object>().ToArray()));
    }

    private static async Task<Result<ForestTopology>> ReadAsync(ControllerModel model)
    {
        using var channel = model.Connections().Connect("dc1.example.com").Value!;

        return await ForestTopology.ReadAsync(channel, Configuration, CancellationToken.None);
    }
}

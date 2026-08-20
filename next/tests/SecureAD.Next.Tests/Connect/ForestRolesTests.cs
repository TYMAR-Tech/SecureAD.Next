using SecureAD.Audit.Connect;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Finding out which controller holds each operations master role, so that ranking can keep an
/// hours-long forest-wide read off the busiest machine in a domain.
///
/// <para>
/// The PDC emulator carries time synchronisation, password change chaining, account lockout and
/// Group Policy editing for a whole domain. Auditing from it is the one clearly bad choice available
/// to selection, and it is the choice made by accident whenever a ranker cannot tell which machine
/// that is - which is why <see cref="PdcEmulatorKnowledge.NotYetEstablished"/> is a state of its own
/// rather than being allowed to look like a controller holding no role.
/// </para>
/// </summary>
public sealed class ForestRolesTests
{
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Schema = "CN=Schema," + Configuration;
    private const string Sites = "CN=Sites," + Configuration;
    private const string Root = "DC=example,DC=com";
    private const string Child = "DC=child,DC=example,DC=com";

    /// <summary>
    /// A role is recorded on the object it governs, naming its holder by that controller's
    /// <c>nTDSDSA</c> distinguished name. Resolving that to a host name is what lets ranking act on
    /// it, because a host name is what a connection is opened to.
    /// </summary>
    [Fact]
    public async Task AForestRoleIsResolvedToTheControllerHoldingIt()
    {
        var model = ForestOf(["DC1", "DC2"], schemaMaster: "DC2");

        var roles = await ReadAsync(model);

        Assert.Equal("dc2.example.com", roles.Value!.SchemaMaster!.HostName);
    }

    /// <summary>
    /// The two forest roles live on different objects, and reading one is not reading the other.
    /// </summary>
    [Fact]
    public async Task TheDomainNamingMasterIsReadFromThePartitionsContainer()
    {
        var model = ForestOf(["DC1", "DC2"], domainNamingMaster: "DC2");

        var roles = await ReadAsync(model);

        Assert.Equal("dc2.example.com", roles.Value!.DomainNamingMaster!.HostName);
    }

    /// <summary>
    /// A holder the forest names but this run cannot match to a candidate is carried with the name
    /// the forest gave and no host name, rather than dropped. An absence this product created may
    /// not be presented as a fact about the forest.
    /// </summary>
    [Fact]
    public async Task AnUnmatchedRoleHolderIsCarriedRatherThanDropped()
    {
        var model = ForestOf(["DC1"], schemaMaster: "DC9");

        var roles = await ReadAsync(model);

        Assert.Null(roles.Value!.SchemaMaster!.HostName);
        Assert.Equal(SettingsDn("DC9"), roles.Value!.SchemaMaster!.OwnerDn);
    }

    /// <summary>
    /// Discovery opens no second connection, so a foreign domain's naming context head is not
    /// readable from it. Every domain is therefore left explicitly unasked rather than being ranked
    /// as though the question had been answered.
    /// </summary>
    [Fact]
    public async Task DiscoveryLeavesEveryDomainPdcEmulatorNotYetEstablished()
    {
        var model = ForestOf(["DC1"], pdcEmulator: "DC1");

        var roles = await ReadAsync(model);

        Assert.All(
            roles.Value!.PdcEmulators,
            pdc => Assert.Equal(PdcEmulatorKnowledge.NotYetEstablished, pdc.Knowledge));
        Assert.Equal([Root, Child], roles.Value!.PdcEmulators.Select(p => p.NamingContext));
    }

    /// <summary>
    /// The failure this whole enumeration exists to prevent: a domain nothing has asked about must
    /// not report its controllers as holding no role, because a ranker acting on that would sort the
    /// PDC emulator equal with every other machine and could pin the audit straight onto it.
    /// </summary>
    [Fact]
    public async Task AControllerInAnUnaskedDomainDoesNotReportAsHoldingNoRole()
    {
        var model = ForestOf(["DC1"], pdcEmulator: "DC1");

        var roles = await ReadAsync(model);

        Assert.False(roles.Value!.HoldsAnEstablishedRole("dc1.example.com"));
        Assert.Equal(
            PdcEmulatorKnowledge.NotYetEstablished,
            roles.Value!.PdcEmulators.Single(p => p.NamingContext == Root).Knowledge);
    }

    /// <summary>
    /// Preflight holds a connection to each domain already, so establishing the PDC emulator there
    /// costs no connection of its own.
    /// </summary>
    [Fact]
    public async Task PreflightEstablishesADomainPdcEmulator()
    {
        var model = ForestOf(["DC1", "DC2"], pdcEmulator: "DC2");

        var roles = await ReadAsync(model);
        using var channel = model.Connections().Connect("dc1.example.com").Value!;
        var topology = await ForestTopology.ReadAsync(channel, Configuration, CancellationToken.None);

        var established = await ForestRoles.EstablishPdcEmulatorAsync(
            channel, Root, topology.Value!, CancellationToken.None);

        Assert.Equal(PdcEmulatorKnowledge.Established, established.Knowledge);
        Assert.Equal("dc2.example.com", established.Holder!.HostName);
        Assert.True(roles.Value!.With(established).HoldsAnEstablishedRole("dc2.example.com"));
    }

    /// <summary>
    /// A PDC read that fails does not stop the run - the domain is still audited. What is lost is
    /// the ability to keep the audit off that domain's busiest machine, and it is recorded as lost
    /// rather than absorbed into "holds no role".
    /// </summary>
    [Fact]
    public async Task APdcReadThatFailsIsRecordedRatherThanTakenAsNoRole()
    {
        var model = ForestOf(["DC1", "DC2"], pdcEmulator: "DC2");
        model.RefusesToRead.Add(Root);

        using var channel = model.Connections().Connect("dc1.example.com").Value!;
        var topology = await ForestTopology.ReadAsync(channel, Configuration, CancellationToken.None);

        var established = await ForestRoles.EstablishPdcEmulatorAsync(
            channel, Root, topology.Value!, CancellationToken.None);

        Assert.Equal(PdcEmulatorKnowledge.CouldNotBeRead, established.Knowledge);
        Assert.Null(established.Holder);
    }

    /// <summary>
    /// Establishing one domain's PDC emulator says nothing about any other domain's.
    /// </summary>
    [Fact]
    public async Task EstablishingOneDomainLeavesTheOthersUnasked()
    {
        var model = ForestOf(["DC1", "DC2"], pdcEmulator: "DC2");

        var roles = await ReadAsync(model);
        using var channel = model.Connections().Connect("dc1.example.com").Value!;
        var topology = await ForestTopology.ReadAsync(channel, Configuration, CancellationToken.None);

        var updated = roles.Value!.With(await ForestRoles.EstablishPdcEmulatorAsync(
            channel, Root, topology.Value!, CancellationToken.None));

        Assert.Equal(
            PdcEmulatorKnowledge.NotYetEstablished,
            updated.PdcEmulators.Single(p => p.NamingContext == Child).Knowledge);
    }

    /// <summary>
    /// An object that names no holder is a forest that was asked and said nothing, which is not the
    /// same as a read that failed and is not the same as a question never put.
    /// </summary>
    [Fact]
    public async Task ARoleObjectNamingNoHolderIsNotAFailure()
    {
        var model = ForestOf(["DC1"]);

        var roles = await ReadAsync(model);

        Assert.True(roles.IsSuccess);
        Assert.Null(roles.Value!.SchemaMaster);
    }

    /// <summary>
    /// A schema head that cannot be read stops the plan. Ranking without it would silently lose the
    /// only forest-wide role information a run gets for free.
    /// </summary>
    [Fact]
    public async Task ARoleObjectThatCannotBeReadStopsThePlan()
    {
        var model = ForestOf(["DC1"]);
        model.RefusesToRead.Add(Schema);

        var roles = await ReadAsync(model);

        Assert.False(roles.IsSuccess);
        Assert.Equal("Capture.RoleOwnerCouldNotBeRead", roles.Error!.Code);
    }

    private static string SettingsDn(string host) =>
        "CN=NTDS Settings,CN=" + host + ",CN=Servers,CN=London," + Sites;

    private static void AddRoleObject(ControllerModel model, string dn, string? holder) =>
        model.AddObject(
            dn,
            holder is null ? [] : [("fSMORoleOwner", (object[])[SettingsDn(holder)])]);

    private static ControllerModel ForestOf(
        string[] hosts,
        string? schemaMaster = null,
        string? domainNamingMaster = null,
        string? pdcEmulator = null)
    {
        var model = new ControllerModel();

        // Every forest has these three objects, and each names a role holder only where a test says
        // so - an object present and silent is what "asked, and the forest said nothing" looks like,
        // which is neither a failed read nor a question never put.
        AddRoleObject(model, Schema, schemaMaster);
        AddRoleObject(model, "CN=Partitions," + Configuration, domainNamingMaster);
        AddRoleObject(model, Root, pdcEmulator);

        foreach (var host in hosts)
        {
            model.AddObject(
                "CN=" + host + ",CN=Servers,CN=London," + Sites,
                ("dNSHostName", [host.ToLowerInvariant() + ".example.com"]));
            model.AddObject(SettingsDn(host), ("msDS-hasMasterNCs", [Root, Child]));
        }

        return model;
    }

    private static async Task<Result<ForestRoles>> ReadAsync(ControllerModel model)
    {
        using var channel = model.Connections().Connect("dc1.example.com").Value!;

        var topology = await ForestTopology.ReadAsync(
            channel, Configuration, CancellationToken.None);

        return await ForestRoles.ReadAsync(
            channel,
            Configuration,
            Schema,
            topology.Value!,
            [Root, Child],
            CancellationToken.None);
    }
}

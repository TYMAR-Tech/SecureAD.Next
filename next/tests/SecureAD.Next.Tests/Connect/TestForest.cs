using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Next.Tests.Capture;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Builds a controller model that has the site and server objects every real forest has.
/// </summary>
/// <remarks>
/// <para>
/// <c>ControllerModel</c>'s default forest declares partitions and cross-references but no
/// <c>CN=Sites</c> container, which was harmless while each domain was read from its own DNS name
/// and is not now: discovery ranks controllers out of that container, so a model without one
/// describes a forest that has no controllers at all.
/// </para>
/// <para>
/// Seeded here rather than in <c>ControllerModel</c> itself so that the object counts every capture
/// test asserts on are left alone. That is a compromise and it is recorded as a finding at
/// <c>S-40</c>: a shared fixture missing an object every forest has is how a test comes to pass
/// against a forest shape that cannot exist (<c>F-S39-4</c>).
/// </para>
/// </remarks>
internal static class TestForest
{
    internal const string Configuration = "CN=Configuration,DC=example,DC=com";
    internal const string Schema = "CN=Schema,CN=Configuration,DC=example,DC=com";
    internal const string Sites = "CN=Sites," + Configuration;
    internal const string DefaultSite = "Default-First-Site-Name";

    /// <summary>
    /// Adds the objects every forest has that discovery now reads: the schema head and the
    /// Partitions container, which carry the two forest-level operations master roles.
    /// </summary>
    /// <remarks>
    /// Their absence is <c>F-S39-4</c>: a fixture missing an object every real forest has lets a
    /// component be blamed for refusing a read that should have succeeded.
    /// </remarks>
    internal static ControllerModel WithForestRoleObjects(this ControllerModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        model.AddObject(Schema);
        model.AddObject("CN=Partitions," + Configuration);

        return model;
    }

    /// <summary>
    /// Adds one controller: its server object, its host name, and the partitions it holds a
    /// writable replica of.
    /// </summary>
    internal static ControllerModel WithController(
        this ControllerModel model,
        string host,
        string site,
        params string[] writableNamingContexts)
    {
        ArgumentNullException.ThrowIfNull(model);

        model.AddObject(
            $"CN={host},CN=Servers,CN={site},{Sites}",
            ("dNSHostName", [host + ".example.com"]));

        model.AddObject(
            $"CN=NTDS Settings,CN={host},CN=Servers,CN={site},{Sites}",
            ("msDS-hasMasterNCs", writableNamingContexts.Cast<object>().ToArray()));

        return model;
    }

    /// <summary>
    /// The forest as discovery would describe it, with one controller per named host in one site.
    /// </summary>
    internal static async Task<ForestPlan> PlanAsync(
        ControllerModel model,
        IReadOnlyDictionary<string, string>? overrides = null,
        string? operatorAddress = "10.0.0.5")
    {
        ArgumentNullException.ThrowIfNull(model);

        using var channel = model.Connections().Connect(model.DomainController).Value!;

        var plan = await ForestDiscovery.PlanAsync(
            channel,
            operatorAddress is null ? [] : [System.Net.IPAddress.Parse(operatorAddress)],
            overrides ?? new Dictionary<string, string>(),
            CancellationToken.None);

        return plan.Value!;
    }

    /// <summary>
    /// Adds the subnet that puts this machine in the named site.
    /// </summary>
    internal static ControllerModel WithSubnet(
        this ControllerModel model, string prefix, string site)
    {
        ArgumentNullException.ThrowIfNull(model);

        model.AddObject(
            $"CN={prefix},CN=Subnets,{Sites}",
            ("siteObject", [$"CN={site},{Sites}"]));

        return model;
    }
}

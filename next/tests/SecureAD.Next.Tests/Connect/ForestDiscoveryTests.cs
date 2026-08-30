using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Reading a controller's RootDSE and planning the run from it.
///
/// <para>
/// This closes the gap that made <c>CapturePlan</c> unbuildable from a directory: it required the
/// naming contexts "as branch A discovered them" and nothing discovered them.
/// </para>
/// </summary>
public sealed class ForestDiscoveryTests
{
    [Fact]
    public async Task ThePlanReadsEveryPartitionTheControllerPublishes()
    {
        var plan = await PlanAsync(new ControllerModel());

        Assert.True(plan.IsSuccess);
        Assert.Equal(
            [
                "CN=Configuration,DC=example,DC=com",
                "CN=Schema,CN=Configuration,DC=example,DC=com",
                "DC=example,DC=com",
            ],
            plan.Value!.Units.Select(u => u.NamingContext).OrderBy(n => n, StringComparer.Ordinal));
    }

    /// <summary>
    /// Configuration and schema come first, because everything else is interpreted against them
    /// and capture is fail-fast. That ordering is <c>CapturePlan</c>'s and this checks discovery
    /// does not disturb it.
    /// </summary>
    [Fact]
    public async Task ConfigurationAndSchemaArePlannedFirst()
    {
        var plan = await PlanAsync(new ControllerModel());

        Assert.Equal(
            [NamingContextKind.Configuration, NamingContextKind.Schema, NamingContextKind.Domain],
            plan.Value!.Units.Select(u => u.Kind));
    }

    /// <summary>
    /// A controller that does not state a partition is not one a run can plan against. Inferring
    /// it from the shape of another name would be this product deciding what the forest contains.
    /// </summary>
    [Fact]
    public async Task AControllerThatDoesNotStateTheSchemaPartitionIsRefused()
    {
        var controller = new ControllerModel { SchemaNamingContext = null };

        var plan = await PlanAsync(controller);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.RootDseDidNotStateThePartition", plan.Error!.Code);
    }

    /// <summary>
    /// A partition that was stated and could not be read is a failure of this product, and it says
    /// so instead of blaming the controller.
    ///
    /// <para>
    /// This is the defect a lab run found on 2026-08-14. A live directory returns attribute values
    /// as bytes; the readers filtered for .NET strings and found none; and the run reported that
    /// <c>addc.ad.lab</c> had not published <c>configurationNamingContext</c> - which it had, as
    /// every domain controller does. An operator was sent to look at his forest for a fault in
    /// this code, which is what <c>docs/decisions/0002</c> exists to prevent: unavailable output is
    /// never phrased as a statement about the directory.
    /// </para>
    /// </summary>
    [Fact]
    public async Task APartitionThatWasStatedAndCouldNotBeReadIsNotReportedAsUnstated()
    {
        var controller = new ControllerModel
        {
            ServesAnUnreadableConfigurationNamingContext = true,
        };

        var plan = await PlanAsync(controller);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.AttributeCouldNotBeReadAsText", plan.Error!.Code);
        Assert.DoesNotContain("did not state", plan.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// And the ordinary case works against values in the shape a directory actually sends them.
    /// </summary>
    [Fact]
    public async Task AForestIsDiscoveredFromValuesServedAsBytes()
    {
        var controller = new ControllerModel();

        Assert.True(controller.ServesTextAsBytes);

        var plan = await PlanAsync(controller);

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Equal("example.com", plan.Value!.ForestFqdn);
    }

    [Fact]
    public async Task AControllerThatDoesNotStateTheConfigurationPartitionIsRefused()
    {
        var controller = new ControllerModel { ConfigurationNamingContext = null };

        var plan = await PlanAsync(controller);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.RootDseDidNotStateThePartition", plan.Error!.Code);
    }

    /// <summary>
    /// A partition the forest declares and the run does not read is named, not silently dropped.
    ///
    /// <para>
    /// <b>This assertion is <c>F-S28-2</c> and it is written to be capable of failing.</b> Its
    /// predecessor asserted that nothing was left unread, against a model publishing exactly the
    /// three partitions it planned - so it held for the trivial reason rather than the tested one.
    /// Adding an application partition to the model was not enough on its own either: while
    /// discovery treated every published partition as a domain, everything published was still
    /// planned and the list was still empty. Naming the expected partition is what makes the
    /// difference between the two implementations visible.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheApplicationPartitionIsRecordedAsOneTheRunDoesNotRead()
    {
        var plan = await PlanAsync(new ControllerModel());

        Assert.True(plan.IsSuccess);
        Assert.Equal(["DC=DomainDnsZones,DC=example,DC=com"], plan.Value!.NotRead);
    }

    [Fact]
    public async Task ACrossReferenceThatIsNotALocalNamingContextIsNotAnUnreadPartition()
    {
        var controller = new ControllerModel();
        controller.CrossReferences.Add(
            new CrossReference("DC=external,DC=example", "external.example", "0"));

        var plan = await PlanAsync(controller);

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.DoesNotContain("DC=external,DC=example", plan.Value!.NotRead);
    }

    /// <summary>
    /// The cross-references are asked for in the Partitions container beneath the configuration
    /// partition the controller named, and not somewhere else. A search of the wrong container
    /// returns nothing, and nothing is indistinguishable from a forest with no application
    /// partitions.
    /// </summary>
    [Fact]
    public async Task TheCrossReferencesAreReadFromThePartitionsContainer()
    {
        var controller = new ControllerModel();

        await PlanAsync(controller);

        Assert.Equal(
            "CN=Partitions,CN=Configuration,DC=example,DC=com",
            controller.CrossReferenceSearchBase);
    }

    private static async Task<SecureAD.Kernel.Result<CapturePlan>> PlanAsync(
        ControllerModel controller)
    {
        // Every real forest has a CN=Sites container naming its controllers, and discovery now
        // ranks out of it. A model without one describes a forest with no controllers at all, so
        // the default fixture is given the one controller it already claims to be.
        controller.WithForestRoleObjects()
            .WithController("dc01", TestForest.DefaultSite, "DC=example,DC=com");

        var opened = controller.Connections().Connect(
            CaptureUnit.Create(
                "DC=example,DC=com",
                NamingContextKind.Domain,
                controller.DomainController).Value!);

        using var channel = opened.Value!;

        var plan = await ForestDiscovery.PlanAsync(
            channel, [], new Dictionary<string, string>(), CancellationToken.None);

        return plan.IsSuccess
            ? SecureAD.Kernel.Result<CapturePlan>.Success(plan.Value!.Capture)
            : SecureAD.Kernel.Result<CapturePlan>.Failure(plan.Error!);
    }
}

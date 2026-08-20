using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// Inventory row B6's other half: which naming contexts a run reads, and what it says about the ones
/// it does not.
/// </summary>
public sealed class CapturePlanTests
{
    private const string Controller = "dc01.example.com";
    private const string Configuration = "CN=Configuration,DC=example,DC=com";
    private const string Schema = "CN=Schema,CN=Configuration,DC=example,DC=com";
    private const string Domain = "DC=example,DC=com";
    private const string ForestDnsZones = "DC=ForestDnsZones,DC=example,DC=com";

    private static string[] Published() =>
        [Domain, Configuration, Schema, ForestDnsZones];

    private static SecureAD.Kernel.Result<CapturePlan> Plan(
        IEnumerable<(string NamingContext, string DnsName, string DomainController)>? domains = null,
        IEnumerable<string>? published = null,
        IEnumerable<string>? notRead = null) =>
        CapturePlan.For(
            Controller,
            "example.com",
            Configuration,
            Schema,
            domains ?? [(Domain, "example.com", Controller)],
            published ?? Published(),
            notRead ?? [ForestDnsZones]);

    [Fact]
    public void TheConfigurationAndSchemaPartitionsAreReadFirst()
    {
        var plan = Plan();

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Equal(
            [NamingContextKind.Configuration, NamingContextKind.Schema, NamingContextKind.Domain],
            plan.Value.Units.Select(u => u.Kind));
    }

    // ---------------------------------------------------------------------------------------
    // Exclusions. An attested exclusion has to reach the reading, not only the evidence.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An excluded domain is not read.
    /// </summary>
    /// <remarks>
    /// Found in the lab: a domain the operator unticked was recorded in the bundle as excluded and
    /// then captured anyway, because the attestation reached
    /// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>'s table and nothing
    /// else. That bundle contradicts itself - an attestation saying nobody looked, filed beside the
    /// objects captured when somebody did - and the attestation is the half that looks
    /// authoritative.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainIsNotRead()
    {
        var plan = Plan(
        [
            (Domain, "example.com", Controller),
            ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
        ],
        published: [Domain, "DC=child,DC=example,DC=com", Configuration, Schema, ForestDnsZones]);

        var trimmed = plan.Value.Excluding(["DC=child,DC=example,DC=com"]);

        Assert.DoesNotContain(
            "DC=child,DC=example,DC=com",
            trimmed.Units.Select(u => u.NamingContext));
        Assert.Contains(Domain, trimmed.Units.Select(u => u.NamingContext));
    }

    /// <summary>
    /// Excluding a domain does not shrink the denominator its coverage is measured against.
    /// </summary>
    /// <remarks>
    /// The forest still declares the domain that was left out. Trimming
    /// <see cref="CapturePlan.DeclaredDomains"/> would let the run report full coverage of a forest
    /// it did not fully read, which is <c>F-S28-1</c> arriving by the front door.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainStillCountsAgainstCoverage()
    {
        var plan = Plan(
        [
            (Domain, "example.com", Controller),
            ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
        ],
        published: [Domain, "DC=child,DC=example,DC=com", Configuration, Schema, ForestDnsZones]);

        var trimmed = plan.Value.Excluding(["DC=child,DC=example,DC=com"]);

        Assert.Equal(plan.Value.DeclaredDomains, trimmed.DeclaredDomains);
        Assert.False(trimmed.IsComplete);
    }

    /// <summary>
    /// The forest-wide partitions survive an exclusion, because no domain owns them.
    /// </summary>
    /// <remarks>
    /// Matching on naming context alone would be enough to remove a partition that happened to
    /// share a name, and the configuration and schema partitions are what everything else is
    /// interpreted against per <c>0014</c>.
    /// </remarks>
    [Fact]
    public void ExcludingADomainLeavesTheForestWidePartitionsAlone()
    {
        var trimmed = Plan().Value.Excluding([Domain]);

        Assert.Equal(
            [NamingContextKind.Configuration, NamingContextKind.Schema],
            trimmed.Units.Select(u => u.Kind));
    }

    /// <summary>
    /// Excluding nothing changes nothing.
    /// </summary>
    [Fact]
    public void ExcludingNothingLeavesThePlanAsItWas()
    {
        var plan = Plan().Value;

        Assert.Same(plan, plan.Excluding([]));
    }

    /// <summary>
    /// The two forest-wide partitions are read from the controller the operator named, because that
    /// is the one controller the run is known to be able to reach.
    /// </summary>
    [Fact]
    public void TheForestWidePartitionsAreReadFromTheNamedController()
    {
        var plan = Plan();

        Assert.All(
            plan.Value.Units.Where(u => u.Kind != NamingContextKind.Domain),
            u => Assert.Equal(Controller, u.DomainController));
    }

    /// <summary>
    /// Each domain is read from the controller it was discovered with, which is how a run given one
    /// controller reaches a forest of nine domains.
    /// </summary>
    [Fact]
    public void EachDomainIsReadFromItsOwnController()
    {
        var plan = Plan(
        [
            (Domain, "example.com", Controller),
            ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
        ]);

        Assert.Equal(
            "child.example.com",
            plan.Value.Units.Single(u => u.NamingContext == "DC=child,DC=example,DC=com")
                .DomainController);
    }

    /// <summary>
    /// A partition the forest declares and the run does not read is recorded rather than ignored.
    /// Silence about a partition is what an audit tool cannot produce.
    ///
    /// <para>
    /// The list arrives from the forest's cross-references. It was once computed by subtracting the
    /// units planned from the list they were planned from, which is empty by construction - so a
    /// run that saw one domain of nine reported nothing missing. That is <c>F-S28-1</c>.
    /// </para>
    /// </summary>
    [Fact]
    public void APartitionTheForestDeclaresAndTheRunDoesNotReadIsRecorded()
    {
        var plan = Plan();

        Assert.Equal([ForestDnsZones], plan.Value.NotRead);
    }

    /// <summary>
    /// The unread list is the forest's answer and is not recomputed from what this controller
    /// happened to publish. A controller publishing nothing beyond what was planned does not turn
    /// an application partition the forest has into one nobody mentions.
    /// </summary>
    [Fact]
    public void TheUnreadListDoesNotDependOnWhatTheControllerPublishes()
    {
        var plan = Plan(published: [Domain, Configuration, Schema]);

        Assert.Equal([ForestDnsZones], plan.Value.NotRead);
    }

    [Fact]
    public void APartitionTheControllerDoesNotServeIsRefusedBeforeTheRunStarts()
    {
        var plan = Plan(published: [Configuration, Schema]);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.DomainControllerDoesNotServeNamingContext", plan.Error!.Code);
    }

    [Fact]
    public void AControllerThatPublishesNothingIsAFailedQuestionRatherThanAnAnswerOfNo()
    {
        var plan = Plan(published: []);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.DomainControllerNamedNoPartitions", plan.Error!.Code);
    }

    /// <summary>
    /// A domain read from a different controller is not checked against the named controller's
    /// partition list, because that list says nothing about it.
    ///
    /// <para>
    /// Without this the first child domain in any forest would be refused, since the controller the
    /// operator named does not publish it. Confirming it needs a connection to its own controller,
    /// which is what happens before any reading begins.
    /// </para>
    /// </summary>
    [Fact]
    public void ADomainOnAnotherControllerIsNotCheckedAgainstThisControllersPartitions()
    {
        var plan = Plan(
        [
            (Domain, "example.com", Controller),
            ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
        ]);

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Equal(4, plan.Value.Units.Count);
    }

    /// <summary>
    /// A plan naming no domain at all is refused. It would seal a bundle holding the configuration
    /// and schema partitions - no principals, no permissions, nothing to audit - while looking like
    /// a capture that worked.
    /// </summary>
    [Fact]
    public void APlanThatReadsNoDomainIsRefused()
    {
        var plan = Plan(domains: []);

        Assert.False(plan.IsSuccess);
        Assert.Equal("Capture.CapturePlanReadsNoDomain", plan.Error!.Code);
    }

    [Fact]
    public void AForestWithSeveralDomainsPlansAUnitForEach()
    {
        var plan = Plan(
            [
                (Domain, "example.com", Controller),
                ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
            ],
            [.. Published(), "DC=child,DC=example,DC=com"]);

        Assert.True(plan.IsSuccess, plan.Error?.Description);
        Assert.Equal(4, plan.Value.Units.Count);
    }

    /// <summary>
    /// Every domain the forest declared has a unit, so the plan says it covers the forest.
    /// </summary>
    [Fact]
    public void APlanCoveringEveryDeclaredDomainIsComplete()
    {
        var plan = Plan(
            [
                (Domain, "example.com", Controller),
                ("DC=child,DC=example,DC=com", "child.example.com", "child.example.com"),
            ],
            [.. Published(), "DC=child,DC=example,DC=com"]);

        Assert.Equal(["example.com", "child.example.com"], plan.Value.DeclaredDomains);
        Assert.True(plan.Value.IsComplete);
    }

    /// <summary>
    /// And a plan whose units do not cover the declaration says so.
    ///
    /// <para>
    /// Asserted against the record directly rather than through <c>For</c>, because <c>For</c>
    /// builds the units from the declaration and so cannot produce the mismatch. That is the point:
    /// the flag this replaced was computed from the list it was checking, so it could not be false
    /// under any input at all. This one can, and here it is.
    /// </para>
    /// </summary>
    [Fact]
    public void APlanThatDoesNotCoverEveryDeclaredDomainIsNotComplete()
    {
        var oneUnitTwoDomainsDeclared = new CapturePlan(
            [CaptureUnit.Create(Domain, NamingContextKind.Domain, Controller).Value!],
            NotRead: [],
            DeclaredDomains: ["example.com", "child.example.com"],
            ForestFqdn: "example.com");

        Assert.False(oneUnitTwoDomainsDeclared.IsComplete);
    }
}

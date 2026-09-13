using SecureAD.Audit.Capture;
using SecureAD.Audit.Sysvol;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Sysvol;

/// <summary>
/// Putting nine domains' policy inventories back into one, which is the SYSVOL denominator.
/// </summary>
/// <remarks>
/// <para>
/// <b>What is at stake is a number, not a crash.</b> Under
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> each domain is read by its own
/// sink and builds its own inventory. Per <c>docs/decisions/0044</c> SYSVOL is allowed to report
/// coverage at all only because that denominator is built from LDAP before any file is opened - so
/// a merge that dropped entries would leave a run reporting full coverage of a share it had only
/// partly read. Nothing downstream could tell.
/// </para>
/// <para>
/// <b>The denominator lives in two lists and the second is the one that would be forgotten.</b>
/// <c>Policies</c> holds the policies whose files can be found; <c>UnlocatablePolicies</c> holds
/// the ones the directory returned without a <c>gPCFileSysPath</c>. Carrying only the first is the
/// plausible mistake, and it fails upwards: <c>DeclaredPoliciesAreComplete</c> would answer true.
/// Each list therefore has a test that fires when it is dropped, and the completeness pair has a
/// negative control so the assertion is discriminating rather than merely true.
/// </para>
/// </remarks>
public sealed class GpoInventoryTests
{
    private static readonly Guid FirstPolicy =
        Guid.Parse("31b2f340-016d-11d2-945f-00c04fb984f9");

    private static readonly Guid SecondPolicy =
        Guid.Parse("6ac1786c-016f-11d2-945f-00c04fb984f9");

    private static readonly Guid ThirdPolicy =
        Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    // ---------------------------------------------------------------------------------------
    // The policies that can be read
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AbsorbedPoliciesJoinTheDenominator()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));
        var domain = InventoryOf(("fabrikam.com", SecondPolicy));

        forest.Absorb(domain);

        Assert.Equal(2, forest.Policies.Count);
    }

    [Fact]
    public void AbsorbedPoliciesKeepTheOnesAlreadyHeld()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOf(("fabrikam.com", SecondPolicy)));

        Assert.Contains(forest.Policies, p => p.GpoGuid == FirstPolicy);
    }

    [Fact]
    public void AbsorbedPoliciesArriveWithTheirOwnIdentity()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOf(("fabrikam.com", SecondPolicy)));

        Assert.Contains(forest.Policies, p => p.GpoGuid == SecondPolicy);
    }

    /// <summary>
    /// The order is the order the domains were merged in, which under the fan-out is plan order.
    /// </summary>
    /// <remarks>
    /// A denominator ordered by whichever controller answered first would put the same forest in a
    /// different order every run, and an operator comparing two SYSVOL coverage records would be
    /// reading a difference the forest does not have.
    /// </remarks>
    [Fact]
    public void AbsorbedPoliciesFollowTheOnesAlreadyHeld()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOf(("fabrikam.com", SecondPolicy), ("fabrikam.com", ThirdPolicy)));

        Assert.Equal(
            [FirstPolicy, SecondPolicy, ThirdPolicy],
            forest.Policies.Select(p => p.GpoGuid));
    }

    // ---------------------------------------------------------------------------------------
    // The policies that cannot be read, which are the half that would be dropped
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A policy another domain could not locate is carried, so it stays in the denominator.
    /// </summary>
    /// <remarks>
    /// <b>This is the fire test for the dangerous half.</b> Dropping
    /// <c>UnlocatablePolicies</c> at the merge leaves every other assertion in this class passing.
    /// </remarks>
    [Fact]
    public void AnAbsorbedUnlocatablePolicyIsCarried()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOfUnlocatable(("fabrikam.com", SecondPolicy)));

        var unlocatable = Assert.Single(forest.UnlocatablePolicies);

        Assert.Equal(SecondPolicy, unlocatable.GpoGuid);
    }

    /// <summary>
    /// Absorbing a domain that could not locate a policy makes the denominator incomplete.
    /// </summary>
    /// <remarks>
    /// The consequence the list exists for. Without it a run reports having read the whole of
    /// SYSVOL while a policy nobody could find is missing from the count it read itself against.
    /// </remarks>
    [Fact]
    public void AnAbsorbedUnlocatablePolicyMakesTheDenominatorIncomplete()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOfUnlocatable(("fabrikam.com", SecondPolicy)));

        Assert.False(forest.DeclaredPoliciesAreComplete);
    }

    /// <summary>
    /// The negative control for the test above: a merge of domains that located everything leaves
    /// the denominator complete.
    /// </summary>
    /// <remarks>
    /// Without this, <see cref="AnAbsorbedUnlocatablePolicyMakesTheDenominatorIncomplete"/> would
    /// also pass against an inventory that answered <c>false</c> unconditionally, which is an
    /// assertion that measures nothing.
    /// </remarks>
    [Fact]
    public void AbsorbingDomainsThatLocatedEverythingLeavesTheDenominatorComplete()
    {
        var forest = InventoryOf(("contoso.com", FirstPolicy));

        forest.Absorb(InventoryOf(("fabrikam.com", SecondPolicy)));

        Assert.True(forest.DeclaredPoliciesAreComplete);
    }

    // ---------------------------------------------------------------------------------------
    // What is refused
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnInventoryRefusesToAbsorbItself()
    {
        var inventory = InventoryOf(("contoso.com", FirstPolicy));

        var refusal = Assert.Throws<InvalidOperationException>(
            () => inventory.Absorb(inventory));

        Assert.Contains("counted twice", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInventoryRefusesToAbsorbNothing()
    {
        var inventory = new GpoInventory();

        Assert.Throws<ArgumentNullException>(() => inventory.Absorb(null!));
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An inventory built the way a run builds one - by observing captured directory objects -
    /// rather than by reaching past <c>Observe</c> into the lists under test.
    /// </summary>
    private static GpoInventory InventoryOf(params (string Domain, Guid Policy)[] policies)
    {
        var inventory = new GpoInventory();

        foreach (var (domain, policy) in policies)
        {
            inventory.Observe(PolicyObject(domain, policy, located: true), policy);
        }

        return inventory;
    }

    /// <summary>
    /// The same, for policies the directory returned without saying where their files live.
    /// </summary>
    private static GpoInventory InventoryOfUnlocatable(
        params (string Domain, Guid Policy)[] policies)
    {
        var inventory = new GpoInventory();

        foreach (var (domain, policy) in policies)
        {
            inventory.Observe(PolicyObject(domain, policy, located: false), policy);
        }

        return inventory;
    }

    private static CapturedObject PolicyObject(string domain, Guid policy, bool located)
    {
        var dn = $"CN={{{policy}}},CN=Policies,CN=System,{DnOf(domain)}";

        List<AttributeValues> attributes =
        [
            Attribute("objectClass", "top", "container", "groupPolicyContainer"),
            Attribute("displayName", $"Policy in {domain}"),
        ];

        if (located)
        {
            attributes.Add(
                Attribute("gPCFileSysPath", $@"\\{domain}\SysVol\{domain}\Policies\{{{policy}}}"));
        }

        return CapturedObject.Create(dn, attributes);
    }

    private static string DnOf(string domain) =>
        string.Join(",", domain.Split('.').Select(label => "DC=" + label));

    private static AttributeValues Attribute(string name, params string[] values) =>
        new(name, values, AttributeCompleteness.Complete, NextRange: null);
}

using System.Net;
using SecureAD.Audit.Connect;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Working out which site the machine running the audit is in, by matching its own addresses
/// against the ranges the forest declares.
///
/// <para>
/// This is the input that puts a nearby controller ahead of a distant one. Getting it wrong does
/// not fail: it produces a plausible answer that costs hours of a capture, which is why the
/// longest-prefix rule and the no-match case both have tests of their own.
/// </para>
/// </summary>
public sealed class OperatorSiteTests
{
    [Fact]
    public void AMachineInsideADeclaredRangeIsInThatSite()
    {
        var site = OperatorSite.For(
            [new ForestSubnet("10.20.0.0/16", "London")],
            [IPAddress.Parse("10.20.30.40")]);

        Assert.Equal("London", site);
    }

    /// <summary>
    /// The case this rule exists for: a regional range and an office range both contain the
    /// machine, and only the narrower one says where it actually is.
    /// </summary>
    [Fact]
    public void TheNarrowestRangeContainingTheMachineWins()
    {
        var site = OperatorSite.For(
            [
                new ForestSubnet("10.0.0.0/8", "Region"),
                new ForestSubnet("10.20.30.0/24", "Office"),
            ],
            [IPAddress.Parse("10.20.30.40")]);

        Assert.Equal("Office", site);
    }

    /// <summary>
    /// Declaration order must not decide the answer, or two runs a week apart could rank
    /// controllers differently with nothing in the forest having changed.
    /// </summary>
    [Fact]
    public void TheNarrowestRangeWinsWhicheverOrderTheForestReturnedThem()
    {
        var site = OperatorSite.For(
            [
                new ForestSubnet("10.20.30.0/24", "Office"),
                new ForestSubnet("10.0.0.0/8", "Region"),
            ],
            [IPAddress.Parse("10.20.30.40")]);

        Assert.Equal("Office", site);
    }

    /// <summary>
    /// Incomplete subnet coverage is common. No site is an answer, and it is not the same as a
    /// wrong one.
    /// </summary>
    [Fact]
    public void AMachineInsideNoDeclaredRangeHasNoSite()
    {
        var site = OperatorSite.For(
            [new ForestSubnet("10.20.0.0/16", "London")],
            [IPAddress.Parse("192.168.1.5")]);

        Assert.Null(site);
    }

    [Fact]
    public void AForestDeclaringNoRangesLeavesTheRunWithNoSite()
    {
        Assert.Null(OperatorSite.For([], [IPAddress.Parse("10.20.30.40")]));
    }

    [Fact]
    public void AnIPv6MachineIsMatchedAgainstAnIPv6Range()
    {
        var site = OperatorSite.For(
            [new ForestSubnet("2001:db8:1::/48", "Oslo")],
            [IPAddress.Parse("2001:db8:1::20")]);

        Assert.Equal("Oslo", site);
    }

    /// <summary>
    /// An address is never inside a range of the other family, and asking is a defect rather than a
    /// question with an answer.
    /// </summary>
    [Fact]
    public void AnIPv4MachineIsNotPlacedByAnIPv6Range()
    {
        var site = OperatorSite.For(
            [new ForestSubnet("2001:db8:1::/48", "Oslo")],
            [IPAddress.Parse("10.20.30.40")]);

        Assert.Null(site);
    }

    /// <summary>
    /// A machine with several addresses is placed by whichever of them the forest describes most
    /// precisely, not by whichever the operating system happened to list first.
    /// </summary>
    [Fact]
    public void AMachineWithSeveralAddressesIsPlacedByTheNarrowestMatch()
    {
        var site = OperatorSite.For(
            [
                new ForestSubnet("10.0.0.0/8", "Region"),
                new ForestSubnet("192.168.1.0/24", "Office"),
            ],
            [IPAddress.Parse("10.20.30.40"), IPAddress.Parse("192.168.1.5")]);

        Assert.Equal("Office", site);
    }

    /// <summary>
    /// A subnet object whose name is not a range is a defect in the customer's directory. It cannot
    /// place anything, and it must not stop an audit that has nothing else wrong with it.
    /// </summary>
    [Fact]
    public void AMalformedRangeIsSkippedRatherThanStoppingTheRun()
    {
        var site = OperatorSite.For(
            [
                new ForestSubnet("not-a-subnet", "Broken"),
                new ForestSubnet("10.20.0.0/16", "London"),
            ],
            [IPAddress.Parse("10.20.30.40")]);

        Assert.Equal("London", site);
    }
}

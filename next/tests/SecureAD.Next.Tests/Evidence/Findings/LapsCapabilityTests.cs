using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Evidence.Findings;

/// <summary>
/// What LAPS product a computer can run, and what that answer rests on.
/// </summary>
/// <remarks>
/// <para>
/// <b>The fixtures are real values read from <c>ad.lab</c> on 2026-09-03, not invented ones.</b>
/// <c>F-S44-2</c> and SEC-027 both record what internally consistent checks are worth: a rule and its
/// tests written from one wrong belief agree with each other perfectly. The operating system names
/// and version strings below were read out of a live directory, so the classifier is checked against
/// something that did not come from this repository.
/// </para>
/// <para>
/// This matters most for the exact spelling. <c>10.0 (20348)</c> - with a space, and the build in
/// parentheses - is what Active Directory actually stores, and a parser written against an imagined
/// format would pass every test made up alongside it.
/// </para>
/// </remarks>
public sealed class LapsCapabilityTests
{
    /// <summary>
    /// Windows Server 2022, read from <c>ad.lab</c>. Windows LAPS shipped for it.
    /// </summary>
    [Fact]
    public void AServer2022MachineIsWindowsLapsCapable()
    {
        var capability = LapsCapability.Of(
            Computer("Windows Server 2022 Datacenter", "10.0 (20348)"));

        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, capability.Basis);
        Assert.True(capability.IsServer);
    }

    /// <summary>
    /// Windows Server 2016, read from <c>ad.lab</c>. Windows LAPS was never backported to it, so a
    /// missing modern timestamp says nothing about the machine and SEC-094 must not report it.
    /// </summary>
    [Fact]
    public void AServer2016MachineIsLegacyLapsOnly()
    {
        var capability = LapsCapability.Of(
            Computer("Windows Server 2016 Datacenter", "10.0 (14393)"));

        Assert.Equal(LapsCapabilityKind.LegacyLapsOnly, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, capability.Basis);
    }

    /// <summary>
    /// Windows 11, read from <c>ad.lab</c>. A client, and Windows LAPS shipped for it.
    /// </summary>
    [Fact]
    public void AWindows11ClientIsWindowsLapsCapable()
    {
        var capability = LapsCapability.Of(Computer("Windows 11 Enterprise", "10.0 (26200)"));

        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, capability.Kind);
        Assert.False(capability.IsServer);
    }

    /// <summary>
    /// <b>The collision, and the reason both attributes are captured.</b> Windows 10 1607 and
    /// Windows Server 2016 are both build 14393, and they land on opposite sides of the Windows LAPS
    /// boundary. A classifier reading the build alone gets one of them wrong whichever way it
    /// guesses.
    /// </summary>
    [Fact]
    public void OneBuildNumberYieldsTwoAnswersBecauseTheFamilyDiffers()
    {
        var build = LapsPlatformCatalog.SharedServer2016AndWindows10Build
            .ToString(CultureInfo.InvariantCulture);

        var server = LapsCapability.Of(
            Computer("Windows Server 2016 Datacenter", $"10.0 ({build})"));
        var client = LapsCapability.Of(Computer("Windows 10 Enterprise", $"10.0 ({build})"));

        Assert.Equal(LapsCapabilityKind.LegacyLapsOnly, server.Kind);
        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, client.Kind);
    }

    /// <summary>
    /// A bundle sealed before catalogue version 6 carries no build number, and must still be
    /// judgeable - saying so rather than going silent, per <c>docs/decisions/0086</c>.
    /// </summary>
    [Fact]
    public void WithoutAVersionTheNameIsUsedAndTheFindingSaysSo()
    {
        var capability = LapsCapability.Of(Computer("Windows Server 2022 Datacenter", null));

        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemName, capability.Basis);
    }

    /// <summary>
    /// <b>The two the predecessor got wrong.</b> Its grid classed Windows 10 and Server 2012 as
    /// <c>N/A</c> - not applicable - which reported nothing about a large slice of a real estate.
    /// Windows LAPS runs on Windows 10; legacy LAPS runs on Server 2012.
    /// </summary>
    [Theory]
    [InlineData("Windows 10 Enterprise", LapsCapabilityKind.WindowsLapsCapable)]
    [InlineData("Windows Server 2012 R2 Standard", LapsCapabilityKind.LegacyLapsOnly)]
    public void TheNameFallbackDoesNotRepeatThePredecessorsTwoBlindSpots(
        string name, LapsCapabilityKind expected)
    {
        Assert.Equal(expected, LapsCapability.Of(Computer(name, null)).Kind);
    }

    /// <summary>
    /// Nothing to read from is Unknown, and Unknown is never quietly promoted into a capability.
    /// SEC-094 stays silent about such a machine; SEC-091 still reports it.
    /// </summary>
    [Fact]
    public void AMachineWithNoOperatingSystemInformationIsUnknown()
    {
        var capability = LapsCapability.Of(Computer(null, null));

        Assert.Equal(LapsCapabilityKind.Unknown, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.NothingToReadFrom, capability.Basis);
        Assert.Null(capability.IsServer);
    }

    /// <summary>
    /// An unrecognised name is Unknown rather than being forced into one side or the other. The
    /// predecessor's <c>ELSE 'Unknown'</c> did this correctly and it is kept.
    /// </summary>
    [Fact]
    public void AnUnrecognisedNameIsUnknownRatherThanGuessed()
    {
        Assert.Equal(
            LapsCapabilityKind.Unknown,
            LapsCapability.Of(Computer("Ubuntu 24.04.1 LTS", null)).Kind);
    }

    /// <summary>
    /// The build number is preferred over the name where both are present, so a machine whose name
    /// nobody has a string for is still classified correctly.
    /// </summary>
    [Fact]
    public void TheVersionIsPreferredOverTheName()
    {
        var capability = LapsCapability.Of(Computer("Windows Server vNext Datacenter", "10.0 (30000)"));

        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, capability.Basis);
    }

    private static ObjectAttributes Computer(string? operatingSystem, string? version)
    {
        var attributes = new List<ObjectAttribute>
        {
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, "person", null),
                    new AttributeValue(2, "organizationalPerson", null),
                    new AttributeValue(3, "user", null),
                    new AttributeValue(4, "computer", null),
                ]),
        };

        if (operatingSystem is not null) attributes.Add(Single("operatingSystem", operatingSystem));
        if (version is not null) attributes.Add(Single("operatingSystemVersion", version));

        return new ObjectAttributes(
            "CN=LABHOST,CN=Computers,DC=ad,DC=lab",
            Guid.NewGuid(),
            DateTimeOffset.UnixEpoch,
            EvidenceCompleteness.Complete,
            attributes,
            DomainFqdn: "ad.lab");
    }

    private static ObjectAttribute Single(string ldapDisplayName, string value) =>
        new(ldapDisplayName, AttributeCardinality.SingleValued, [new AttributeValue(0, value, null)]);
}

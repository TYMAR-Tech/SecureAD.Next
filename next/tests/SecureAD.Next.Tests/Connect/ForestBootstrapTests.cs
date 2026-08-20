using SecureAD.Audit.Connect;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// Finding the forest the machine is already in, so a run can begin from a click rather than from a
/// typed host name.
///
/// <para>
/// The connection is made to a <b>domain name</b> and not to a host, because a domain name is
/// something the machine already knows and a host name is not. What these tests hold in place is
/// which name is tried, in what order, and that the machine's own knowledge is preferred to
/// anything a person has to type.
/// </para>
/// </summary>
public sealed class ForestBootstrapTests
{
    /// <summary>
    /// The ordinary route in: the machine's own DNS domain suffix, handed to the locator.
    /// </summary>
    [Fact]
    public void ADomainJoinedMachineStartsFromItsOwnDnsDomain()
    {
        var forest = new ForestModel().Answering("example.com", new ControllerModel());

        var entry = ForestBootstrap.Start(forest, Machine("example.com", "EXAMPLE"));

        Assert.True(entry.IsSuccess);
        Assert.Equal("example.com", entry.Value!.Name);
        Assert.Equal(ForestEntrySource.MachineDnsDomain, entry.Value!.Source);
    }

    /// <summary>
    /// The DNS suffix is preferred where both exist. A NetBIOS name is an older and shorter form
    /// that a disjoint namespace can make ambiguous.
    /// </summary>
    [Fact]
    public void TheDnsDomainIsPreferredToTheNetBiosName()
    {
        var forest = new ForestModel()
            .Answering("example.com", new ControllerModel())
            .Answering("EXAMPLE", new ControllerModel());

        var entry = ForestBootstrap.Start(forest, Machine("example.com", "EXAMPLE"));

        Assert.Equal("example.com", entry.Value!.Name);
    }

    /// <summary>
    /// A machine with a NetBIOS domain and no DNS suffix is still in a forest, and the locator can
    /// still resolve the older form.
    /// </summary>
    [Fact]
    public void AMachineWithNoDnsSuffixFallsBackToItsNetBiosDomain()
    {
        var forest = new ForestModel().Answering("EXAMPLE", new ControllerModel());

        var entry = ForestBootstrap.Start(forest, Machine(dnsDomain: null, netBiosDomain: "EXAMPLE"));

        Assert.Equal("EXAMPLE", entry.Value!.Name);
        Assert.Equal(ForestEntrySource.MachineNetBiosDomain, entry.Value!.Source);
    }

    /// <summary>
    /// A machine in no domain is not in a forest, and saying so is more use than an empty field.
    /// </summary>
    [Fact]
    public void AMachineInNoDomainSaysSoRatherThanGuessing()
    {
        var entry = ForestBootstrap.Start(new ForestModel(), Machine(null, null));

        Assert.False(entry.IsSuccess);
        Assert.Equal("Capture.MachineIsInNoDomain", entry.Error!.Code);
    }

    /// <summary>
    /// And it does not attempt a connection to anything on the way to saying so - there is no name
    /// to attempt one to.
    /// </summary>
    [Fact]
    public void AMachineInNoDomainConnectsToNothing()
    {
        var forest = new ForestModel();

        ForestBootstrap.Start(forest, Machine(null, null));

        Assert.Equal(0, forest.ConnectionsAttempted);
    }

    /// <summary>
    /// The recovery path, for a machine that is not domain-joined or an operator auditing a forest
    /// that is not his own.
    /// </summary>
    [Fact]
    public void ATypedNameIsAvailableAsARecoveryPath()
    {
        var forest = new ForestModel().Answering("dc1.other.com", new ControllerModel());

        var entry = ForestBootstrap.StartFromTypedName(forest, "dc1.other.com");

        Assert.Equal(ForestEntrySource.TypedName, entry.Value!.Source);
    }

    /// <summary>
    /// A domain name that answers nothing is reported rather than retried against a different name.
    /// Trying the NetBIOS form after the DNS form failed would report the second failure for the
    /// first attempt, and an operator would be told the wrong thing about their own forest.
    /// </summary>
    [Fact]
    public void ADnsDomainThatDoesNotAnswerIsNotRetriedAsNetBios()
    {
        var forest = new ForestModel().Answering("EXAMPLE", new ControllerModel());

        var entry = ForestBootstrap.Start(forest, Machine("example.com", "EXAMPLE"));

        Assert.False(entry.IsSuccess);
        Assert.Equal(1, forest.ConnectionsAttempted);
    }

    private static IMachineDomain Machine(string? dnsDomain, string? netBiosDomain) =>
        new StubMachine(dnsDomain, netBiosDomain);

    private sealed record StubMachine(string? DnsDomain, string? NetBiosDomain) : IMachineDomain;
}

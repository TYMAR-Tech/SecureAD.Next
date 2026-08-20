using SecureAD.Audit.Capture;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// What the machine running the audit knows about its own domain membership.
/// </summary>
/// <remarks>
/// This is the whole of the seam between selection and the machine it runs on. It exists so that
/// bootstrap can be exercised for a domain-joined machine, a workgroup machine and a machine with a
/// NetBIOS name but no DNS suffix without any of those being the machine the tests run on.
/// </remarks>
public interface IMachineDomain
{
    /// <summary>
    /// The machine's DNS domain suffix, or <see langword="null"/> where it has none.
    /// </summary>
    string? DnsDomain { get; }

    /// <summary>
    /// The machine's NetBIOS domain name, or <see langword="null"/> where it has none.
    /// </summary>
    /// <remarks>
    /// Second choice rather than equal choice. A NetBIOS name is a domain name the locator can still
    /// resolve, but it is an older and shorter form that a disjoint namespace can make ambiguous.
    /// </remarks>
    string? NetBiosDomain { get; }
}

/// <summary>
/// Where the name the first connection was made to came from.
/// </summary>
public enum ForestEntrySource
{
    /// <summary>The machine's own DNS domain suffix. The ordinary route in.</summary>
    MachineDnsDomain = 0,

    /// <summary>The machine's NetBIOS domain name, used when it has no DNS suffix.</summary>
    MachineNetBiosDomain = 1,

    /// <summary>
    /// A name an operator typed. The recovery path, for a machine that is not domain-joined or an
    /// operator auditing a forest that is not his own.
    /// </summary>
    TypedName = 2,
}

/// <summary>
/// The first connection of a run, and where the name it was made to came from.
/// </summary>
/// <param name="Channel">
/// The open connection. It answers one question - what forest is this - and is
/// <b>never</b> the controller anything is captured from.
/// </param>
/// <param name="Name">The domain name, or typed host name, the connection was made to.</param>
/// <param name="Source">Where that name came from.</param>
public sealed record ForestEntry(IDirectoryChannel Channel, string Name, ForestEntrySource Source);

/// <summary>
/// Finds the forest the machine is already in, so that a run can begin from a click rather than
/// from a typed host name.
/// </summary>
/// <remarks>
/// <para>
/// <b>The first connection is made to a domain name, not to a host.</b> That indirection is the
/// whole mechanism: a domain name is something the machine already knows, and a host name is not.
/// The Windows domain controller locator turns the one into a nearby live controller. This is
/// <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c>, and it is the sanctioned use of DNS
/// that <c>0050</c> describes - bootstrapping, never enumerating. Nothing about <i>which</i>
/// controllers exist comes from it.
/// </para>
/// <para>
/// <b>A typed name is the weakest input available</b> and so is the recovery path rather than the
/// ordinary route in. It is the one thing in the whole plan that nothing verifies before use, it
/// names a machine rather than a directory, and mistyping it is indistinguishable from naming a
/// controller that is down.
/// </para>
/// <para>
/// <b>The controller this lands on is not pinned.</b> It answers what forest this is, and selection
/// proceeds from the configuration partition it yields. A run that treated it as the controller to
/// capture from would be reading a whole forest from whichever machine the locator happened to
/// return, which is the behaviour <c>0050</c> exists to replace.
/// </para>
/// </remarks>
public static class ForestBootstrap
{
    /// <summary>
    /// Opens the first connection using the machine's own domain membership.
    /// </summary>
    /// <param name="factory">How a connection is opened, which walks the security ladder.</param>
    /// <param name="machine">What the machine knows about its own domain.</param>
    public static Result<ForestEntry> Start(IDirectoryChannelFactory factory, IMachineDomain machine)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(machine);

        if (!string.IsNullOrWhiteSpace(machine.DnsDomain))
        {
            return Connect(factory, machine.DnsDomain, ForestEntrySource.MachineDnsDomain);
        }

        if (!string.IsNullOrWhiteSpace(machine.NetBiosDomain))
        {
            return Connect(factory, machine.NetBiosDomain, ForestEntrySource.MachineNetBiosDomain);
        }

        return Result<ForestEntry>.Failure(AuditError.Create(
            ErrorCategory.Capture,
            "MachineIsInNoDomain",
            ErrorSeverity.Failed,
            "This machine has no DNS domain suffix and no NetBIOS domain name, so it is not joined "
            + "to a forest and there is nothing for the run to start from automatically. Name a "
            + "domain controller of the forest to audit instead.",
            context: null));
    }

    /// <summary>
    /// Opens the first connection to a name an operator gave, which is the recovery path.
    /// </summary>
    /// <param name="factory">How a connection is opened.</param>
    /// <param name="name">The domain or host name typed by the operator.</param>
    public static Result<ForestEntry> StartFromTypedName(
        IDirectoryChannelFactory factory, string name)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return Connect(factory, name, ForestEntrySource.TypedName);
    }

    /// <summary>
    /// Finds the forest the ordinary way, falling back to a typed name only when that fails.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order is <c>docs/decisions/0053-the-tool-finds-its-own-forest.md</c> and is not an
    /// implementation detail. A machine in a forest already knows its own domain name, so the
    /// ordinary run needs nothing typed at all. Trying a typed name first would make the recovery
    /// path the normal one, and would report a typing mistake as though the forest were unreachable.
    /// </para>
    /// <para>
    /// A typed name is not tried when <see cref="Start"/> succeeded, even if the operator supplied
    /// one - the machine's own forest is the forest, and quietly auditing a different one because a
    /// stale name was left in a field is not a thing this may do.
    /// </para>
    /// </remarks>
    /// <param name="factory">How a connection is opened.</param>
    /// <param name="machine">The machine's own domain names.</param>
    /// <param name="typedName">
    /// A name an operator gave, used only when this machine cannot find a forest of its own. Null
    /// or blank for the ordinary case.
    /// </param>
    public static Result<ForestEntry> Enter(
        IDirectoryChannelFactory factory, IMachineDomain machine, string? typedName)
    {
        ArgumentNullException.ThrowIfNull(factory);
        ArgumentNullException.ThrowIfNull(machine);

        var ownForest = Start(factory, machine);

        if (ownForest.IsSuccess || string.IsNullOrWhiteSpace(typedName))
        {
            return ownForest;
        }

        return StartFromTypedName(factory, typedName);
    }

    /// <summary>
    /// Opens the connection and keeps the failure in the operator's own terms.
    /// </summary>
    /// <remarks>
    /// The failure carries the name that was tried, because the same refusal means different things
    /// depending on where the name came from: a machine's own domain failing to answer is a broken
    /// forest, and a typed name failing to answer may simply be a typo.
    /// </remarks>
    private static Result<ForestEntry> Connect(
        IDirectoryChannelFactory factory, string name, ForestEntrySource source)
    {
        var channel = factory.Connect(name);

        return channel.IsSuccess
            ? new ForestEntry(channel.Value!, name, source)
            : Result<ForestEntry>.Failure(channel.Error!);
    }
}

using SecureAD.Audit.Capture;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// A forest of controllers: which host answers, and what each one holds.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ControllerModel"/> is one controller, and preflight's whole subject is what happens
/// when several domains answer differently - one reachable, one not, one serving the wrong
/// partition. This maps a host name to a controller model and refuses the hosts that are not in
/// the map.
/// </para>
/// <para>
/// <b>It is not a second controller model.</b> Every channel it hands out is one of the models',
/// so the behaviour a channel exhibits - paging, ranges, RootDSE, refused reads - is defined in
/// exactly one place. What is added here is only which host answers at all, which is a fact about
/// a forest rather than about a controller.
/// </para>
/// </remarks>
internal sealed class ForestModel : IDirectoryChannelFactory
{
    private readonly Dictionary<string, ControllerModel> _byHost =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Adds a controller reachable at <paramref name="host"/>.</summary>
    /// <param name="host">The name a run connects to, which for a domain is its DNS name.</param>
    /// <param name="controller">What answers there.</param>
    public ForestModel Answering(string host, ControllerModel controller)
    {
        controller.AnswersTo.Add(host);
        _byHost[host] = controller;
        return this;
    }

    /// <summary>How many connections have been asked for, across every host.</summary>
    /// <remarks>
    /// Counted with <see cref="Interlocked"/> because preflight asks several domains at once, and
    /// a plain increment loses connections under that. A test asserting a domain cost one
    /// connection would then pass while having counted nothing reliable.
    /// </remarks>
    public int ConnectionsAttempted => Volatile.Read(ref _connectionsAttempted);

    private int _connectionsAttempted;

    /// <inheritdoc/>
    public Result<IDirectoryChannel> Connect(CaptureUnit unit)
    {
        ArgumentNullException.ThrowIfNull(unit);

        return Connect(unit.DomainController);
    }

    /// <inheritdoc/>
    public Result<IDirectoryChannel> Connect(string domainController)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainController);

        Interlocked.Increment(ref _connectionsAttempted);

        if (!_byHost.TryGetValue(domainController, out var controller))
        {
            return AuditError.Create(
                ErrorCategory.Capture,
                "ConnectionRungRefused",
                ErrorSeverity.Failed,
                $"{domainController} did not accept a connection on any port: "
                + "The LDAP server is unavailable.",
                context: domainController);
        }

        return controller.Connections().Connect(domainController);
    }
}

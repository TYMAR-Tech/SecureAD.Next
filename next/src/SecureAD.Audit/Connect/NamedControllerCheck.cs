using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// What one named controller answered when it was asked what it serves.
/// </summary>
/// <param name="Host">The host that was asked, as the operator typed it.</param>
/// <param name="RungReached">
/// How protected the connection was, or <see langword="null"/> where nothing answered at all.
/// </param>
/// <param name="ServesTheDomain">
/// Whether the controller published the domain it was named for. A controller that answered and
/// serves something else is a different fault from one that did not answer, and reads differently.
/// </param>
/// <param name="Fault">Why the check failed, or <see langword="null"/> where it did not.</param>
public sealed record NamedControllerAnswer(
    string Host,
    ConnectionSecurityLevel? RungReached,
    bool ServesTheDomain,
    AuditError? Fault)
{
    /// <summary>Whether this controller may be read for the domain it was named for.</summary>
    public bool IsUsable => Fault is null && ServesTheDomain;
}

/// <summary>
/// Proves one controller an operator named, by asking that controller and nothing else.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists rather than another pass over the forest.</b> Checking a typed host used to
/// cost a full discovery - a bootstrap connection, the configuration partition, the candidate list
/// for every domain in the forest - to answer a question about one machine. That is finding
/// <c>F-S41-4</c>. An operator correcting a typo in a nine-domain forest paid for the whole forest
/// each time he pressed the button.
/// </para>
/// <para>
/// <b>It asks the host what it serves rather than asking the forest whether it should.</b> This is
/// the predecessor's <c>ForestDcPreflightService</c> shape, and it answers the question an operator
/// actually asked: <i>is this machine one I can read this domain from</i>. A controller the forest
/// does not list can still answer that, and a controller the forest does list can still be switched
/// off. The forest's list is a description written by replication, and this is the machine itself.
/// </para>
/// <para>
/// <b>What it deliberately does not decide.</b> Whether the forest names this host is a separate
/// fact and stays separately reported - a host that answers and serves the right partition while
/// the forest does not list it is a real and useful signal, not a refusal, and the site column
/// stays <i>not established</i> for it per
/// <c>docs/decisions/0056-the-visual-language-encodes-three-states.md</c>. Whether the run may pin
/// it remains <c>ControllerSelection</c>'s, which refuses an override the forest does not list, and
/// that refusal is unchanged.
/// </para>
/// <para>
/// <b>This file reads and never dispatches</b>, per <c>SerializedDirectoryAccessGateTests</c>.
/// </para>
/// </remarks>
public static class NamedControllerCheck
{
    /// <summary>
    /// Connects to one host and asks whether it serves the domain it was named for.
    /// </summary>
    /// <param name="connections">How the connection to the named host is opened.</param>
    /// <param name="host">The controller the operator named, by DNS host name.</param>
    /// <param name="namingContext">The domain it was named for.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public static Task<NamedControllerAnswer> AskAsync(
        IDirectoryChannelFactory connections,
        string host,
        string namingContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connections);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContext);

        cancellationToken.ThrowIfCancellationRequested();

        var opened = connections.Connect(host);

        if (!opened.IsSuccess)
        {
            // Nothing answered, so nothing is known about this machine - not its security posture,
            // not what it serves. Reporting a rung here would be finding F-S35-1: a claim about a
            // customer's forest the product did not measure.
            return Task.FromResult(new NamedControllerAnswer(
                host, RungReached: null, ServesTheDomain: false, opened.Error!));
        }

        using var channel = opened.Value!;

        var serves = channel.NamingContextsServed.Any(held =>
            string.Equals(held, namingContext, StringComparison.OrdinalIgnoreCase));

        if (serves)
        {
            return Task.FromResult(new NamedControllerAnswer(
                host, channel.SecurityLevel, ServesTheDomain: true, Fault: null));
        }

        return Task.FromResult(new NamedControllerAnswer(
            host,
            channel.SecurityLevel,
            ServesTheDomain: false,
            AuditError.Create(
                ErrorCategory.Capture,
                "NamedControllerDoesNotServeTheDomain",
                ErrorSeverity.Failed,
                $"{host} answered, and it does not hold {namingContext}. It serves "
                + $"{string.Join(", ", channel.NamingContextsServed)}. Reading the domain from a "
                + "controller that does not hold it would produce an empty answer rather than an "
                + "error, so the name is refused here instead.",
                namingContext)));
    }
}

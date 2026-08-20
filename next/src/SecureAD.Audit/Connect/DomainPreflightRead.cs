using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// What one domain answered: the four questions, and its PDC emulator where it could be read.
/// </summary>
internal sealed record DomainAnswers(DomainPreflight Preflight, DomainPdcEmulator? Established);

/// <summary>
/// The preflight questions put to one domain, over one connection to one controller.
/// </summary>
/// <remarks>
/// <para>
/// <b>This file reads, and never dispatches.</b> That division is the whole reason it exists
/// separately from <see cref="Preflight"/>: <c>SerializedDirectoryAccessGateTests</c> holds that a
/// file may fan work out or speak to a directory, never both, because two requests in flight
/// against one controller compete for a single budget of paged-search state and can silently
/// truncate each other. Everything here is strictly serial and must stay so - the concurrency, when
/// there is any, belongs to the caller and is expressed over domains that sit on different
/// controllers.
/// </para>
/// <para>
/// <b>It was part of <see cref="Preflight"/> until 2026-08-16.</b> Splitting it changed no
/// behaviour; it made the rule above enforceable on a file that had never been watched, because the
/// guard matched only raw LDAP type names and everything here speaks through
/// <see cref="IDirectoryChannel"/>.
/// </para>
/// </remarks>
internal static class DomainPreflightRead
{
    /// <summary>
    /// The container each domain's fine-grained password policies live in, relative to the domain's
    /// naming context.
    /// </summary>
    /// <remarks>
    /// Composed here rather than in <see cref="CaptureSearchRequestFactory"/>, so that nothing in
    /// the request factory has to know the shape of a domain partition's name. That is the same
    /// division <c>ForestPartitions</c> makes for the Partitions container.
    /// </remarks>
    private const string PasswordSettingsContainerPrefix =
        "CN=Password Settings Container,CN=System,";

    /// <summary>
    /// One domain: connect, confirm the partition, read the Password Settings Container.
    /// </summary>
    /// <remarks>
    /// A failure at any point stops this domain and never the pass. What it does not do is invent
    /// answers to the questions it did not reach - they stay
    /// <see cref="PreflightAnswer.NotAsked"/>, because a question nobody put has no answer and
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids rendering one.
    /// </remarks>
    /// <param name="connections">How a connection to this domain's controller is opened.</param>
    /// <param name="unit">The domain being asked, and the controller it is pinned to.</param>
    /// <param name="plan">The forest as discovery described it.</param>
    /// <param name="cancellationToken">Cancellation for a check an operator stopped.</param>
    public static async Task<DomainAnswers> AskAsync(
        IDirectoryChannelFactory connections,
        CaptureUnit unit,
        ForestPlan plan,
        CancellationToken cancellationToken)
    {
        var opened = connections.Connect(unit);
        if (!opened.IsSuccess)
        {
            // Nothing answered, so nothing is known about this controller - not its security
            // posture, not whether it serves the partition, not what it would let this account
            // read. Reporting a rung here would be finding F-S35-1: a claim about a customer's
            // forest that the product did not measure.
            return new DomainAnswers(
                new DomainPreflight(
                    unit.NamingContext,
                    unit.DomainController,
                    RungReached: null,
                    PreflightAnswer.NotAsked,
                    PreflightAnswer.NotAsked,
                    [opened.Error!]),
                Established: null);
        }

        using var channel = opened.Value!;

        var faults = new List<AuditError>();

        var confirmed = unit.ConfirmServedBy(channel.NamingContextsServed);
        if (!confirmed.IsSuccess)
        {
            faults.Add(confirmed.Error!);
        }

        var passwordSettings = await ReadPasswordSettingsContainerAsync(
            channel, unit, faults, cancellationToken).ConfigureAwait(false);

        // One extra base request on a connection that already exists, per 0055, which is why it
        // costs no connection of its own. A read that fails does not fail the domain: what is lost
        // is the ability to keep the audit off this domain's busiest machine, and that loss is
        // carried as CouldNotBeRead rather than rendered as "holds no role".
        var established = await ForestRoles
            .EstablishPdcEmulatorAsync(
                channel, unit.NamingContext, plan.Topology, cancellationToken)
            .ConfigureAwait(false);

        return new DomainAnswers(
            new DomainPreflight(
                unit.NamingContext,
                channel.DomainController,
                channel.SecurityLevel,
                confirmed.IsSuccess ? PreflightAnswer.Yes : PreflightAnswer.No,
                passwordSettings,
                faults),
            established);
    }

    /// <summary>
    /// The fourth question: could this account read the domain's Password Settings Container.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A failure is recorded as a degradation rather than as a fault that stops the run.
    /// <c>0048</c> states that Enterprise Admins is not required and that the supported posture is
    /// an ordinary account with read access delegated per domain, so a run that refused to start
    /// over one container would refuse the posture that record supports. What the answer buys is
    /// paid later: a report that says it could not tell, instead of one saying the domain has no
    /// fine-grained password policy when it has several.
    /// </para>
    /// <para>
    /// A cancellation is not an answer and is not caught here. An operator who stopped the check
    /// has not discovered anything about the container.
    /// </para>
    /// </remarks>
    private static async Task<PreflightAnswer> ReadPasswordSettingsContainerAsync(
        IDirectoryChannel channel,
        CaptureUnit unit,
        List<AuditError> faults,
        CancellationToken cancellationToken)
    {
        var container = PasswordSettingsContainerPrefix + unit.NamingContext;

        try
        {
            await channel
                .SendAsync(
                    CaptureSearchRequestFactory.ForPasswordSettingsContainer(container),
                    cancellationToken)
                .ConfigureAwait(false);

            return PreflightAnswer.Yes;
        }
        catch (DirectoryException refused)
        {
            faults.Add(AuditError.Create(
                ErrorCategory.Capture,
                "PasswordSettingsContainerUnreadable",
                ErrorSeverity.Degraded,
                $"{container} could not be read from {channel.DomainController}: "
                + refused.Message
                + " This run can still read the domain. What it will not be able to say is "
                + "whether the domain has any fine-grained password policy, because a caller "
                + "without access to that container reads it as empty rather than as denied - so "
                + "the report will say it could not tell rather than that there is none.",
                context: unit.NamingContext));

            return PreflightAnswer.No;
        }
    }
}

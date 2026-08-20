using SecureAD.Audit.Capture;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Walks the connection-security ladder: tries each permitted rung in order and stops at the first
/// that answers.
/// </summary>
/// <remarks>
/// <para>
/// This is the ladder's descent, separated from the thing that actually opens a socket so that the
/// descent can be checked. There is no forest in a build agent, so the alternative was a rule
/// stated in prose beside code nothing exercised - and the rule here is the one that decides
/// whether a customer's evidence crossed a protected channel.
/// </para>
/// <para>
/// <b>What it will not do.</b> It will not try a rung the run did not permit, and the filtering is
/// <see cref="ConnectionSecurityLadder.PermittedBy"/>'s rather than a condition inside the loop -
/// so there is one statement of what a run may do rather than two that could disagree. It will not
/// re-order the rungs, and it will not carry on past the first success.
/// </para>
/// </remarks>
public static class ConnectionLadderWalk
{
    /// <summary>
    /// Tries each permitted rung from the top, and returns the first connection that opened.
    /// </summary>
    /// <param name="domainController">The host being connected to. Named in every failure.</param>
    /// <param name="allowance">What the auditor declared before the run started.</param>
    /// <param name="log">Where the rung that answered is recorded, by controller.</param>
    /// <param name="attempt">
    /// Opens a connection at one rung, or says why it could not. Called at most once per rung, in
    /// order, and not at all once one has succeeded.
    /// </param>
    public static Result<IDirectoryChannel> Descend(
        string domainController,
        UnprotectedConnectionAllowance allowance,
        ConnectionSecurityLog log,
        Func<ConnectionSecurityRung, Result<IDirectoryChannel>> attempt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domainController);
        ArgumentNullException.ThrowIfNull(allowance);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(attempt);

        var refused = 0;
        var declined = new List<string>();
        var failures = new List<AuditError>();

        foreach (var rung in ConnectionSecurityLadder.PermittedBy(allowance))
        {
            var outcome = attempt(rung);
            if (outcome.IsSuccess)
            {
                log.Record(domainController, rung.Level, refused);
                return outcome;
            }

            refused++;
            declined.Add($"{rung.Level}: {outcome.Error!.Description}");
            failures.Add(outcome.Error!);
        }

        var tried = string.Join("; ", declined) + ".";

        // Nothing came back from this machine at any rung, so nothing about it was observed. What
        // is wrong is between here and there - a name, a route, a firewall, a switched-off server -
        // and none of it is a fact about the customer's forest.
        if (!failures.Any(failure =>
            ConnectionFailureReason.ProvesTheControllerAnswered(failure.Code)))
        {
            var timedOut = failures.All(failure => ConnectionFailureReason.Is(
                failure.Code, ConnectionFailureReason.DidNotAnswerInTime));

            return Refuse(
                log,
                "DomainControllerDidNotAnswer",
                $"{domainController} did not answer on any port that was tried, so nothing is "
                + "known about it - not what it accepts, and not whether it is a domain controller "
                + (timedOut
                    ? "at all. Every attempt ran out of time rather than being refused, which is "
                    + "what a firewall dropping packets looks like from here. "
                    : "at all. The name may not resolve, the host may be switched off, or a "
                    + "firewall may be in the way; from here those look alike. ")
                + "It was tried: " + tried,
                domainController);
        }

        // It answered, and it would not have this account. Descending the ladder never had a
        // chance of helping, and the run's protection has nothing to do with it.
        var rejected = failures.FirstOrDefault(failure => ConnectionFailureReason.Is(
            failure.Code, ConnectionFailureReason.CredentialsWereRejected));

        if (rejected is not null)
        {
            return Refuse(
                log,
                "CredentialsWereRejected",
                $"{domainController} answered and would not accept the account this run is using. "
                + "That is a credential, not a network fault and not a weakness in the forest: the "
                + "controller was reached and it declined to authenticate. It was tried: " + tried,
                domainController);
        }

        return allowance.IsDeclared
            ? Refuse(
                log,
                "DomainControllerAcceptedNoConnection",
                $"{domainController} accepted no connection on any rung of the ladder, including "
                + "an unprotected one, which this run was permitted to use. It was tried: " + tried,
                domainController)
            : Refuse(
                log,
                "DomainControllerAcceptedNoProtectedConnection",
                $"{domainController} accepted no protected connection, and this run was not "
                + "permitted to use an unprotected one. That is a finding about the forest as much "
                + "as about this run: a controller accepting nothing signed leaves its LDAP traffic "
                + "open to alteration in transit. It was tried: " + tried,
                domainController);
    }

    /// <summary>
    /// Ends a descent that reached the bottom of the permitted rungs, recording the failure in the
    /// log as well as returning it.
    /// </summary>
    /// <remarks>
    /// Both, rather than either. The caller acts on the returned error, and the log is what a
    /// preflight reads afterwards to say how many controllers answered and how many did not - a
    /// question it could not answer from a list of the ones that did.
    /// </remarks>
    private static Result<IDirectoryChannel> Refuse(
        ConnectionSecurityLog log, string reason, string description, string domainController)
    {
        var error = AuditError.Create(
            ErrorCategory.Capture, reason, ErrorSeverity.Failed, description, domainController);

        log.RecordFailure(error);
        return error;
    }
}

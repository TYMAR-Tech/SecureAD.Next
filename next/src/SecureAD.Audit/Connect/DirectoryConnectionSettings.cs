using SecureAD.Audit.Capture;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Everything a run decides about how it connects, decided once before anything is read.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A1, and docs/layers/connect/how-a-connection-is-opened.md was the document
/// bound to it.
/// It is short on purpose. Every field here is one something reads: a setting nothing consumes is
/// dead weight that looks like a lever, which is the failure inventory row B1 refuses to carry
/// forward on the capture side.
/// </para>
/// <para>
/// <b>What is not here.</b> A choice of transport, because that is the ladder's and the ladder is
/// not configurable - an operator who could pin the connection to one rung could pin it to the
/// bottom one without declaring anything. A choice of authentication, because it is Negotiate. A
/// referral setting, because there is one referral policy and
/// <c>CaptureSearchRequestFactory</c> owns it. And nothing about which controller to use, which is
/// the plan's rather than the connection's.
/// </para>
/// <para>
/// <b>Nothing here is persisted between runs.</b> In particular the allowance is not: see
/// <see cref="UnprotectedConnectionAllowance"/>.
/// </para>
/// </remarks>
/// <param name="Credential">Who the run binds as.</param>
/// <param name="Allowance">
/// Whether this run was declared permitted to read over an unprotected connection. Required rather
/// than defaulted, so a run that permits nothing has said so - gate 1's second half forbids a
/// collaborator that can be omitted, and this is a collaborator whose absence would be a decision.
/// </param>
/// <param name="ConnectTimeout">
/// How long one attempt at one rung may take before it is abandoned and the next rung is tried.
/// This bounds the whole ladder walk, so it is short: four rungs at thirty seconds each, against
/// twelve controllers, is a preflight that takes a quarter of an hour to discover a typo in a host
/// name.
/// </param>
/// <param name="ResponseTimeout">
/// How long the client waits for a controller to answer one request, once a connection is open.
/// A different question from <paramref name="ConnectTimeout"/>, and a much longer answer.
/// </param>
public sealed record DirectoryConnectionSettings(
    DirectoryCredential Credential,
    UnprotectedConnectionAllowance Allowance,
    TimeSpan ConnectTimeout,
    TimeSpan ResponseTimeout)
{
    /// <summary>
    /// The connect timeout used when a run does not state one.
    /// </summary>
    /// <remarks>
    /// Ten seconds, which is the timeout the previous product's preflight used per controller and
    /// the one thing about that component the map recorded as worth keeping. A controller that has
    /// not completed a TCP connection and a bind in ten seconds is not a controller a multi-hour
    /// capture should be reading from.
    /// </remarks>
    public static TimeSpan DefaultConnectTimeout { get; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// How much longer than the server's own search limit the client waits.
    /// </summary>
    /// <remarks>
    /// The server's limit is measured at the server. The client's has to cover that plus the round
    /// trip and the transfer of a thousand objects with their security descriptors, so waiting
    /// exactly <see cref="ServerLimits.QueryDuration"/> would still give up first on a page the
    /// controller answered just in time.
    /// </remarks>
    public static TimeSpan ResponseMargin { get; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// The per-request response timeout used when a run does not state one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It exists because there was only one budget and it was the connect one.</b>
    /// <c>LdapConnection.Timeout</c> is not a connect budget in the way its name suggests: the
    /// platform's client passes the same field to <c>ldap_connect</c> and to every
    /// <c>BeginSendRequest</c>, so a value chosen for opening a socket silently became the time a
    /// search page was allowed to take. Ten seconds is ample for the first and absurd for the
    /// second, and the symptom on a customer's forest would read as a slow directory rather than as
    /// a client that stopped waiting.
    /// </para>
    /// <para>
    /// <b>The floor is the server's own limit, not a guess.</b> Capture puts
    /// <see cref="ServerLimits.QueryDuration"/> on every search it sends, which is Microsoft's
    /// documented <c>MaxQueryDuration</c> default and the longest a controller will lawfully spend
    /// assembling one page. A client waiting less than that abandons work the controller was still
    /// doing - and <see cref="RetryPolicy.ClientTimeout"/> answers a client timeout by reading the
    /// whole naming context again from its first page, so the cost of being impatient is a re-read
    /// of a partition rather than a retried page.
    /// </para>
    /// <para>
    /// <b>What it costs.</b> A controller that has genuinely stopped answering now holds a capture
    /// for two and a half minutes per request rather than ten seconds. That is the right way round
    /// - the alternative is abandoning pages that were about to arrive - but it is a real change in
    /// how a bad run feels, and it is the reason the connect budget stays short and separate.
    /// </para>
    /// </remarks>
    public static TimeSpan DefaultResponseTimeout { get; } =
        ServerLimits.QueryDuration + ResponseMargin;

    /// <summary>
    /// Settings for a run binding as the logged-on user, refusing unprotected connections.
    /// </summary>
    /// <remarks>
    /// The shape of an ordinary run, named so that the ordinary case is not assembled by hand at
    /// every call site and quietly assembled differently at one of them.
    /// </remarks>
    public static DirectoryConnectionSettings Default { get; } = new(
        DirectoryCredential.LoggedOnUser,
        UnprotectedConnectionAllowance.Refused,
        DefaultConnectTimeout,
        DefaultResponseTimeout);
}

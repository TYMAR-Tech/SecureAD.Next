namespace SecureAD.Audit.Connect;

/// <summary>
/// Everything a run decides about how it connects, decided once before anything is read.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A1, and <c>docs/next/S-14-the-connection.md</c> is the document bound to it.
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
public sealed record DirectoryConnectionSettings(
    DirectoryCredential Credential,
    UnprotectedConnectionAllowance Allowance,
    TimeSpan ConnectTimeout)
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
    /// Settings for a run binding as the logged-on user, refusing unprotected connections.
    /// </summary>
    /// <remarks>
    /// The shape of an ordinary run, named so that the ordinary case is not assembled by hand at
    /// every call site and quietly assembled differently at one of them.
    /// </remarks>
    public static DirectoryConnectionSettings Default { get; } = new(
        DirectoryCredential.LoggedOnUser,
        UnprotectedConnectionAllowance.Refused,
        DefaultConnectTimeout);
}

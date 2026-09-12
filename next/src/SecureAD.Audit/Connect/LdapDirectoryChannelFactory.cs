using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Kernel;

namespace SecureAD.Audit.Connect;

/// <summary>
/// The one place in this product that opens a connection to a domain controller.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row A2, and docs/layers/connect/how-a-connection-is-opened.md was the document
/// bound to it.
/// It walks the ladder recorded at
/// <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c>, binds with Negotiate,
/// applies the referral policy, reads the controller's RootDSE, and hands back a channel.
/// </para>
/// <para>
/// <b>One owner, held by a build failure.</b> <c>ConnectionSecurityGateTests</c> fails the build if
/// an <see cref="LdapConnection"/> is constructed, or a transport-security option assigned,
/// anywhere else in the tree. That is the same shape as the referral policy's guard and it exists
/// for the same reason: the correctness is invisible at the point where it is lost. A second place
/// that opens a connection is a second ladder, and the first sign the two disagree is a customer's
/// evidence having crossed a network unprotected with nothing saying so.
/// </para>
/// <para>
/// <b>Why the factory rather than a connection is what capture is handed.</b> One line of the
/// failure policy at docs/layers/audit/limits-and-failures.md: a failure that ends the conversation with
/// a controller takes the paging bookmark with it, and the answer is to read the naming context
/// again from its first page on a <i>fresh connection</i>. Something handed a connection could not
/// do that.
/// </para>
/// </remarks>
public sealed class LdapDirectoryChannelFactory : IDirectoryChannelFactory
{
    private readonly DirectoryConnectionSettings _settings;
    private readonly ConnectionSecurityLog _log;

    /// <summary>
    /// Creates the factory for one run.
    /// </summary>
    /// <param name="settings">
    /// How this run connects, including the declared allowance. Required rather than defaulted: a
    /// run that permits nothing has said so.
    /// </param>
    /// <param name="log">
    /// Where the rung each controller answered on is recorded. Required for the same reason - a
    /// factory that could be built without one would be a product that sometimes did not know what
    /// its own evidence crossed.
    /// </param>
    public LdapDirectoryChannelFactory(
        DirectoryConnectionSettings settings, ConnectionSecurityLog log)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(log);

        _settings = settings;
        _log = log;
    }

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

        return ConnectionLadderWalk.Descend(
            domainController,
            _settings.Allowance,
            _log,
            rung => Open(domainController, rung));
    }

    /// <summary>
    /// Opens and binds one connection at one rung, and asks the controller about itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the part no test reaches, and that is stated rather than glossed.</b> There is no
    /// domain controller in a build agent. What is checked is everything around it: that the ladder
    /// is descended in order and stops where it should - <see cref="ConnectionLadderWalk"/> - and
    /// that nothing else in the tree does any of this, which is the build guard's. The rest waits
    /// on the lab session that inventory row B20 carries.
    /// </para>
    /// <para>
    /// <b>The RootDSE read is part of opening, not a later question.</b> A connection whose
    /// capability list was never read cannot say whether the domain-scope control is worth sending,
    /// and a capture pass refuses to run on one - so a channel that could exist without having
    /// asked would be a channel that fails later for a reason decided here.
    /// </para>
    /// </remarks>
    private Result<IDirectoryChannel> Open(string domainController, ConnectionSecurityRung rung)
    {
        LdapConnection? connection = null;

        try
        {
            var identifier = new LdapDirectoryIdentifier(
                domainController, rung.Port, fullyQualifiedDnsHostName: true, connectionless: false);

            connection = new LdapConnection(identifier, _settings.Credential.ForBind())
            {
                AuthType = AuthType.Negotiate,
                Timeout = _settings.ConnectTimeout,
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = rung.UseTls;
            connection.SessionOptions.Signing = rung.Sign;
            connection.SessionOptions.Sealing = rung.Seal;

            CaptureSearchRequestFactory.ApplyReferralPolicy(connection.SessionOptions);

            connection.Bind();

            var rootDse = ReadRootDse(connection);

            var channel = new LdapDirectoryChannel(
                connection,
                domainController,
                rung.Level,
                rootDse.SupportedControls,
                rootDse.NamingContexts);

            connection = null;
            return channel;
        }
        catch (DirectoryException failure)
        {
            connection?.Dispose();

            // Classified rather than flattened. What the directory said is the difference between
            // "check your network" and "your password expired", and between a security finding
            // about the forest and a claim this run has no right to make.
            return AuditError.Create(
                ErrorCategory.Capture,
                ConnectionFailureReason.Of(failure),
                ErrorSeverity.Failed,
                $"{domainController} did not accept a {rung.Level} connection on port {rung.Port}: "
                + failure.Message,
                context: domainController);
        }
    }

    /// <summary>
    /// Reads the two things about a controller that the rest of a capture depends on: which controls
    /// it advertises, and which partitions it serves.
    /// </summary>
    private static (IReadOnlyList<string> SupportedControls, IReadOnlyList<string> NamingContexts)
        ReadRootDse(LdapConnection connection)
    {
        var response = (SearchResponse)connection.SendRequest(
            CaptureSearchRequestFactory.ForRootDse());

        if (response.ResultCode != ResultCode.Success || response.Entries.Count == 0)
        {
            throw new LdapException(
                (int)response.ResultCode,
                "The controller did not answer a read of its own RootDSE. Without it neither the "
                + "controls it advertises nor the partitions it serves are known, and a capture "
                + "pass refuses to run on a connection that cannot say.");
        }

        var entry = response.Entries[0];

        return (Values(entry, "supportedControl"), Values(entry, "namingContexts"));
    }

    private static List<string> Values(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName))
            return [];

        return entry.Attributes[attributeName].GetValues(typeof(string)).Cast<string>().ToList();
    }
}

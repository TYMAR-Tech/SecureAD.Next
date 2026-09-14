using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Resources;
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
    private static readonly ResourceManager Wording = new(
        "SecureAD.Audit.Resources.ConnectionFailures", typeof(LdapDirectoryChannelFactory).Assembly);

    private readonly DirectoryConnectionSettings _settings;
    private readonly ConnectionSecurityLog _log;
    private readonly Action<LdapConnection> _bind;
    private readonly Func<LdapConnection, SearchRequest, SearchResponse> _sendRequest;

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
        : this(settings, log, connection => connection.Bind(),
            (connection, request) => (SearchResponse)connection.SendRequest(request))
    {
    }

    /// <summary>
    /// Creates the factory with replaceable LDAP operations for offline verification of the
    /// bind/RootDSE boundary. Connection creation, protection, timeouts and disposal stay here.
    /// </summary>
    /// <param name="settings">How this run connects.</param>
    /// <param name="log">Where connection outcomes are recorded.</param>
    /// <param name="bind">Authenticates the configured connection, or throws a directory error.</param>
    /// <param name="sendRequest">Sends the RootDSE request, or throws a directory error.</param>
    public LdapDirectoryChannelFactory(
        DirectoryConnectionSettings settings,
        ConnectionSecurityLog log,
        Action<LdapConnection> bind,
        Func<LdapConnection, SearchRequest, SearchResponse> sendRequest)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(bind);
        ArgumentNullException.ThrowIfNull(sendRequest);

        _settings = settings;
        _log = log;
        _bind = bind;
        _sendRequest = sendRequest;
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
    /// The LDAP calls can be replaced in offline tests, so a successful bind followed by a failed
    /// RootDSE read exercises this boundary rather than an invented ladder outcome. Real transport
    /// negotiation still requires lab verification; synthetic success is not evidence of that.
    /// </para>
    /// <para>
    /// <b>The RootDSE read is part of opening, not a later question.</b> A connection whose
    /// capability list was never read cannot say whether the domain-scope control is worth sending,
    /// and a capture pass refuses to run on one - so a channel that could exist without having
    /// asked would be a channel that fails later for a reason decided here.
    /// </para>
    /// <para>
    /// <b>Two budgets on one property, moved between them at the bind.</b>
    /// <c>LdapConnection.Timeout</c> looks like a connect timeout and is not one: the platform's
    /// client hands the same field to <c>ldap_connect</c> and to every <c>BeginSendRequest</c>. So
    /// it is held at <see cref="DirectoryConnectionSettings.ConnectTimeout"/> while the socket is
    /// opened and the bind is done - which is what keeps a ladder walk against an unreachable host
    /// short - and raised to <see cref="DirectoryConnectionSettings.ResponseTimeout"/> the moment
    /// there is a controller on the other end, because from then on every use of it is a wait for
    /// an answer rather than a wait for a connection. Setting it once, at construction, gave every
    /// search page of a multi-hour capture the ten seconds meant for opening a socket.
    /// </para>
    /// </remarks>
    private Result<IDirectoryChannel> Open(string domainController, ConnectionSecurityRung rung)
    {
        LdapConnection? connection = null;
        var bound = false;

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

            _bind(connection);
            bound = true;

            // The connection is open and a controller answered it. Everything after this line is a
            // request waiting on an answer, and a page of a thousand objects with their security
            // descriptors is not a ten-second job on a forest of any size.
            connection.Timeout = _settings.ResponseTimeout;

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
            // A bind that succeeded cannot become a refusal of protection because a later read
            // failed, even if that read itself asks for stronger authentication (P-214).
            return AuditError.Create(
                ErrorCategory.Capture,
                bound ? ConnectionFailureReason.RootDseReadFailed : ConnectionFailureReason.Of(failure),
                ErrorSeverity.Failed,
                bound
                    ? Format("RootDseReadFailed", domainController, rung.Level, Details(failure))
                    : Format("ConnectionRejected", domainController, rung.Level, rung.Port, Details(failure)),
                context: domainController);
        }
        finally
        {
            connection?.Dispose();
        }
    }

    /// <summary>
    /// Reads the two things about a controller that the rest of a capture depends on: which controls
    /// it advertises, and which partitions it serves.
    /// </summary>
    private (IReadOnlyList<string> SupportedControls, IReadOnlyList<string> NamingContexts)
        ReadRootDse(LdapConnection connection)
    {
        var response = _sendRequest(connection,
            CaptureSearchRequestFactory.ForRootDse());

        if (response.ResultCode != ResultCode.Success)
            throw new DirectoryOperationException(response);

        if (response.Entries.Count == 0)
            throw new DirectoryException(Format("RootDseMissing"));

        var entry = response.Entries[0];

        return (Values(entry, "supportedControl"), Values(entry, "namingContexts"));
    }

    private static string Details(DirectoryException failure)
    {
        var response = (failure as DirectoryOperationException)?.Response;
        var message = failure.Message;
        if (!string.IsNullOrWhiteSpace(response?.ErrorMessage)
            && !message.Contains(response.ErrorMessage, StringComparison.Ordinal))
            message += " " + response.ErrorMessage;

        int? code = response is not null ? (int)response.ResultCode
            : failure is LdapException ldap ? ldap.ErrorCode : null;

        return code is { } result
            ? Format("LdapResult", (ResultCode)result, result, message)
            : message;
    }

    private static string Format(string key, params object[] values) =>
        string.Format(CultureInfo.CurrentCulture,
            Wording.GetString(key, CultureInfo.CurrentUICulture)
                ?? throw new InvalidOperationException(key), values);

    private static List<string> Values(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName))
            return [];

        return entry.Attributes[attributeName].GetValues(typeof(string)).Cast<string>().ToList();
    }
}

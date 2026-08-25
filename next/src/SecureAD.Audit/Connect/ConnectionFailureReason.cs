using System.DirectoryServices.Protocols;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Why one connection attempt failed, as far as the protocol is willing to say.
/// </summary>
/// <remarks>
/// <para>
/// <b>These exist because "it did not connect" is four different problems with four different
/// remedies.</b> A controller that never answered is a network, DNS or firewall matter. One that
/// answered and rejected the credentials is a password. One that answered and demanded better
/// protection is a finding about the forest. One whose TLS failed is a certificate. Telling an
/// operator to check his network when his password expired sends him hunting for a fault that is
/// not there.
/// </para>
/// <para>
/// <b>The distinction was being thrown away.</b> Every failure was caught as a
/// <see cref="DirectoryException"/> and flattened into a message, and the code underneath it -
/// which is precisely what separates these - was discarded. The visible cost was a false security
/// claim: a run whose credentials were rejected reported that the controller <i>accepted nothing
/// signed</i>, which accuses a customer's forest of a weakness on the strength of a stale password.
/// That is the shape of <c>F-S35-1</c>, and
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids it.
/// </para>
/// <para>
/// <b>What this cannot tell apart.</b> A name that does not resolve and a host that is switched off
/// both arrive as <c>ServerDown</c>. Separating them means resolving the name deliberately, which is
/// a further act and not one this makes.
/// </para>
/// </remarks>
internal static class ConnectionFailureReason
{
    /// <summary>Nothing answered at that address.</summary>
    public const string DidNotAnswer = "ControllerDidNotAnswer";

    /// <summary>Something is there and did not reply in time.</summary>
    public const string DidNotAnswerInTime = "ControllerDidNotAnswerInTime";

    /// <summary>The controller answered, and would not accept this account.</summary>
    public const string CredentialsWereRejected = "CredentialsWereRejected";

    /// <summary>The controller answered, and demanded protection this rung did not offer.</summary>
    public const string ProtectionWasRefused = "ProtectionWasRefused";

    /// <summary>The connection could not be established, so nothing about it was observed.</summary>
    public const string ProtectedChannelFailed = "ProtectedChannelCouldNotBeEstablished";

    /// <summary>It failed, and the protocol did not say anything this code understands.</summary>
    public const string Refused = "ConnectionRungRefused";

    /// <summary>Nothing answered at that address, so nothing about it was observed.</summary>
    private const int ServerDown = 81;

    /// <summary>Something is there, and it did not reply inside the timeout.</summary>
    private const int TimedOut = 85;

    /// <summary>The connection could not be established. Says nothing about the server.</summary>
    private const int ConnectError = 91;

    /// <summary>The controller answered and would not authenticate this account (LDAP 49).</summary>
    private const int InvalidCredentials = 49;

    /// <summary>The controller answered and demanded stronger authentication (LDAP 8).</summary>
    private const int StrongerAuthRequired = 8;

    /// <summary>The controller answered and demanded confidentiality (LDAP 13).</summary>
    private const int ConfidentialityRequired = 13;

    /// <summary>
    /// Classifies a failure by what the directory said, not by what it looked like.
    /// </summary>
    /// <remarks>
    /// Anything unrecognised falls to <see cref="Refused"/>, which carries no claim about the
    /// controller. An unknown code guessed into a security finding is the fault this file exists to
    /// remove, so the unknown case says less rather than more.
    /// </remarks>
    /// <param name="failure">What the connection attempt threw.</param>
    public static string Of(DirectoryException failure) => failure switch
    {
        LdapException { ErrorCode: ServerDown } => DidNotAnswer,
        LdapException { ErrorCode: TimedOut } => DidNotAnswerInTime,
        LdapException { ErrorCode: ConnectError } => ProtectedChannelFailed,
        LdapException { ErrorCode: InvalidCredentials } => CredentialsWereRejected,
        LdapException { ErrorCode: StrongerAuthRequired } => ProtectionWasRefused,
        LdapException { ErrorCode: ConfidentialityRequired } => ProtectionWasRefused,

        // A DirectoryOperationException is a response: the controller answered and said no.
        DirectoryOperationException => ProtectionWasRefused,

        _ => Refused,
    };

    /// <summary>
    /// Whether a failure proves the controller answered at all.
    /// </summary>
    /// <remarks>
    /// The ladder may only describe what a controller accepts if something came back from it. This
    /// is that test, and it is deliberately strict: an unrecognised failure does not count as an
    /// answer, because a security claim resting on a code nobody classified is a claim the product
    /// did not measure.
    /// <para>
    /// <see cref="ProtectedChannelFailed"/> is not on this list, and that is the whole of
    /// <c>D-4</c>. It carries LDAP 91, which Microsoft defines as <i>"cannot establish the
    /// connection"</i> - a failure on this side of the wire. It was listed here on the strength of a
    /// comment reading <i>in practice, TLS</i>, which would have meant the controller answered and
    /// negotiated badly. On Microsoft's wording nothing came back at all, and <c>0018</c> says a
    /// failure this side may not carry a finding.
    /// </para>
    /// </remarks>
    /// <param name="code">The <c>Category.Reason</c> code of a failed attempt.</param>
    public static bool ProvesTheControllerAnswered(string code) =>
        Is(code, CredentialsWereRejected)
        || Is(code, ProtectionWasRefused);

    /// <summary>Whether a code carries this reason.</summary>
    /// <param name="code">The <c>Category.Reason</c> code of a failed attempt.</param>
    /// <param name="reason">One of the reasons named here.</param>
    public static bool Is(string code, string reason) =>
        code.EndsWith('.' + reason, StringComparison.Ordinal);
}

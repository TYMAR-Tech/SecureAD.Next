using SecureAD.Evidence;

namespace SecureAD.Audit.Connect;

/// <summary>
/// One rung of the connection-security ladder: a named level, the port it uses, and what it asks
/// the transport for.
/// </summary>
/// <param name="Level">The level recorded against a controller if this rung is the one that answers.</param>
/// <param name="Port">The TCP port this rung connects to.</param>
/// <param name="UseTls">Whether TLS is established before anything is sent.</param>
/// <param name="Sign">Whether the SASL layer is asked to sign - integrity.</param>
/// <param name="Seal">Whether the SASL layer is asked to encrypt - confidentiality.</param>
/// <param name="RequiresDeclaredAllowance">
/// Whether this rung may be attempted only where the run carried a declared allowance. True on
/// exactly one rung, and <see cref="ConnectionSecurityLadder"/> asserts that.
/// </param>
public sealed record ConnectionSecurityRung(
    ConnectionSecurityLevel Level,
    int Port,
    bool UseTls,
    bool Sign,
    bool Seal,
    bool RequiresDeclaredAllowance);

/// <summary>
/// The ordered list of ways this product will connect to a domain controller, most protected first.
/// </summary>
/// <remarks>
/// <para>
/// This is <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c> expressed as
/// data, and docs/layers/connect/the-connection-ladder.md was the document bound to it.
/// </para>
/// <para>
/// <b>Why a list rather than a chain of branches.</b> Written as if/else - try LDAPS, else try
/// signing, else give up - a fourth way of connecting is an edit to every place that assumed there
/// were three. Written as a list it is one entry. That matters here more than it sounds, because
/// the set of acceptable transports is decided by other people: Windows Server 2025 changed the
/// default posture for new deployments
/// (<see href="https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing">LDAP signing
/// for Active Directory Domain Services</see>), and it will change again.
/// </para>
/// <para>
/// <b>What is not here.</b> A simple bind. Authentication is Negotiate on every rung, so no
/// credential crosses the wire in clear text at any point: Microsoft's account of a simple bind on
/// port 389 is that <i>"There's no security for these sessions. This is because credentials are
/// transmitted in clear text"</i>
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023">LDAP
/// session security settings and requirements after ADV190023 is installed</see>). A rung that did
/// that would not be a lower rung; it would be a different product.
/// </para>
/// </remarks>
public static class ConnectionSecurityLadder
{
    /// <summary>The port LDAP over TLS listens on.</summary>
    public const int LdapsPort = 636;

    /// <summary>The port plain LDAP listens on, which the SASL rungs protect from inside.</summary>
    public const int LdapPort = 389;

    /// <summary>
    /// The rungs, in the order they are tried. First that answers wins; nothing below the one that
    /// answered is attempted.
    /// </summary>
    public static IReadOnlyList<ConnectionSecurityRung> Rungs { get; } =
    [
        new(ConnectionSecurityLevel.Ldaps, LdapsPort, UseTls: true, Sign: false, Seal: false,
            RequiresDeclaredAllowance: false),
        new(ConnectionSecurityLevel.SignedAndSealed, LdapPort, UseTls: false, Sign: true, Seal: true,
            RequiresDeclaredAllowance: false),
        new(ConnectionSecurityLevel.Signed, LdapPort, UseTls: false, Sign: true, Seal: false,
            RequiresDeclaredAllowance: false),
        new(ConnectionSecurityLevel.Unprotected, LdapPort, UseTls: false, Sign: false, Seal: false,
            RequiresDeclaredAllowance: true),
    ];

    /// <summary>
    /// The rungs this run is permitted to attempt, in order.
    /// </summary>
    /// <remarks>
    /// The bottom rung is filtered out here rather than skipped inside the connecting loop, so that
    /// there is one statement of what a run may do and the loop has no opinion about it.
    /// </remarks>
    /// <param name="allowance">What the auditor declared before the run started.</param>
    public static IEnumerable<ConnectionSecurityRung> PermittedBy(
        UnprotectedConnectionAllowance allowance)
    {
        ArgumentNullException.ThrowIfNull(allowance);

        return Rungs.Where(r => !r.RequiresDeclaredAllowance || allowance.IsDeclared);
    }
}

using System.Net;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Who a capture binds to a domain controller as.
/// </summary>
/// <remarks>
/// <para>
/// This is half of inventory row A1, and docs/layers/connect/how-a-connection-is-opened.md was the
/// document bound
/// to it. There are two answers and no third: the account the product is already running under, or
/// an account an operator typed in for this run.
/// </para>
/// <para>
/// <b>Authentication is Negotiate either way.</b> The credential decides <i>whose</i> identity is
/// presented, never <i>how</i> - because how is settled at
/// <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c> and there is no rung on
/// which a password crosses the wire in clear text.
/// </para>
/// <para>
/// <b>What happens to a password.</b> It is held in a <see cref="NetworkCredential"/> for as long
/// as the run holds this object and is then released with it. Nothing writes it to disk, to the
/// bundle, or to a log. It is not part of this type's public surface - <see cref="ToString"/>
/// discloses neither the password nor the user name, and no public member returns either - so a
/// caller cannot print it by accident, which is the way this normally happens. That is enforced
/// rather than intended: <c>DirectoryCredentialTests</c> asserts it, and this type is deliberately
/// not a record, because a record's compiler-generated <c>ToString</c> prints every member it has.
/// </para>
/// <para>
/// <b>Nothing is remembered between runs.</b> The map records a file named
/// <c>SavedCredential.cs</c> in the previous product containing no such type - a folder and a
/// filename left behind by a credential-persistence feature that was designed and never built. It
/// was right not to build it, and it stays unbuilt: a tool that reads a directory and writes
/// nothing to it has no business holding a customer's administrative password from one week to the
/// next.
/// </para>
/// </remarks>
public sealed class DirectoryCredential
{
    private readonly NetworkCredential? _explicitCredential;

    private DirectoryCredential(NetworkCredential? explicitCredential, string describedAs)
    {
        _explicitCredential = explicitCredential;
        DescribedAs = describedAs;
    }

    /// <summary>
    /// Bind as the account the product is already running under.
    /// </summary>
    /// <remarks>
    /// The ordinary case, and the one that needs no secret to exist anywhere: an auditor signed in
    /// to an administrative workstation runs the tool, and Negotiate presents the identity the
    /// process already has.
    /// </remarks>
    public static DirectoryCredential LoggedOnUser { get; } =
        new(explicitCredential: null, describedAs: "the logged-on user");

    /// <summary>
    /// How this credential may be described in a log, a progress line or an error message. Never
    /// the password, and never the user name.
    /// </summary>
    /// <remarks>
    /// A user name is not a secret, but it is half of one, and an audit tool's logs travel: they go
    /// into support tickets and get pasted into chat. There is no operational question this product
    /// answers better by naming the account, so it does not.
    /// </remarks>
    public string DescribedAs { get; }

    /// <summary>Whether this binds as the process identity rather than a supplied account.</summary>
    public bool IsLoggedOnUser => _explicitCredential is null;

    /// <summary>
    /// Bind as an account an operator supplied for this run.
    /// </summary>
    /// <param name="userName">The account name.</param>
    /// <param name="domain">The domain the account belongs to.</param>
    /// <param name="password">The password. Held for the life of this object and never written down.</param>
    public static DirectoryCredential For(string userName, string domain, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        return new DirectoryCredential(
            new NetworkCredential(userName, password, domain),
            describedAs: "an account supplied for this run");
    }

    /// <summary>
    /// What this credential is, for a human. Deliberately says nothing that would be worth
    /// intercepting.
    /// </summary>
    public override string ToString() => DescribedAs;

    /// <summary>
    /// The credential to hand the LDAP client, or <c>null</c> to bind as the process identity.
    /// </summary>
    /// <remarks>
    /// Internal, so the secret is reachable only from inside the project that opens connections,
    /// and in practice only from the one file permitted to open one.
    /// </remarks>
    internal NetworkCredential? ForBind() => _explicitCredential;
}

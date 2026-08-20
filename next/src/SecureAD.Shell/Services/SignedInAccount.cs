namespace SecureAD.Shell.Services;

/// <summary>
/// The Windows account this product is running as.
/// </summary>
/// <remarks>
/// <para>
/// <b>Captured, never typed.</b>
/// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c> settles that the account
/// which ran an exclusion is taken from Windows rather than asked for, because a name an operator
/// types for himself is a name he can get wrong - and the one place it would be discovered wrong
/// is an audit somebody is relying on.
/// </para>
/// <para>
/// <b>Not a seam.</b> There is nothing here to stand in for: it reads two environment values and
/// cannot fail, contact anything or take time. An interface over it would be an abstraction whose
/// only implementation is this one.
/// </para>
/// </remarks>
internal static class SignedInAccount
{
    /// <summary>
    /// The signed-in account, qualified by its domain, as Windows reports it.
    /// </summary>
    /// <remarks>
    /// Qualified because a bare user name is ambiguous across the several domains an audit of a
    /// forest is by definition looking at, and an unqualified name in evidence is a name an auditor
    /// cannot resolve to a person.
    /// </remarks>
    public static string Name() =>
        $"{Environment.UserDomainName}\\{Environment.UserName}";
}

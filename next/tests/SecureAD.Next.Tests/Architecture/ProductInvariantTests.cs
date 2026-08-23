using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Enforces the product invariants against the rebuild tree. They were stated in the old product's
/// docs/INVARIANTS.md, which is no longer in the repository, so this class is now where they live.
///
/// <para>
/// These duplicate <c>NonDestructiveInvariantTests</c> in the old tree, and the duplication is
/// deliberate. That test resolves <c>src/</c> and recurses it, so while the rebuild lived at
/// <c>src/next/</c> it was covered for free. It no longer does, because the same mechanism also
/// applied the old tree's *design* assertions to new code — <c>SqliteConnectionChokepointTests</c>
/// requires every read connection to come from the old <c>DatabaseConnectionFactory</c>, which the
/// rebuild deliberately does not have.
/// </para>
/// <para>
/// Inheriting the product's central promise by accident of folder placement was fragile even while
/// it worked. Stating it here means moving the tree again cannot silently drop it.
/// </para>
/// </summary>
public sealed class ProductInvariantTests
{
    /// <summary>
    /// I-1. <c>System.DirectoryServices.Protocols</c> expresses every directory mutation as one of
    /// these request types. If none are constructed, no LDAP write can occur.
    /// </summary>
    private static readonly string[] LdapWriteRequestTypes =
    [
        "ModifyRequest",
        "AddRequest",
        "DeleteRequest",
        "ModifyDNRequest",
    ];

    /// <summary>
    /// I-3. APIs that persist a secret. <c>NetworkCredential</c> is intentionally absent: holding a
    /// password in memory for the duration of a capture is supported. What must not appear is
    /// anything that writes one to disk.
    /// </summary>
    private static readonly string[] CredentialPersistenceApis =
    [
        "ProtectedData.Protect",
        "CredWrite",
        "PasswordVault",
        "SetPassword",
    ];

    [Fact]
    public void TheRebuildNeverWritesToActiveDirectory()
    {
        var offenders = RebuildTree.Scan(RebuildTree.ProductionFiles(), LdapWriteRequestTypes);

        Assert.True(
            offenders.Count == 0,
            "SecureAD must never write to Active Directory (invariant I-1). Found LDAP write "
            + "request types in:" + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    [Fact]
    public void TheRebuildNeverPersistsCredentials()
    {
        var offenders = RebuildTree.Scan(RebuildTree.ProductionFiles(), CredentialPersistenceApis);

        Assert.True(
            offenders.Count == 0,
            "Credentials must never be persisted (invariant I-3). Found credential-storage APIs "
            + "in:" + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// The scanner reads real files. A guard that passes because it found nothing to look at
    /// guarantees nothing, which is the failure mode the old tree's scanner self-tests exist to
    /// prevent.
    /// </summary>
    [Fact]
    public void TheScannerReadsRealProductionFiles()
    {
        var files = RebuildTree.ProductionFiles().ToList();

        Assert.True(
            files.Count > 0,
            $"Found no production .cs files under {Path.Combine(RebuildTree.Root(), "src")}.");
        Assert.Contains(files, f => f.EndsWith("Result.cs", StringComparison.Ordinal));
    }

    /// <summary>
    /// The scanner detects a forbidden pattern when one is present. Asserted against this test
    /// project's own source, which names every forbidden term above, so the check needs no
    /// temporary file and cannot be defeated by the comment filter.
    /// </summary>
    [Fact]
    public void TheScannerDetectsAForbiddenPatternWhenPresent()
    {
        var hits = RebuildTree.Scan(RebuildTree.AllFiles(), LdapWriteRequestTypes);

        Assert.True(
            hits.Count > 0,
            "The scanner found no occurrence of the forbidden LDAP write types anywhere under the "
            + "rebuild tree, including this file, which declares them. The scanner is not working.");
    }
}

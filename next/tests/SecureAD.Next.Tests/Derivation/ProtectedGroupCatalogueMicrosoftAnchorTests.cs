using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Pins <see cref="ProtectedGroupCatalogue"/> to the values Microsoft publishes.
/// </summary>
/// <remarks>
/// <para>
/// <b>The values are transcribed, so something has to hold them still.</b> The catalogue is the
/// fifteen accounts and groups listed in <i>Appendix C: Protected Accounts and Groups in Active
/// Directory</i>. A wrong entry does not announce itself: a missing one reports a protected account
/// as unprotected, and an invented one reports protection nobody has. The schema GUID catalogue had
/// eleven wrong entries out of a hundred and every test over it passed for months, which is the
/// reason this file exists rather than a general test of the matching logic.
/// </para>
/// <para>
/// <b>What it cannot check.</b> That Microsoft has not revised the page since it was read - only a
/// person re-reading it can say that, which is what the harvest date in
/// <c>docs/MICROSOFT-VERIFICATION.md</c> records. And it cannot check that a given domain still
/// protects these, because <c>dSHeuristics</c> can remove entries and this product does not capture
/// it.
/// </para>
/// </remarks>
public sealed class ProtectedGroupCatalogueMicrosoftAnchorTests
{
    private const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

    /// <summary>
    /// The nine domain-relative identifiers Microsoft lists, and no others.
    /// </summary>
    [Fact]
    public void TheDomainRelativeIdentifiersAreTheOnesMicrosoftPublishes()
    {
        int[] published =
        [
            500, // Administrator
            502, // Krbtgt
            512, // Domain Admins
            516, // Domain Controllers
            518, // Schema Admins
            519, // Enterprise Admins
            521, // Read-only Domain Controllers
            526, // Key Admins
            527, // Enterprise Key Admins
        ];

        Assert.Equal(published, ProtectedGroupCatalogue.DomainRelativeIdentifiers.Order());
    }

    /// <summary>
    /// The six builtin groups Microsoft lists, and no others.
    /// </summary>
    [Fact]
    public void TheBuiltinSidsAreTheOnesMicrosoftPublishes()
    {
        string[] published =
        [
            "S-1-5-32-544", // Administrators
            "S-1-5-32-548", // Account Operators
            "S-1-5-32-549", // Server Operators
            "S-1-5-32-550", // Print Operators
            "S-1-5-32-551", // Backup Operators
            "S-1-5-32-552", // Replicator
        ];

        Assert.Equal(published, ProtectedGroupCatalogue.BuiltinSids.Order(StringComparer.Ordinal));
    }

    /// <summary>
    /// Fifteen entries, which is what the source lists.
    /// </summary>
    /// <remarks>
    /// A count on its own proves little, but it catches an entry added without the two lists above
    /// being reconsidered against the page.
    /// </remarks>
    [Fact]
    public void TheCatalogueHoldsFifteenProtectedPrincipals()
    {
        Assert.Equal(
            15,
            ProtectedGroupCatalogue.DomainRelativeIdentifiers.Count
            + ProtectedGroupCatalogue.BuiltinSids.Count);
    }

    /// <summary>
    /// Cert Publishers is absent, and its absence is a decision.
    /// </summary>
    /// <remarks>
    /// It was protected between Windows 2000 SP4 and Windows Server 2003 and was removed afterwards.
    /// The same source's version table is what says so, and a reader who finds it missing should
    /// find this test rather than assume an oversight.
    /// </remarks>
    [Fact]
    public void CertPublishersIsDeliberatelyAbsent()
    {
        Assert.False(ProtectedGroupCatalogue.IsInThePublishedCatalogue(DomainSid + "-517"));
    }

    /// <summary>
    /// What establishes each kind of edge is recorded, and the two are not equally established.
    /// </summary>
    /// <remarks>
    /// Distribution nesting rests on product documentation - <i>Reducing the Active Directory Attack
    /// Surface</i> states that transitive membership confers the restricted security regardless of
    /// whether it came through a security or a distribution group. Primary-group traversal rests on
    /// nothing, and is not followed.
    /// </remarks>
    [Fact]
    public void TheProvenanceOfEachEdgeKindIsRecorded()
    {
        Assert.Equal(
            ProtectedEdgeProvenance.Documented,
            ProtectedGroupCatalogue.Default.DistributionNestingProvenance);

        Assert.Equal(
            ProtectedEdgeProvenance.NotEstablished,
            ProtectedGroupCatalogue.Default.PrimaryGroupProvenance);
    }
}

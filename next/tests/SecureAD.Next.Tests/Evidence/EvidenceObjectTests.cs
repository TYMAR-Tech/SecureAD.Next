using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// <c>D2</c> of <c>F-S29-3</c>. What an object says about its own completeness has to be a
/// statement that can come out either way; the member it replaced could not.
/// </summary>
public class EvidenceObjectTests
{
    /// <summary>
    /// An encrypted connection cannot have had confidential attributes stripped from it, so an
    /// attribute that is absent is absent from the directory.
    /// </summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Ldaps)]
    [InlineData(ConnectionSecurityLevel.SignedAndSealed)]
    public void AnObjectReadOverAnEncryptedConnectionIsComplete(ConnectionSecurityLevel security)
    {
        Assert.Equal(
            EvidenceCompleteness.Complete,
            ObjectReadOver(security).Completeness);
    }

    /// <summary>
    /// The half that makes the member worth having. A controller may strip confidential attributes
    /// from an unencrypted search and return no error, so silence about a value is not evidence that
    /// the value is absent. <c>Signed</c> requires no declared allowance, so this is where an
    /// ordinary run lands with nobody choosing it.
    /// </summary>
    [Theory]
    [InlineData(ConnectionSecurityLevel.Signed)]
    [InlineData(ConnectionSecurityLevel.Unprotected)]
    public void AnObjectReadOverAnUnencryptedConnectionMayBeMissingConfidentialValues(
        ConnectionSecurityLevel security)
    {
        Assert.Equal(
            EvidenceCompleteness.MayBeMissingConfidentialValues,
            ObjectReadOver(security).Completeness);
    }

    /// <summary>
    /// The trap <c>S-30</c> named: a completeness member defined as "everything it tried to read, it
    /// read" is true in every bundle forever, because capture is fail-fast and an incomplete run
    /// never seals. Suppressing referrals is what the partition's own completeness is about, and it
    /// must not reach the object's.
    /// </summary>
    [Fact]
    public void SuppressingReferralsDoesNotChangeWhatAnObjectSaysAboutItself()
    {
        var suppressed = ObjectReadOver(ConnectionSecurityLevel.Ldaps) with
        {
            Coverage = CoverageOver(ConnectionSecurityLevel.Ldaps) with
            {
                ReferralsSuppressed = true,
            },
        };

        Assert.Equal(EvidenceCompleteness.Complete, suppressed.Completeness);
    }

    private static EvidenceObject ObjectReadOver(ConnectionSecurityLevel security) => new(
        CoverageOver(security),
        "CN=Alice,DC=contoso,DC=com",
        Guid.Parse("11111111-2222-3333-4444-555555555555"),
        [],
        DateTimeOffset.UnixEpoch);

    private static PartitionCoverage CoverageOver(ConnectionSecurityLevel security) => new(
        "DC=contoso,DC=com",
        NamingContextKind.Domain,
        "dc01.contoso.com",
        security,
        1,
        1,
        0,
        [],
        false);
}

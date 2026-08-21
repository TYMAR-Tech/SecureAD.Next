using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Every <see cref="UserAccountControlWording"/> flag, pinned to the values Microsoft publishes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this matters.</b> These bits decide whether an account can log on at all, whether its
/// password ever expires, whether it can be attacked without Kerberos pre-authentication, and
/// whether a service running as it can impersonate whoever calls. A wrong bit does not throw and
/// does not look odd - it renders as a confident sentence beside an account it is not true of, and
/// an operator has no reason to doubt it.
/// </para>
/// <para>
/// <b>Where these numbers came from, and why three sources rather than two.</b>
/// <c>adschema/a-useraccountcontrol</c> states the bits as a table and
/// <c>iads/ne-iads-ads_user_flag_enum</c> states them as a C enum - but both descend from
/// <c>iads.h</c>, so their agreement is one lineage read twice. It reads like corroboration and is
/// not. KB 305144 is maintained separately, and it publishes a bit the other two do not:
/// <c>0x04000000</c>, marking a read-only domain controller. That flag was missing from this
/// product until a source outside the family was consulted, and an earlier version of this very
/// class would have rejected it as invented. <c>next/tools/harvest-user-account-control-flags.ps1</c>
/// re-runs all three comparisons on demand.
/// </para>
/// <para>
/// <b>The wording is deliberately not pinned here.</b> A test can hold a number; it cannot judge
/// whether a sentence is fair to an administrator reading a report. That judgement is the owner's
/// and is recorded in <c>docs/MICROSOFT-VERIFICATION.md</c>, not enforced by this class. Pinning
/// the prose would make every reasonable improvement look like a regression.
/// </para>
/// <para>
/// <b>Three bits are deliberately unworded.</b> Microsoft's table has no entry at all for
/// <c>0x00000004</c> and lists <c>0x00004000</c> and <c>0x00008000</c> as not used. A value setting
/// one of them therefore arrives as an unworded bit rather than silently as nothing.
/// </para>
/// </remarks>
public sealed class UserAccountControlWordingMicrosoftAnchorTests
{
    /// <summary>
    /// Every bit Microsoft publishes, with the <c>iads.h</c> identifier it publishes for it.
    /// </summary>
    [Theory]
    [InlineData(0x00000001u, "ADS_UF_SCRIPT")]
    [InlineData(0x00000002u, "ADS_UF_ACCOUNTDISABLE")]
    [InlineData(0x00000008u, "ADS_UF_HOMEDIR_REQUIRED")]
    [InlineData(0x00000010u, "ADS_UF_LOCKOUT")]
    [InlineData(0x00000020u, "ADS_UF_PASSWD_NOTREQD")]
    [InlineData(0x00000040u, "ADS_UF_PASSWD_CANT_CHANGE")]
    [InlineData(0x00000080u, "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED")]
    [InlineData(0x00000100u, "ADS_UF_TEMP_DUPLICATE_ACCOUNT")]
    [InlineData(0x00000200u, "ADS_UF_NORMAL_ACCOUNT")]
    [InlineData(0x00000800u, "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT")]
    [InlineData(0x00001000u, "ADS_UF_WORKSTATION_TRUST_ACCOUNT")]
    [InlineData(0x00002000u, "ADS_UF_SERVER_TRUST_ACCOUNT")]
    [InlineData(0x00010000u, "ADS_UF_DONT_EXPIRE_PASSWD")]
    [InlineData(0x00020000u, "ADS_UF_MNS_LOGON_ACCOUNT")]
    [InlineData(0x00040000u, "ADS_UF_SMARTCARD_REQUIRED")]
    [InlineData(0x00080000u, "ADS_UF_TRUSTED_FOR_DELEGATION")]
    [InlineData(0x00100000u, "ADS_UF_NOT_DELEGATED")]
    [InlineData(0x00200000u, "ADS_UF_USE_DES_KEY_ONLY")]
    [InlineData(0x00400000u, "ADS_UF_DONT_REQUIRE_PREAUTH")]
    [InlineData(0x00800000u, "ADS_UF_PASSWORD_EXPIRED")]
    [InlineData(0x01000000u, "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION")]
    [InlineData(0x04000000u, "PARTIAL_SECRETS_ACCOUNT")]
    public void WhenMicrosoftPublishesAFlag_ThenTheTableCarriesItAtThatBit(uint bit, string identifier)
    {
        var flag = UserAccountControlWording.Documented.SingleOrDefault(
            f => string.Equals(f.Identifier, identifier, StringComparison.Ordinal));

        Assert.True(
            flag is not null,
            $"Microsoft publishes {identifier} and the table has no entry for it. A bit with no "
            + "word is carried as an unworded bit, so an operator would see a hexadecimal number "
            + "where a sentence belongs.");

        Assert.Equal(bit, flag!.Bit);
    }

    /// <summary>
    /// The table invents nothing. A bit Microsoft does not publish is one no directory sets, and
    /// a sentence for it would be a statement about an account that cannot be true.
    /// </summary>
    [Fact]
    public void TheTableCarriesNoBitMicrosoftDoesNotPublish()
    {
        uint[] published =
        [
            0x00000001, 0x00000002, 0x00000008, 0x00000010, 0x00000020, 0x00000040,
            0x00000080, 0x00000100, 0x00000200, 0x00000800, 0x00001000, 0x00002000,
            0x00010000, 0x00020000, 0x00040000, 0x00080000, 0x00100000, 0x00200000,
            0x00400000, 0x00800000, 0x01000000, 0x04000000,
        ];

        var invented = UserAccountControlWording.Documented
            .Where(f => !published.Contains(f.Bit))
            .Select(f => $"{f.Identifier} = 0x{f.Bit:X8}")
            .ToArray();

        Assert.True(
            invented.Length == 0,
            "The table carries bits neither Microsoft page publishes: "
            + string.Join(", ", invented));
    }

    /// <summary>
    /// The three bits Microsoft does not word are not worded here either, so a value setting one
    /// of them is reported as unread rather than as nothing.
    /// </summary>
    [Theory]
    [InlineData(0x00000004u)]
    [InlineData(0x00004000u)]
    [InlineData(0x00008000u)]
    public void WhenMicrosoftWordsNoFlagAtABit_ThenTheValueArrivesWithThatBitUnworded(uint bit)
    {
        var reading = UserAccountControlWording.Of(bit.ToString(System.Globalization.CultureInfo.InvariantCulture));

        Assert.NotNull(reading);
        Assert.False(reading!.FlagsAreComplete);
        Assert.Equal(bit, reading.UnwordedBits);
    }

    /// <summary>
    /// No two entries claim the same bit or the same identifier. A duplicate would let one of the
    /// checks above pass against the wrong row while the operator reads the other.
    /// </summary>
    [Fact]
    public void NoBitOrIdentifierAppearsTwice()
    {
        Assert.Equal(
            UserAccountControlWording.Documented.Count,
            UserAccountControlWording.Documented.Select(f => f.Bit).Distinct().Count());

        Assert.Equal(
            UserAccountControlWording.Documented.Count,
            UserAccountControlWording.Documented
                .Select(f => f.Identifier)
                .Distinct(StringComparer.Ordinal)
                .Count());
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass over an empty table and report that
    /// nothing is wrong with it.
    /// </summary>
    [Fact]
    public void TheTableIsPopulatedAndEveryEntryCarriesAWord()
    {
        Assert.Equal(22, UserAccountControlWording.Documented.Count);

        Assert.All(
            UserAccountControlWording.Documented,
            f => Assert.False(string.IsNullOrWhiteSpace(f.Wording)));
    }
}

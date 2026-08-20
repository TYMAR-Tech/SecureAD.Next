using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Wording a <c>userAccountControl</c> value, one bit at a time against Microsoft Learn's own
/// table.
/// </summary>
/// <remarks>
/// <b>Bit by bit, and not in the aggregate.</b> This is the wording where being wrong is invisible:
/// a mistaken bit renders as a confident <i>Disabled</i> beside an account that is enabled, and
/// nothing on screen could reveal it. A test asserting that some flags come back would pass with
/// two of them transposed, so every documented value is asserted against
/// <c>learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol</c> by its number.
/// </remarks>
public sealed class UserAccountControlWordingTests
{
    /// <summary>
    /// Learn's table, transcribed a second time and independently of the source, so that a typo in
    /// the table under test is a disagreement rather than something both copies share.
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
    public void EachDocumentedBitIsWordedUnderTheIdentifierLearnGivesIt(uint bit, string identifier)
    {
        var worded = UserAccountControlWording.Of(bit.ToString())!;

        Assert.Equal([identifier], worded.Flags.Select(f => f.Identifier));
    }

    /// <summary>
    /// The value an operator meets most often: a disabled ordinary user, which Learn's own article
    /// uses as its worked example - 514 is 2 + 512.
    /// </summary>
    [Fact]
    public void ADisabledOrdinaryAccountReadsAsBothOfItsFlags()
    {
        var worded = UserAccountControlWording.Of("514")!;

        Assert.Equal(
            ["ADS_UF_ACCOUNTDISABLE", "ADS_UF_NORMAL_ACCOUNT"],
            worded.Flags.Select(f => f.Identifier));
    }

    [Fact]
    public void TheFlagsAreInAscendingBitOrder()
    {
        var worded = UserAccountControlWording.Of("528")!;

        Assert.Equal([0x10u, 0x200u], worded.Flags.Select(f => f.Bit));
    }

    /// <summary>
    /// An account setting nothing is a real value and not a missing one.
    /// </summary>
    [Fact]
    public void AValueOfZeroSetsNoFlags()
    {
        Assert.Empty(UserAccountControlWording.Of("0")!.Flags);
    }

    [Fact]
    public void TheValueIsCarriedAsTheDirectoryHoldsIt()
    {
        Assert.Equal(514u, UserAccountControlWording.Of("514")!.Value);
    }

    // ---------------------------------------------------------------------------------------
    // The two bits the directory stopped keeping current (S-57 #23)
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The wording used to read "The account is currently locked out." Microsoft's own sentence is
    /// that in a Windows Server 2003 domain <c>LOCK_OUT</c> and <c>PASSWORD_EXPIRED</c> "have been
    /// replaced with a new attribute called <c>ms-DS-User-Account-Control-Computed</c>", so the
    /// stored bit is not the current state of anything and the word <i>currently</i> was the whole
    /// defect.
    ///
    /// <para>
    /// Both bits are checked, because Microsoft names them in one sentence and the pair being
    /// treated differently is what showed the lockout wording was an oversight rather than a
    /// decision. Checked together so they cannot drift apart again.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(0x00000010u)]
    [InlineData(0x00800000u)]
    public void NeitherBitTheDirectoryStoppedKeepingIsWordedAsCurrentState(uint bit)
    {
        Assert.DoesNotContain(
            "currently", Documented(bit).Wording, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And it names where the answer actually lives, rather than only withdrawing the claim. A
    /// reader who cannot see the replacement attribute has been told less, not more.
    /// </summary>
    [Fact]
    public void TheLockoutBitNamesTheAttributeThatReplacedIt()
    {
        Assert.Contains(
            "msDS-User-Account-Control-Computed",
            Documented(0x00000010u).Wording,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The obvious fallback is wrong too, so the wording says so. Learn's <c>Lockout-Time</c>
    /// remarks: the value "may be non zero, yet the account is not locked out" - only
    /// <c>lockoutTime</c> plus the domain's <c>Lockout-Duration</c> decides.
    /// </summary>
    [Fact]
    public void TheLockoutBitDoesNotLeaveLockoutTimeLookingSufficient()
    {
        Assert.Contains(
            "Lockout-Duration", Documented(0x00000010u).Wording, StringComparison.Ordinal);
    }

    private static UserAccountControlFlag Documented(uint bit) =>
        UserAccountControlWording.Documented.Single(f => f.Bit == bit);

    // ---------------------------------------------------------------------------------------
    // Bits with no word
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A bit this build has no word for is kept. Dropping it would let a screen show a complete
    /// list of flags for a value that was not completely read.
    /// </summary>
    [Fact]
    public void ABitWithNoWordingIsCarriedRatherThanDropped()
    {
        Assert.Equal(0x4000u, UserAccountControlWording.Of("16896")!.UnwordedBits);
    }

    [Fact]
    public void ABitWithNoWordingIsSaidToMakeTheFlagsIncomplete()
    {
        Assert.False(UserAccountControlWording.Of("16896")!.FlagsAreComplete);
    }

    /// <summary>
    /// 16896 is 0x4000 + 0x200: the unworded bit does not cost the value its worded ones.
    /// </summary>
    [Fact]
    public void ABitWithNoWordingLeavesTheWordedOnesAlone()
    {
        var worded = UserAccountControlWording.Of("16896")!;

        Assert.Equal(["ADS_UF_NORMAL_ACCOUNT"], worded.Flags.Select(f => f.Identifier));
    }

    [Fact]
    public void AValueWhoseBitsAreAllWordedSaysSo()
    {
        Assert.True(UserAccountControlWording.Of("514")!.FlagsAreComplete);
    }

    // ---------------------------------------------------------------------------------------
    // Text that is not a value
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Text this build cannot read is not worded into anything. A zero here would be a statement
    /// that the account sets no flags, which nobody knows.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("NORMAL_ACCOUNT")]
    [InlineData("-2")]
    [InlineData("5.14")]
    [InlineData(null)]
    public void TextThatIsNotAValueIsNotWorded(string? stored)
    {
        Assert.Null(UserAccountControlWording.Of(stored));
    }

    // ---------------------------------------------------------------------------------------
    // The table itself
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Learn lists 0x4000 and 0x8000 as not used and says nothing at all about 0x4. Wording any of
    /// them would be inventing a meaning, so their absence is asserted rather than left to be
    /// noticed if somebody fills the gaps in.
    /// </summary>
    [Theory]
    [InlineData(0x00000004u)]
    [InlineData(0x00004000u)]
    [InlineData(0x00008000u)]
    public void ABitLearnDoesNotDefineIsNotWorded(uint bit)
    {
        Assert.DoesNotContain(UserAccountControlWording.Documented, f => f.Bit == bit);
    }

    [Fact]
    public void NoTwoFlagsClaimTheSameBit()
    {
        Assert.Equal(
            UserAccountControlWording.Documented.Count,
            UserAccountControlWording.Documented.Select(f => f.Bit).Distinct().Count());
    }

    [Fact]
    public void EveryFlagIsOneBit()
    {
        Assert.All(
            UserAccountControlWording.Documented,
            f => Assert.Equal(1, System.Numerics.BitOperations.PopCount(f.Bit)));
    }
}

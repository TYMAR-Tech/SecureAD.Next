using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Reading the timestamps this product captures, including the values that are not times.
/// </summary>
/// <remarks>
/// <b>The sentinels are the subject.</b> A date read correctly is worth little here; every one of
/// these attributes carries a value that looks like a number, is not a moment, and renders as a
/// confident date to anybody who treats it as one. Each is asserted against the attribute's own
/// page on Microsoft Learn.
/// </remarks>
public sealed class DirectoryTimeTests
{
    /// <summary>When the run read the object. Every age below is measured from here.</summary>
    private static readonly DateTimeOffset Captured = new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);

    // ---------------------------------------------------------------------------------------
    // The two syntaxes
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The epoch itself, asserted on an attribute that has no sentinel at zero. On the three that
    /// do, zero means something other than 1601 and this could not be asserted at all.
    /// </summary>
    [Fact]
    public void AnIntervalIsCountedFrom1601()
    {
        var worded = DirectoryTime.WordTimestamp("ms-Mcs-AdmPwdExpirationTime", "0", Captured)!;

        Assert.Equal(new DateTimeOffset(1601, 1, 1, 0, 0, 0, TimeSpan.Zero), worded.Instant);
    }

    /// <summary>One day is 864,000,000,000 hundred-nanosecond units.</summary>
    [Fact]
    public void AnIntervalCountsInHundredNanosecondUnits()
    {
        var worded = DirectoryTime.WordTimestamp(
            "ms-Mcs-AdmPwdExpirationTime", "864000000000", Captured)!;

        Assert.Equal(new DateTimeOffset(1601, 1, 2, 0, 0, 0, TimeSpan.Zero), worded.Instant);
    }

    [Fact]
    public void AGeneralizedTimeIsReadAsWritten()
    {
        var worded = DirectoryTime.WordTimestamp("whenCreated", "20240705143000.0Z", Captured)!;

        Assert.Equal(new DateTimeOffset(2024, 7, 5, 14, 30, 0, TimeSpan.Zero), worded.Instant);
    }

    /// <summary>
    /// The syntax comes from the attribute and never from the shape of the value. A generalized
    /// time parses perfectly well as an interval and lands in the seventeenth century, which is
    /// exactly the sort of wrong that reads as a real answer.
    /// </summary>
    [Fact]
    public void AGeneralizedTimeIsNotReadAsAnInterval()
    {
        var worded = DirectoryTime.WordTimestamp("whenCreated", "20240705143000.0Z", Captured)!;

        Assert.Equal(2024, worded.Instant!.Value.Year);
    }

    [Fact]
    public void AnAttributeThatIsNotATimestampIsNotWorded()
    {
        Assert.Null(DirectoryTime.WordTimestamp("sAMAccountName", "133637220000000000", Captured));
    }

    [Fact]
    public void TextThatIsNotATimestampIsNotWorded()
    {
        Assert.Null(DirectoryTime.WordTimestamp("pwdLastSet", "yesterday", Captured));
    }

    // ---------------------------------------------------------------------------------------
    // accountExpires - two values mean never
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Learn: an account created never-expiring holds the maximum, and one whose expiry was
    /// removed holds zero. Handling one and not the other renders the other as a date in 1601 or
    /// in 30828, and both read as a real expiry.
    /// </summary>
    [Theory]
    [InlineData("0")]
    [InlineData("9223372036854775807")]
    public void BothOfTheValuesMeaningNeverAreReadAsNever(string stored)
    {
        var worded = DirectoryTime.WordTimestamp("accountExpires", stored, Captured)!;

        Assert.Equal("Never expires", worded.Worded);
    }

    [Fact]
    public void AnAccountThatNeverExpiresNamesNoMoment()
    {
        Assert.Null(DirectoryTime.WordTimestamp("accountExpires", "0", Captured)!.Instant);
    }

    [Fact]
    public void AnAccountWithAnExpiryIsReadAsADate()
    {
        var worded = DirectoryTime.WordTimestamp("accountExpires", "133637220000000000", Captured)!;

        Assert.Equal(new DateTimeOffset(2024, 6, 24, 17, 0, 0, TimeSpan.Zero), worded.Instant);
    }

    // ---------------------------------------------------------------------------------------
    // pwdLastSet - zero is a requirement, not a date
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Zero is how the directory records <i>this password must be set at the next logon</i>, and
    /// the accounts it is true of are the ones an auditor is looking for. Read as an interval it
    /// becomes 1601-01-01, which reads as an ancient password rather than as no password.
    /// </summary>
    [Fact]
    public void APasswordNeverSetIsNotReadAsADateIn1601()
    {
        var worded = DirectoryTime.WordTimestamp("pwdLastSet", "0", Captured)!;

        Assert.Null(worded.Instant);
        Assert.StartsWith("Never set.", worded.Worded, StringComparison.Ordinal);
    }

    /// <summary>
    /// Learn qualifies the meaning: the requirement only takes effect on an account whose password
    /// is not set never to expire. This wording carries the qualification rather than dropping it.
    /// </summary>
    [Fact]
    public void APasswordNeverSetSaysWhatTheRequirementDependsOn()
    {
        var worded = DirectoryTime.WordTimestamp("pwdLastSet", "0", Captured)!;

        Assert.Contains("never to expire", worded.Worded, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // lastLogonTimestamp - replicated, and coarse by design
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The caveat is the point of capturing this attribute rather than <c>lastLogon</c>. A dormant
    /// account judgement made without it is wrong by up to a fortnight, and nothing on screen would
    /// show it.
    /// </summary>
    [Fact]
    public void ALastLogonCarriesTheWarningThatItIsDaysOutOfDate()
    {
        var worded = DirectoryTime.WordTimestamp(
            "lastLogonTimestamp", "133637220000000000", Captured)!;

        Assert.Contains("9", worded.Caveat!, StringComparison.Ordinal);
        Assert.Contains("14 days", worded.Caveat!, StringComparison.Ordinal);
    }

    [Fact]
    public void AnAccountThatHasNeverLoggedOnSaysSo()
    {
        var worded = DirectoryTime.WordTimestamp("lastLogonTimestamp", "0", Captured)!;

        Assert.Equal("No logon has been recorded", worded.Worded);
    }

    /// <summary>
    /// Nothing else carries a caveat, so the one that does is not lost among decoration.
    /// </summary>
    [Fact]
    public void AnOrdinaryTimestampCarriesNoCaveat()
    {
        var worded = DirectoryTime.WordTimestamp("pwdLastSet", "133637220000000000", Captured)!;

        Assert.Null(worded.Caveat);
    }

    // ---------------------------------------------------------------------------------------
    // The age is measured against the run
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A bundle is sealed evidence. A password last set six days before a capture is a fact about
    /// that forest and stays one; measured against the reader's own clock it would say something
    /// different every morning.
    /// </summary>
    [Fact]
    public void AnAgeIsMeasuredFromTheRunAndNotFromToday()
    {
        var worded = DirectoryTime.WordTimestamp(
            "whenCreated", "20260907090000.0Z", Captured)!;

        Assert.Contains("6 days before this run", worded.Worded, StringComparison.Ordinal);
    }

    [Fact]
    public void AValueFromTheDayOfTheRunSaysSo()
    {
        var worded = DirectoryTime.WordTimestamp("whenCreated", "20260913080000.0Z", Captured)!;

        Assert.Contains("the day of this run", worded.Worded, StringComparison.Ordinal);
    }

    /// <summary>
    /// A timestamp after the capture is a defect in the directory - Microsoft documents accounts
    /// whose lastLogonTimestamp is in the future and how to repair them. It is stated rather than
    /// hidden, because hiding it would be this product covering for a broken object.
    /// </summary>
    [Fact]
    public void AValueAfterTheRunIsStatedRatherThanHidden()
    {
        var worded = DirectoryTime.WordTimestamp("whenCreated", "20260920090000.0Z", Captured)!;

        Assert.Contains("7 days after this run", worded.Worded, StringComparison.Ordinal);
    }

    [Fact]
    public void TheMomentIsShownBesideTheAge()
    {
        var worded = DirectoryTime.WordTimestamp("whenCreated", "20260907090000.0Z", Captured)!;

        Assert.StartsWith("2026-09-07 09:00 UTC", worded.Worded, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // The table
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Every attribute named as a timestamp is one this product actually captures. A table naming
    /// something the catalogue does not request would word nothing and read as though it did.
    /// </summary>
    [Fact]
    public void EveryTimestampNamedIsAnAttributeThisProductCaptures()
    {
        var captured = SecureAD.Kernel.Capture.CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        Assert.All(DirectoryTime.Attributes.Keys, a => Assert.Contains(a, captured));
    }
}

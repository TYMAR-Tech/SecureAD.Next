using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Reading one setting out of the forest's <c>dSHeuristics</c> string.
/// </summary>
/// <remarks>
/// <para>
/// <b>The cases here are the specification's own, not invented ones.</b> MS-ADTS 6.1.1.2.4.1.2
/// illustrates its rules with worked examples - a string of length zero, a string of two characters
/// asked for a third, and a seven-character string built by defaulting the first six. Testing
/// against the examples the document chose to give is the closest this can get to testing against
/// the document.
/// </para>
/// <para>
/// <b>What these cannot prove.</b> Whether the position numbers are the right ones for the settings
/// this product cares about. That is a question about which row of the table to read, and it is
/// pinned separately by <c>DirectoryHeuristicsMicrosoftAnchorTests</c>.
/// </para>
/// </remarks>
public sealed class DirectoryHeuristicsTests
{
    /// <summary>
    /// A character the forest stated is read as stated.
    /// </summary>
    [Fact]
    public void AStatedCharacterIsReadFromThePositionMicrosoftNumbers()
    {
        // Sixteen characters, the last of them 'f'. Microsoft calls that character 16.
        var read = DirectoryHeuristics.CharacterAt("000000000100000f", 16);

        Assert.Equal('f', read.Value);
    }

    /// <summary>
    /// Positions are one-based, so character 16 is not the seventeenth.
    /// </summary>
    /// <remarks>
    /// <b>The off-by-one is the whole risk in this type.</b> Reading position 16 as index 16 would
    /// silently return character 17, which in a longer string is a different setting entirely - and
    /// the answer would look plausible rather than wrong.
    /// </remarks>
    [Fact]
    public void ThePositionIsOneBasedAndNotAnIndex()
    {
        // Position 1 is the first character, so a string beginning '2' reads '2' and not '0'.
        var read = DirectoryHeuristics.CharacterAt("2000000001", 1);

        Assert.Equal('2', read.Value);
    }

    /// <summary>
    /// A string that ends before the position asked for gives the documented default.
    /// </summary>
    /// <remarks>
    /// MS-ADTS: "If dSHeuristics is only two Unicode characters long, then the fDoListObject
    /// heuristic, which would be represented by the third character in the string, is FALSE."
    /// </remarks>
    [Fact]
    public void ACharacterPastTheEndOfTheStringTakesTheDocumentedDefault()
    {
        var read = DirectoryHeuristics.CharacterAt("00", 3);

        Assert.Equal('0', read.Value);
    }

    /// <summary>
    /// A short string is a normal string, not a malformed one.
    /// </summary>
    /// <remarks>
    /// The order of the characters is fixed and truncation is the only way to omit one, so every
    /// value is a prefix of a longer one nobody wrote. Treating a short string as a fault would
    /// make the ordinary case an error.
    /// </remarks>
    [Fact]
    public void AShortStringIsNotAFailure()
    {
        var read = DirectoryHeuristics.CharacterAt("00", 3);

        Assert.Equal(HeuristicReadOutcome.DefaultedByAbsence, read.Outcome);
    }

    /// <summary>
    /// An empty string is a read that found nothing, and every character defaults.
    /// </summary>
    /// <remarks>
    /// MS-ADTS: "If dSHeuristics is not present or has length of zero, then the fSupFirstLastANR
    /// heuristic is FALSE."
    /// </remarks>
    [Fact]
    public void AnEmptyStringDefaultsEveryCharacter()
    {
        var read = DirectoryHeuristics.CharacterAt(string.Empty, 1);

        Assert.Equal('0', read.Value);
    }

    /// <summary>
    /// A forest that stated nothing is not the same as one nobody read.
    /// </summary>
    /// <remarks>
    /// <b>This is the distinction the type exists for.</b> An absent attribute is a documented
    /// answer; an unread one is no answer. If both returned the default, a bundle captured before
    /// this attribute was requested would report that its forest excluded no groups - which nobody
    /// established.
    /// </remarks>
    [Fact]
    public void AnUnreadStringIsNotReadAsTheDefault()
    {
        var read = DirectoryHeuristics.CharacterAt(dsHeuristics: null, 16);

        Assert.Equal(HeuristicReadOutcome.NotRead, read.Outcome);
    }

    /// <summary>
    /// An unread string yields no character at all, rather than a plausible one.
    /// </summary>
    [Fact]
    public void AnUnreadStringYieldsNoCharacter()
    {
        var read = DirectoryHeuristics.CharacterAt(dsHeuristics: null, 16);

        Assert.Null(read.Value);
    }

    /// <summary>
    /// A character that was read vouches for itself; one that was not does not.
    /// </summary>
    [Theory]
    [InlineData("000000000100000f", true)]
    [InlineData("", true)]
    [InlineData(null, false)]
    public void ACharacterSaysWhetherAnythingWasRead(string? value, bool expected)
    {
        var read = DirectoryHeuristics.CharacterAt(value, 16);

        Assert.Equal(expected, read.IsComplete);
    }

    /// <summary>
    /// The position asked for comes back with the answer.
    /// </summary>
    /// <remarks>
    /// A caller holding several characters at once needs each to say which setting it is, or two
    /// answers become interchangeable.
    /// </remarks>
    [Fact]
    public void TheAnswerCarriesThePositionItWasAskedFor()
    {
        var read = DirectoryHeuristics.CharacterAt("000000000100000f", 12);

        Assert.Equal(12, read.Position);
    }

    /// <summary>
    /// A position that is not one-based is refused rather than resolved.
    /// </summary>
    /// <remarks>
    /// Zero is the index somebody reaches for when they believe the string is zero-based, and
    /// returning the first character for it would confirm the belief.
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void APositionThatIsNotOneBasedIsRefused(int position)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => DirectoryHeuristics.CharacterAt("000000000100000f", position));
    }
}

using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Pins <c>dwAdminSDExMask</c> to what Microsoft publishes, bit by bit.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two sources, and each answers half the question.</b>
/// <see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5">MS-ADTS
/// 6.1.1.2.4.1.2</see> gives the position and the encoding: character 16, "valid values from the
/// set 0-9 and a-f", interpreted "as a hex digit and converted into a 4-bit value". It does not say
/// which group each bit stands for. That is in
/// <see href="https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980">Microsoft's
/// support article</see>, which the schema page for <c>dSHeuristics</c> links to for exactly this:
/// "Bit 0: Account Operators, Bit 1: Server Operators, Bit 2: Print Operators, Bit 3: Backup
/// Operators".
/// </para>
/// <para>
/// <b>Why this is a separate class from <c>DirectoryHeuristicsTests</c>.</b> Those test that the
/// reader does what this product intends; these test that what it intends is what Microsoft
/// documented. A single class would let a misreading of the source pass as long as the code agreed
/// with it, which is how the predecessor's schema catalogue acquired two wrong GUIDs.
/// </para>
/// <para>
/// <b>The article's own worked example is the strongest case here.</b> It states that "a value of
/// 'c' would exclude Print Operators (0100) and Backup Operators (1000)", which pins the encoding,
/// the bit order and two of the four assignments in one sentence Microsoft wrote.
/// </para>
/// </remarks>
public sealed class DirectoryHeuristicsMicrosoftAnchorTests
{
    /// <summary>Sets character 16 of an otherwise defaulted string.</summary>
    /// <remarks>
    /// Character 10 must be <c>1</c> or a domain controller rejects the write, so a real string
    /// carrying character 16 always carries that too. Building the fixture the way the directory
    /// requires means these run against strings a forest could actually hold.
    /// </remarks>
    private static string WithMask(char maskCharacter) =>
        "000000000" + "1" + "00000" + maskCharacter;

    /// <summary>
    /// Each bit excludes the group Microsoft assigns it, and no other.
    /// </summary>
    [Theory]
    [InlineData('1', AdminSdExcludableGroup.AccountOperators)]
    [InlineData('2', AdminSdExcludableGroup.ServerOperators)]
    [InlineData('4', AdminSdExcludableGroup.PrintOperators)]
    [InlineData('8', AdminSdExcludableGroup.BackupOperators)]
    public void EachBitExcludesTheGroupMicrosoftAssignsIt(
        char maskCharacter, AdminSdExcludableGroup expected)
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask(maskCharacter));

        Assert.Equal([expected], mask.Excluded);
    }

    /// <summary>
    /// Microsoft's own worked example: <c>c</c> excludes Print Operators and Backup Operators.
    /// </summary>
    /// <remarks>
    /// Quoted from the support article: "A value of 'c' would exclude Print Operators (0100) and
    /// Backup Operators (1000) because the binary sum 1100 reflects a hexadecimal value of 0xC."
    /// </remarks>
    [Fact]
    public void TheArticlesWorkedExampleResolvesAsItStates()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask('c'));

        Assert.Equal(
            [AdminSdExcludableGroup.PrintOperators, AdminSdExcludableGroup.BackupOperators],
            mask.Excluded);
    }

    /// <summary>
    /// The article's other stated example: <c>1</c> excludes Account Operators.
    /// </summary>
    /// <remarks>
    /// Quoted: "For example, a value of 0001 means exclude Account Operators."
    /// </remarks>
    [Fact]
    public void TheArticlesOtherExampleExcludesAccountOperatorsAlone()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask('1'));

        Assert.Equal([AdminSdExcludableGroup.AccountOperators], mask.Excluded);
    }

    /// <summary>
    /// The value Microsoft's own instructions tell an administrator to write.
    /// </summary>
    /// <remarks>
    /// The article's procedure says to type <c>000000000100000f</c>, so this is the exact string a
    /// forest following Microsoft's guidance ends up holding - and it excludes all four.
    /// </remarks>
    [Fact]
    public void TheValueTheArticleTellsAnAdministratorToWriteExcludesAllFour()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions("000000000100000f");

        Assert.Equal(4, mask.Excluded.Count);
    }

    /// <summary>
    /// The mask is read as a hex digit, so <c>a</c> is ten rather than a letter with no meaning.
    /// </summary>
    /// <remarks>
    /// Ten is bits 1 and 3 - Server Operators and Backup Operators - which is a combination decimal
    /// parsing cannot produce at all.
    /// </remarks>
    [Fact]
    public void ALetterIsReadAsAHexDigitAndNotDiscarded()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask('a'));

        Assert.Equal(
            [AdminSdExcludableGroup.ServerOperators, AdminSdExcludableGroup.BackupOperators],
            mask.Excluded);
    }

    /// <summary>
    /// A zero mask excludes nothing, and that is an answer rather than a silence.
    /// </summary>
    [Fact]
    public void AZeroMaskExcludesNothingAndSaysItWasRead()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask('0'));

        Assert.True(mask.IsComplete);
    }

    /// <summary>
    /// A forest with no value excludes nothing, because every character defaults to zero.
    /// </summary>
    [Fact]
    public void AForestWithNoValueExcludesNothing()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(string.Empty);

        Assert.Empty(mask.Excluded);
    }

    /// <summary>
    /// A forest nobody read is not reported as excluding nothing.
    /// </summary>
    /// <remarks>
    /// <b>The failure this guards is silent.</b> Every bundle captured before catalogue version 5
    /// carries no value for this attribute. If those read as "excludes nothing", the product would
    /// state that four operator groups are protected in forests where nobody ever asked.
    /// </remarks>
    [Fact]
    public void AForestNobodyReadIsNotReportedAsExcludingNothing()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(dsHeuristics: null);

        Assert.False(mask.IsComplete);
    }

    /// <summary>
    /// A character Microsoft documents no meaning for excludes nothing.
    /// </summary>
    /// <remarks>
    /// <b>The safe direction is the larger protected set.</b> Reporting a group as unprotected when
    /// it is protected is a false alarm an operator can check against the directory. Reporting one
    /// as protected when it is not is a hole nobody is told about. So an undocumented character
    /// leaves the catalogue at its published size.
    /// </remarks>
    [Theory]
    [InlineData('z')]
    [InlineData('-')]
    [InlineData(' ')]
    public void AnUndocumentedCharacterExcludesNothing(char maskCharacter)
    {
        var mask = DirectoryHeuristics.AdminSdExclusions(WithMask(maskCharacter));

        Assert.Empty(mask.Excluded);
    }

    /// <summary>
    /// The character the mask was read from comes back with it.
    /// </summary>
    /// <remarks>
    /// An operator checking this product against <c>ldp.exe</c> needs the value the directory
    /// holds, not only this product's reading of it.
    /// </remarks>
    [Fact]
    public void TheCharacterTheMaskWasReadFromIsCarriedWithIt()
    {
        var mask = DirectoryHeuristics.AdminSdExclusions("000000000100000f");

        Assert.Equal('f', mask.Character);
    }

    /// <summary>
    /// Every excludable group is one the protected catalogue actually holds.
    /// </summary>
    /// <remarks>
    /// The RIDs are the enum's values, so a mismatch between these and the catalogue would mean the
    /// exclusion silently removes nothing. 548 to 551 are the four operator groups in the built-in
    /// domain.
    /// </remarks>
    [Theory]
    [InlineData(AdminSdExcludableGroup.AccountOperators, 548)]
    [InlineData(AdminSdExcludableGroup.ServerOperators, 549)]
    [InlineData(AdminSdExcludableGroup.PrintOperators, 550)]
    [InlineData(AdminSdExcludableGroup.BackupOperators, 551)]
    public void EachExcludableGroupCarriesItsWellKnownIdentifier(
        AdminSdExcludableGroup group, int rid)
    {
        Assert.Equal(rid, (int)group);
    }
}

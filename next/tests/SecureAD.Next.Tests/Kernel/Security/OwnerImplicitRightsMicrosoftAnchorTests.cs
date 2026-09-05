using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Pins <c>BlockOwnerImplicitRights</c> to what Microsoft publishes: the position, the value
/// semantics, and the three conditions that decide whether an owner keeps the rights nobody
/// granted them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this matters more than most anchors.</b> An object's owner normally holds
/// <c>WRITE_DAC</c> - the right to rewrite the object's permission list - without any entry saying
/// so. Two rules are being written on that fact. If this product says an owner can rewrite
/// permissions where the platform stops them, it has told a customer something false about a
/// permission, and a customer makes a security decision on the strength of it.
/// </para>
/// <para>
/// <b>Two sources, and the second is the one a previous reading missed.</b>
/// <see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5">MS-ADTS
/// 6.1.1.2.4.1.2</see> gives the position and the fallbacks: character 29, <i>"if this character is
/// '0', '1', '2', or '3' the heuristic is set to the equivalent numeric value; if not set it
/// defaults to 0; if it has any other value it defaults to 1"</i>. It does not say what blocking
/// requires.
/// <see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c">MS-ADTS
/// 6.1.3.4</see> does, and it lists <b>three</b> conditions rather than one - the heuristic, the
/// owner's membership, and the object's class.
/// </para>
/// <para>
/// <b>The class condition is the reason this class exists.</b> <c>P-138</c> records the heuristic
/// as restricting "the implicit rights an owner receives", without qualification. Implemented that
/// way, a forest that sets the heuristic would make this product silent about every organizational
/// unit, group, user and certificate template owned by a non-administrator - hiding real latent
/// authority behind a setting that never applied to them. The negative controls below are what stop
/// that reading from returning.
/// </para>
/// </remarks>
public sealed class OwnerImplicitRightsMicrosoftAnchorTests
{
    /// <summary>Builds a 29-character string carrying <paramref name="setting"/> at position 29.</summary>
    /// <remarks>
    /// Characters 10 and 20 are not padding. A domain controller rejects a string of ten or more
    /// characters whose tenth is not <c>1</c>, and one of twenty or more whose twentieth is not
    /// <c>2</c>, so a string long enough to carry character 29 always carries both. Building the
    /// fixture the way the directory requires means these run against strings a forest could hold.
    /// </remarks>
    private static string WithSetting(char setting) =>
        new string('0', 9) + "1" + new string('0', 9) + "2" + new string('0', 8) + setting;

    /// <summary>The fixture is the length and shape the specification requires.</summary>
    /// <remarks>
    /// A self-test on the helper. If <see cref="WithSetting"/> drifted by a character, every test
    /// below would read a neighbouring heuristic and still pass or fail for reasons that look
    /// convincing. <c>docs/next/README.md</c> requires a scanner self-test for exactly this shape.
    /// </remarks>
    [Fact]
    public void TheFixtureCarriesTheSettingAtCharacterTwentyNine()
    {
        var built = WithSetting('1');

        Assert.Equal(29, built.Length);
        Assert.Equal('1', built[28]);
        Assert.Equal('1', built[9]);
        Assert.Equal('2', built[19]);
        Assert.Equal(
            '1', DirectoryHeuristics.CharacterAt(built, 29).Value);
    }

    /// <summary>
    /// Each of the four documented characters resolves to its equivalent numeric value.
    /// </summary>
    [Theory]
    [InlineData('0', 0)]
    [InlineData('1', 1)]
    [InlineData('2', 2)]
    [InlineData('3', 3)]
    public void EachDocumentedCharacterResolvesToItsNumericValue(char stated, int expected)
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights(WithSetting(stated));

        Assert.Equal(expected, setting.Value);
        Assert.Equal(HeuristicReadOutcome.Stated, setting.Outcome);
    }

    /// <summary>
    /// Only the value 1 blocks. This is the negative control for reading the heuristic as a
    /// severity dial.
    /// </summary>
    /// <remarks>
    /// <b>2 and 3 are settings of the same heuristic that do not block.</b> Reading "anything above
    /// zero is hardened" would make this product silent about owners who really can rewrite their
    /// objects' permissions - the direction that hides a capability rather than inventing one, and
    /// the one no permission review would catch either.
    /// </remarks>
    [Theory]
    [InlineData('0', false)]
    [InlineData('1', true)]
    [InlineData('2', false)]
    [InlineData('3', false)]
    public void OnlyTheValueOneBlocks(char stated, bool expected)
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights(WithSetting(stated));

        Assert.Equal(expected, setting.BlocksWhereItApplies);
    }

    /// <summary>
    /// An absent character defaults to 0, so a forest that never set the attribute does not block.
    /// </summary>
    /// <remarks>
    /// MS-ADTS: <i>"If this character is not set, the BlockOwnerImplicitRights heuristic defaults
    /// to 0."</i> The attribute does not exist by default, so this is the state of most forests.
    /// </remarks>
    [Fact]
    public void AnAbsentCharacterDefaultsToNotBlocking()
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights("0000000001");

        Assert.Equal(0, setting.Value);
        Assert.False(setting.BlocksWhereItApplies);
        Assert.Equal(HeuristicReadOutcome.DefaultedByAbsence, setting.Outcome);
        Assert.True(setting.IsComplete);
    }

    /// <summary>
    /// A character outside the documented set defaults to 1, which is Microsoft's rule and not
    /// this product's.
    /// </summary>
    /// <remarks>
    /// <b>This is the opposite of how <c>dwAdminSDExMask</c> treats an undocumented character</b>,
    /// and deliberately so. There the specification defines no behaviour, so this product refuses
    /// to resolve one. Here Microsoft states what the server does - defaults to 1 - so the reader
    /// follows the platform. The outcome is still reported as <c>Malformed</c> so a caller can see
    /// the forest wrote something nobody planned for.
    /// </remarks>
    [Theory]
    [InlineData('4')]
    [InlineData('9')]
    [InlineData('x')]
    public void AnUndocumentedCharacterDefaultsToOne(char stated)
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights(WithSetting(stated));

        Assert.Equal(1, setting.Value);
        Assert.True(setting.BlocksWhereItApplies);
        Assert.Equal(HeuristicReadOutcome.Malformed, setting.Outcome);
    }

    /// <summary>
    /// An unread attribute is not a defaulted one, and says so.
    /// </summary>
    /// <remarks>
    /// A bundle whose configuration object was never read has no answer. Reporting the documented
    /// default there would let a run that could not look claim the forest does not block, which is
    /// the shape <c>docs/decisions/0002</c> exists to prevent.
    /// </remarks>
    [Fact]
    public void AnUnreadAttributeIsNotAnAnswer()
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights(null);

        Assert.Null(setting.Value);
        Assert.Equal(HeuristicReadOutcome.NotRead, setting.Outcome);
        Assert.False(setting.IsComplete);
        Assert.False(setting.BlocksWhereItApplies);
    }

    /// <summary>
    /// All three of Microsoft's conditions must hold before an owner's implicit rights are blocked.
    /// </summary>
    /// <remarks>
    /// Quoted from MS-ADTS 6.1.3.4: the implicit rights are blocked when the heuristic is set to 1,
    /// <i>and</i> <i>"the requester is a member of neither the Domain Administrators or the
    /// Enterprise Administrators group"</i>, <i>and</i> <i>"the objectClass being added or modified
    /// is either of type computer or is derived from type computer"</i>.
    /// </remarks>
    [Theory]
    [InlineData('1', true, false, true)]   // all three hold
    [InlineData('1', false, false, false)] // not a computer object
    [InlineData('1', true, true, false)]   // owner is a domain or enterprise administrator
    [InlineData('0', true, false, false)]  // the forest does not block
    [InlineData('2', true, false, false)]  // the forest set a value that does not block
    public void AllThreeConditionsMustHold(
        char stated,
        bool isComputerClass,
        bool ownerIsDomainOrEnterpriseAdmin,
        bool expected)
    {
        var setting = DirectoryHeuristics.OwnerImplicitRights(WithSetting(stated));

        var blocked = DirectoryHeuristics.BlocksImplicitOwnerRights(
            setting, isComputerClass, ownerIsDomainOrEnterpriseAdmin);

        Assert.Equal(expected, blocked);
    }

    /// <summary>
    /// The negative control that matters: a hardened forest does not silence the owner question
    /// for objects that are not computers.
    /// </summary>
    /// <remarks>
    /// <b>Named rather than folded into the theory above, because this is the defect being
    /// prevented.</b> An organizational unit, a group, a user and a certificate template are the
    /// objects an ownership rule is most worth having on, and a reading of the heuristic that
    /// dropped the class condition would report every one of them as safe in a forest that set it.
    /// </remarks>
    [Fact]
    public void AHardenedForestStillLeavesNonComputerObjectsAnswerable()
    {
        var hardened = DirectoryHeuristics.OwnerImplicitRights(WithSetting('1'));

        Assert.False(DirectoryHeuristics.BlocksImplicitOwnerRights(
            hardened, objectIsComputerClass: false, ownerIsDomainOrEnterpriseAdmin: false));
    }
}

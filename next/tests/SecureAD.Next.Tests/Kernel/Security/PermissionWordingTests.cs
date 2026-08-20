using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Saying an access control entry in words: what it names, and what it refuses to hide.
/// </summary>
public sealed class PermissionWordingTests
{
    private static readonly PermissionWordingWriter Writer = new(SchemaGuidCatalog.Embedded);

    // ---------------------------------------------------------------------------------------
    // The whole of it
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void EveryRightAtOnceIsFullControl()
    {
        var wording = Writer.Describe(0x000F01FF, objectTypeGuid: null);

        Assert.Equal("Full control", wording.Summary);
    }

    /// <summary>
    /// A mask granting nothing says so, rather than leaving a blank that reads as though the row
    /// failed to load.
    /// </summary>
    [Fact]
    public void AMaskGrantingNothingSaysSo()
    {
        var wording = Writer.Describe(0, objectTypeGuid: null);

        Assert.Equal("No rights", wording.Summary);
    }

    // ---------------------------------------------------------------------------------------
    // Full control is a whole mask, not a floor
    //
    // The shortcut that renders full control in two words tested for a SUBSET: any mask
    // containing full control's bits took it, whatever else it carried. Everything else was then
    // dropped and the result declared complete. S-58 findings 9 and 10.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The bit that must never be silently swallowed. Microsoft: ACCESS_SYSTEM_SECURITY
    /// <i>MUST NOT be set in an ACE that is part of a DACL</i>. Finding an entry carrying it is
    /// finding malformed or hostile evidence, and the subset shortcut hid it behind the two most
    /// reassuring words the product prints.
    /// </summary>
    [Fact]
    public void FullControlPlusAccessSystemSecurityDoesNotHideTheExtraBit()
    {
        var wording = Writer.Describe(0x000F01FF | 0x01000000, objectTypeGuid: null);

        Assert.Contains(wording.Rights, r => r.Bits == 0x01000000);
    }

    /// <summary>
    /// The gap left by the shorthand fix: shorthand arriving <i>alongside</i> real rights was
    /// still lost, because the full-control shortcut returned before the shorthand was named.
    /// </summary>
    [Fact]
    public void FullControlPlusAShorthandBitDoesNotHideTheShorthand()
    {
        var wording = Writer.Describe(unchecked(0x000F01FF | (int)0x10000000), objectTypeGuid: null);

        Assert.Contains(wording.Rights, r => r.Bits == unchecked((int)0x10000000));
    }

    /// <summary>
    /// <c>RightsAreComplete</c> exists to stop exactly this. It was returned <c>true</c>
    /// unconditionally on the shortcut, so a mask with unnameable bits claimed to be fully read.
    /// </summary>
    [Fact]
    public void FullControlCarryingAnUnnameableBitIsNotReportedComplete()
    {
        var wording = Writer.Describe(0x000F01FF | 0x00800000, objectTypeGuid: null);

        Assert.False(wording.RightsAreComplete);
    }

    /// <summary>
    /// A mask that is exactly full control still reads as the two words an administrator expects.
    /// The fix must narrow the shortcut, not remove it.
    /// </summary>
    [Fact]
    public void AMaskThatIsExactlyFullControlStillReadsAsFullControl()
    {
        var wording = Writer.Describe(0x000F01FF, objectTypeGuid: null);

        Assert.Equal("Full control", wording.Summary);
        Assert.True(wording.RightsAreComplete);
    }

    /// <summary>
    /// Full control scoped to one object type is not full control over the object. The shortcut
    /// ignored <c>objectTypeGuid</c> entirely, so a scoped entry was described as unscoped.
    /// </summary>
    [Fact]
    public void FullControlScopedToAnObjectTypeIsNotDescribedAsUnscoped()
    {
        var scoped = Writer.Describe(0x000F01FF, Guid("User-Change-Password"));
        var unscoped = Writer.Describe(0x000F01FF, objectTypeGuid: null);

        Assert.NotEqual(unscoped.Summary, scoped.Summary);
    }

    // ---------------------------------------------------------------------------------------
    // Windows' shorthand bits, which a stored entry is not supposed to still carry
    //
    // The domain controller normally replaces the shorthand with the specific rights it stands
    // for when the permission is written. [MS-DTYP] 2.4.3 says the access check does not do that
    // for a shorthand bit found in an entry already attached to an object, so this product must
    // not either - it would report rights the directory may not honour. S-56 R2.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData(unchecked((int)0x10000000), "Full control (shorthand - may not be enforced)")]
    [InlineData(unchecked((int)0x40000000), "Write (shorthand - may not be enforced)")]
    [InlineData(unchecked((int)0x80000000), "Read (shorthand - may not be enforced)")]
    [InlineData(unchecked((int)0x20000000), "List contents (shorthand - may not be enforced)")]
    public void AShorthandBitIsNamedAndSaysItMayNotBeEnforced(int mask, string expected)
    {
        var wording = Writer.Describe(mask, objectTypeGuid: null);

        var right = Assert.Single(wording.Rights);
        Assert.Equal(expected, right.Name);
    }

    /// <summary>
    /// It must be a <i>named</i> right. An unnamed one is refused classification, so the most open
    /// entry in a forest would render as one unjudgeable right and the row would fall silent.
    /// </summary>
    [Fact]
    public void AShorthandBitIsNamedSoItCanStillBeJudged()
    {
        var wording = Writer.Describe(unchecked((int)0x10000000), objectTypeGuid: null);

        Assert.True(Assert.Single(wording.Rights).IsNamed);
    }

    /// <summary>
    /// The defect this replaced: the shorthand was translated and then reported as though the
    /// mapped rights were in force, which is what a real full-control entry means.
    /// </summary>
    [Fact]
    public void AShorthandFullControlIsNotWordedAsARealFullControl()
    {
        var shorthand = Writer.Describe(unchecked((int)0x10000000), objectTypeGuid: null);
        var real = Writer.Describe(0x000F01FF, objectTypeGuid: null);

        Assert.NotEqual(real.Summary, shorthand.Summary);
    }

    // ---------------------------------------------------------------------------------------
    // A control access right, and a GUID that turns out not to be one
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A genuine extended right keeps its bare name, because that is the label the ACL editor
    /// shows and this screen may not invent a second word for one right.
    /// </summary>
    [Fact]
    public void AGenuineExtendedRightIsNamedExactlyAsMicrosoftNamesIt()
    {
        var wording = Writer.Describe(ControlAccess, Guid("User-Change-Password"));

        Assert.Equal("User-Change-Password", wording.Summary);
    }

    /// <summary>
    /// A property set named by the control-access bit is not an extended right, and used to render
    /// as a bare noun.
    /// </summary>
    /// <remarks>
    /// Property sets live in the extended-rights container but publish
    /// <c>validAccesses: 48</c> - read and write property, not control access - so an entry naming
    /// one with this bit is naming something the catalogue knows under another kind. Rendered bare
    /// it produced rows reading <i>Private-Information, Write Private-Information, Read
    /// Private-Information</i>, whose first item read as a fragment rather than a right.
    /// </remarks>
    [Fact]
    public void APropertySetNamedByTheControlAccessBitIsNotRenderedAsABareNoun()
    {
        var wording = Writer.Describe(ControlAccess, Guid("General-Information"));

        Assert.Equal("Control access to General-Information", wording.Summary);
    }

    /// <summary>
    /// The row an operator actually saw: one GUID read three ways by three bits of one mask, which
    /// Microsoft documents as the defined behaviour - the purpose of the GUID depends on the access
    /// rights in the mask. Every item now carries a verb.
    /// </summary>
    [Fact]
    public void OneGuidReadByThreeBitsGivesThreeReadableRights()
    {
        var wording = Writer.Describe(
            ControlAccess | WriteProperty | ReadProperty, Guid("General-Information"));

        Assert.Equal(
            "Control access to General-Information, Write General-Information, "
            + "Read General-Information",
            wording.Summary);
    }

    private const int ReadProperty = 0x00000010;
    private const int WriteProperty = 0x00000020;
    private const int ControlAccess = 0x00000100;

    private static string Guid(string ldapName) =>
        SchemaGuidCatalog.Embedded.GuidFor(ldapName)
        ?? throw new InvalidOperationException($"The catalogue does not know {ldapName}.");

    // ---------------------------------------------------------------------------------------
    // Rights that are limited to one thing, and rights that are not
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void WritingAnyPropertySaysAllProperties()
    {
        var wording = Writer.Describe(0x00000020, objectTypeGuid: null);

        Assert.Equal("Write all properties", wording.Summary);
    }

    /// <summary>
    /// The difference between <i>write everything</i> and <i>write one attribute</i> is the whole
    /// of a delegation, and a viewer that showed both as "Write" would hide it.
    /// </summary>
    [Fact]
    public void WritingOneAttributeNamesThatAttribute()
    {
        var member = SchemaGuidCatalog.Embedded.GuidFor("member");

        var wording = Writer.Describe(0x00000020, member);

        Assert.Equal("Write member", wording.Summary);
    }

    /// <summary>
    /// Active Directory gives the <c>member</c> attribute and the <i>Self-Membership</i> validated
    /// write the same GUID. Which one an entry means depends on the bit set beside it, and the two
    /// are not close: writing <c>member</c> lets a principal add anybody to a group, while
    /// Self-Membership lets them add only themselves.
    /// </summary>
    [Fact]
    public void OneGuidMeaningTwoThingsIsNamedByTheRightBesideIt()
    {
        var shared = SchemaGuidCatalog.Embedded.GuidFor("member");

        var written = Writer.Describe(0x00000020, shared);
        var validated = Writer.Describe(0x00000008, shared);

        Assert.Equal("Write member", written.Summary);
        Assert.Equal("Validated write to Self-Membership", validated.Summary);
    }

    [Fact]
    public void AnExtendedRightIsNamedRatherThanShownAsAGuid()
    {
        var resetPassword = SchemaGuidCatalog.Embedded.GuidFor("User-Force-Change-Password");

        var wording = Writer.Describe(0x00000100, resetPassword);

        Assert.Equal("User-Force-Change-Password", wording.Summary);
    }

    [Fact]
    public void EveryExtendedRightAtOnceSaysAllOfThem()
    {
        var wording = Writer.Describe(0x00000100, objectTypeGuid: null);

        Assert.Equal("All extended rights", wording.Summary);
    }

    /// <summary>
    /// A GUID the catalogue does not know is still a right somebody holds. It is shown as the GUID
    /// rather than dropped, because hiding it would hide access.
    /// </summary>
    [Fact]
    public void AGuidTheCatalogueDoesNotKnowIsShownRatherThanDropped()
    {
        var unknown = "11111111-2222-3333-4444-555555555555";

        var wording = Writer.Describe(0x00000100, unknown);

        Assert.Contains(unknown, wording.Summary, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // The rights that let somebody take an object over
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ModifyingPermissionsIsSaidPlainly()
    {
        var wording = Writer.Describe(0x00040000, objectTypeGuid: null);

        Assert.Equal("Modify permissions", wording.Summary);
    }

    /// <summary>
    /// The word is Microsoft's own. ADSI Edit labels <c>WRITE_OWNER</c> "Modify Owner" for a
    /// directory object; "Take ownership" is the file system's label for the same bit, and the two
    /// tools sit side by side on the same administrator's screen.
    /// </summary>
    [Fact]
    public void ModifyingTheOwnerIsSaidTheWayTheDirectoryToolsSayIt()
    {
        var wording = Writer.Describe(0x00080000, objectTypeGuid: null);

        Assert.Equal("Modify owner", wording.Summary);
    }

    [Fact]
    public void SeveralRightsAreAllListed()
    {
        var wording = Writer.Describe(0x00040000 | 0x00080000, objectTypeGuid: null);

        Assert.Equal(
            ["Modify permissions", "Modify owner"],
            wording.Rights.Select(r => r.Name));
    }

    /// <summary>
    /// Each right carries the bits that produced it, so a caller can ask the classifier about one
    /// right rather than about the whole entry.
    /// </summary>
    [Fact]
    public void EachRightCarriesTheBitThatNamedIt()
    {
        var wording = Writer.Describe(0x00040000 | 0x00080000, objectTypeGuid: null);

        Assert.Equal([0x00040000, 0x00080000], wording.Rights.Select(r => r.Bits));
    }

    /// <summary>
    /// <i>Full control</i> is one grant an administrator removes in one action, not fifteen, so it
    /// is one right - and it carries every bit it stands for rather than only the ones spelled out.
    /// </summary>
    [Fact]
    public void FullControlIsOneRightCarryingTheWholeMask()
    {
        var wording = Writer.Describe(0x000F01FF, objectTypeGuid: null);

        var right = Assert.Single(wording.Rights);
        Assert.Equal("Full control", right.Name);
        Assert.Equal(0x000F01FF, right.Bits);
    }

    // ---------------------------------------------------------------------------------------
    // What it will not hide
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// This is the guard the type exists for. An access mask is a set of bits; naming the known
    /// ones and silently discarding the rest would show an administrator less access than the
    /// object grants, which is the one failure an audit tool cannot have.
    /// </summary>
    [Fact]
    public void ABitWithNoWordForItIsCountedRatherThanDiscarded()
    {
        var wording = Writer.Describe(0x00040000 | 0x00000200, objectTypeGuid: null);

        Assert.False(wording.RightsAreComplete);
    }

    [Fact]
    public void ABitWithNoWordForItIsShownAsItsValue()
    {
        var wording = Writer.Describe(0x00040000 | 0x00000200, objectTypeGuid: null);

        Assert.Contains("0x00000200", wording.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// The left-over item says it is unnamed, and this is what stops it being judged. A bit this
    /// build has no word for has not been examined, so a verdict of
    /// <see cref="PermissionVerdict.NotDangerous"/> on it would report access nobody looked at as
    /// safe - the failure <see cref="PermissionAssessment"/> exists to prevent.
    /// </summary>
    [Fact]
    public void TheLeftOverBitsAreMarkedAsSomethingThisBuildCannotName()
    {
        var wording = Writer.Describe(0x00040000 | 0x00000200, objectTypeGuid: null);

        var unnamed = Assert.Single(wording.Rights, r => !r.IsNamed);
        Assert.Equal(0x00000200, unnamed.Bits);
    }

    /// <summary>
    /// And a right this build does have a word for says so, so the flag separates the two cases
    /// rather than being false on everything.
    /// </summary>
    [Fact]
    public void ARightThisBuildHasAWordForSaysSo()
    {
        var wording = Writer.Describe(0x00040000 | 0x00000200, objectTypeGuid: null);

        var named = Assert.Single(wording.Rights, r => r.IsNamed);
        Assert.Equal("Modify permissions", named.Name);
    }

    [Fact]
    public void AMaskThisBuildUnderstandsWhollySaysSo()
    {
        var wording = Writer.Describe(0x00040000, objectTypeGuid: null);

        Assert.True(wording.RightsAreComplete);
    }

    // ---------------------------------------------------------------------------------------
    // Agreement with the classifier
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The bit values are written twice - once here to name rights, once in the classifier to
    /// judge them - so that a change to either cannot silently alter the other. This asserts the
    /// two still agree, which is the price of keeping them apart.
    /// </summary>
    [Fact]
    public void TheWordingAndTheClassifierAgreeOnWhatModifyPermissionsIs()
    {
        const int writeDac = 0x00040000;

        var wording = Writer.Describe(writeDac, objectTypeGuid: null);
        var assessment = new DangerousPermissionClassifier(SchemaGuidCatalog.Embedded)
            .Classify(AceType.AccessAllowed, writeDac, objectTypeGuid: null);

        Assert.Equal("Modify permissions", wording.Summary);
        Assert.Equal(PermissionVerdict.Dangerous, assessment.Verdict);
    }
}

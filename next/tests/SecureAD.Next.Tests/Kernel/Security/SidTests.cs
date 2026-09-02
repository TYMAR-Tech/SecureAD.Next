using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Moving a security identifier between the two forms this product stores it in.
/// </summary>
/// <remarks>
/// This matters because a name is put against a permission by matching one form to the other. A
/// SID read wrongly does not fail loudly - it fails by naming the wrong principal, which is the
/// product telling a customer something false about who can do what.
/// </remarks>
public sealed class SidTests
{
    private const string DomainAdmins = "S-1-5-21-1834058357-2590327168-2246012571-512";

    /// <summary>
    /// A built-in group's SID is recognised as belonging to the built-in domain, so a derivation
    /// can keep one domain's copy of it apart from another's.
    /// </summary>
    /// <remarks>
    /// <b>Every domain in a forest has an <c>S-1-5-32-544</c> and they are different groups.</b>
    /// Microsoft's <i>Security identifiers</i> calls the built-in domain "local in scope", and a
    /// lab forest of three domains carried 84 objects sharing a built-in SID. Treating them as one
    /// principal unions their memberships, which reports one domain's local Administrators as
    /// containing another's. See <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c>.
    /// </remarks>
    /// <param name="sid">A built-in SID.</param>
    [Theory]
    [InlineData("S-1-5-32-544")]
    [InlineData("S-1-5-32-545")]
    [InlineData("S-1-5-32-551")]
    public void ABuiltinGroupIsRecognisedAsBelongingToTheBuiltinDomain(string sid) =>
        Assert.True(Sid.IsBuiltinDomain(sid));

    /// <summary>
    /// A domain principal is not treated as built-in, because its SID already carries the domain
    /// that issued it and is unique forest-wide.
    /// </summary>
    /// <remarks>
    /// Scoping one of these would split a single principal into one per domain it was seen from,
    /// which is the opposite defect and just as wrong.
    /// </remarks>
    /// <param name="sid">A SID from outside the built-in domain.</param>
    [Theory]
    [InlineData(DomainAdmins)]
    [InlineData("S-1-5-11")]
    [InlineData("S-1-1-0")]
    [InlineData("S-1-5-18")]
    public void ASidOutsideTheBuiltinDomainIsNotScopedToADomain(string sid) =>
        Assert.False(Sid.IsBuiltinDomain(sid));

    /// <summary>
    /// The built-in domain itself is not mistaken for a principal inside it.
    /// </summary>
    /// <remarks>
    /// <c>S-1-5-32</c> is the domain, not a group in it. The prefix test requires the trailing
    /// separator so a SID that merely starts with the same digits cannot pass.
    /// </remarks>
    [Fact]
    public void TheBuiltinDomainItselfIsNotAPrincipalInIt() =>
        Assert.False(Sid.IsBuiltinDomain("S-1-5-32"));

    /// <summary>
    /// A SID nobody supplied is not claimed to be built-in.
    /// </summary>
    [Fact]
    public void ASidThatIsNotThereIsNotBuiltin() =>
        Assert.False(Sid.IsBuiltinDomain(null));

    [Fact]
    public void AWellKnownSidIsWrittenTheWayWindowsWritesIt()
    {
        byte[] localSystem = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

        Assert.Equal("S-1-5-18", Sid.ToText(localSystem));
    }

    /// <summary>
    /// A SID survives the round trip unchanged, which is what makes matching an access control
    /// entry's trustee to a captured object's <c>objectSid</c> sound.
    /// </summary>
    [Fact]
    public void ASidSurvivesBeingParsedAndWrittenAgain()
    {
        var bytes = Sid.ToBytes(DomainAdmins);

        Assert.Equal(DomainAdmins, Sid.ToText(bytes));
    }

    [Fact]
    public void TheSubAuthorityCountIsRecorded()
    {
        var bytes = Sid.ToBytes(DomainAdmins)!;

        Assert.Equal(5, bytes[1]);
    }

    /// <summary>
    /// The authority is six bytes big-endian while the sub-authorities are four bytes little-
    /// endian. Getting either the wrong way round produces a SID that looks plausible and belongs
    /// to nobody.
    /// </summary>
    [Fact]
    public void TheAuthorityIsWrittenBigEndian()
    {
        var bytes = Sid.ToBytes("S-1-5-18")!;

        Assert.Equal<byte[]>([0, 0, 0, 0, 0, 5], bytes[2..8]);
    }

    [Fact]
    public void ASidWithNoSubAuthoritiesIsLegal()
    {
        Assert.Equal("S-1-5", Sid.ToText(Sid.ToBytes("S-1-5")));
    }

    // ---------------------------------------------------------------------------------------
    // What it refuses
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A truncated SID is bytes this product cannot name. Building a shorter SID out of the bytes
    /// that did arrive would put a name against the wrong principal.
    /// </summary>
    [Fact]
    public void ATruncatedSidIsRefusedRatherThanShortened()
    {
        byte[] truncated = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0];

        Assert.Null(Sid.ToText(truncated));
    }

    [Fact]
    public void BytesTooShortToBeASidAreRefused()
    {
        Assert.Null(Sid.ToText([1, 1, 0]));
    }

    [Fact]
    public void TextThatIsNotASidIsRefused()
    {
        Assert.Null(Sid.ToBytes("Domain Admins"));
    }

    [Fact]
    public void ASidWithAnUnreadableSubAuthorityIsRefused()
    {
        Assert.Null(Sid.ToBytes("S-1-5-21-notanumber"));
    }

    [Fact]
    public void NothingIsRefused()
    {
        Assert.Null(Sid.ToBytes(null));
    }

    // ---------------------------------------------------------------------------------------
    // Structure, not just length. S-57 finding #24.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The defect <c>#24</c> names. Every read was bounds-checked, so nothing could crash or
    /// over-read, and the revision byte was taken on trust - which meant a structurally invalid
    /// SID rendered as though it were a principal.
    /// </summary>
    /// <remarks>
    /// <c>[MS-DTYP]</c> 2.4.2.2: the revision "MUST be set to 0x01".
    /// </remarks>
    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    [InlineData(255)]
    public void ASidWithARevisionWindowsDoesNotDefineIsRefused(byte revision)
    {
        byte[] bytes = [revision, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];

        Assert.Null(Sid.ToText(bytes));
    }

    /// <summary>
    /// <c>[MS-DTYP]</c> 2.4.2.2: "The maximum number of elements allowed is 15." The bound was
    /// never checked, so a count of 200 was accepted as long as the buffer happened to be long
    /// enough to hold it.
    /// </summary>
    [Fact]
    public void ASidWithMoreSubAuthoritiesThanWindowsAllowsIsRefused()
    {
        var bytes = new byte[8 + (16 * 4)];
        bytes[0] = 1;
        bytes[1] = 16;

        Assert.Null(Sid.ToText(bytes));
    }

    /// <summary>
    /// The bound is a maximum and not a smaller number: exactly fifteen is legal and must still
    /// be read, or the fix would refuse SIDs the directory is entitled to hand over.
    /// </summary>
    [Fact]
    public void ASidWithExactlyFifteenSubAuthoritiesIsRead()
    {
        var bytes = new byte[8 + (15 * 4)];
        bytes[0] = 1;
        bytes[1] = 15;
        bytes[7] = 5;

        var text = Sid.ToText(bytes);

        Assert.NotNull(text);
        Assert.Equal(15, text.Split('-').Length - 3);
    }

    /// <summary>
    /// The two directions agree about what a SID is. Text the byte reader would refuse must not
    /// convert, or a SID could round-trip into a form this product then declines to read back.
    /// </summary>
    [Theory]
    [InlineData("S-2-5-21-1-2-3")]
    [InlineData("S-0-5-21")]
    public void TextWithARevisionWindowsDoesNotDefineIsRefused(string text)
    {
        Assert.Null(Sid.ToBytes(text));
    }

    [Fact]
    public void TextWithMoreSubAuthoritiesThanWindowsAllowsIsRefused()
    {
        var text = "S-1-5" + string.Concat(Enumerable.Repeat("-1", 16));

        Assert.Null(Sid.ToBytes(text));
    }

    /// <summary>
    /// The last sub-authority is returned as the relative identifier, which is the part of a SID
    /// that means the same thing in every domain.
    /// </summary>
    /// <remarks>
    /// Microsoft, <i>Security identifiers</i>: "the last value in the series, the RID, identifies a
    /// particular account or group relative to a domain." Reading any other position would rank a
    /// principal by a number that identifies its domain instead of itself.
    /// </remarks>
    /// <param name="sid">A SID.</param>
    /// <param name="expected">The relative identifier it carries.</param>
    [Theory]
    [InlineData(DomainAdmins, 512)]
    [InlineData("S-1-5-32-544", 544)]
    [InlineData("S-1-5-21-1834058357-2590327168-2246012571-1157", 1157)]
    [InlineData("S-1-5-21-1834058357-2590327168-2246012571-500", 500)]
    public void TheRelativeIdentifierIsTheLastSubAuthority(string sid, int expected) =>
        Assert.Equal(expected, Sid.RelativeIdentifier(sid));

    /// <summary>
    /// A SID with no sub-authorities has no relative identifier, and is not reported as zero.
    /// </summary>
    /// <remarks>
    /// <b>Zero is a value, not an absence.</b> <c>SECURITY_NULL_RID</c> is 0, so returning it for
    /// "there wasn't one" would hand a caller a relative identifier Microsoft defines and let it
    /// act on it.
    /// </remarks>
    /// <param name="sid">A SID carrying no sub-authority, or text that is not a SID at all.</param>
    [Theory]
    [InlineData("S-1-5")]
    [InlineData("S-1-1")]
    [InlineData("")]
    [InlineData("not a sid")]
    [InlineData("S-2-5-21-1-2-3")]
    public void TextCarryingNoRelativeIdentifierReturnsNullRatherThanZero(string sid) =>
        Assert.Null(Sid.RelativeIdentifier(sid));

    /// <summary>
    /// The issuing domain is the SID without its relative identifier, so two principals of one
    /// domain share it and two of different domains do not.
    /// </summary>
    /// <remarks>
    /// Microsoft, <i>Security identifiers</i>: "no two domains in an enterprise share the same
    /// domain identifier." This is what lets a rule say a SID history value came from somewhere
    /// other than the account's own domain without asking the directory anything.
    /// </remarks>
    [Fact]
    public void TwoPrincipalsOfOneDomainShareAnIssuingDomainAndTwoOfDifferentDomainsDoNot()
    {
        const string otherDomainAdmins = "S-1-5-21-99887766-55443322-11009988-512";

        Assert.Equal("S-1-5-21-1834058357-2590327168-2246012571", Sid.IssuingDomain(DomainAdmins));
        Assert.Equal(
            Sid.IssuingDomain(DomainAdmins),
            Sid.IssuingDomain("S-1-5-21-1834058357-2590327168-2246012571-1157"));
        Assert.NotEqual(Sid.IssuingDomain(DomainAdmins), Sid.IssuingDomain(otherDomainAdmins));
    }

    /// <summary>
    /// Text the byte writer would refuse yields no relative identifier and no issuing domain, so
    /// this type cannot be talked into ranking a principal off a shape nothing else believes.
    /// </summary>
    /// <param name="text">Text that is not a SID.</param>
    [Theory]
    [InlineData("S-1-5-21-not-a-number-512")]
    [InlineData("X-1-5-21-1-2-3-512")]
    [InlineData("S-1-99999999999999999999-512")]
    public void TextTheByteWriterRefusesIsRefusedHereToo(string text)
    {
        Assert.Null(Sid.RelativeIdentifier(text));
        Assert.Null(Sid.IssuingDomain(text));
    }
}

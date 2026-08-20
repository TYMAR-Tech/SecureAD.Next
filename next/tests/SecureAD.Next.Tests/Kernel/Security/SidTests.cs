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
}

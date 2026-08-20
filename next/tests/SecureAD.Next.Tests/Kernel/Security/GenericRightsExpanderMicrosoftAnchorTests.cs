using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// The generic-right mappings, pinned to the values Microsoft publishes in MS-ADTS 5.1.3.2.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> <c>GenericRightsExpanderTests</c> asserts the GENERIC_ALL expansion
/// and nothing else about the other three. Its expected value, <c>0x000F01FF</c>, was written
/// from the same understanding that produced the code, so it could not have caught a wrong bit -
/// it would simply have been wrong in the same direction. GENERIC_READ, GENERIC_WRITE and
/// GENERIC_EXECUTE had no expected value asserted anywhere.
/// </para>
/// <para>
/// <b>Why a wrong bit here would matter more than anywhere else.</b> A GENERIC_ALL ACE is
/// expanded before it is compared or graded for severity. One wrong bit in that mapping changes
/// what every such ACE in the forest is understood to grant, in every run, with no symptom -
/// no parse fails, no count moves, nothing looks unusual.
/// </para>
/// <para>
/// <b>Where these numbers came from.</b> <c>next/tools/harvest-ms-adts-access-rights.ps1</c>
/// fetches MS-ADTS 5.1.3.2, extracts the thirteen specific access-right bits and the four
/// mapping equations Microsoft states, and computes each mapping value by OR-ing the bits it
/// names. The values below were taken from that script's output, not from reading the code.
/// </para>
/// <para>
/// <b>What is checked is behaviour, not the constants.</b> The mapping constants are private,
/// so each row goes through <see cref="GenericRightsExpander.Expand"/>. That is the stronger
/// check anyway: it pins what the type does rather than what it stores.
/// </para>
/// </remarks>
public sealed class GenericRightsExpanderMicrosoftAnchorTests
{
    private const int GenericRead = unchecked((int)0x80000000);
    private const int GenericWrite = 0x40000000;
    private const int GenericExecute = 0x20000000;
    private const int GenericAll = 0x10000000;

    /// <summary>
    /// Each row is one generic right and the specific-rights mask MS-ADTS 5.1.3.2 maps it to.
    /// </summary>
    [Theory]
    [InlineData(GenericRead, 0x00020094)]    // GR = RC | LC | RP | LO
    [InlineData(GenericWrite, 0x00020028)]   // GW = RC | WP | VW
    [InlineData(GenericExecute, 0x00020004)] // GX = RC | LC
    [InlineData(GenericAll, 0x000F01FF)]     // GA = DE | RC | WD | WO | CC | DC | DT | RP | WP | LC | LO | CR | VW
    public void WhenAGenericRightIsExpanded_ThenItYieldsTheMaskMicrosoftPublishes(
        int genericBit,
        int expectedMask)
    {
        Assert.Equal(expectedMask, GenericRightsExpander.Expand(genericBit));
    }

    /// <summary>
    /// The four generic bit positions themselves, from the same section. A correct mapping
    /// reached from the wrong bit position would still expand the wrong ACEs.
    /// </summary>
    [Theory]
    [InlineData(GenericRead)]
    [InlineData(GenericWrite)]
    [InlineData(GenericExecute)]
    [InlineData(GenericAll)]
    public void WhenAGenericBitIsPresent_ThenItIsRecognisedAsGeneric(int genericBit)
    {
        Assert.True(GenericRightsExpander.HasGenericRights(genericBit));
    }

    /// <summary>
    /// Negative control. Every specific-rights bit MS-ADTS 5.1.3.2 defines must expand to
    /// itself unchanged, and must not be mistaken for a generic bit. Without this a mapping
    /// that simply returned <c>0x000F01FF</c> for everything would pass the rows above.
    /// </summary>
    [Theory]
    [InlineData(0x00000001)] // CC RIGHT_DS_CREATE_CHILD
    [InlineData(0x00000002)] // DC RIGHT_DS_DELETE_CHILD
    [InlineData(0x00000004)] // LC RIGHT_DS_LIST_CONTENTS
    [InlineData(0x00000008)] // VW RIGHT_DS_WRITE_PROPERTY_EXTENDED
    [InlineData(0x00000010)] // RP RIGHT_DS_READ_PROPERTY
    [InlineData(0x00000020)] // WP RIGHT_DS_WRITE_PROPERTY
    [InlineData(0x00000040)] // DT RIGHT_DS_DELETE_TREE
    [InlineData(0x00000080)] // LO RIGHT_DS_LIST_OBJECT
    [InlineData(0x00000100)] // CR RIGHT_DS_CONTROL_ACCESS
    [InlineData(0x00010000)] // DE RIGHT_DELETE
    [InlineData(0x00020000)] // RC RIGHT_READ_CONTROL
    [InlineData(0x00040000)] // WD RIGHT_WRITE_DAC
    [InlineData(0x00080000)] // WO RIGHT_WRITE_OWNER
    public void WhenASpecificRightIsExpanded_ThenNothingIsAddedOrRemoved(int specificBit)
    {
        Assert.False(GenericRightsExpander.HasGenericRights(specificBit));
        Assert.Equal(specificBit, GenericRightsExpander.Expand(specificBit));
    }
}

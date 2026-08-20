using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Expanding generic rights into the AD-specific bits they stand for.
///
/// <para>
/// <c>GENERIC_ALL</c> and the expanded specific-rights mask are the same permission written two
/// ways. Comparing them unexpanded reports a delta where the directory changed nothing, which is
/// the false positive this expansion exists to remove.
/// </para>
/// </summary>
public sealed class GenericRightsExpanderTests
{
    private const int GenericRead = unchecked((int)0x80000000);
    private const int GenericWrite = 0x40000000;
    private const int GenericExecute = 0x20000000;
    private const int GenericAll = 0x10000000;

    [Fact]
    public void WhenGenericAllIsSet_ThenTheFullSpecificMaskReplacesIt()
    {
        var expanded = GenericRightsExpander.Expand(GenericAll);

        Assert.Equal(0x000F01FF, expanded);
        Assert.Equal(0, expanded & GenericAll);
    }

    [Fact]
    public void WhenGenericReadIsSet_ThenReadControlAndReadPropertyReplaceIt()
    {
        var expanded = GenericRightsExpander.Expand(GenericRead);

        Assert.Equal(0, expanded & GenericRead);
        Assert.NotEqual(0, expanded & 0x00020000); // READ_CONTROL
        Assert.NotEqual(0, expanded & 0x00000010); // DS_READ_PROPERTY
    }

    [Fact]
    public void WhenGenericWriteIsSet_ThenWritePropertyReplacesIt()
    {
        var expanded = GenericRightsExpander.Expand(GenericWrite);

        Assert.Equal(0, expanded & GenericWrite);
        Assert.NotEqual(0, expanded & 0x00000020); // DS_WRITE_PROPERTY
    }

    [Fact]
    public void WhenGenericExecuteIsSet_ThenListContentsReplacesIt()
    {
        var expanded = GenericRightsExpander.Expand(GenericExecute);

        Assert.Equal(0, expanded & GenericExecute);
        Assert.NotEqual(0, expanded & 0x00000004); // DS_LIST_CONTENTS
    }

    [Fact]
    public void WhenNoGenericBitIsSet_ThenTheMaskIsUnchanged()
    {
        Assert.Equal(0x000F01FF, GenericRightsExpander.Expand(0x000F01FF));
    }

    /// <summary>
    /// Expansion adds bits rather than replacing the mask, so a right granted explicitly alongside
    /// a generic one survives.
    /// </summary>
    [Fact]
    public void WhenGenericAndSpecificAreMixed_ThenBothSurvive()
    {
        var expanded = GenericRightsExpander.Expand(GenericRead | 0x00000001);

        Assert.NotEqual(0, expanded & 0x00000001); // DS_CREATE_CHILD, granted explicitly
        Assert.NotEqual(0, expanded & 0x00000010); // DS_READ_PROPERTY, from the expansion
    }

    /// <summary>
    /// The two forms of the same permission must be indistinguishable after expansion. This is the
    /// property the whole component exists for, stated directly.
    /// </summary>
    [Fact]
    public void WhenGenericAllAndItsExpansionAreCompared_ThenTheyAreEqual()
    {
        Assert.Equal(
            GenericRightsExpander.Expand(0x000F01FF),
            GenericRightsExpander.Expand(GenericAll));
    }

    [Theory]
    [InlineData(GenericRead)]
    [InlineData(GenericWrite)]
    [InlineData(GenericExecute)]
    [InlineData(GenericAll)]
    public void WhenAGenericBitIsSet_ThenItIsDetected(int mask)
    {
        Assert.True(GenericRightsExpander.HasGenericRights(mask));
    }

    [Fact]
    public void WhenNoGenericBitIsSet_ThenNoneIsDetected()
    {
        Assert.False(GenericRightsExpander.HasGenericRights(0x000F01FF));
    }
}

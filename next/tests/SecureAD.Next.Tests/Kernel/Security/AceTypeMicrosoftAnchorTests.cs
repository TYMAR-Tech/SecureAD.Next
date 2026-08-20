using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Every <see cref="AceType"/> value, pinned to MS-DTYP 2.4.4.1.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this matters more than most.</b> This enum decides whether an entry allows or denies.
/// Swap two values and the product reports a deny as an allow - it would tell a customer a
/// permission is safe when it is the opposite. Nothing else in the parser can catch that: the
/// bytes still parse, the counts still add up, and every other test still passes.
/// </para>
/// <para>
/// <b>Where these numbers came from.</b> <c>next/tools/harvest-ms-dtyp-ace-types.ps1</c> fetches
/// MS-DTYP 2.4.4.1 and extracts all twenty constants. The same page was read independently
/// through the Microsoft Learn documentation service and the two agreed.
/// </para>
/// <para>
/// <b>Ten of twenty are deliberately absent.</b> Six are marked "Reserved for future use" by
/// Microsoft and have no structure to parse. The other four are audit and system types that
/// appear only in a SACL, and <c>docs/decisions/0036</c> says capture never requests one. The
/// enum is therefore not a copy of Microsoft's table and should not become one; what it must be
/// is correct about every value it does define, and complete over the types a DACL can hold.
/// </para>
/// </remarks>
public sealed class AceTypeMicrosoftAnchorTests
{
    /// <summary>
    /// Each row is a constant Microsoft publishes, with the value it publishes for it.
    /// </summary>
    [Theory]
    [InlineData(AceType.AccessAllowed, 0x00)]               // ACCESS_ALLOWED_ACE_TYPE
    [InlineData(AceType.AccessDenied, 0x01)]                // ACCESS_DENIED_ACE_TYPE
    [InlineData(AceType.SystemAudit, 0x02)]                 // SYSTEM_AUDIT_ACE_TYPE
    [InlineData(AceType.AccessAllowedObject, 0x05)]         // ACCESS_ALLOWED_OBJECT_ACE_TYPE
    [InlineData(AceType.AccessDeniedObject, 0x06)]          // ACCESS_DENIED_OBJECT_ACE_TYPE
    [InlineData(AceType.SystemAuditObject, 0x07)]           // SYSTEM_AUDIT_OBJECT_ACE_TYPE
    [InlineData(AceType.AccessAllowedCallback, 0x09)]       // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    [InlineData(AceType.AccessDeniedCallback, 0x0A)]        // ACCESS_DENIED_CALLBACK_ACE_TYPE
    [InlineData(AceType.AccessAllowedCallbackObject, 0x0B)] // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    [InlineData(AceType.AccessDeniedCallbackObject, 0x0C)]  // ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    public void WhenAnAceTypeIsDefined_ThenItCarriesTheValueMicrosoftPublishes(
        AceType type,
        int expected)
    {
        Assert.Equal(expected, (int)type);
    }

    /// <summary>
    /// Every access-allowed and access-denied form Microsoft defines is present. These are the
    /// types an entry in a DACL can carry, so one missing is a permission the product cannot
    /// read - and an unrecognised deny is the dangerous direction.
    /// </summary>
    [Theory]
    [InlineData(0x00)]
    [InlineData(0x01)]
    [InlineData(0x05)]
    [InlineData(0x06)]
    [InlineData(0x09)]
    [InlineData(0x0A)]
    [InlineData(0x0B)]
    [InlineData(0x0C)]
    public void WhenMicrosoftDefinesAnAccessAceType_ThenTheEnumHasIt(int value)
    {
        Assert.True(
            Enum.IsDefined(typeof(AceType), (byte)value),
            $"MS-DTYP 2.4.4.1 defines an access ACE type 0x{value:X2} that AceType does not. An "
            + "entry the product cannot name is an entry it cannot judge.");
    }

    /// <summary>
    /// The enum invents nothing. A value not in Microsoft's table would be a type no directory
    /// ever sends, and a name for it invites code that pretends to handle it.
    /// </summary>
    [Fact]
    public void TheEnumDefinesNoValueMicrosoftDoesNot()
    {
        int[] published =
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ];

        var invented = Enum.GetValues<AceType>()
            .Where(t => !published.Contains((int)t))
            .Select(t => $"{t} = 0x{(int)t:X2}")
            .ToArray();

        Assert.True(
            invented.Length == 0,
            "AceType defines values MS-DTYP 2.4.4.1 does not publish: "
            + string.Join(", ", invented));
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass over an empty enum and report
    /// that nothing is wrong with it.
    /// </summary>
    [Fact]
    public void TheEnumIsPopulated()
    {
        Assert.Equal(10, Enum.GetValues<AceType>().Length);
    }
}

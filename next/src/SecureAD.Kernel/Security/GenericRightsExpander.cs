namespace SecureAD.Kernel.Security;

/// <summary>
/// Expands generic access rights (GENERIC_ALL, GENERIC_WRITE, GENERIC_READ, GENERIC_EXECUTE)
/// into the AD-specific explicit mask bits they represent.
///
/// <para>
/// <b>For comparison and severity only. This does not say what a stored entry grants.</b> A raw
/// generic bit and its expansion are the same permission only at the moment one is written or
/// requested, when the resource manager performs the mapping and clears the generic bit.
/// [MS-DTYP] 2.4.3 states that the access-check algorithm does <b>not</b> map generic bits found in
/// an ACE already attached to an object, and that such an ACE might produce unintended results. So
/// expanding a stored mask and reporting the result manufactures rights the domain controller would
/// not grant.
/// </para>
/// <para>
/// Normalising for comparison is still correct and is why this exists: comparing a raw generic bit
/// against an expanded mask produces a delta where the directory changed nothing. Reading the mask
/// that grants most is also sound for judging <i>severity</i>, which is a different question from
/// what the entry says. What must not happen is one mask serving comparison and semantics at once.
/// The raw mask stays on <see cref="ParsedAce"/> and the expanded one on
/// <see cref="CanonicalAce"/>, so both remain available and which is which is never in doubt.
/// Required by <c>docs/next/S-56</c> R2.
/// </para>
/// <para>
/// This summary previously said a raw generic bit and an expanded mask were the same permission
/// written two ways. That is false for a stored ACE, and it was the sentence the defect rested on.
/// </para>
/// </summary>
public static class GenericRightsExpander
{
    // Generic right bit positions (from winnt.h)
    private const int GENERIC_READ = unchecked((int)0x80000000);
    private const int GENERIC_WRITE = 0x40000000;
    private const int GENERIC_EXECUTE = 0x20000000;
    private const int GENERIC_ALL = 0x10000000;

    // AD DS generic right mappings (per MS-ADTS §5.1.3.2)
    // These are the standard mappings for directory service objects.

    /// <summary>
    /// DS_GENERIC_READ = READ_CONTROL | DS_LIST_CONTENTS | DS_READ_PROPERTY | DS_LIST_OBJECT
    /// </summary>
    private const int DS_GENERIC_READ = 0x00020000   // READ_CONTROL
                                      | 0x00000004   // DS_LIST_CONTENTS (ACTRL_DS_LIST)
                                      | 0x00000010   // DS_READ_PROPERTY (ACTRL_DS_READ_PROP)
                                      | 0x00000080;  // DS_LIST_OBJECT (ACTRL_DS_LIST_OBJECT)

    /// <summary>
    /// DS_GENERIC_WRITE = READ_CONTROL | DS_WRITE_PROPERTY | DS_WRITE_PROPERTY_EXTENDED (Self)
    /// </summary>
    private const int DS_GENERIC_WRITE = 0x00020000   // READ_CONTROL
                                       | 0x00000020   // DS_WRITE_PROPERTY (ACTRL_DS_WRITE_PROP)
                                       | 0x00000008;  // DS_SELF (ACTRL_DS_SELF / Validated Writes)

    /// <summary>
    /// DS_GENERIC_EXECUTE = READ_CONTROL | DS_LIST_CONTENTS
    /// </summary>
    private const int DS_GENERIC_EXECUTE = 0x00020000  // READ_CONTROL
                                         | 0x00000004; // DS_LIST_CONTENTS

    /// <summary>
    /// DS_GENERIC_ALL = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | all DS-specific rights.
    /// 0x000F01FF covers standard rights (0x000F0000) + all DS-specific rights (0x000001FF).
    /// </summary>
    private const int DS_GENERIC_ALL = 0x000F01FF;

    /// <summary>
    /// Expands generic rights in the access mask to their AD DS explicit equivalents.
    /// Generic bits are cleared after expansion.
    /// </summary>
    /// <param name="accessMask">Raw access mask potentially containing generic rights.</param>
    /// <returns>Access mask with generic rights expanded to explicit bits.</returns>
    public static int Expand(int accessMask)
    {
        var result = accessMask;

        if ((result & GENERIC_ALL) != 0)
        {
            result |= DS_GENERIC_ALL;
            result &= ~GENERIC_ALL;
        }

        if ((result & GENERIC_READ) != 0)
        {
            result |= DS_GENERIC_READ;
            result &= ~GENERIC_READ;
        }

        if ((result & GENERIC_WRITE) != 0)
        {
            result |= DS_GENERIC_WRITE;
            result &= ~GENERIC_WRITE;
        }

        if ((result & GENERIC_EXECUTE) != 0)
        {
            result |= DS_GENERIC_EXECUTE;
            result &= ~GENERIC_EXECUTE;
        }

        return result;
    }

    /// <summary>Returns true if the access mask contains any generic right bits.</summary>
    public static bool HasGenericRights(int accessMask)
    {
        return (accessMask & (GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE)) != 0;
    }
}

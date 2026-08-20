namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Registry value types as stored in a Registry.pol entry's Type field.
/// Values match the REG_* constants from the Win32 registry spec ([MS-GPREG] / winnt.h).
/// </summary>
public enum RegistryValueType : uint
{
    /// <summary>REG_NONE (0): No defined value type.</summary>
    None = 0,

    /// <summary>REG_SZ (1): Null-terminated UTF-16LE string.</summary>
    String = 1,

    /// <summary>REG_EXPAND_SZ (2): Null-terminated UTF-16LE string with unexpanded environment references.</summary>
    ExpandString = 2,

    /// <summary>REG_BINARY (3): Free-form binary data.</summary>
    Binary = 3,

    /// <summary>REG_DWORD (4): 32-bit little-endian number.</summary>
    Dword = 4,

    /// <summary>REG_DWORD_BIG_ENDIAN (5): 32-bit big-endian number.</summary>
    DwordBigEndian = 5,

    /// <summary>REG_LINK (6): Null-terminated UTF-16LE symbolic link string.</summary>
    Link = 6,

    /// <summary>REG_MULTI_SZ (7): Sequence of null-terminated UTF-16LE strings, terminated by an extra null.</summary>
    MultiString = 7,

    /// <summary>REG_QWORD (11): 64-bit little-endian number.</summary>
    Qword = 11
}

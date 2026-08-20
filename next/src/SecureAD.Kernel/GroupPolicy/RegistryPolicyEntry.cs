using System.Buffers.Binary;
using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// A single value entry parsed from a Registry.pol file (group policy registry settings).
/// Pure data record — the raw <see cref="Data"/> bytes are preserved verbatim; the typed
/// accessors interpret them on demand without mutating the entry.
/// </summary>
/// <param name="KeyPath">Registry key path (e.g., "Software\Policies\Microsoft\Windows\...").</param>
/// <param name="ValueName">Registry value name under <paramref name="KeyPath"/>. May be empty for a default value.</param>
/// <param name="RegistryType">Raw 32-bit registry value type as stored in the entry (REG_* constant).</param>
/// <param name="Data">Raw value bytes exactly as stored in the file. Length matches the entry's size field.</param>
public sealed record RegistryPolicyEntry(
    string KeyPath,
    string ValueName,
    uint RegistryType,
    byte[] Data)
{
    /// <summary>
    /// The <see cref="RegistryType"/> mapped to a strongly-typed value. Unknown raw types are
    /// preserved by the cast (compare against <see cref="RegistryType"/> when fidelity matters).
    /// </summary>
    public RegistryValueType ValueType => (RegistryValueType)RegistryType;

    /// <summary>
    /// Interprets <see cref="Data"/> as a 32-bit number when the type is REG_DWORD or
    /// REG_DWORD_BIG_ENDIAN and at least 4 bytes are present.
    /// </summary>
    /// <returns>The DWORD value, or null if the type/length does not match.</returns>
    public uint? AsDword()
    {
        if (Data.Length < sizeof(uint))
        {
            return null;
        }

        return ValueType switch
        {
            RegistryValueType.Dword => BinaryPrimitives.ReadUInt32LittleEndian(Data),
            RegistryValueType.DwordBigEndian => BinaryPrimitives.ReadUInt32BigEndian(Data),
            _ => null
        };
    }

    /// <summary>
    /// Interprets <see cref="Data"/> as a 64-bit little-endian number when the type is REG_QWORD
    /// and at least 8 bytes are present.
    /// </summary>
    /// <returns>The QWORD value, or null if the type/length does not match.</returns>
    public ulong? AsQword()
    {
        if (ValueType != RegistryValueType.Qword || Data.Length < sizeof(ulong))
        {
            return null;
        }

        return BinaryPrimitives.ReadUInt64LittleEndian(Data);
    }

    /// <summary>
    /// Interprets <see cref="Data"/> as a UTF-16LE string when the type is REG_SZ, REG_EXPAND_SZ,
    /// or REG_LINK. The trailing null terminator is removed.
    /// </summary>
    /// <returns>The decoded string, or null if the type does not match.</returns>
    public string? AsString()
    {
        return ValueType switch
        {
            RegistryValueType.String or RegistryValueType.ExpandString or RegistryValueType.Link
                => Encoding.Unicode.GetString(Data).TrimEnd('\0'),
            _ => null
        };
    }

    /// <summary>
    /// Interprets <see cref="Data"/> as a REG_MULTI_SZ sequence of UTF-16LE strings.
    /// Empty entries (including the double-null terminator) are omitted.
    /// </summary>
    /// <returns>
    /// The decoded strings, or null if the type does not match. Null rather than an empty list,
    /// because a REG_MULTI_SZ holding no strings and a value that is not a REG_MULTI_SZ at all
    /// are different answers, and returning the same empty list for both is the ambiguity gate 4
    /// and decision 0002 exist to prevent. <see cref="AsString"/> already draws the distinction
    /// this way.
    /// </returns>
    public IReadOnlyList<string>? AsMultiString()
    {
        if (ValueType != RegistryValueType.MultiString)
        {
            return null;
        }

        if (Data.Length == 0)
        {
            return [];
        }

        return Encoding.Unicode.GetString(Data)
            .Split('\0', StringSplitOptions.RemoveEmptyEntries);
    }
}

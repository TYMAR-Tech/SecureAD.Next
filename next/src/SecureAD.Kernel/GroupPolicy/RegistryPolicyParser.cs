using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Parses raw Registry.pol bytes into <see cref="ParsedRegistryPolicy"/>.
/// Pure binary parsing — no OS/platform calls, no file or registry access.
/// Implements the POL file format from [MS-GPREG] §2.2: an 8-byte header ("PReg" + version)
/// followed by a sequence of "[key;value;type;size;data]" entries encoded in UTF-16LE,
/// where key/value are null-terminated strings and type/size are little-endian DWORDs.
/// </summary>
/// <remarks>
/// Original implementation written from the public Microsoft Open Specification
/// [MS-GPREG] (Group Policy: Registry Extension Encoding), §2.2 "Message Syntax".
/// Spec: https://learn.microsoft.com/openspecs/windows_protocols/ms-gpreg.
/// Not derived from any third-party parser source.
/// </remarks>
public static class RegistryPolicyParser
{
    // Header: 4-byte signature "PReg" + 4-byte version, both little-endian.
    private const int HeaderSize = 8;
    private const uint Signature = 0x67655250; // 'P','R','e','g' read little-endian
    private const uint ExpectedVersion = 1;

    // Structural delimiters, stored as their UTF-16LE code units.
    private const ushort OpenBracket = '[';
    private const ushort CloseBracket = ']';
    private const ushort Semicolon = ';';
    private const ushort NullChar = 0;

    private const int CharSize = sizeof(ushort); // one UTF-16LE code unit
    private const int FieldSize = sizeof(uint);  // type/size DWORD width

    /// <summary>
    /// Parses raw Registry.pol bytes into their registry value entries.
    /// </summary>
    /// <param name="rawPolicy">Raw Registry.pol file bytes.</param>
    /// <returns>Parsed result with entries and any errors. Partial results are returned on malformed input.</returns>
    public static ParsedRegistryPolicy ParsePolicyFile(ReadOnlySpan<byte> rawPolicy)
    {
        var errors = new List<string>();
        var entries = new List<RegistryPolicyEntry>();

        if (rawPolicy.Length < HeaderSize)
        {
            errors.Add($"Registry.pol too short: {rawPolicy.Length} bytes, minimum {HeaderSize}");
            return new ParsedRegistryPolicy(entries, errors);
        }

        var signature = BinaryPrimitives.ReadUInt32LittleEndian(rawPolicy);
        if (signature != Signature)
        {
            errors.Add($"Invalid Registry.pol signature: 0x{signature:X8} (expected 0x{Signature:X8})");
            return new ParsedRegistryPolicy(entries, errors);
        }

        var version = BinaryPrimitives.ReadUInt32LittleEndian(rawPolicy[4..]);
        if (version != ExpectedVersion)
        {
            errors.Add($"Unexpected Registry.pol version: {version} (expected {ExpectedVersion})");
        }

        var offset = HeaderSize;
        var index = 0;
        while (offset < rawPolicy.Length)
        {
            if (!TryParseEntry(rawPolicy, ref offset, index, errors, out var entry))
            {
                break;
            }

            entries.Add(entry);
            index++;
        }

        return new ParsedRegistryPolicy(entries, errors);
    }

    /// <summary>
    /// Parses a single "[key;value;type;size;data]" entry, advancing <paramref name="offset"/>
    /// past it on success. On any structural error an entry-scoped message is recorded and false
    /// is returned, leaving the caller to stop with the entries parsed so far.
    /// </summary>
    private static bool TryParseEntry(
        ReadOnlySpan<byte> data, ref int offset, int index, List<string> errors,
        [NotNullWhen(true)] out RegistryPolicyEntry? entry)
    {
        entry = null;

        if (!TryConsumeChar(data, ref offset, OpenBracket))
        {
            errors.Add($"Entry {index}: expected '[' at offset {offset}");
            return false;
        }

        if (!TryReadString(data, ref offset, out var keyPath))
        {
            errors.Add($"Entry {index}: unterminated key path at offset {offset}");
            return false;
        }

        if (!TryConsumeChar(data, ref offset, Semicolon))
        {
            errors.Add($"Entry {index}: expected ';' after key path at offset {offset}");
            return false;
        }

        if (!TryReadString(data, ref offset, out var valueName))
        {
            errors.Add($"Entry {index}: unterminated value name at offset {offset}");
            return false;
        }

        if (!TryConsumeChar(data, ref offset, Semicolon))
        {
            errors.Add($"Entry {index}: expected ';' after value name at offset {offset}");
            return false;
        }

        if (!TryReadDword(data, ref offset, out var registryType))
        {
            errors.Add($"Entry {index}: truncated type field at offset {offset}");
            return false;
        }

        if (!TryConsumeChar(data, ref offset, Semicolon))
        {
            errors.Add($"Entry {index}: expected ';' after type at offset {offset}");
            return false;
        }

        if (!TryReadDword(data, ref offset, out var size))
        {
            errors.Add($"Entry {index}: truncated size field at offset {offset}");
            return false;
        }

        if (!TryConsumeChar(data, ref offset, Semicolon))
        {
            errors.Add($"Entry {index}: expected ';' after size at offset {offset}");
            return false;
        }

        if (offset + (long)size > data.Length)
        {
            errors.Add($"Entry {index}: data size {size} exceeds remaining bytes at offset {offset}");
            return false;
        }

        var valueData = data.Slice(offset, (int)size).ToArray();
        offset += (int)size;

        if (!TryConsumeChar(data, ref offset, CloseBracket))
        {
            errors.Add($"Entry {index}: expected ']' at offset {offset}");
            return false;
        }

        entry = new RegistryPolicyEntry(keyPath, valueName, registryType, valueData);
        return true;
    }

    /// <summary>
    /// Consumes a single expected UTF-16LE code unit, advancing the offset on a match.
    /// </summary>
    private static bool TryConsumeChar(ReadOnlySpan<byte> data, ref int offset, ushort expected)
    {
        if (offset + CharSize > data.Length)
        {
            return false;
        }

        if (BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]) != expected)
        {
            return false;
        }

        offset += CharSize;
        return true;
    }

    /// <summary>
    /// Reads a null-terminated UTF-16LE string, advancing the offset past the terminator.
    /// </summary>
    private static bool TryReadString(ReadOnlySpan<byte> data, ref int offset, out string value)
    {
        value = string.Empty;
        var start = offset;

        while (offset + CharSize <= data.Length)
        {
            if (BinaryPrimitives.ReadUInt16LittleEndian(data[offset..]) == NullChar)
            {
                value = Encoding.Unicode.GetString(data[start..offset]);
                offset += CharSize; // consume the null terminator
                return true;
            }

            offset += CharSize;
        }

        return false; // no null terminator before end of buffer
    }

    /// <summary>
    /// Reads a 32-bit little-endian value, advancing the offset on success.
    /// </summary>
    private static bool TryReadDword(ReadOnlySpan<byte> data, ref int offset, out uint value)
    {
        value = 0;
        if (offset + FieldSize > data.Length)
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(data[offset..]);
        offset += FieldSize;
        return true;
    }
}

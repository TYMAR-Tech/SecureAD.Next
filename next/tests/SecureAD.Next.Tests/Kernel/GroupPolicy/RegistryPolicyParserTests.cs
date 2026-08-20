using System.Buffers.Binary;
using System.Text;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public class RegistryPolicyParserTests
{
    // --- Header parsing ---

    [Fact]
    public void WhenInputTooShort_ThenReturnsError()
    {
        var result = RegistryPolicyParser.ParsePolicyFile(new byte[4]);

        Assert.NotEmpty(result.Errors);
        Assert.Contains(result.Errors, e => e.Contains("too short"));
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void WhenEmptyInput_ThenReturnsError()
    {
        var result = RegistryPolicyParser.ParsePolicyFile(ReadOnlySpan<byte>.Empty);

        Assert.NotEmpty(result.Errors);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void WhenInvalidSignature_ThenReturnsError()
    {
        var bytes = new byte[8];
        Encoding.ASCII.GetBytes("Junk").CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 1);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Contains(result.Errors, e => e.Contains("signature"));
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void WhenValidHeaderNoEntries_ThenNoErrorsAndNoEntries()
    {
        var bytes = BuildPolicyFile();

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Empty(result.Errors);
        Assert.Empty(result.Entries);
    }

    [Fact]
    public void WhenUnexpectedVersion_ThenReturnsErrorButStillParses()
    {
        var entry = BuildEntry("Software\\Policies\\Test", "Enabled", BuildDwordData(1));
        var bytes = BuildPolicyFile(version: 99, entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Contains(result.Errors, e => e.Contains("version"));
        Assert.Single(result.Entries);
    }

    // --- Single entry parsing ---

    [Fact]
    public void WhenDwordEntry_ThenKeyValueAndTypeParsed()
    {
        var entry = BuildEntry(
            "Software\\Policies\\Microsoft\\Windows",
            "DisableThing",
            BuildDwordData(1));
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Empty(result.Errors);
        var parsed = Assert.Single(result.Entries);
        Assert.Equal("Software\\Policies\\Microsoft\\Windows", parsed.KeyPath);
        Assert.Equal("DisableThing", parsed.ValueName);
        Assert.Equal(RegistryValueType.Dword, parsed.ValueType);
    }

    [Fact]
    public void WhenDwordEntry_ThenAsDwordReturnsValue()
    {
        var entry = BuildEntry("Key", "Value", BuildDwordData(0x12345678));
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Equal(0x12345678u, result.Entries[0].AsDword());
    }

    [Fact]
    public void WhenStringEntry_ThenAsStringReturnsValueWithoutTerminator()
    {
        var entry = BuildEntry("Key", "Path", BuildStringData("C:\\Windows"), RegistryValueType.String);
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Equal(RegistryValueType.String, result.Entries[0].ValueType);
        Assert.Equal("C:\\Windows", result.Entries[0].AsString());
    }

    [Fact]
    public void WhenQwordEntry_ThenAsQwordReturnsValue()
    {
        var entry = BuildEntry("Key", "Big", BuildQwordData(0x1122334455667788), RegistryValueType.Qword);
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Equal(0x1122334455667788ul, result.Entries[0].AsQword());
    }

    [Fact]
    public void WhenBigEndianDword_ThenAsDwordReturnsValue()
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(data, 0x0000002A);
        var entry = BuildEntry("Key", "BE", data, RegistryValueType.DwordBigEndian);
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Equal(42u, result.Entries[0].AsDword());
    }

    [Fact]
    public void WhenMultiStringEntry_ThenAsMultiStringReturnsStrings()
    {
        var entry = BuildEntry("Key", "List", BuildMultiStringData(["alpha", "beta", "gamma"]), RegistryValueType.MultiString);
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Equal(RegistryValueType.MultiString, result.Entries[0].ValueType);
        Assert.Equal(["alpha", "beta", "gamma"], result.Entries[0].AsMultiString());
    }

    [Fact]
    public void WhenEmptyValueName_ThenParsedAsEmptyString()
    {
        var entry = BuildEntry("Key", "", BuildDwordData(0));
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Empty(result.Errors);
        Assert.Equal(string.Empty, result.Entries[0].ValueName);
    }

    // --- Type-accessor mismatches ---

    [Fact]
    public void WhenAsStringOnDword_ThenReturnsNull()
    {
        var entry = BuildEntry("Key", "Value", BuildDwordData(1));
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Null(result.Entries[0].AsString());
    }

    [Fact]
    public void WhenAsDwordOnString_ThenReturnsNull()
    {
        var entry = BuildEntry("Key", "Value", BuildStringData("text"), RegistryValueType.String);
        var bytes = BuildPolicyFile(entries: [entry]);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Null(result.Entries[0].AsDword());
    }

    // --- Multiple entries ---

    [Fact]
    public void WhenMultipleEntries_ThenAllParsedInOrder()
    {
        var entries = new[]
        {
            BuildEntry("Key1", "A", BuildDwordData(1)),
            BuildEntry("Key2", "B", BuildStringData("hello"), RegistryValueType.String),
            BuildEntry("Key3", "C", BuildDwordData(3)),
        };
        var bytes = BuildPolicyFile(entries: entries);

        var result = RegistryPolicyParser.ParsePolicyFile(bytes);

        Assert.Empty(result.Errors);
        Assert.Equal(3, result.Entries.Count);
        Assert.Equal("Key1", result.Entries[0].KeyPath);
        Assert.Equal("hello", result.Entries[1].AsString());
        Assert.Equal(3u, result.Entries[2].AsDword());
    }

    // --- Error resilience ---

    [Fact]
    public void WhenSizeExceedsBuffer_ThenReturnsErrorWithPartialResults()
    {
        var good = BuildEntry("Key1", "A", BuildDwordData(1));
        var bytes = BuildPolicyFile(entries: [good]);

        // Append a malformed entry whose declared size runs past the buffer.
        var malformed = BuildEntryWithRawSize("Key2", "B", RegistryValueType.Binary, declaredSize: 9999, actualData: [0x01, 0x02]);
        var combined = Concat(bytes, malformed);

        var result = RegistryPolicyParser.ParsePolicyFile(combined);

        Assert.Single(result.Entries); // the first good entry survives
        Assert.Contains(result.Errors, e => e.Contains("exceeds remaining bytes"));
    }

    [Fact]
    public void WhenUnterminatedString_ThenReturnsError()
    {
        // Header + '[' + key chars with no null terminator and no closing structure.
        using var ms = new MemoryStream();
        WriteHeader(ms, version: 1);
        WriteChar(ms, '[');
        ms.Write(Encoding.Unicode.GetBytes("NoTerminator"));

        var result = RegistryPolicyParser.ParsePolicyFile(ms.ToArray());

        Assert.Contains(result.Errors, e => e.Contains("unterminated key path"));
    }

    [Fact]
    public void WhenMissingCloseBracket_ThenReturnsError()
    {
        var entry = BuildEntry("Key", "Value", BuildDwordData(1));
        var full = BuildPolicyFile(entries: [entry]);
        // Drop the trailing ']' (last 2 bytes).
        var truncated = full.AsSpan(0, full.Length - 2).ToArray();

        var result = RegistryPolicyParser.ParsePolicyFile(truncated);

        Assert.Contains(result.Errors, e => e.Contains("expected ']'"));
    }

    // =====================================================================
    //  Registry.pol byte builders — construct valid PReg bytes for tests
    // =====================================================================

    private static byte[] BuildPolicyFile(uint version = 1, byte[][]? entries = null)
    {
        using var ms = new MemoryStream();
        WriteHeader(ms, version);

        if (entries is not null)
        {
            foreach (var entry in entries)
            {
                ms.Write(entry);
            }
        }

        return ms.ToArray();
    }

    private static void WriteHeader(MemoryStream ms, uint version)
    {
        ms.Write(Encoding.ASCII.GetBytes("PReg")); // signature
        var versionBytes = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(versionBytes, version);
        ms.Write(versionBytes);
    }

    private static byte[] BuildEntry(string keyPath, string valueName, byte[] data,
        RegistryValueType type = RegistryValueType.Dword)
    {
        return BuildEntryWithRawSize(keyPath, valueName, type, (uint)data.Length, data);
    }

    private static byte[] BuildEntryWithRawSize(string keyPath, string valueName,
        RegistryValueType type, uint declaredSize, byte[] actualData)
    {
        using var ms = new MemoryStream();
        WriteChar(ms, '[');
        WriteNullTerminatedString(ms, keyPath);
        WriteChar(ms, ';');
        WriteNullTerminatedString(ms, valueName);
        WriteChar(ms, ';');
        WriteDword(ms, (uint)type);
        WriteChar(ms, ';');
        WriteDword(ms, declaredSize);
        WriteChar(ms, ';');
        ms.Write(actualData);
        WriteChar(ms, ']');
        return ms.ToArray();
    }

    private static void WriteChar(MemoryStream ms, char c)
    {
        var buf = new byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buf, c);
        ms.Write(buf);
    }

    private static void WriteNullTerminatedString(MemoryStream ms, string value)
    {
        ms.Write(Encoding.Unicode.GetBytes(value));
        ms.Write([0, 0]); // UTF-16LE null terminator
    }

    private static void WriteDword(MemoryStream ms, uint value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, value);
        ms.Write(buf);
    }

    private static byte[] BuildDwordData(uint value)
    {
        var data = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(data, value);
        return data;
    }

    private static byte[] BuildQwordData(ulong value)
    {
        var data = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(data, value);
        return data;
    }

    private static byte[] BuildStringData(string value)
    {
        // UTF-16LE string with null terminator.
        return [.. Encoding.Unicode.GetBytes(value), 0, 0];
    }

    private static byte[] BuildMultiStringData(string[] values)
    {
        using var ms = new MemoryStream();
        foreach (var value in values)
        {
            ms.Write(Encoding.Unicode.GetBytes(value));
            ms.Write([0, 0]);
        }
        ms.Write([0, 0]); // final terminating null
        return ms.ToArray();
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var combined = new byte[first.Length + second.Length];
        first.CopyTo(combined, 0);
        second.CopyTo(combined, first.Length);
        return combined;
    }
}

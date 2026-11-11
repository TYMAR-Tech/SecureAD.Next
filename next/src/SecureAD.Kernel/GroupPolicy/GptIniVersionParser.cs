using System.Globalization;
using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

public sealed record ParsedGptIniVersion(uint? Version, string? OriginalValue, IReadOnlyList<string> Errors);

/// <summary>Reads the unique General/Version field required by MS-GPOL 2.2.4, without file access.</summary>
public static class GptIniVersionParser
{
    public static ParsedGptIniVersion Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Contains((byte)0) || bytes.StartsWith(new byte[] { 0xef, 0xbb, 0xbf })
            || bytes.StartsWith(new byte[] { 0xff, 0xfe }) || bytes.StartsWith(new byte[] { 0xfe, 0xff }))
            return Invalid("GPT.ini does not contain the qualified ANSI syntax.");
        // Required INI identifiers and the decimal version are ASCII in every ANSI code page.
        // A one-to-one mapping leaves unrelated values opaque rather than guessing their locale.
        var text = Encoding.Latin1.GetString(bytes);
        using var lines = new StringReader(text);
        var sections = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        HashSet<string>? keys = null;
        var section = "";
        string? original = null;
        uint? version = null;
        var lineNumber = 0;
        while (lines.ReadLine() is { } raw)
        {
            lineNumber++;
            var line = raw.Trim(' ', '\t');
            if (line.Length == 0 || line[0] == ';') continue;
            if (line[0] == '[')
            {
                if (line[^1] != ']') return Invalid($"Line {lineNumber} has an unusable section header.");
                section = line[1..^1];
                if (section.Length == 0 || section.Any(value => !AsciiLetter(value) && value is not ('_' or ' ' or '\t'))
                    || !sections.TryAdd(section, new(StringComparer.OrdinalIgnoreCase)))
                    return Invalid($"Line {lineNumber} has an unsupported or repeated section identifier.");
                keys = sections[section];
                continue;
            }
            var separator = line.IndexOf('=');
            if (keys is null || separator <= 0) return Invalid($"Line {lineNumber} is not a key in a declared section.");
            var key = line[..separator].Trim(' ', '\t');
            if (key.Length == 0 || key.Any(value => !AsciiLetter(value) && !char.IsAsciiDigit(value) && value != '_')
                || !keys.Add(key))
                return Invalid($"Line {lineNumber} has an unsupported or repeated key identifier.");
            if (!section.Equals("General", StringComparison.OrdinalIgnoreCase)
                || !key.Equals("Version", StringComparison.OrdinalIgnoreCase)) continue;
            original = raw[(raw.IndexOf('=') + 1)..];
            if (!uint.TryParse(original.Trim(' ', '\t'), NumberStyles.None, CultureInfo.InvariantCulture, out var number))
                return Invalid("The captured General/Version value is not an unsigned 32-bit decimal integer.");
            version = number;
        }
        return version is null ? Invalid("GPT.ini has no unique usable General/Version field.")
            : new(version, original, Array.Empty<string>());

        static bool AsciiLetter(char value) => value is >= 'A' and <= 'Z' or >= 'a' and <= 'z';
        static ParsedGptIniVersion Invalid(string reason) => new(null, null, [reason]);
    }
}

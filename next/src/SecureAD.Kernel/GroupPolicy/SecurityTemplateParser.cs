using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Parses GptTmpl.inf security-template bytes/text into <see cref="ParsedSecurityTemplate"/>.
/// Pure parsing — no OS/platform calls, no file access.
/// GptTmpl.inf is an INI-style security template (see Windows "Security Templates"): a sequence
/// of "[Section]" headers each followed by "Name = Value" lines, ';'-prefixed comments, and blank
/// lines. Real templates are typically UTF-16LE with a byte-order mark; this parser detects the
/// BOM and falls back to UTF-8.
/// </summary>
/// <remarks>
/// Original implementation written from the public Windows "Security Templates" / Security
/// Configuration documentation. Not derived from any third-party parser source.
/// </remarks>
public static class SecurityTemplateParser
{
    /// <summary>
    /// Parses raw GptTmpl.inf bytes, detecting the text encoding from a leading byte-order mark
    /// (UTF-16LE, UTF-16BE, or UTF-8) and defaulting to UTF-8 when no BOM is present.
    /// </summary>
    /// <param name="rawTemplate">Raw GptTmpl.inf file bytes.</param>
    /// <returns>Parsed result with sections and any errors.</returns>
    public static ParsedSecurityTemplate ParseTemplateFile(ReadOnlySpan<byte> rawTemplate)
    {
        var (encoding, bomLength) = DetectEncoding(rawTemplate);
        var text = encoding.GetString(rawTemplate[bomLength..]);
        return ParseTemplateFile(text);
    }

    /// <summary>
    /// Parses GptTmpl.inf content that has already been decoded to a string.
    /// </summary>
    /// <param name="text">The decoded security-template text.</param>
    /// <returns>Parsed result with sections and any errors.</returns>
    public static ParsedSecurityTemplate ParseTemplateFile(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var errors = new List<string>();
        var sections = new Dictionary<string, IReadOnlyList<SecurityTemplateSetting>>(StringComparer.OrdinalIgnoreCase);
        List<SecurityTemplateSetting>? current = null;

        var lineNumber = 0;
        foreach (var rawLine in EnumerateLines(text))
        {
            lineNumber++;
            var line = rawLine.Trim();

            if (line.Length == 0 || line[0] == ';')
            {
                continue; // blank or comment
            }

            if (line[0] == '[')
            {
                if (line[^1] != ']')
                {
                    errors.Add($"Line {lineNumber}: malformed section header '{line}'");
                    continue;
                }

                var sectionName = line[1..^1].Trim();
                if (!sections.TryGetValue(sectionName, out var existing))
                {
                    current = [];
                    sections[sectionName] = current;
                }
                else
                {
                    // Duplicate section header — append into the existing section.
                    current = (List<SecurityTemplateSetting>)existing;
                }

                continue;
            }

            var separatorIndex = line.IndexOf('=');
            if (separatorIndex < 0)
            {
                errors.Add($"Line {lineNumber}: expected 'Name = Value' but found '{line}'");
                continue;
            }

            if (current is null)
            {
                errors.Add($"Line {lineNumber}: setting '{line}' appears before any section header");
                continue;
            }

            var name = line[..separatorIndex].Trim();
            var value = line[(separatorIndex + 1)..].Trim();
            current.Add(new SecurityTemplateSetting(name, value));
        }

        return new ParsedSecurityTemplate(sections, errors);
    }

    /// <summary>
    /// Detects text encoding from a leading byte-order mark.
    /// </summary>
    /// <returns>The encoding to use and the number of BOM bytes to skip.</returns>
    private static (Encoding Encoding, int BomLength) DetectEncoding(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        {
            return (Encoding.Unicode, 2); // UTF-16LE
        }

        if (bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
        {
            return (Encoding.BigEndianUnicode, 2); // UTF-16BE
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            return (Encoding.UTF8, 3);
        }

        return (Encoding.UTF8, 0);
    }

    /// <summary>
    /// Splits text into lines on CRLF, CR, or LF without allocating a separator array per call.
    /// </summary>
    private static IEnumerable<string> EnumerateLines(string text)
    {
        var start = 0;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c is '\r' or '\n')
            {
                yield return text[start..i];

                // Treat CRLF as a single break.
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
                {
                    i++;
                }

                start = i + 1;
            }
        }

        if (start < text.Length)
        {
            yield return text[start..];
        }
    }
}

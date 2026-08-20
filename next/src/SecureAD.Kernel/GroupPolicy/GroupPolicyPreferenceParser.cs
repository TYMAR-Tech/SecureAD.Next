using System.Text;
using System.Xml;

namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Scans Group Policy Preferences (GPP) XML files for the <c>cpassword</c> attribute
/// (MS14-025 / CVE-2014-1812). A non-empty <c>cpassword</c> is an encrypted credential stored in
/// SYSVOL; because the AES key is published in [MS-GPPREF], any authenticated user who can read
/// SYSVOL can decrypt it — so its mere presence is a credential exposure.
/// <para>
/// <b>Presence-only by design.</b> This parser never decrypts the value and never returns or stores
/// it. It reads the attribute solely to test whether it is present and non-empty, then discards it.
/// The credential is never placed in the result type, so it cannot leak downstream. The published
/// decryption key is intentionally absent from this codebase.
/// </para>
/// <para>
/// Parsing is XXE-hardened (DTD processing prohibited, no external entity resolution) because GPP
/// files come from SYSVOL and could be attacker-influenced.
/// </para>
/// </summary>
/// <remarks>
/// Original implementation written from the public [MS-GPPREF] (Group Policy: Preferences Extension
/// Data Structure) specification and MS14-025. Not derived from any third-party tool.
/// </remarks>
public static class GroupPolicyPreferenceParser
{
    private const string CpasswordAttribute = "cpassword";

    // Attributes that name the account a stored password belongs to, across GPP file types:
    // Groups.xml (userName / newName), Services.xml (accountName), ScheduledTasks.xml (runAs),
    // DataSources.xml (username), Drives.xml (userName), Printers.xml (username).
    private static readonly string[] AccountAttributes =
        ["userName", "accountName", "runAs", "username", "newName"];

    /// <summary>
    /// Scans raw GPP XML bytes for non-empty <c>cpassword</c> attributes.
    /// </summary>
    /// <param name="xml">Raw GPP XML file bytes (UTF-8, possibly with a BOM).</param>
    /// <returns>Presence-only findings and any parse errors. The password value is never included.</returns>
    public static ParsedGppFile ParsePreferenceFile(ReadOnlySpan<byte> xml)
    {
        if (xml.Length == 0)
        {
            return new ParsedGppFile([], []);
        }

        // Skip a UTF-8 BOM if present — a leading BOM character is invalid at the XML document root.
        if (xml.Length >= 3 && xml[0] == 0xEF && xml[1] == 0xBB && xml[2] == 0xBF)
        {
            xml = xml[3..];
        }

        return ParsePreferenceFile(Encoding.UTF8.GetString(xml));
    }

    /// <summary>
    /// Scans GPP XML content for non-empty <c>cpassword</c> attributes.
    /// </summary>
    /// <param name="xml">The GPP XML text.</param>
    /// <returns>Presence-only findings and any parse errors. The password value is never included.</returns>
    public static ParsedGppFile ParsePreferenceFile(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);

        var findings = new List<GppPasswordFinding>();
        var errors = new List<string>();

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, // block DTD / entity-expansion attacks
            XmlResolver = null,                     // never resolve external entities
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true,
        };

        try
        {
            using var stringReader = new StringReader(xml);
            using var reader = XmlReader.Create(stringReader, settings);

            // Depth-indexed element names. In GPP files the cpassword attribute lives on the inner
            // <Properties> element, but the descriptive type is the parent (<User>, <NTService>,
            // <Task>, <DataSource>, <Drive>, <SharedPrinter>). Track names by depth so a finding
            // reports the parent element rather than the literal cpassword-bearing "Properties".
            var elementByDepth = new List<string>();

            while (reader.Read())
            {
                if (reader.NodeType != XmlNodeType.Element)
                {
                    continue;
                }

                var depth = reader.Depth;
                while (elementByDepth.Count <= depth)
                {
                    elementByDepth.Add(string.Empty);
                }
                elementByDepth[depth] = reader.LocalName;

                if (!reader.HasAttributes)
                {
                    continue;
                }

                var elementType = depth > 0 ? elementByDepth[depth - 1] : reader.LocalName;
                ScanElement(reader, elementType, findings);
            }
        }
        catch (XmlException ex)
        {
            errors.Add($"GPP XML parse error: {ex.Message}");
        }

        return new ParsedGppFile(findings, errors);
    }

    /// <summary>
    /// Inspects the current element's attributes for a non-empty <c>cpassword</c>. When found,
    /// records a presence-only finding using the supplied parent element type and any
    /// account-naming attribute. The password value is read only to test emptiness and is never
    /// retained.
    /// </summary>
    private static void ScanElement(XmlReader reader, string elementType, List<GppPasswordFinding> findings)
    {
        string? accountName = null;
        string? sourceAttribute = null;
        var hasPassword = false;

        for (var i = 0; i < reader.AttributeCount; i++)
        {
            reader.MoveToAttribute(i);

            if (string.Equals(reader.LocalName, CpasswordAttribute, StringComparison.OrdinalIgnoreCase))
            {
                // Test presence only; never keep the value.
                hasPassword = !string.IsNullOrEmpty(reader.Value);
            }
            else if (sourceAttribute is null && IsAccountAttribute(reader.LocalName) && !string.IsNullOrEmpty(reader.Value))
            {
                accountName = reader.Value;
                sourceAttribute = reader.LocalName;
            }
        }

        reader.MoveToElement();

        if (hasPassword)
        {
            findings.Add(new GppPasswordFinding(elementType, accountName, sourceAttribute));
        }
    }

    private static bool IsAccountAttribute(string attributeName)
    {
        foreach (var candidate in AccountAttributes)
        {
            if (string.Equals(attributeName, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

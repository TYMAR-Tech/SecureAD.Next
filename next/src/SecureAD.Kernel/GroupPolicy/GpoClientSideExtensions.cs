namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// Helpers for the GPO <c>gPCMachineExtensionNames</c> attribute, which lists the client-side
/// extensions (CSEs) whose settings a GPO contains. Used to smart-filter SYSVOL capture to only
/// the GPOs that hold settings SecureAD analyzes (Registry.pol and GptTmpl.inf), avoiding an
/// SMB fetch for every GPO in the forest.
/// </summary>
/// <remarks>
/// The attribute is a single Unicode string formatted as one or more bracketed groups:
/// <c>[{CSE-GUID}{tool-GUID}...][{CSE-GUID}{tool-GUID}...]</c>. The first GUID in each group
/// identifies the client-side extension. CSE GUID values are documented in the
/// ADMX_GroupPolicy policy CSP (CSE_Registry / CSE_Security).
/// </remarks>
public static class GpoClientSideExtensions
{
    /// <summary>
    /// Parses the client-side-extension GUIDs from a <c>gPCMachineExtensionNames</c> value.
    /// Returns the first (CSE) GUID of each bracketed group, in order, deduplicated, beside a
    /// record of any token that could not be read.
    /// </summary>
    /// <param name="gpcMachineExtensionNames">The raw attribute value, or null/empty.</param>
    /// <returns>
    /// The distinct CSE GUIDs the GPO declares, and what could not be read. An absent or empty
    /// attribute yields an empty list and no errors: the GPO declared nothing, which is a fact
    /// rather than a failure.
    /// </returns>
    public static ParsedCseList ParseCseGuids(string? gpcMachineExtensionNames)
    {
        if (string.IsNullOrWhiteSpace(gpcMachineExtensionNames))
        {
            return new ParsedCseList([], []);
        }

        var result = new List<Guid>();
        var seen = new HashSet<Guid>();
        var errors = new List<string>();

        var span = gpcMachineExtensionNames.AsSpan();
        var depth = 0;
        var groupStart = -1;
        var sawFirstInGroup = false;

        for (var i = 0; i < span.Length; i++)
        {
            var c = span[i];
            switch (c)
            {
                case '[':
                    depth++;
                    sawFirstInGroup = false;
                    break;

                case ']':
                    depth = depth > 0 ? depth - 1 : 0;
                    break;

                case '{':
                    if (depth > 0)
                    {
                        groupStart = i + 1;
                    }
                    break;

                case '}':
                    if (depth > 0 && groupStart >= 0)
                    {
                        // Only the first GUID in each bracketed group is the CSE.
                        if (!sawFirstInGroup)
                        {
                            var token = span[groupStart..i];
                            if (Guid.TryParse(token, out var guid))
                            {
                                if (seen.Add(guid))
                                {
                                    result.Add(guid);
                                }
                            }
                            else
                            {
                                // Recorded rather than skipped silently: an unreadable token may
                                // have been the Registry or Security extension, and the caller
                                // must not read a shorter list as a shorter declaration.
                                errors.Add(
                                    "Could not read a client-side extension GUID from '"
                                    + token.ToString() + "'.");
                            }
                        }

                        sawFirstInGroup = true;
                        groupStart = -1;
                    }
                    break;
            }
        }

        return new ParsedCseList(result, errors);
    }

    /// <summary>
    /// Decides whether a GPO has on-disk settings this product analyses, used to smart-filter
    /// SYSVOL capture. Permissive by design: when the attribute cannot be read, or cannot be read
    /// in full, this returns <c>true</c> so the GPO is still fetched - correctness over the I/O
    /// saving.
    /// </summary>
    /// <param name="gpcMachineExtensionNames">The raw attribute value, or null/empty.</param>
    /// <returns>
    /// <c>true</c> if the GPO declares an analysable CSE, if the attribute is absent or empty, or
    /// if any part of it could not be read; <c>false</c> only when the whole attribute was
    /// understood and none of the extensions in it are ones this product parses.
    /// </returns>
    /// <remarks>
    /// <b>The error check is not belt and braces.</b> Before it, a value holding one readable
    /// extension and one unreadable token took the non-empty path, and a GPO whose unreadable
    /// token was the Registry or Security extension was skipped - its Registry.pol and GptTmpl.inf
    /// never fetched, and SEC-064, SEC-065, SEC-066 and SEC-093 silently reporting nothing for it
    /// while it looked exactly like a GPO that had been assessed and found clean.
    /// </remarks>
    public static bool HasAnalyzableSettings(string? gpcMachineExtensionNames)
    {
        var parsed = ParseCseGuids(gpcMachineExtensionNames);

        if (parsed.Errors.Count > 0)
        {
            return true; // part of the attribute is unreadable - fetch rather than guess
        }

        if (parsed.Cses.Count == 0)
        {
            return true; // unknown - fetch rather than risk skipping real settings
        }

        foreach (var cse in parsed.Cses)
        {
            if (GpoClientSideExtensionCatalog.Contains(cse))
            {
                return true;
            }
        }

        return false;
    }
}

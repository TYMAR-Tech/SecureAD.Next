using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

public sealed record RegistryPolicyValue(int EntryIndex, string KeyPath, string ValueName, RegistryPolicyEntry Source);
public sealed record RegistryPolicyIssue(int EntryIndex, string KeyPath, string ValueName, string Reason);

public sealed record RegistryPolicyEvaluation(
    IReadOnlyList<RegistryPolicyValue> Values, IReadOnlyList<RegistryPolicyIssue> Issues)
{
    public RegistryPolicyValue? Find(string key, string name) => Values.FirstOrDefault(value =>
        string.Equals(value.KeyPath, key, StringComparison.OrdinalIgnoreCase)
        && string.Equals(value.ValueName, name, StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<RegistryPolicyIssue> IssuesFor(string key) =>
        Issues.Where(issue => RegistryPolicyInterpreter.Within(key, issue.KeyPath)).ToArray();
}

public static class RegistryPolicyInterpreter
{
    private static readonly UnicodeEncoding StrictUnicode = new(false, false, true);

    public static RegistryPolicyEvaluation Evaluate(IReadOnlyList<RegistryPolicyEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var keys = new Dictionary<string, Dictionary<string, RegistryPolicyValue>>(StringComparer.OrdinalIgnoreCase);
        var absent = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var cleared = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deleted = new List<string>();
        var issues = new List<RegistryPolicyIssue>();
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            var name = entry.ValueName;
            if (!keys.TryGetValue(entry.KeyPath, out var values))
                keys.Add(entry.KeyPath, values = new(StringComparer.OrdinalIgnoreCase));
            if (!name.StartsWith("**", StringComparison.Ordinal))
            {
                Set(name);
                continue;
            }
            if (name.StartsWith("**soft.", StringComparison.OrdinalIgnoreCase))
            {
                var target = name[7..];
                if (values.ContainsKey(target)) continue;
                var knownAbsent = cleared.Contains(entry.KeyPath)
                    || deleted.Any(key => Within(entry.KeyPath, key))
                    || absent.TryGetValue(entry.KeyPath, out var names) && names.Contains(target);
                Set(target);
                if (!knownAbsent) Limit("This conditional write depends on pre-existing client registry state.");
                continue;
            }
            if (Same(name, "**SecureKey"))
            {
                if (entry.ValueType != RegistryValueType.Dword || entry.Data.Length != sizeof(uint))
                    Limit("The key-security operation does not contain one DWORD.");
                continue;
            }
            if (!TryReadString(entry, out var text))
            {
                Limit("The special operation does not contain a qualified null-terminated REG_SZ value.");
                continue;
            }
            if (name.StartsWith("**Del.", StringComparison.OrdinalIgnoreCase))
            {
                if (text != " ") { Limit("A single-value deletion requires the documented single-space data."); continue; }
                Remove(name[6..]);
            }
            // MS-GPREG 3.2.5.1.2 requires the period; the older overview omits it.
            else if (Same(name, "**DelVals."))
            {
                if (text != " ") { Limit("An all-values deletion requires the documented single-space data."); continue; }
                values.Clear();
                cleared.Add(entry.KeyPath);
            }
            else if (Same(name, "**DeleteValues") || Same(name, "**DeleteKeys"))
            {
                var names = text.Split(';');
                if (names.Any(string.IsNullOrEmpty)
                    || Same(name, "**DeleteKeys") && names.Any(part => part.Contains('\\')))
                {
                    Limit("The deletion list does not contain qualified nonempty immediate names.");
                    continue;
                }
                foreach (var target in names)
                {
                    if (Same(name, "**DeleteValues")) Remove(target);
                    else
                    {
                        var path = entry.KeyPath.Length == 0 ? target : entry.KeyPath + "\\" + target;
                        foreach (var key in keys.Keys.Where(key => Within(key, path)).ToArray()) keys.Remove(key);
                        deleted.Add(path);
                    }
                }
            }
            else Limit("This special registry-policy operation is not qualified.");

            void Set(string target) => values[target] = new(index, entry.KeyPath, target, entry);
            void Remove(string target)
            {
                values.Remove(target);
                if (!absent.TryGetValue(entry.KeyPath, out var names))
                    absent.Add(entry.KeyPath, names = new(StringComparer.OrdinalIgnoreCase));
                names.Add(target);
            }
            void Limit(string reason) => issues.Add(new(index, entry.KeyPath, entry.ValueName, reason));
        }
        return new(keys.Values.SelectMany(values => values.Values).OrderBy(value => value.EntryIndex).ToArray(),
            issues.ToArray());
    }

    public static bool TryReadString(RegistryPolicyEntry entry, [NotNullWhen(true)] out string? text)
    {
        text = null;
        if (entry.ValueType != RegistryValueType.String || entry.Data.Length < 2 || entry.Data.Length % 2 != 0
            || entry.Data[^1] != 0 || entry.Data[^2] != 0)
            return false;
        try { text = StrictUnicode.GetString(entry.Data.AsSpan(0, entry.Data.Length - 2)); }
        catch (DecoderFallbackException) { return false; }
        return !text.Contains('\0');
    }

    internal static bool Within(string key, string root) => root.Length == 0 || Same(key, root)
        || key.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase);
    private static bool Same(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

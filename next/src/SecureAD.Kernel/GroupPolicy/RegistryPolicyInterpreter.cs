using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Text;

namespace SecureAD.Kernel.GroupPolicy;

public sealed record RegistryPolicyValue(int EntryIndex, string KeyPath, string ValueName, RegistryPolicyEntry Source);
public sealed record RegistryPolicyIssue(int EntryIndex, string KeyPath, string ValueName, string Reason);
public sealed record RegistryPolicyInstructions(IReadOnlyList<RegistryPolicyInstruction> Instructions,
    IReadOnlyList<RegistryPolicyIssue> Issues);

public enum RegistryPolicyInstructionKind
{
    Unsupported,
    SetValue,
    SetIfAbsent,
    DeleteValue,
    ClearValues,
    DeleteKey,
    KeySecurity,
}

public sealed record RegistryPolicyInstruction(int EntryIndex, RegistryPolicyEntry Source,
    RegistryPolicyInstructionKind Kind, string KeyPath, string? ValueName, string? Reason)
{
    public bool Affects(string key, string name) => Kind switch
    {
        RegistryPolicyInstructionKind.SetValue or RegistryPolicyInstructionKind.SetIfAbsent
            or RegistryPolicyInstructionKind.DeleteValue =>
            string.Equals(KeyPath, key, StringComparison.OrdinalIgnoreCase)
            && string.Equals(ValueName, name, StringComparison.OrdinalIgnoreCase),
        RegistryPolicyInstructionKind.ClearValues => string.Equals(KeyPath, key, StringComparison.OrdinalIgnoreCase),
        RegistryPolicyInstructionKind.DeleteKey or RegistryPolicyInstructionKind.Unsupported =>
            RegistryPolicyInterpreter.Within(key, KeyPath),
        RegistryPolicyInstructionKind.KeySecurity => false,
        _ => throw new InvalidDataException("The registry instruction kind is invalid."),
    };
}

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
    private static readonly Meter PreparationMeter = new("SecureAD.Kernel.GroupPolicy");
    private static readonly Counter<long> InstructionDecodes = PreparationMeter.CreateCounter<long>("registry.instruction_decodes");
    private static readonly UnicodeEncoding StrictUnicode = new(false, false, true);

    public static RegistryPolicyEvaluation Evaluate(IReadOnlyList<RegistryPolicyEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        var keys = new Dictionary<string, Dictionary<string, RegistryPolicyValue>>(StringComparer.OrdinalIgnoreCase);
        var absent = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var cleared = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deleted = new List<string>();
        var issues = new List<RegistryPolicyIssue>();
        foreach (var instruction in ReadInstructions(entries).Instructions)
        {
            var entry = instruction.Source;
            if (!keys.TryGetValue(instruction.KeyPath, out var values))
                keys.Add(instruction.KeyPath, values = new(StringComparer.OrdinalIgnoreCase));
            if (instruction.Kind == RegistryPolicyInstructionKind.SetIfAbsent)
            {
                var target = instruction.ValueName!;
                if (values.ContainsKey(target)) continue;
                var knownAbsent = cleared.Contains(instruction.KeyPath)
                    || deleted.Any(key => Within(instruction.KeyPath, key))
                    || absent.TryGetValue(instruction.KeyPath, out var names) && names.Contains(target);
                Set(target);
                if (!knownAbsent) Limit("This conditional write depends on pre-existing client registry state.");
            }
            else if (instruction.Kind == RegistryPolicyInstructionKind.SetValue) Set(instruction.ValueName!);
            else if (instruction.Kind == RegistryPolicyInstructionKind.DeleteValue)
            {
                values.Remove(instruction.ValueName!);
                if (!absent.TryGetValue(instruction.KeyPath, out var names))
                    absent.Add(instruction.KeyPath, names = new(StringComparer.OrdinalIgnoreCase));
                names.Add(instruction.ValueName!);
            }
            else if (instruction.Kind == RegistryPolicyInstructionKind.ClearValues)
            {
                values.Clear();
                cleared.Add(instruction.KeyPath);
            }
            else if (instruction.Kind == RegistryPolicyInstructionKind.DeleteKey)
            {
                foreach (var key in keys.Keys.Where(key => Within(key, instruction.KeyPath)).ToArray()) keys.Remove(key);
                deleted.Add(instruction.KeyPath);
            }
            else if (instruction.Kind == RegistryPolicyInstructionKind.Unsupported) Limit(instruction.Reason!);
            else if (instruction.Kind != RegistryPolicyInstructionKind.KeySecurity)
                throw new InvalidDataException("The registry instruction kind is invalid.");

            void Set(string target) => values[target] = new(instruction.EntryIndex, instruction.KeyPath, target, entry);
            void Limit(string reason) => issues.Add(new(instruction.EntryIndex, entry.KeyPath, entry.ValueName, reason));
        }
        return new(keys.Values.SelectMany(values => values.Values).OrderBy(value => value.EntryIndex).ToArray(),
            issues.ToArray());
    }

    public static RegistryPolicyInstructions ReadInstructions(IReadOnlyList<RegistryPolicyEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        InstructionDecodes.Add(1);
        var result = new List<RegistryPolicyInstruction>();
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            var name = entry.ValueName;
            if (!name.StartsWith("**", StringComparison.Ordinal)) Add(RegistryPolicyInstructionKind.SetValue, name);
            else if (name.StartsWith("**soft.", StringComparison.OrdinalIgnoreCase))
                Add(RegistryPolicyInstructionKind.SetIfAbsent, name[7..]);
            else if (Same(name, "**SecureKey"))
            {
                if (entry.ValueType == RegistryValueType.Dword && entry.Data.Length == sizeof(uint))
                    Add(RegistryPolicyInstructionKind.KeySecurity, null);
                else Limit("The key-security operation does not contain one DWORD.");
            }
            else if (!TryReadString(entry, out var text))
                Limit("The special operation does not contain a qualified null-terminated REG_SZ value.");
            else if (name.StartsWith("**Del.", StringComparison.OrdinalIgnoreCase))
            {
                if (text == " ") Add(RegistryPolicyInstructionKind.DeleteValue, name[6..]);
                else Limit("A single-value deletion requires the documented single-space data.");
            }
            // MS-GPREG 3.2.5.1.2 requires the period; the older overview omits it.
            else if (Same(name, "**DelVals."))
            {
                if (text == " ") Add(RegistryPolicyInstructionKind.ClearValues, null);
                else Limit("An all-values deletion requires the documented single-space data.");
            }
            else if (Same(name, "**DeleteValues") || Same(name, "**DeleteKeys"))
            {
                var names = text.Split(';');
                if (names.Any(string.IsNullOrEmpty)
                    || Same(name, "**DeleteKeys") && names.Any(part => part.Contains('\\')))
                    Limit("The deletion list does not contain qualified nonempty immediate names.");
                else foreach (var target in names)
                {
                    if (Same(name, "**DeleteValues")) Add(RegistryPolicyInstructionKind.DeleteValue, target);
                    else result.Add(new(index, entry, RegistryPolicyInstructionKind.DeleteKey,
                        entry.KeyPath.Length == 0 ? target : entry.KeyPath + "\\" + target, null, null));
                }
            }
            else Limit("This special registry-policy operation is not qualified.");

            void Add(RegistryPolicyInstructionKind kind, string? value) =>
                result.Add(new(index, entry, kind, entry.KeyPath, value, null));
            void Limit(string reason) =>
                result.Add(new(index, entry, RegistryPolicyInstructionKind.Unsupported, entry.KeyPath, null, reason));
        }
        return new(result, result.Where(instruction => instruction.Kind == RegistryPolicyInstructionKind.Unsupported)
            .Select(instruction => new RegistryPolicyIssue(instruction.EntryIndex, instruction.Source.KeyPath,
                instruction.Source.ValueName, instruction.Reason!)).ToArray());
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

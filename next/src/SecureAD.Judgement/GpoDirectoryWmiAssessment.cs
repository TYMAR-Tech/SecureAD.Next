using System.Collections.Immutable;
using System.Globalization;
using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal enum GpoDirectoryWmiState { Unresolved, MatchesRecordedPlatform, DoesNotMatchRecordedPlatform }

internal sealed record GpoDirectoryOsFacts(ObjectAttributes OriginalValues, string? Version, uint? ProductType,
    ImmutableArray<AuditError> Limitations);

internal sealed record GpoDirectoryQueryAssessment(CapturedWmiQuery Query, GpoDirectoryWmiState State,
    ImmutableArray<AuditError> Limitations);

internal sealed record GpoDirectoryWmiAssessment(Guid CaptureGenerationId, string EvidenceSeal,
    CapturedObjectIdentity Computer, GpoWmiConditionKey? Condition, GpoDirectoryOsFacts Facts,
    ImmutableArray<GpoDirectoryQueryAssessment> Queries, GpoDirectoryWmiState State,
    ImmutableArray<AuditError> Limitations)
{
    internal const string Assumption =
        "The captured directory platform information represents the computer's WMI operating-system values, "
        + "and the specified WMI namespace and class are available.";
    internal bool IsObservedWmiResult => false;

    internal static GpoDirectoryWmiAssessment Of(GpoLinkHierarchy hierarchy, GpoWmiFilterReading wmi,
        GpoConditionalApplicability conditional, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (hierarchy.CaptureGenerationId == Guid.Empty || string.IsNullOrWhiteSpace(hierarchy.EvidenceSeal)
            || hierarchy.Computer.CaptureGenerationId != hierarchy.CaptureGenerationId
            || wmi.Policy.CaptureGenerationId != hierarchy.CaptureGenerationId
            || hierarchy.Computer.ObjectGuid != hierarchy.ComputerValues.ObjectGuid
            || hierarchy.Computer.DistinguishedName != hierarchy.ComputerValues.DistinguishedName)
            throw new InvalidDataException("The directory-based WMI assessment does not bind the captured computer and policy.");
        var key = conditional.Wmi?.Condition;
        if (key is { } bound && (bound.CaptureGenerationId != hierarchy.CaptureGenerationId
            || bound.EvidenceSeal != hierarchy.EvidenceSeal || bound.ComputerObjectId != hierarchy.Computer.ObjectId
            || wmi.Filter is not { } filter || bound.FilterObjectId != filter.ObjectId
            || filter.CaptureGenerationId != hierarchy.CaptureGenerationId))
            throw new InvalidDataException("The directory-based WMI assessment uses another computer or filter condition.");
        var facts = ReadFacts(hierarchy.ComputerValues);
        var queries = ImmutableArray.CreateBuilder<GpoDirectoryQueryAssessment>();
        var errors = new List<AuditError>();
        if (!wmi.Definition.IsSuccess) errors.Add(wmi.Definition.Error);
        else
            foreach (var query in wmi.Definition.Value)
            {
                token.ThrowIfCancellationRequested();
                queries.Add(AssessQuery(query, facts, token));
            }
        if (conditional.UnavailableReason is { } unavailable) errors.Add(unavailable);
        if (key is null && errors.Count == 0)
            errors.Add(Error("GpoDirectoryWmiConditionUnavailable",
                "The captured filter does not establish a qualified whole-filter condition.", hierarchy.Computer.DistinguishedName));
        errors.AddRange(queries.SelectMany(query => query.Limitations));
        var state = key is null || queries.Count == 0 || queries.Any(query => query.State == GpoDirectoryWmiState.Unresolved)
            ? GpoDirectoryWmiState.Unresolved
            : queries.All(query => query.State == GpoDirectoryWmiState.MatchesRecordedPlatform)
                ? GpoDirectoryWmiState.MatchesRecordedPlatform : GpoDirectoryWmiState.DoesNotMatchRecordedPlatform;
        return new(hierarchy.CaptureGenerationId, hierarchy.EvidenceSeal, hierarchy.Computer, key, facts,
            queries.ToImmutable(), state, errors.Distinct().ToImmutableArray());
    }

    internal static GpoDirectoryOsFacts ReadFacts(ObjectAttributes values)
    {
        var errors = new List<AuditError>();
        var name = SingleText(values.Find("operatingSystem"));
        bool? server = name is not null && ServerName.IsMatch(name) ? true
            : name is not null && ClientName.IsMatch(name) ? false : null;
        var version = server.HasValue ? ReadVersion(SingleText(values.Find("operatingSystemVersion"))) : null;
        if (version is null)
            errors.Add(Error("GpoDirectoryWmiVersionUnavailable",
                "The directory information does not establish a supported Windows family and complete OS version.",
                values.DistinguishedName));
        uint? product = null;
        var flagsText = SingleText(values.Find("userAccountControl"));
        if (server.HasValue && uint.TryParse(flagsText, NumberStyles.None, CultureInfo.InvariantCulture, out var flags))
        {
            var control = new UserAccountControlEvidence(flags);
            var writableController = (flags & 0x2000) != 0;
            var member = (flags & 0x1000) != 0;
            if ((flags & (0x0200 | 0x0800)) == 0)
            {
                if (control.HasDomainControllerFlag && server == true && !(writableController && member)) product = 2;
                else if (!control.HasDomainControllerFlag && member) product = server == true ? 3U : 1U;
            }
        }
        if (product is null)
            errors.Add(Error("GpoDirectoryWmiProductTypeUnavailable",
                "The directory OS family and account flags do not establish an unambiguous supported product type.",
                values.DistinguishedName));
        return new(values, version, product, errors.ToImmutableArray());
    }

    private static GpoDirectoryQueryAssessment AssessQuery(CapturedWmiQuery query, GpoDirectoryOsFacts facts,
        CancellationToken token)
    {
        var errors = new List<AuditError>();
        if (query.Reading.State != WqlReadingState.ParsedConditions)
            return new(query, GpoDirectoryWmiState.Unresolved,
                [query.Reading.Error ?? throw new InvalidDataException("An unparsed WMI query has no recorded reason.")]);
        var conditions = query.Reading.Conditions
            ?? throw new InvalidDataException("A parsed WMI query has no recorded conditions.");
        if (!string.Equals(query.Namespace, @"root\CIMv2", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(conditions.ClassName, "Win32_OperatingSystem", StringComparison.OrdinalIgnoreCase))
            return Unavailable("GpoDirectoryWmiQueryUnsupported",
                "The directory-based assessment supports only root\\CIMv2 Win32_OperatingSystem queries.");
        if (conditions.Postfix.IsDefaultOrEmpty)
            return Unavailable("GpoDirectoryWmiPredicateUnavailable",
                "A query without supported platform conditions does not establish a directory-based filter assessment.");
        var stack = new Stack<bool?>();
        foreach (var part in conditions.Postfix)
        {
            token.ThrowIfCancellationRequested();
            if (part is WqlComparisonToken comparison)
            {
                var answer = Compare(comparison, facts);
                stack.Push(answer);
                if (!answer.HasValue)
                    errors.Add(Error("GpoDirectoryWmiComparisonUnavailable",
                        "A required platform value or comparison is outside the qualified directory-based subset.",
                        comparison.Property));
            }
            else if (part is WqlLogicalToken logical)
            {
                var needed = logical.Operator == WqlLogicalOperator.Not ? 1 : 2;
                if (stack.Count < needed) throw new InvalidDataException("The captured WMI expression stack is incomplete.");
                var right = stack.Pop();
                if (needed == 1) stack.Push(!right);
                else
                {
                    var left = stack.Pop();
                    stack.Push(logical.Operator switch
                    {
                        WqlLogicalOperator.And => left & right,
                        WqlLogicalOperator.Or => left | right,
                        _ => throw new InvalidDataException("The captured WMI logical operator is unsupported."),
                    });
                }
            }
            else throw new InvalidDataException("The captured WMI expression contains an unsupported token.");
        }
        if (stack.Count != 1) throw new InvalidDataException("The captured WMI expression does not have one complete result.");
        var result = stack.Pop();
        // Even a decisive Boolean branch cannot qualify another unsupported query fragment.
        return new(query, errors.Count != 0 || result is null ? GpoDirectoryWmiState.Unresolved
            : result.Value ? GpoDirectoryWmiState.MatchesRecordedPlatform : GpoDirectoryWmiState.DoesNotMatchRecordedPlatform,
            errors.ToImmutableArray());

        GpoDirectoryQueryAssessment Unavailable(string code, string reason) =>
            new(query, GpoDirectoryWmiState.Unresolved, [Error(code, reason, query.Query)]);
    }

    private static bool? Compare(WqlComparisonToken test, GpoDirectoryOsFacts facts)
    {
        if (string.Equals(test.Property, "Version", StringComparison.OrdinalIgnoreCase))
        {
            if (facts.Version is not { } actual) return null;
            if (test.Comparison is WqlComparison.IsNull or WqlComparison.IsNotNull)
                return test.Literal is null ? test.Comparison == WqlComparison.IsNotNull : null;
            if (test.Literal is not { Kind: WqlLiteralKind.Text } literal) return null;
            if (test.Comparison == WqlComparison.Like)
            {
                var prefix = literal.Value.EndsWith('%') ? literal.Value[..^1] : literal.Value;
                if (prefix.Any(character => character is not (>= '0' and <= '9') and not '.')) return null;
                return literal.Value.EndsWith('%') ? actual.StartsWith(prefix, StringComparison.Ordinal)
                    : actual == prefix;
            }
            if (literal.Value.Length == 0
                || literal.Value.Any(character => character is not (>= '0' and <= '9') and not '.')) return null;
            // Version is CIM_STRING, not a numerically ordered System.Version.
            return Relates(string.CompareOrdinal(actual, literal.Value), test.Comparison);
        }
        if (string.Equals(test.Property, "ProductType", StringComparison.OrdinalIgnoreCase))
        {
            if (facts.ProductType is not { } actual) return null;
            if (test.Comparison is WqlComparison.IsNull or WqlComparison.IsNotNull)
                return test.Literal is null ? test.Comparison == WqlComparison.IsNotNull : null;
            if (test.Literal is not { } literal
                || literal.Kind is not (WqlLiteralKind.Text or WqlLiteralKind.SignedInteger or WqlLiteralKind.UnsignedInteger)
                || !uint.TryParse(literal.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var expected)) return null;
            return Relates(actual.CompareTo(expected), test.Comparison);
        }
        return null;
    }

    private static bool? Relates(int comparison, WqlComparison operation) => operation switch
    {
        WqlComparison.Equal => comparison == 0,
        WqlComparison.NotEqual => comparison != 0,
        WqlComparison.Less => comparison < 0,
        WqlComparison.LessOrEqual => comparison <= 0,
        WqlComparison.Greater => comparison > 0,
        WqlComparison.GreaterOrEqual => comparison >= 0,
        _ => null,
    };

    private static string? ReadVersion(string? text)
    {
        if (text is null) return null;
        var matched = DirectoryVersion.Match(text);
        if (!matched.Success) return null;
        var components = new[] { matched.Groups[1].Value, matched.Groups[2].Value,
            matched.Groups[3].Success ? matched.Groups[3].Value : matched.Groups[4].Value };
        for (var index = 0; index < components.Length; index++)
            if (!uint.TryParse(components[index], NumberStyles.None, CultureInfo.InvariantCulture, out var value)
                || value.ToString(CultureInfo.InvariantCulture) != components[index] || index != 1 && value == 0)
                return null;
        return string.Join('.', components);
    }

    private static string? SingleText(ObjectAttribute? attribute) =>
        attribute is { Values.Count: 1 } && attribute.Values[0] is { Ordinal: 0, Text: { } text, Bytes: null }
            ? text : null;

    private static AuditError Error(string code, string reason, string context) =>
        AuditError.Create(ErrorCategory.Evidence, code, ErrorSeverity.Degraded, reason, context);

    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;
    private static readonly Regex ServerName = new(
        @"\A(?:Microsoft )?Windows Server [0-9]{4}(?: R2)?(?: (?:Standard|Datacenter|Enterprise|Essentials|Foundation|Web)(?: Evaluation)?(?: \(Server Core Installation\))?)?\z", Options);
    private static readonly Regex ClientName = new(
        @"\A(?:Microsoft )?Windows (?:7|8(?:\.1)?|10|11)(?: (?:Home|Professional|Pro|Enterprise|Education|Ultimate)(?: (?:N|LTSC|Evaluation))?)?\z", Options);
    private static readonly Regex DirectoryVersion = new(@"\A([0-9]+)\.([0-9]+)(?: \(([0-9]+)\)|\.([0-9]+))\z", Options);
}

using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

internal sealed record CapturedWmiReference(string DomainFqdn, Guid FilterId, string IgnoredFlags);

internal sealed record CapturedWmiQuery(string Language, string Namespace, string Query, WqlQueryReading Reading);

/// <summary>Source-bound conjunctive query definition; parsing never establishes a filter match.</summary>
internal sealed record GpoWmiFilterReading(
    CapturedObjectIdentity Policy,
    ObjectAttributes PolicyValues,
    CapturedWmiReference? Reference,
    CapturedObjectIdentity? Filter,
    ObjectAttributes? FilterValues,
    Result<ImmutableArray<CapturedWmiQuery>> Definition);

internal enum WqlReadingState
{
    Unavailable,
    Rejected,
    Unsupported,
    ParsedConditions,
}

internal enum WqlLiteralKind
{
    Text,
    SignedInteger,
    UnsignedInteger,
    Real,
}

internal enum WqlComparison
{
    Equal,
    NotEqual,
    GreaterOrEqual,
    LessOrEqual,
    Less,
    Greater,
    Like,
    IsNull,
    IsNotNull,
}

internal enum WqlLogicalOperator
{
    And,
    Or,
    Not,
}

internal sealed record WqlLiteral(WqlLiteralKind Kind, string Value, uint NativeType);
internal abstract record WqlConditionToken;
internal sealed record WqlComparisonToken(string Property, WqlComparison Comparison, WqlLiteral? Literal) : WqlConditionToken;
internal sealed record WqlLogicalToken(WqlLogicalOperator Operator) : WqlConditionToken;
internal sealed record WqlConditions(string ClassName, ImmutableArray<WqlConditionToken> Postfix);

internal sealed record WqlQueryReading(
    string OriginalQuery, WqlReadingState State, WqlConditions? Conditions, AuditError? Error, int? NativeCode)
{
    internal static WqlQueryReading Failed(string query, WqlReadingState state, string reason,
        string description, int? nativeCode) =>
        new(query, state, null, AuditError.Create(ErrorCategory.Evidence, reason, ErrorSeverity.Degraded,
            description, query), nativeCode);
}

internal static class CapturedWmiEncoding
{
    // MS-GPOL 2.2.4 defines this reference and requires clients to ignore its final flags field.
    internal static Result<CapturedWmiReference> Reference(string raw)
    {
        ArgumentNullException.ThrowIfNull(raw);
        if (raw.Length < 2 || raw[0] != '[' || raw[^1] != ']')
            return InvalidReference();
        var fields = raw[1..^1].Split(';');
        if (fields.Length != 3 || string.IsNullOrWhiteSpace(fields[0]) || fields[0] != fields[0].Trim()
            || fields[0].Contains('[') || fields[0].Contains(']') || fields[0].Contains('\0')
            || fields[1] != fields[1].Trim() || !Guid.TryParse(fields[1], out var identifier) || identifier == Guid.Empty)
            return InvalidReference();
        return Result<CapturedWmiReference>.Success(new(fields[0], identifier, fields[2]));

        Result<CapturedWmiReference> InvalidReference() => Result<CapturedWmiReference>.Failure(AuditError.Create(
            ErrorCategory.Evidence, "GpoWmiReferenceUnsupported", ErrorSeverity.Degraded,
            "The captured WMI filter reference is not a supported domain/filter/flags reference.", raw));
    }

    internal static Result<ImmutableArray<(string Language, string Namespace, string Query)>> Queries(
        string raw, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(raw);
        cancellationToken.ThrowIfCancellationRequested();
        var position = 0;
        if (!Number(out var count) || count == 0)
            return Invalid("The captured WMI filter query wrapper has no usable query count.");
        var queries = ImmutableArray.CreateBuilder<(string Language, string Namespace, string Query)>();
        for (var index = 0; index < count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Number(out var languageLength) || !Number(out var namespaceLength) || !Number(out var queryLength)
                || !Part(languageLength, out var language) || !Part(namespaceLength, out var nameSpace)
                || !Part(queryLength, out var query))
                return Invalid("The captured WMI filter query wrapper has inconsistent lengths or delimiters.");
            if (language.Length == 0 || nameSpace.Length == 0 || query.Length == 0
                || language.Contains('\0') || nameSpace.Contains('\0') || query.Contains('\0'))
                return Invalid("The captured WMI filter query wrapper has an empty or embedded-null field.");
            queries.Add((language, nameSpace, query));
        }
        if (position != raw.Length)
            return Invalid("The captured WMI filter query wrapper has unconsumed trailing content.");
        return Result<ImmutableArray<(string, string, string)>>.Success(queries.ToImmutable());

        bool Number(out int value)
        {
            value = 0;
            var separator = raw.IndexOf(';', position);
            if (separator <= position || !int.TryParse(raw.AsSpan(position, separator - position),
                NumberStyles.None, CultureInfo.InvariantCulture, out value))
                return false;
            position = separator + 1;
            return true;
        }

        bool Part(int length, out string value)
        {
            value = "";
            if (length < 0 || length >= raw.Length - position || raw[position + length] != ';')
                return false;
            value = raw.Substring(position, length);
            position += length + 1;
            return true;
        }

        Result<ImmutableArray<(string, string, string)>> Invalid(string description) =>
            Result<ImmutableArray<(string, string, string)>>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "GpoWmiDefinitionUnsupported", ErrorSeverity.Degraded, description, raw));
    }
}

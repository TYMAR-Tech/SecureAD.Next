using System.Collections.Immutable;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Schema;

namespace SecureAD.Evidence;

public sealed partial class BundleReader
{
    /// <summary>Reads one generation-bound policy's captured filter without evaluating it or contacting WMI.</summary>
    internal GpoWmiFilterReading ReadGpoWmiFilter(CapturedObjectIdentity policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var policyValues = ReadGpoPolicyValues(policy, ["objectClass", "displayName", "gPCWQLFilter"], cancellationToken);
        var identity = policy with
        {
            DistinguishedName = policyValues.DistinguishedName,
            ObjectGuid = policyValues.ObjectGuid,
            ObjectClass = AttributeReading.LastText(policyValues, "objectClass"),
            DomainFqdn = policyValues.DomainFqdn,
            PrincipalSid = null,
        };
        CapturedWmiReference? reference = null;
        CapturedObjectIdentity? filter = null;
        ObjectAttributes? filterValues = null;
        if (identity.ObjectGuid is null || identity.ObjectGuid == Guid.Empty
            || !string.Equals(AttributeReading.LastText(policyValues, "objectClass"), "groupPolicyContainer", StringComparison.OrdinalIgnoreCase))
            return Failure("GpoWmiPolicyIdentityInvalid", "The selected captured object is not an identifiable Group Policy object.");
        var capturedReference = policyValues.Find("gPCWQLFilter");
        if (capturedReference?.HasValue != true)
            return Failure("GpoWmiReferenceNotReturned", "No usable WMI filter reference was returned for this captured policy; this does not prove that it has no filter.");
        var rawReference = SingleText(capturedReference);
        if (rawReference is null)
            return Failure("GpoWmiReferenceUnsupported", "The captured WMI filter reference is not exactly one original text value.");
        var decoded = ReadPreparedWmiReference(identity.ObjectId, rawReference, cancellationToken);
        if (!decoded.IsSuccess) return Reading(Result<ImmutableArray<CapturedWmiQuery>>.Failure(decoded.Error));
        reference = decoded.Value;
        cancellationToken.ThrowIfCancellationRequested();
        var contexts = ReadNamingContexts();
        if (!contexts.IsSuccess) return Reading(Result<ImmutableArray<CapturedWmiQuery>>.Failure(contexts.Error));
        var roots = contexts.Value.Where(pair => pair.Value == NamingContextKind.Domain
            && string.Equals(DnHelper.DnToFqdn(pair.Key), reference.DomainFqdn, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (roots.Length != 1)
            return Failure("GpoWmiDomainUnavailable", "The filter's exact domain naming context was not captured unambiguously.");
        var filterDn = $"CN={reference.FilterId:B},CN=SOM,CN=WMIPolicy,CN=System,{roots[0].Key}";
        var match = ReadObjectNameMatch(filterDn);
        if (match.Ambiguous)
            return Failure("GpoWmiFilterAmbiguous", "More than one captured row represents the referenced WMI filter name; no definition was selected.");
        if (match.ObjectId is null)
            return Failure("GpoWmiFilterNotCaptured", "The referenced WMI filter object was not captured at its exact domain-scoped location.");
        filter = ReadObjectIdentity(filterDn)
            ?? throw new InvalidDataException("The uniquely selected filter disappeared from its captured generation.");
        filterValues = ReadGpoFilterValues(filter, cancellationToken);
        var capturedId = SingleText(filterValues.Find("msWMI-ID"));
        if (filter.ObjectGuid is null || filter.ObjectGuid == Guid.Empty
            || !string.Equals(filter.DomainFqdn, reference.DomainFqdn, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(AttributeReading.LastText(filterValues, "objectClass"), "msWMI-Som", StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParse(capturedId, out var filterId) || filterId != reference.FilterId)
            return Failure("GpoWmiFilterIdentityMismatch", "The captured WMI object does not establish the referenced filter identity and resource domain.");
        var rawDefinition = SingleText(filterValues.Find("msWMI-Parm2"));
        if (rawDefinition is null)
            return Failure("GpoWmiDefinitionUnavailable", "The captured filter does not contain exactly one usable text query definition.");
        return Reading(ReadPreparedWmiDefinition(filter.ObjectId, rawDefinition, cancellationToken));

        GpoWmiFilterReading Reading(Result<ImmutableArray<CapturedWmiQuery>> definition) =>
            new(identity, policyValues, reference, filter, filterValues, definition);
        GpoWmiFilterReading Failure(string reason, string description) =>
            Reading(Result<ImmutableArray<CapturedWmiQuery>>.Failure(AuditError.Create(ErrorCategory.Evidence,
                reason, ErrorSeverity.Degraded, description, policy.DistinguishedName)));
    }

    private Result<ImmutableArray<CapturedWmiQuery>> ReadPreparedWmiDefinition(long filterId, string raw,
        CancellationToken token)
    {
        CheckGpoPreparationLifetime(token);
        RecordGpoPreparation("wmi-definition-request");
        if (_gpoWmiDefinitions is not null && _gpoWmiDefinitions.TryGetValue(filterId, out var saved))
        {
            RecordGpoPreparation("wmi-definition-hit");
            return saved;
        }
        RecordGpoPreparation("wmi-definition-decode");
        var decoded = CapturedWmiEncoding.Queries(raw, token);
        if (!decoded.IsSuccess) return Remember(Result<ImmutableArray<CapturedWmiQuery>>.Failure(decoded.Error));
        var queries = ImmutableArray.CreateBuilder<CapturedWmiQuery>();
        foreach (var value in decoded.Value)
        {
            token.ThrowIfCancellationRequested();
            var parsed = value.Language == "WQL" ? WindowsWqlParser.Read(value.Query, token)
                : WqlQueryReading.Failed(value.Query, WqlReadingState.Unsupported, "WmiLanguageUnsupported",
                    "The captured query does not declare the supported WQL language.", null);
            queries.Add(new(value.Language, value.Namespace, value.Query, parsed));
        }
        return Remember(Result<ImmutableArray<CapturedWmiQuery>>.Success(queries.ToImmutable()));

        Result<ImmutableArray<CapturedWmiQuery>> Remember(Result<ImmutableArray<CapturedWmiQuery>> definition)
        {
            CheckGpoPreparationLifetime(token);
            if (_protection is not null && CanReuseWmiDefinition(definition))
                (_gpoWmiDefinitions ??= []).Add(filterId, definition);
            else RecordGpoPreparation("wmi-definition-not-retained");
            return definition;
        }
    }

    internal static bool CanReuseWmiDefinition(Result<ImmutableArray<CapturedWmiQuery>> definition) =>
        !definition.IsSuccess || definition.Value.All(query =>
            query.Reading.State != WqlReadingState.Unavailable && query.Reading.NativeCode is null);

    private static string? SingleText(ObjectAttribute? attribute) =>
        attribute is { Values.Count: 1 } && attribute.Values[0] is { Ordinal: 0, Text: { } text, Bytes: null }
            ? text : null;
}

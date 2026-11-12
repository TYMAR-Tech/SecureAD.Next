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
        var policyValues = ReadObjectAttributesAt(policy, ["objectClass", "displayName", "gPCWQLFilter"]).Snapshot();
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
        var decoded = CapturedWmiEncoding.Reference(rawReference);
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
        filterValues = ReadObjectAttributesAt(filter, ["objectClass", "msWMI-ID", "msWMI-Name", "msWMI-Parm2"]).Snapshot();
        var capturedId = SingleText(filterValues.Find("msWMI-ID"));
        if (filter.ObjectGuid is null || filter.ObjectGuid == Guid.Empty
            || !string.Equals(filter.DomainFqdn, reference.DomainFqdn, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(AttributeReading.LastText(filterValues, "objectClass"), "msWMI-Som", StringComparison.OrdinalIgnoreCase)
            || !Guid.TryParse(capturedId, out var filterId) || filterId != reference.FilterId)
            return Failure("GpoWmiFilterIdentityMismatch", "The captured WMI object does not establish the referenced filter identity and resource domain.");
        var rawDefinition = SingleText(filterValues.Find("msWMI-Parm2"));
        if (rawDefinition is null)
            return Failure("GpoWmiDefinitionUnavailable", "The captured filter does not contain exactly one usable text query definition.");
        var decodedQueries = CapturedWmiEncoding.Queries(rawDefinition, cancellationToken);
        if (!decodedQueries.IsSuccess) return Reading(Result<ImmutableArray<CapturedWmiQuery>>.Failure(decodedQueries.Error));
        var queries = ImmutableArray.CreateBuilder<CapturedWmiQuery>();
        foreach (var value in decodedQueries.Value)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var parsed = value.Language == "WQL"
                ? WindowsWqlParser.Read(value.Query, cancellationToken)
                : WqlQueryReading.Failed(value.Query, WqlReadingState.Unsupported, "WmiLanguageUnsupported",
                    "The captured query does not declare the supported WQL language.", null);
            queries.Add(new(value.Language, value.Namespace, value.Query, parsed));
        }
        return Reading(Result<ImmutableArray<CapturedWmiQuery>>.Success(queries.ToImmutable()));

        GpoWmiFilterReading Reading(Result<ImmutableArray<CapturedWmiQuery>> definition) =>
            new(identity, policyValues, reference, filter, filterValues, definition);
        GpoWmiFilterReading Failure(string reason, string description) =>
            Reading(Result<ImmutableArray<CapturedWmiQuery>>.Failure(AuditError.Create(ErrorCategory.Evidence,
                reason, ErrorSeverity.Degraded, description, policy.DistinguishedName)));
    }

    private static string? SingleText(ObjectAttribute? attribute) =>
        attribute is { Values.Count: 1 } && attribute.Values[0] is { Ordinal: 0, Text: { } text, Bytes: null }
            ? text : null;
}

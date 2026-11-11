using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal enum GpoApplicabilityState { Unknown, DoesNotApply, Applies }

internal readonly record struct GpoWmiConditionKey(Guid CaptureGenerationId, string EvidenceSeal,
    long ComputerObjectId, long FilterObjectId);

internal sealed record GpoWmiAlternatives(GpoWmiConditionKey Condition,
    GpoApplicabilityState WhenMatches, GpoApplicabilityState WhenDoesNotMatch);

internal sealed record GpoConditionalApplicability(bool HasOpenPolicyScope, GpoWmiAlternatives? Wmi,
    AuditError? UnavailableReason)
{
    internal static GpoConditionalApplicability Of(GpoLinkHierarchy hierarchy, GpoApplicabilityState domainOu,
        GpoApplicabilityState policyState, GpoWmiFilterReading wmi)
    {
        var openScope = !hierarchy.SiteScopeResolved || !hierarchy.DomainOuEvidenceComplete;
        if (!wmi.Definition.IsSuccess) return new(openScope, null, wmi.Definition.Error);
        var queries = wmi.Definition.Value;
        if (queries.Length != 1)
            throw new InvalidDataException("A qualified WMI condition must contain one captured query.");
        if (queries[0].Reading.State != WqlReadingState.ParsedConditions)
            return new(openScope, null, queries[0].Reading.Error
                ?? throw new InvalidDataException("An unqualified WMI query has no recorded reason."));
        if (queries[0].Reading.Conditions is null || wmi.Filter is not { } filter || wmi.FilterValues is null
            || hierarchy.CaptureGenerationId == Guid.Empty || string.IsNullOrWhiteSpace(hierarchy.EvidenceSeal)
            || hierarchy.Computer.CaptureGenerationId != hierarchy.CaptureGenerationId
            || wmi.Policy.CaptureGenerationId != hierarchy.CaptureGenerationId
            || filter.CaptureGenerationId != hierarchy.CaptureGenerationId
            || filter.ObjectId <= 0 || filter.ObjectGuid is null || filter.ObjectGuid == Guid.Empty)
            throw new InvalidDataException("The conditional WMI outcome does not bind qualified captured sources.");
        if (hierarchy.Computer.ObjectId <= 0 || hierarchy.Computer.ObjectGuid is null
            || hierarchy.Computer.ObjectGuid == Guid.Empty
            || !string.Equals(hierarchy.Computer.ObjectClass, "computer", StringComparison.OrdinalIgnoreCase))
            return new(openScope, null, AuditError.Create(ErrorCategory.Evidence,
                "GpoConditionalComputerUnqualified", ErrorSeverity.Degraded,
                "The captured subject is not a qualified computer for conditional WMI outcomes.",
                hierarchy.Computer.DistinguishedName));
        var whenMatches = policyState == GpoApplicabilityState.DoesNotApply
            || domainOu == GpoApplicabilityState.DoesNotApply && hierarchy.SiteScopeResolved
                ? GpoApplicabilityState.DoesNotApply
                : policyState == GpoApplicabilityState.Applies && domainOu == GpoApplicabilityState.Applies
                    ? GpoApplicabilityState.Applies : GpoApplicabilityState.Unknown;
        return new(openScope, new(new(hierarchy.CaptureGenerationId, hierarchy.EvidenceSeal,
            hierarchy.Computer.ObjectId, filter.ObjectId), whenMatches, GpoApplicabilityState.DoesNotApply), null);
    }
}

internal sealed record GpoProtocolAssessment(CapturedGpoProtocolInputs Inputs,
    uint? FunctionalityVersion, uint? Flags, uint? DirectoryVersion, ImmutableArray<AuditError> Limitations)
{
    internal bool? FunctionalitySupported => FunctionalityVersion is { } version ? version == 2 : null;

    // MS-GPOL 2.2.4 defines a bit field, including flags=3, and requires ignoring other bits.
    internal bool? ComputerHalfEnabled => Flags is { } flags ? (flags & 2) == 0 : null;

    // MS-GPOL 3.2.5.1.6 tests the two complete versions, not just their machine halves.
    internal bool? NonEmpty => DirectoryVersion is > 0 || Inputs.TemplateVersion.Version is > 0 ? true
        : DirectoryVersion == 0 && Inputs.TemplateVersion.Version == 0 ? false : null;

    internal GpoApplicabilityState State =>
        FunctionalitySupported == false || ComputerHalfEnabled == false || NonEmpty == false
            ? GpoApplicabilityState.DoesNotApply
            : FunctionalitySupported == true && ComputerHalfEnabled == true && NonEmpty == true
                ? GpoApplicabilityState.Applies : GpoApplicabilityState.Unknown;
}

/// <summary>Configured prerequisites and scope, with unevaluated WMI and unresolved site scope kept separate.</summary>
internal sealed record GpoComputerApplicability(Guid CaptureGenerationId, string EvidenceSeal,
    Guid? DerivationGenerationId, CapturedObjectIdentity Computer, CapturedObjectIdentity Policy,
    GpoLinkHierarchy Hierarchy, ImmutableArray<GpoHierarchyLink> PolicyLinks, GpoApplicabilityState DomainOuState,
    GpoSecurityAssessment Security, GpoProtocolAssessment Protocol, GpoWmiFilterReading Wmi,
    GpoConditionalApplicability Conditional,
    GpoApplicabilityState PolicyState, GpoApplicabilityState State, ImmutableArray<AuditError> Limitations);

internal sealed record GpoComputerInputs(GpoLinkHierarchy Hierarchy,
    ImmutableArray<GpoComputerApplicability> Policies);

internal sealed class GpoComputerApplicabilityReader : IDisposable
{
    private readonly ProtectedRunFiles _files;
    private readonly GpoLinkHierarchyReader _hierarchy;
    private readonly GpoSecurityFilterReader _security;
    private bool _disposed;

    private GpoComputerApplicabilityReader(ProtectedRunFiles files, GpoLinkHierarchyReader hierarchy,
        GpoSecurityFilterReader security) => (_files, _hierarchy, _security) = (files, hierarchy, security);

    internal BundleReader Bundle => _hierarchy.Bundle;

    internal static Result<GpoComputerApplicabilityReader> Open(string directory, CancellationToken token)
    {
        var files = new ProtectedRunFiles(directory);
        GpoLinkHierarchyReader? hierarchy = null;
        GpoSecurityFilterReader? security = null;
        var accepted = false;
        try
        {
            var links = GpoLinkHierarchyReader.Open(files, token);
            if (!links.IsSuccess) return Result<GpoComputerApplicabilityReader>.Failure(links.Error);
            hierarchy = links.Value;
            var permissions = GpoSecurityFilterReader.Open(files, token);
            if (!permissions.IsSuccess) return Result<GpoComputerApplicabilityReader>.Failure(permissions.Error);
            security = permissions.Value;
            accepted = true;
            return new GpoComputerApplicabilityReader(files, hierarchy, security);
        }
        finally
        {
            if (!accepted)
            {
                security?.Dispose();
                hierarchy?.Dispose();
                files.Dispose();
            }
        }
    }

    internal Result<GpoComputerApplicability> Assess(CapturedObjectIdentity computer, CapturedObjectIdentity policy,
        CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        var hierarchy = _hierarchy.Read(computer, token);
        return Assess(hierarchy, policy, token);
    }

    internal Result<GpoComputerInputs> ReadComputer(CapturedObjectIdentity computer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        var hierarchy = _hierarchy.Read(computer, token);
        var results = ImmutableArray.CreateBuilder<GpoComputerApplicability>();
        foreach (var policy in hierarchy.Links.Where(link => link.State != GpoLinkHierarchyState.Excluded && link.Policy is not null)
            .Select(link => link.Policy!).DistinctBy(policy => policy.ObjectId))
        {
            token.ThrowIfCancellationRequested();
            var read = Assess(hierarchy, policy, token);
            if (!read.IsSuccess) return Result<GpoComputerInputs>.Failure(read.Error);
            results.Add(read.Value);
        }
        RequireCurrent();
        return new GpoComputerInputs(hierarchy, results.ToImmutable());
    }

    private Result<GpoComputerApplicability> Assess(GpoLinkHierarchy hierarchy, CapturedObjectIdentity policy,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var security = _security.Assess(hierarchy.Computer, policy, token);
        var captured = Bundle.ReadGpoProtocolInputs(security.Policy, token);
        RequireCurrent();
        if (!captured.IsSuccess) return Result<GpoComputerApplicability>.Failure(captured.Error);
        var protocol = ReadProtocol(captured.Value);
        var wmi = Bundle.ReadGpoWmiFilter(security.Policy, token);
        if (hierarchy.CaptureGenerationId != security.CaptureGenerationId
            || hierarchy.CaptureGenerationId != captured.Value.CaptureGenerationId
            || hierarchy.EvidenceSeal != security.EvidenceSeal
            || hierarchy.Computer != security.Computer || security.Policy != captured.Value.Policy
            || security.Policy != wmi.Policy)
            throw new InvalidDataException("The GPO applicability components do not bind the same captured sources.");
        var links = hierarchy.Links.Where(link => link.Policy?.ObjectId == security.Policy.ObjectId
            || link.Policy is null && string.Equals(link.Link.DistinguishedName, security.Policy.DistinguishedName,
                StringComparison.OrdinalIgnoreCase)).ToImmutableArray();
        var domainOu = links.Any(link => link.State == GpoLinkHierarchyState.Included) ? GpoApplicabilityState.Applies
            : hierarchy.DomainOuEvidenceComplete && links.All(link => link.State == GpoLinkHierarchyState.Excluded)
                ? GpoApplicabilityState.DoesNotApply : GpoApplicabilityState.Unknown;
        var policyState = security.Decision == GpoSecurityDecision.Excluded || protocol.State == GpoApplicabilityState.DoesNotApply
            ? GpoApplicabilityState.DoesNotApply
            : security.Decision == GpoSecurityDecision.Included && protocol.State == GpoApplicabilityState.Applies
                ? GpoApplicabilityState.Applies : GpoApplicabilityState.Unknown;
        // Missing site scope can add another occurrence; it cannot undo a policy-wide exclusion.
        // No qualified captured input yet establishes WMI truth or absence, even after successful parsing.
        var state = policyState == GpoApplicabilityState.DoesNotApply
            || domainOu == GpoApplicabilityState.DoesNotApply && hierarchy.SiteScopeResolved
                ? GpoApplicabilityState.DoesNotApply : GpoApplicabilityState.Unknown;
        var errors = hierarchy.Limitations.Concat(security.Limitations).Concat(protocol.Limitations).ToList();
        if (!wmi.Definition.IsSuccess) errors.Add(wmi.Definition.Error);
        else errors.AddRange(wmi.Definition.Value.Where(query => query.Reading.Error is not null)
            .Select(query => query.Reading.Error!));
        errors.Add(Error("GpoApplicabilityWmiUnresolved",
            "Captured WMI configuration and parsed conditions do not establish that this policy is unfiltered or that its filter matches.",
            security.Policy.DistinguishedName));
        var conditional = GpoConditionalApplicability.Of(hierarchy, domainOu, policyState, wmi);
        if (conditional.UnavailableReason is { } unavailable) errors.Add(unavailable);
        token.ThrowIfCancellationRequested();
        RequireCurrent();
        return new GpoComputerApplicability(hierarchy.CaptureGenerationId, hierarchy.EvidenceSeal,
            security.DerivationGenerationId, hierarchy.Computer, security.Policy, hierarchy, links, domainOu,
            security, protocol, wmi, conditional, policyState, state, errors.Distinct().ToImmutableArray());
    }

    private static GpoProtocolAssessment ReadProtocol(CapturedGpoProtocolInputs inputs)
    {
        var errors = new List<AuditError>();
        var functionality = Number("gPCFunctionalityVersion");
        var flags = Number("flags");
        var version = Number("versionNumber");
        if (inputs.TemplateVersion.Error is { } error) errors.Add(error);
        return new(inputs, functionality, flags, version, errors.ToImmutableArray());

        uint? Number(string name)
        {
            var attribute = inputs.PolicyValues.Find(name);
            if (attribute?.HasValue != true)
            {
                errors.Add(Error("GpoApplicabilityInputMissing",
                    $"The required captured {name} value was not returned.", inputs.Policy.DistinguishedName));
                return null;
            }
            if (attribute is { Values.Count: 1 }
                && attribute.Values[0] is { Ordinal: 0, Text: { } text, Bytes: null }
                && uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var value))
                return value;
            errors.Add(Error("GpoApplicabilityInputUnsupported",
                $"The captured {name} value is not one original unsigned 32-bit integer.",
                inputs.Policy.DistinguishedName));
            return null;
        }
    }

    internal void RequireCurrent()
    {
        _hierarchy.RequireCurrent();
        _security.RequireCurrent();
    }

    private static AuditError Error(string code, string description, string context) =>
        AuditError.Create(ErrorCategory.Evidence, code, ErrorSeverity.Degraded, description, context);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _security.Dispose();
        _hierarchy.Dispose();
        _files.Dispose();
    }
}

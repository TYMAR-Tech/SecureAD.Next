using System.Collections.Immutable;
using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

internal enum GpoLinkHierarchyState { Unresolved, Excluded, Included }
internal enum GpoLinkContainerKind { OrganizationalUnit, Domain }

internal sealed record GpoLinkContainer(string DistinguishedName, GpoLinkContainerKind Kind,
    CapturedObjectIdentity? Identity, ObjectAttributes? Values, bool? BlocksInheritance,
    ImmutableArray<PolicyLink> Links, ImmutableArray<AuditError> Limitations);

internal sealed record GpoHierarchyLink(int ContainerIndex, PolicyLink Link, uint? Options,
    bool? Disabled, bool? Enforced, CapturedObjectIdentity? Policy, ObjectAttributes? PolicyValues,
    GpoLinkHierarchyState State, string Reason, int? DomainOuProcessingOrder);

/// <summary>Structural domain/OU scope only; Read/Apply, site scope, WMI and winning settings are separate.</summary>
internal sealed record GpoLinkHierarchy(Guid CaptureGenerationId, string EvidenceSeal,
    CapturedObjectIdentity Computer, ObjectAttributes ComputerValues, ImmutableArray<GpoLinkContainer> Containers,
    ImmutableArray<GpoHierarchyLink> Links, bool DomainOuEvidenceComplete, bool SiteScopeResolved,
    ImmutableArray<AuditError> Limitations);

internal sealed class GpoLinkHierarchyReader : IDisposable
{
    private readonly JudgingInputs _sources;
    private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
    private readonly IReadOnlySet<string> _domains;
    private bool _disposed;

    private GpoLinkHierarchyReader(JudgingInputs sources, IReadOnlyDictionary<string, NamingContextKind> contexts,
        IReadOnlySet<string> domains) => (_sources, _contexts, _domains) = (sources, contexts, domains);

    internal BundleReader Bundle => _sources.Bundle;

    internal void RequireCurrent() => _sources.RequireCurrent();

    internal static Result<GpoLinkHierarchyReader> Open(string directory, CancellationToken token) =>
        Open(JudgingInputs.Open(directory, token));

    internal static Result<GpoLinkHierarchyReader> Open(ProtectedRunFiles files, CancellationToken token) =>
        Open(JudgingInputs.Open(files, token));

    private static Result<GpoLinkHierarchyReader> Open(Result<JudgingInputs> opened)
    {
        if (!opened.IsSuccess) return Result<GpoLinkHierarchyReader>.Failure(opened.Error);
        var accepted = false;
        try
        {
            var contexts = opened.Value.ReadNamingContexts();
            if (!contexts.IsSuccess) return Result<GpoLinkHierarchyReader>.Failure(contexts.Error);
            var scope = opened.Value.Bundle.ReadScope();
            if (!scope.IsSuccess) return Result<GpoLinkHierarchyReader>.Failure(scope.Error);
            var reader = new GpoLinkHierarchyReader(opened.Value, contexts.Value,
                scope.Value.Domains.Where(domain => domain.Outcome == DomainReadOutcome.Read)
                    .Select(domain => domain.DomainFqdn).ToImmutableHashSet(StringComparer.OrdinalIgnoreCase));
            accepted = true;
            return reader;
        }
        finally { if (!accepted) opened.Value.Dispose(); }
    }

    internal GpoLinkHierarchy Read(CapturedObjectIdentity computer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        _sources.RequireCurrent();
        var values = Bundle.ReadObjectAttributesAt(computer, ["objectClass", "objectSid"]).Snapshot();
        computer = GpoCapturedIdentity.Normalize(computer, values);
        var containers = new List<GpoLinkContainer>();
        var links = new List<GpoHierarchyLink>();
        var errors = new List<AuditError>();
        if (computer.ObjectGuid is null || computer.ObjectGuid == Guid.Empty
            || !Same(computer.ObjectClass, "computer") || computer.DomainFqdn is null || !_domains.Contains(computer.DomainFqdn))
            return Finish("GpoHierarchyComputerUnavailable", "The captured computer lacks a qualified identity or read domain.");
        var roots = _contexts.Where(pair => pair.Value == NamingContextKind.Domain
            && Same(DnHelper.DnToFqdn(pair.Key), computer.DomainFqdn)).Select(pair => pair.Key).ToArray();
        if (roots.Length != 1)
            return Finish("GpoHierarchyDomainUnavailable", "The computer does not have one captured domain naming context.");
        var root = roots[0];
        var names = new List<string>();
        var parent = DnHelper.GetParentDn(computer.DistinguishedName);
        while (parent is not null)
        {
            token.ThrowIfCancellationRequested();
            if (Same(parent, root)) { names.Add(parent); break; }
            if (parent.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                return Finish("GpoHierarchyDomainMismatch", "The computer's ancestor chain reaches another domain.");
            if (parent.StartsWith("OU=", StringComparison.OrdinalIgnoreCase)) names.Add(parent);
            parent = DnHelper.GetParentDn(parent);
        }
        if (names.Count == 0 || !Same(names[^1], root))
            return Finish("GpoHierarchyDomainMismatch", "The captured computer's ancestor chain does not reach its domain root.");
        bool? blocked = false;
        foreach (var name in names)
        {
            token.ThrowIfCancellationRequested();
            var kind = Same(name, root) ? GpoLinkContainerKind.Domain : GpoLinkContainerKind.OrganizationalUnit;
            var container = ReadContainer(name, kind, token);
            var index = containers.Count;
            containers.Add(container);
            errors.AddRange(container.Limitations);
            foreach (var link in container.Links)
            {
                token.ThrowIfCancellationRequested();
                var options = ReadOptions(link.Options);
                bool? disabled = options is { } bits ? (bits & 1) != 0 : null;
                bool? enforced = options is { } flags ? (flags & 2) != 0 : null;
                var state = disabled == true ? GpoLinkHierarchyState.Excluded
                    : options is null ? GpoLinkHierarchyState.Unresolved
                    : enforced == false && blocked == true ? GpoLinkHierarchyState.Excluded
                    : enforced == false && blocked is null ? GpoLinkHierarchyState.Unresolved
                    : GpoLinkHierarchyState.Included;
                var reason = disabled == true ? "LinkDisabled"
                    : options is null ? "LinkOptionsUnsupported"
                    : enforced == false && blocked == true ? "InheritanceBlocked"
                    : enforced == false && blocked is null ? "DescendantInheritanceUnknown" : "CapturedDomainOuLink";
                if (options is null)
                    errors.Add(Error("GpoHierarchyLinkOptionsUnsupported", "A link's original options are not a qualified DWORD flag combination.", name));
                var policy = ReadPolicy(link.DistinguishedName, errors, token);
                if (policy is null && state != GpoLinkHierarchyState.Excluded)
                {
                    state = GpoLinkHierarchyState.Unresolved;
                    reason = "PolicyUnavailable";
                }
                links.Add(new(index, link, options, disabled, enforced, policy?.Identity, policy?.Values,
                    state, reason, null));
            }
            blocked = blocked == true || container.BlocksInheritance == true ? true
                : blocked is null || container.BlocksInheritance is null ? null : false;
        }
        // MS-GPOL 3.2.5.1.3 visits the closest OU first. 3.2.5.1.5 prepends ordinary links
        // and appends enforced links; these are relative domain/OU positions, not winning settings.
        var order = links.Select((link, index) => (Link: link, Index: index))
            .Where(item => item.Link.State != GpoLinkHierarchyState.Excluded && item.Link.Enforced == false).Reverse()
            .Concat(links.Select((link, index) => (Link: link, Index: index))
                .Where(item => item.Link.State != GpoLinkHierarchyState.Excluded && item.Link.Enforced == true))
            .ToArray();
        for (var index = 0; index < order.Length; index++)
            links[order[index].Index] = order[index].Link with { DomainOuProcessingOrder = index + 1 };
        return Finish(null, null);

        GpoLinkHierarchy Finish(string? code, string? description)
        {
            token.ThrowIfCancellationRequested();
            if (code is not null) errors.Add(Error(code, description!, computer.DistinguishedName));
            var complete = errors.Count == 0 && links.All(link => link.State != GpoLinkHierarchyState.Unresolved);
            errors.Add(Error("GpoHierarchySiteUnresolved",
                "Captured directory evidence does not establish this computer's site; site-linked scope and its possible enforced priority remain unresolved.",
                computer.DistinguishedName));
            _sources.RequireCurrent();
            return new(Bundle.Description.CaptureGenerationId, _sources.EvidenceSeal, computer, values,
                containers.ToImmutableArray(), links.ToImmutableArray(), complete, false, errors.Distinct().ToImmutableArray());
        }
    }

    private GpoLinkContainer ReadContainer(string dn, GpoLinkContainerKind kind, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var match = Bundle.ReadObjectNameMatch(dn);
        if (match.Ambiguous || match.ObjectId is null)
            return Missing("GpoHierarchyContainerUnavailable", "The ancestor container is absent or ambiguous in this capture.");
        var identity = Bundle.ReadObjectIdentity(dn)!;
        var values = Bundle.ReadObjectAttributesAt(identity, ["objectClass", "gPLink", "gPOptions"]).Snapshot();
        identity = GpoCapturedIdentity.Normalize(identity, values);
        var expected = kind == GpoLinkContainerKind.Domain ? "domainDNS" : "organizationalUnit";
        if (identity.ObjectGuid is null || identity.ObjectGuid == Guid.Empty || !Same(identity.ObjectClass, expected)
            || identity.DomainFqdn is null || !_domains.Contains(identity.DomainFqdn)
            || !Same(identity.DomainFqdn, DnHelper.DnToFqdn(dn)))
            return new(dn, kind, identity, values, null, [], [Error("GpoHierarchyContainerUnqualified", "The captured ancestor has no qualified container identity or class.", dn)]);
        var errors = new List<AuditError>();
        var parsed = PolicyLinkList.Of(values.Find("gPLink")?.OnlyValue?.Text);
        foreach (var error in parsed.Errors) errors.Add(Error("GpoHierarchyLinkMalformed", error, dn));
        var rawOptions = values.Find("gPOptions")?.OnlyValue?.Text;
        bool? blocks = rawOptions is null ? false
            : rawOptions == "0" ? false : rawOptions == "1" ? true : null;
        if (blocks is null) errors.Add(Error("GpoHierarchyInheritanceUnsupported", "The captured inheritance option is neither absent, zero nor one.", dn));
        return new(dn, kind, identity, values, blocks, parsed.Links.ToImmutableArray(), errors.ToImmutableArray());

        GpoLinkContainer Missing(string code, string description) => new(dn, kind, null, null, null, [], [Error(code, description, dn)]);
    }

    private (CapturedObjectIdentity Identity, ObjectAttributes Values)? ReadPolicy(string dn, List<AuditError> errors, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var match = Bundle.ReadObjectNameMatch(dn);
        if (match.Ambiguous || match.ObjectId is null)
        {
            errors.Add(Error("GpoHierarchyPolicyUnavailable", "A linked policy reference is absent or ambiguous in this capture.", dn));
            return null;
        }
        var identity = Bundle.ReadObjectIdentity(dn)!;
        var values = Bundle.ReadObjectAttributesAt(identity, ["objectClass"]).Snapshot();
        identity = GpoCapturedIdentity.Normalize(identity, values);
        if (identity.ObjectGuid is null || identity.ObjectGuid == Guid.Empty || !Same(identity.ObjectClass, "groupPolicyContainer")
            || identity.DomainFqdn is null || !_domains.Contains(identity.DomainFqdn)
            || !Same(identity.DomainFqdn, DnHelper.DnToFqdn(dn)))
        {
            errors.Add(Error("GpoHierarchyPolicyUnqualified", "The linked row is not a qualified GPO in a captured read domain.", dn));
            return null;
        }
        return (identity, values);
    }

    private static uint? ReadOptions(string raw) => uint.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value)
        && (value & ~3U) == 0 ? value : null;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static AuditError Error(string code, string description, string context) =>
        AuditError.Create(ErrorCategory.Evidence, code, ErrorSeverity.Degraded, description, context);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _sources.Dispose();
    }
}

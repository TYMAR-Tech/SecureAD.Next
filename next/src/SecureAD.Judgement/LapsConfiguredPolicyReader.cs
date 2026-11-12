using System.Collections.Immutable;
using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;

namespace SecureAD.Judgement;

internal sealed class LapsConfiguredPolicyReader : IDisposable
{
    private readonly GpoComputerApplicabilityReader _inputs;
    private bool _disposed;

    private LapsConfiguredPolicyReader(GpoComputerApplicabilityReader inputs) => _inputs = inputs;
    internal BundleReader Bundle => _inputs.Bundle;

    internal static Result<LapsConfiguredPolicyReader> Open(string directory, CancellationToken token)
    {
        var opened = GpoComputerApplicabilityReader.Open(directory, token);
        return opened.IsSuccess ? new LapsConfiguredPolicyReader(opened.Value)
            : Result<LapsConfiguredPolicyReader>.Failure(opened.Error);
    }

    internal static Result<LapsConfiguredPolicyReader> Open(ProtectedRunFiles files, CancellationToken token)
    {
        var opened = GpoComputerApplicabilityReader.Open(files, token);
        return opened.IsSuccess ? new LapsConfiguredPolicyReader(opened.Value)
            : Result<LapsConfiguredPolicyReader>.Failure(opened.Error);
    }

    internal Result<LapsConfiguredPolicy> Read(CapturedObjectIdentity computer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        var batch = _inputs.ReadComputer(computer, token);
        if (!batch.IsSuccess) return Result<LapsConfiguredPolicy>.Failure(batch.Error);
        var policies = new Dictionary<long, LapsRegistryPolicyInput>();
        foreach (var assessment in batch.Value.Policies)
        {
            token.ThrowIfCancellationRequested();
            var values = Bundle.ReadObjectAttributesAt(assessment.Policy, ["gPCMachineExtensionNames"]).Snapshot();
            var state = RegistryExtension(values);
            var error = state == GpoApplicabilityState.Unknown ? AuditError.Create(ErrorCategory.Evidence,
                "LapsRegistryExtensionUnresolved", ErrorSeverity.Degraded,
                "The captured machine-extension declaration does not establish a qualified registry-extension decision.",
                assessment.Policy.DistinguishedName) : null;
            var settings = state == GpoApplicabilityState.DoesNotApply
                || assessment.PolicyState == GpoApplicabilityState.DoesNotApply ? null
                : Bundle.ReadGpoMachineRegistrySettings(assessment.Policy.ObjectGuid!.Value);
            policies.Add(assessment.Policy.ObjectId, new(assessment, state, values, settings, error));
        }
        var result = LapsConfiguredPolicyCalculator.Calculate(batch.Value, policies, token);
        token.ThrowIfCancellationRequested();
        _inputs.RequireCurrent();
        return result;
    }

    internal static GpoApplicabilityState RegistryExtension(ObjectAttributes values)
    {
        var attribute = values.Find("gPCMachineExtensionNames");
        if (attribute is not { Values.Count: 1 }
            || attribute.Values[0] is not { Ordinal: 0, Text: { } raw, Bytes: null }
            || raw.Length == 0)
            return GpoApplicabilityState.Unknown;
        var position = 0;
        var found = false;
        string? previous = null;
        // The capture heuristic is deliberately permissive; exclusion here requires a complete declaration.
        foreach (Match group in Regex.Matches(raw,
            @"\[(?<cse>\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\})(?:\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\})+\]"))
        {
            if (group.Index != position) return GpoApplicabilityState.Unknown;
            var canonical = group.Groups["cse"].Value;
            if (previous is not null && StringComparer.OrdinalIgnoreCase.Compare(previous, canonical) > 0)
                return GpoApplicabilityState.Unknown;
            previous = canonical;
            position += group.Length;
            found |= Guid.Parse(canonical) == GpoClientSideExtensionCatalog.RegistryCse;
        }
        return position != raw.Length ? GpoApplicabilityState.Unknown
            : found ? GpoApplicabilityState.Applies : GpoApplicabilityState.DoesNotApply;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _inputs.Dispose();
    }
}

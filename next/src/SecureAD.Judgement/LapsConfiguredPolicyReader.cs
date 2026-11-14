using System.Collections.Immutable;
using System.Text.RegularExpressions;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;

namespace SecureAD.Judgement;

internal sealed class LapsConfiguredPolicyReader : IDisposable
{
    private readonly GpoComputerApplicabilityReader _inputs;
    private readonly Dictionary<long, (GpoApplicabilityState State, AuditError? Error)> _extensions = [];
    private readonly Dictionary<long, PreparedRegistry> _registries = [];
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

    internal static Result<LapsConfiguredPolicyReader> Open(JudgingInputs inputs, CancellationToken token)
    {
        var opened = GpoComputerApplicabilityReader.Open(inputs, token);
        return opened.IsSuccess ? new LapsConfiguredPolicyReader(opened.Value)
            : Result<LapsConfiguredPolicyReader>.Failure(opened.Error);
    }

    internal Result<LapsConfiguredPolicy> Read(CapturedObjectIdentity computer, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        using var calculation = LapsCalculationDiagnostics.Begin(_inputs.Directory);
        var batch = _inputs.ReadComputer(computer, token);
        if (!batch.IsSuccess) return Result<LapsConfiguredPolicy>.Failure(batch.Error);
        var policies = new Dictionary<long, LapsRegistryPolicyInput>();
        using (LapsCalculationDiagnostics.Measure("registry-preparation"))
        {
            foreach (var assessment in batch.Value.Policies)
            {
                token.ThrowIfCancellationRequested();
                var values = Bundle.ReadGpoPolicyValues(assessment.Policy, ["gPCMachineExtensionNames"], token);
                if (!_extensions.TryGetValue(assessment.Policy.ObjectId, out var extension))
                {
                    Bundle.RecordGpoPreparation("registry-extension-preparation");
                    var state = RegistryExtension(values);
                    var error = state == GpoApplicabilityState.Unknown ? AuditError.Create(ErrorCategory.Evidence,
                        "LapsRegistryExtensionUnresolved", ErrorSeverity.Degraded,
                        "The captured machine-extension declaration does not establish a qualified registry-extension decision.",
                        assessment.Policy.DistinguishedName) : null;
                    extension = (state, error);
                    _extensions.Add(assessment.Policy.ObjectId, extension);
                }
                else Bundle.RecordGpoPreparation("registry-extension-hit");
                Bundle.RecordGpoPreparation("registry-settings-request");
                GpoRegistrySettings? settings = null;
                IReadOnlyList<RegistryPolicyInstruction> instructions = [];
                if (extension.State != GpoApplicabilityState.DoesNotApply && assessment.PolicyState != GpoApplicabilityState.DoesNotApply)
                {
                    if (!_registries.TryGetValue(assessment.Policy.ObjectId, out var prepared))
                    {
                        Bundle.RecordGpoPreparation("registry-settings-read");
                        prepared = new(Bundle.ReadGpoMachineRegistrySettings(assessment.Policy.ObjectGuid!.Value));
                        token.ThrowIfCancellationRequested();
                        _registries.Add(assessment.Policy.ObjectId, prepared);
                    }
                    else Bundle.RecordGpoPreparation("registry-settings-hit");
                    (settings, instructions) = prepared.Copy();
                    LapsCalculationDiagnostics.Count("registry-instructions-copied", instructions.Count);
                }
                policies.Add(assessment.Policy.ObjectId, new(assessment, extension.State, values, settings, extension.Error)
                {
                    Instructions = instructions,
                });
            }
        }
        LapsConfiguredPolicy result;
        using (LapsCalculationDiagnostics.Measure("settings-calculation"))
            result = LapsConfiguredPolicyCalculator.Calculate(batch.Value, policies, token);
        token.ThrowIfCancellationRequested();
        using (LapsCalculationDiagnostics.Measure("final-input-check"))
            _inputs.RequireActiveInputs();
        LapsCalculationDiagnostics.Count("computers-calculated", 1);
        return result;
    }

    private sealed class PreparedRegistry(GpoRegistrySettings original)
    {
        private readonly IReadOnlyList<RegistryPolicyInstruction> _instructions =
            RegistryPolicyInterpreter.ReadInstructions(original.Settings).Instructions;

        internal (GpoRegistrySettings Registry, IReadOnlyList<RegistryPolicyInstruction> Instructions) Copy()
        {
            var entries = original.Settings.Select(entry => entry with { Data = entry.Data.ToArray() }).ToImmutableArray();
            var instructions = _instructions.Select(instruction => instruction with
            {
                Source = entries[instruction.EntryIndex],
            }).ToImmutableArray();
            return (original with { Settings = entries, ParseErrors = original.ParseErrors.ToImmutableArray() }, instructions);
        }
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
        _extensions.Clear();
        _registries.Clear();
        _inputs.Dispose();
    }
}

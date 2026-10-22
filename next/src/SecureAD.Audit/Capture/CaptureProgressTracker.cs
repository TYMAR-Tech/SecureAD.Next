using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;

namespace SecureAD.Audit.Capture;

internal sealed class CaptureProgressTracker
{
    private readonly object _gate = new();
    private readonly IProgress<CaptureProgress> _receiver;
    private readonly Dictionary<string, int> _indices;
    private readonly CaptureScopeProgress[] _scopes;
    private CaptureWorkPhase _phase;
    private long? _policies;
    private long? _policiesTotal;
    private long _sequence;
    private CaptureProgress _current;

    internal CaptureProgressTracker(CapturePlan plan, IProgress<CaptureProgress> receiver)
    {
        _receiver = receiver;
        _scopes = plan.Units.Select(unit => new CaptureScopeProgress(unit.NamingContext,
            unit.Kind == NamingContextKind.Domain ? DnHelper.DnToFqdn(unit.NamingContext) : unit.Kind.ToString(),
            unit.Kind == NamingContextKind.Domain, null, CaptureReadState.Waiting)).ToArray();
        _indices = _scopes.Select((scope, index) => (scope, index)).ToDictionary(
            item => item.scope.NamingContext, item => item.index, StringComparer.OrdinalIgnoreCase);
        _current = new(0, CaptureWorkPhase.DirectoryRead, Array.AsReadOnly(_scopes.ToArray()), null);
    }

    internal CaptureProgress Current { get { lock (_gate) return _current; } }

    internal void Start() { lock (_gate) Publish(); }

    internal void Scope(CaptureUnit unit, CaptureReadState state, long? count)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        lock (_gate)
        {
            if (!_indices.TryGetValue(unit.NamingContext, out var index))
                throw new InvalidOperationException("Capture progress names a partition outside the selected plan.");
            var old = _scopes[index];
            // A restart discarded its earlier objects. Never retain the abandoned attempt's maximum.
            _scopes[index] = old with { State = state, ObjectsRead = count };
            Publish();
        }
    }

    internal void Phase(CaptureWorkPhase phase)
    {
        lock (_gate) { _phase = phase; Publish(); }
    }

    internal void State(CaptureUnit unit, CaptureReadState state)
    {
        lock (_gate)
        {
            if (!_indices.TryGetValue(unit.NamingContext, out var index))
                throw new InvalidOperationException("Capture progress names a partition outside the selected plan.");
            Scope(unit, state, _scopes[index].ObjectsRead);
        }
    }

    internal void Policies(long completed)
    {
        if (completed < 0) throw new ArgumentOutOfRangeException(nameof(completed));
        lock (_gate) { _phase = CaptureWorkPhase.PolicyFiles; _policies = completed; Publish(); }
    }

    internal void PolicyInventory(long total)
    {
        if (total < 0) throw new ArgumentOutOfRangeException(nameof(total));
        lock (_gate) { _phase = CaptureWorkPhase.PolicyFiles; _policiesTotal = total; Publish(); }
    }

    private void Publish()
    {
        _current = new(++_sequence, _phase, Array.AsReadOnly(_scopes.ToArray()), _policies) { PoliciesTotal = _policiesTotal };
        _receiver.Report(_current);
    }
}

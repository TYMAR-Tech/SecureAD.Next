using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// Collects possible incoming controllers from captured owners and ACLs during the object stream.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists so scope can be decided before the expensive pass rather than after it.</b> The
/// previous ordering derived detailed control products for every streamed object and only then read
/// them back to work out which handful mattered - in the lab, 112,093 control records and 23,751
/// full-control assessments to justify 51 assessed targets. This performs a bounded scan of the same
/// captured facts, collecting named permissions as candidates without invoking any evaluator.
/// </para>
/// <para>
/// <b>Nothing here decides what a permission grants.</b> A candidate says an ACE names a trustee and
/// a right on an object, which is a captured fact. Whether that constitutes control is the existing
/// evaluators' question, and they remain the only authority on it. Discovery's output admits targets
/// for assessment; it is not an authorization verdict, and
/// <see cref="Tier0RelevanceRelation.FromCapturedPermission"/> keeps
/// <see cref="Tier0State.Unknown"/> on everything it produces to make that unmistakable.
/// </para>
/// <para>
/// <b>Broad principals are one candidate, not thousands.</b> Per decision 0116, Everyone,
/// Authenticated Users and a NULL DACL are recorded once with their source witness and honest
/// incomplete coverage. Expanding them would make most of the forest relevant and reintroduce the
/// cost this removes; omitting them would imply a safety never established. The remediation is the
/// single permission entry, which the retained witness names directly.
/// </para>
/// <para>
/// Modelled on <see cref="SelfMembershipScheduler"/>, which already establishes the shape for a
/// budgeted per-object scan that reports typed limitation reasons rather than silently stopping.
/// </para>
/// </remarks>
internal sealed class Tier0DiscoveryScheduler
{
    private const int WriteDacl = 0x40000;
    private const int WriteOwner = 0x80000;
    private const int GenericAll = 0x10000000;
    private const string Everyone = "S-1-1-0";
    private const string AuthenticatedUsers = "S-1-5-11";

    private readonly Tier0InputBinding _input;
    private readonly bool _captureComplete;
    private readonly Func<string, ObjectAttributes?> _attributes;
    private readonly Func<ObjectAttributes, Tier0Target> _target;
    private readonly CancellationToken _cancellationToken;
    private readonly Dictionary<CandidateKey, PendingCandidate> _candidates = [];
    private readonly HashSet<Tier0DiscoveryLimitation> _limitations = [];
    private readonly Dictionary<string, Tier0Target> _observed = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string Sid, string? Scope), Tier0Target?> _bySid = [];
    private readonly List<(CandidateKey Key, Tier0RelevanceRelation Relation)> _resolved = [];
    private long _objects;
    private long _permissions;
    private long _owners;
    private bool _completed;

    private readonly record struct CandidateKey(string Target, string Holder, ControlCapability Capability, int Ordinal);

    /// <summary>
    /// A collected fact whose holder is resolved after the stream rather than during it.
    /// </summary>
    /// <remarks>
    /// A descriptor names its owner and its trustees by SID. The object that SID belongs to may be
    /// streamed long after the object it controls, so resolving during the stream would drop every
    /// route whose holder happens to sort later - which is a silent loss, not a reported one.
    /// </remarks>
    private readonly record struct PendingCandidate(string HolderSid, string? HolderScope, string? HolderDn,
        Tier0Target Affected, ControlCapability Capability, Tier0CaptureWitness Witness);

    internal Tier0DiscoveryScheduler(Tier0InputBinding input, bool captureComplete,
        Func<string, ObjectAttributes?> attributes, Func<ObjectAttributes, Tier0Target> target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(attributes);
        ArgumentNullException.ThrowIfNull(target);
        if (!input.IsSupported) throw new ArgumentException(null, nameof(input));
        _input = input;
        _captureComplete = captureComplete;
        _attributes = attributes;
        _target = target;
        _cancellationToken = cancellationToken;
        if (!captureComplete) Limit(Tier0DiscoveryReason.CaptureIncomplete, null);
    }

    /// <summary>Every streamed object, so an admitted target need not be re-derived from a control store.</summary>
    internal IReadOnlyDictionary<string, Tier0Target> Observed => _observed;

    /// <summary>
    /// Reads one streamed object's captured owner and entries, collecting candidates without evaluating them.
    /// </summary>
    internal void Observe(ObjectAttributes subject, ObjectPermissions? permissions)
    {
        ArgumentNullException.ThrowIfNull(subject);
        _cancellationToken.ThrowIfCancellationRequested();

        // Observing after resolution would produce a candidate list that silently omits it.
        if (_completed) throw new InvalidOperationException("Discovery has already resolved its candidates.");

        // Recorded before any descriptor check, so a target that discovery could not inspect is
        // still known to have been captured. "Captured but unassessed" and "absent from the
        // capture" are different answers and a reader must be able to tell them apart.
        var target = _target(subject);
        _observed[subject.DistinguishedName] = target;
        if (target.IsValid && target.Sid is { } observedSid)
        {
            // Ambiguity is recorded rather than resolved to whichever object arrived first. A BUILTIN
            // SID repeats across domains by design, which is why the scope is part of the key.
            var key = (observedSid.ToUpperInvariant(), target.SidScope?.ToUpperInvariant());
            _bySid[key] = _bySid.TryGetValue(key, out var previous) && previous != target ? null : target;
        }

        _objects++;
        if (!target.IsValid)
        {
            Limit(Tier0DiscoveryReason.MissingIdentity, subject.DistinguishedName);
            return;
        }
        if (permissions is null || permissions.Availability != DescriptorAvailability.Read
            || permissions.DaclState == DaclState.Unreadable)
        {
            Limit(Tier0DiscoveryReason.DescriptorUnavailable, subject.DistinguishedName);
            return;
        }

        Owner(subject, target, permissions);

        if (permissions.DaclState == DaclState.Null)
        {
            // Everyone, once, with its witness. Not expanded into individual accounts and not omitted.
            Limit(Tier0DiscoveryReason.NullDacl, subject.DistinguishedName);
            Broad(target, Everyone, null);
            return;
        }
        if (permissions.DaclCompleteness != DaclCompleteness.Complete)
            Limit(Tier0DiscoveryReason.DescriptorIncomplete, subject.DistinguishedName);

        foreach (var entry in permissions.Entries)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            _permissions++;
            Entry(subject, target, entry);
        }
    }

    /// <summary>
    /// Resolves collected facts to captured principals, once the whole stream has been observed.
    /// </summary>
    /// <remarks>
    /// <b>Both <see cref="Candidates"/> and <see cref="Coverage"/> require this first.</b> Resolution
    /// cannot happen during the stream, because a holder may be captured after the object it
    /// controls, and it produces limitations of its own - an owner SID belonging to no captured
    /// object is an unresolved trustee. Were coverage readable beforehand it would report fewer
    /// limitations than the same scan reports afterwards, which is a completeness claim that depends
    /// on the order the caller happened to ask in.
    /// </remarks>
    internal void Complete()
    {
        if (_completed) return;
        _completed = true;
        foreach (var (key, pending) in _candidates)
        {
            _cancellationToken.ThrowIfCancellationRequested();
            var controller = Resolve(pending.HolderSid, pending.HolderScope, pending.HolderDn);
            if (controller is null)
            {
                Limit(Tier0DiscoveryReason.UnresolvedTrustee, pending.Affected.DistinguishedName,
                    pending.Witness.PermissionOrdinal, pending.HolderSid);
                continue;
            }

            // An object controlling itself is not a route to anywhere.
            if (controller == pending.Affected) continue;
            _resolved.Add((key, Tier0RelevanceRelation.FromCapturedPermission(_input, controller,
                pending.Affected, pending.Capability, pending.Witness)));
        }
    }

    /// <summary>The discovered candidates, ordered so a run is reproducible.</summary>
    internal IReadOnlyList<Tier0RelevanceRelation> Candidates()
    {
        Complete();
        return _resolved
            .OrderBy(item => item.Key.Target, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Key.Holder, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Key.Capability)
            .ThenBy(item => item.Key.Ordinal)
            .Select(item => item.Relation).ToArray();
    }

    /// <summary>What this scan inspected and what stopped it being complete.</summary>
    internal Tier0DiscoveryCoverage Coverage()
    {
        Complete();
        return new(Tier0DiscoveryCoverage.CurrentVersion,
            _captureComplete, _objects, _permissions, _owners,
            _resolved.Count, _limitations
                .OrderBy(item => item.Reason)
                .ThenBy(item => item.TargetDn, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.PermissionOrdinal)
                .ThenBy(item => item.TrusteeSid, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private void Owner(ObjectAttributes subject, Tier0Target target, ObjectPermissions permissions)
    {
        if (permissions.Owner is not { } owner) return;
        _owners++;

        // An owner can rewrite the DACL below it, so the owner is a possible controller. Whether the
        // owner could be *changed* by someone else is a separate and later question - the ownership
        // evaluator's - and nothing here presumes its answer.
        if (owner.Sid is Everyone or AuthenticatedUsers)
        {
            Broad(target, owner.Sid, null);
            return;
        }
        Add(owner, subject, target, ControlCapability.IsOwnerAndCanRewriteDacl,
            new(target.DistinguishedName, null, owner.Sid, IsOwner: true));
    }
    private void Entry(ObjectAttributes subject, Tier0Target target, PermissionEntry entry)
    {
        // Deny entries are not controller candidates. They remove access rather than granting it,
        // and the evaluators own how deny interacts with order. Recording one as a possible
        // controller would admit a target on the strength of a permission that grants nothing.
        if (!string.Equals(entry.AceType, "AccessAllowed", StringComparison.Ordinal)
            && !string.Equals(entry.AceType, "AccessAllowedObject", StringComparison.Ordinal))
        {
            if (entry.AceType.Contains("Denied", StringComparison.Ordinal)) return;
            Limit(Tier0DiscoveryReason.UnsupportedRoute, subject.DistinguishedName, entry.Ordinal, entry.Trustee.Sid);
            return;
        }

        // INHERIT_ONLY entries govern descendants and grant nothing on this object.
        if (EntryReachReader.FromPropagationFlags(entry.PropagationFlags) == EntryReach.DescendantsOnly) return;

        var capability = Capability(entry.AccessMask);
        if (capability is null) return;

        if (!entry.Trustee.HoldsThePermission)
        {
            // CREATOR OWNER and OWNER RIGHTS are placeholders rather than principals.
            Limit(Tier0DiscoveryReason.UnsupportedRoute, subject.DistinguishedName, entry.Ordinal, entry.Trustee.Sid);
            return;
        }
        if (entry.Trustee.Sid is Everyone or AuthenticatedUsers)
        {
            Broad(target, entry.Trustee.Sid, entry.Ordinal);
            return;
        }

        Add(entry.Trustee, subject, target, capability.Value,
            new(target.DistinguishedName, entry.Ordinal, entry.Trustee.Sid));
    }

    /// <summary>The named primitive, or null when the mask grants nothing that could control the object.</summary>
    private static ControlCapability? Capability(int accessMask)
    {
        if ((accessMask & GenericAll) != 0 || (accessMask & WriteDacl) != 0) return ControlCapability.CanWriteDacl;
        return (accessMask & WriteOwner) != 0 ? ControlCapability.CanSetOwner : null;
    }

    /// <summary>
    /// Finds the captured object a collected fact names, after the whole stream has been observed.
    /// </summary>
    /// <remarks>
    /// SID first, because that is what a descriptor actually stores and what an owner offers at all.
    /// The distinguished name is a fallback for a trustee the capture resolved but whose SID is not
    /// indexed. Returning null is a reportable gap, never a quietly dropped route.
    /// </remarks>
    private Tier0Target? Resolve(string sid, string? scope, string? distinguishedName)
    {
        if (_bySid.TryGetValue((sid.ToUpperInvariant(), scope?.ToUpperInvariant()), out var bySid))
            return bySid;

        // A non-BUILTIN SID is unique forest-wide, so an unscoped match is safe for one.
        if (scope is null && !Sid.IsBuiltinDomain(sid))
        {
            var matches = _bySid.Where(item => string.Equals(item.Key.Sid, sid, StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Value).Distinct().ToArray();
            if (matches.Length == 1) return matches[0];
            if (matches.Length > 1) return null;
        }
        if (distinguishedName is null) return null;
        if (_observed.TryGetValue(distinguishedName, out var observed)) return observed;
        var holder = _attributes(distinguishedName);
        if (holder is null) return null;
        var target = _target(holder);
        return target.IsValid ? target : null;
    }

    /// <summary>
    /// Records a broad principal as one unresolved candidate against the object it was named on.
    /// </summary>
    /// <remarks>
    /// No <see cref="Tier0Target"/> can be built for Everyone, because it resolves to no captured
    /// object. The limitation carries the witness instead, so the route survives as an explicit
    /// incompleteness rather than becoming either an invented principal or silence.
    /// </remarks>
    private void Broad(Tier0Target target, string sid, int? ordinal) =>
        Limit(Tier0DiscoveryReason.BroadTrustee, target.DistinguishedName, ordinal, sid);

    private void Add(PermissionTrustee trustee, ObjectAttributes subject, Tier0Target affected,
        ControlCapability capability, Tier0CaptureWitness witness)
    {
        // SELF names the object itself, and resolving it anywhere else would attribute a permission
        // to the wrong principal. An object controlling itself is not a route to anywhere.
        if (trustee.Sid == "S-1-5-10") return;

        var key = new CandidateKey(affected.DistinguishedName.ToUpperInvariant(),
            trustee.Sid.ToUpperInvariant(), capability, witness.PermissionOrdinal ?? -1);
        if (_candidates.ContainsKey(key)) return;
        _candidates.Add(key, new(trustee.Sid, trustee.DomainFqdn is { } domain && Sid.IsBuiltinDomain(trustee.Sid)
            ? domain : null, trustee.DistinguishedName, affected, capability, witness));
    }

    private void Limit(Tier0DiscoveryReason reason, string? target) => Limit(reason, target, null, null);

    private void Limit(Tier0DiscoveryReason reason, string? target, int? ordinal, string? trustee) =>
        _limitations.Add(new(reason, target, ordinal, trustee));
}

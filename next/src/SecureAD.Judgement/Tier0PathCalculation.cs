using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal sealed record Tier0PathNode(Tier0Target Subject, int? MembershipDistance,
    Tier0PathStep? MembershipNext, Tier0PathStep? Terminal, string? PermissionFingerprint)
{
    public RequesterDaclRequest? RequesterRoute { get; init; }
    public OwnAccountMembershipRequest? OwnAccountRoute { get; init; }
    public MembershipDaclRequest? MembershipDaclRoute { get; init; }

    internal Tier0Reachability Reachability => MembershipDistance is not null || Terminal is not null || RequesterRoute is not null || OwnAccountRoute is not null || MembershipDaclRoute is not null
        ? Tier0Reachability.Reachable : Tier0Reachability.Unknown;
}

internal static class Tier0PathCalculation
{
    internal const int Version = 6;

    internal static IReadOnlyList<Tier0PathNode> Calculate(PathInputs inputs, IReadOnlyList<Tier0Target> targets,
        IEnumerable<ControlEdge> permissions, Func<string, ObjectAttributes?> attributes,
        IReadOnlyDictionary<string, NamingContextKind> contexts, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var nodes = targets.ToDictionary(target => target.DistinguishedName,
            target => new Tier0PathNode(target, null, null, null, null), StringComparer.OrdinalIgnoreCase);
        var incoming = MembershipSteps(inputs, cancellationToken).GroupBy(step => step.To.DistinguishedName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.OrderBy(StepKey, StringComparer.Ordinal).ToArray(), StringComparer.OrdinalIgnoreCase);
        var pending = new Queue<string>();
        foreach (var anchor in inputs.FixedTargets.OrderBy(target => target.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            nodes[anchor.DistinguishedName] = nodes[anchor.DistinguishedName] with { MembershipDistance = 0 };
            pending.Enqueue(anchor.DistinguishedName);
        }
        while (pending.TryDequeue(out var name))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var distance = nodes[name].MembershipDistance ?? throw Tier0PathStorage.InvalidProof();
            foreach (var step in incoming.GetValueOrDefault(name) ?? [])
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!nodes.TryGetValue(step.From.DistinguishedName, out var previous)
                    || previous.Subject != step.From || nodes[name].Subject != step.To) throw Tier0PathStorage.InvalidProof();
                if (previous.MembershipDistance is not null) continue;
                nodes[step.From.DistinguishedName] = previous with { MembershipDistance = checked(distance + 1), MembershipNext = step };
                pending.Enqueue(step.From.DistinguishedName);
            }
        }

        // Terminal authority is deliberately added AFTER the membership sweep. Feeding these nodes
        // back into the queue would turn membership attribution into an unperformed access check.
        var holders = targets.Where(target => target.Sid is not null)
            .GroupBy(target => HolderKey(target.Sid!, target.SidScope), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() == 1).ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);
        var anchors = inputs.FixedTargets.ToDictionary(target => target.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        foreach (var edge in permissions.OrderBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.Capability).ThenBy(edge => edge.Id))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var step = TerminalStep(edge, inputs, anchors, holders, attributes, contexts);
            if (step is null) continue;
            var previous = nodes[step.From.DistinguishedName];
            if (previous.Terminal is not null) continue;
            nodes[step.From.DistinguishedName] = previous with { Terminal = step, PermissionFingerprint = Fingerprint(edge) };
        }
        return nodes.Values.OrderBy(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    internal static IEnumerable<Tier0PathStep> MembershipSteps(PathInputs inputs, CancellationToken cancellationToken)
    {
        foreach (var classification in inputs.Classifications)
        {
            for (var index = 0; index < classification.Supports.Length; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var support = classification.Supports[index];
                if (support.Basis != Tier0Basis.EffectiveMembership) continue;
                var identities = support.Evidence.Select(witness => witness.Object).Append(classification.Target).Append(support.Root)
                    .Distinct().ToDictionary(target => target.DistinguishedName, StringComparer.OrdinalIgnoreCase);
                foreach (var witness in support.Evidence)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Tier0Target? from = null;
                    Tier0Target? to = null;
                    if (witness.Attribute == "member")
                    {
                        from = identities.GetValueOrDefault(witness.Value);
                        to = witness.Object;
                    }
                    else if (witness.Attribute == "memberOf")
                    {
                        from = witness.Object;
                        to = identities.GetValueOrDefault(witness.Value);
                    }
                    else if (witness.Attribute == "primaryGroupID")
                    {
                        from = witness.Object;
                        if (!uint.TryParse(witness.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var rid)
                            || from.Sid is null) throw Tier0PathStorage.InvalidProof();
                        var sid = Sid.IssuingDomain(from.Sid) + "-" + rid.ToString(CultureInfo.InvariantCulture);
                        to = identities.Values.SingleOrDefault(target => target.Sid == sid && target.DomainFqdn == from.DomainFqdn);
                    }
                    else continue;
                    if (from is null || to is null) throw Tier0PathStorage.InvalidProof();
                    yield return new(from, to, Tier0PathStepKind.Membership, classification.Target.DistinguishedName, index, witness, null);
                }
            }
        }
    }

    internal static Tier0PathStep? TerminalStep(ControlEdge edge, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0Target> anchors, IReadOnlyDictionary<string, Tier0Target> holders,
        Func<string, ObjectAttributes?> attributes, IReadOnlyDictionary<string, NamingContextKind> contexts)
    {
        if (edge.Capability is not (ControlCapability.CanWriteDacl or ControlCapability.IsOwnerAndCanRewriteDacl)
            || edge.EvaluationState != ControlEvaluationState.Established || edge.Uncertainty != ControlUncertainty.None
            || edge.GenerationId != inputs.JudgementGenerationId || edge.DerivationGenerationId != inputs.Input?.DerivationGenerationId
            || !anchors.TryGetValue(edge.Target, out var target) || target.ObjectGuid != edge.TargetGuid
            || !holders.TryGetValue(HolderKey(edge.HolderSid, edge.HolderScope), out var holder) || !holder.IsValid)
            return null;
        var subject = attributes(holder.DistinguishedName);
        if (subject is null || Tier0Target.From(subject, holder.NamingContext) != holder
            || RequesterTrusteeReading.HasClass(subject, "foreignSecurityPrincipal")
            || string.Equals(subject.Find("isDeleted")?.OnlyValue?.Text, "TRUE", StringComparison.OrdinalIgnoreCase)) return null;
        if (RequesterTrusteeReading.HasClass(subject, "group"))
        {
            var groupType = RequesterTrusteeReading.Number(subject, "groupType");
            if (groupType is null || (groupType.Value & 0x80000000L) == 0) return null;
            var scope = groupType.Value & 0x0f;
            if (scope is not (2 or 4 or 8)) return null;
            if (scope == 4 && (!contexts.TryGetValue(target.NamingContext, out var context) || context != NamingContextKind.Domain
                || !string.Equals(holder.DomainFqdn, target.DomainFqdn, StringComparison.OrdinalIgnoreCase))) return null;
        }
        else if (!RequesterTrusteeReading.HasClass(subject, "user") && !RequesterTrusteeReading.HasClass(subject, "computer")
            && !RequesterTrusteeReading.HasClass(subject, "inetOrgPerson")) return null;
        return new(holder, target, edge.Capability == ControlCapability.CanWriteDacl
            ? Tier0PathStepKind.WriteDacl : Tier0PathStepKind.CurrentOwnerDacl, null, null, null, edge.Id);
    }

    internal static string HolderKey(string sid, string? scope) => sid + "\0" + (scope ?? string.Empty);
    internal static string Fingerprint<T>(T value)
    {
        // The stream overload can still buffer a whole scalar collection. Consume committed
        // UTF-8 segments directly; only an individual value can require a larger buffer.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        using var buffer = new FingerprintBuffer(hash);
        var options = ProofSerialization.Options;
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Encoder = options.Encoder,
            Indented = options.WriteIndented,
            IndentCharacter = options.IndentCharacter,
            IndentSize = options.IndentSize,
            NewLine = options.NewLine,
            MaxDepth = options.MaxDepth == 0 ? 64 : options.MaxDepth,
        }))
        {
            JsonSerializer.Serialize(writer, value, options);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private sealed class FingerprintBuffer(IncrementalHash hash) : IBufferWriter<byte>, IDisposable
    {
        private byte[] _buffer = [];

        public void Advance(int count) => hash.AppendData(_buffer.AsSpan(0, count));

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
            var minimum = Math.Max(sizeHint, 1);
            if (_buffer.Length < minimum)
            {
                var replacement = ArrayPool<byte>.Shared.Rent(minimum);
                if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = replacement;
            }
            return _buffer;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        public void Dispose()
        {
            if (_buffer.Length != 0) ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = [];
        }
    }

    private static string StepKey(Tier0PathStep step) => step.From.DistinguishedName.ToUpperInvariant() + "\0"
        + step.To.DistinguishedName.ToUpperInvariant() + "\0" + JsonSerializer.Serialize(step, ProofSerialization.Options);
}

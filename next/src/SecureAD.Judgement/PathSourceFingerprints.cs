using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal enum PathSourceFamily
{
    OwnAccountMembership,
    RequesterDacl,
}

internal sealed class PathSourceFingerprints
{
    private const int Version = 1;
    private static readonly Meter Meter = new("SecureAD.Judgement.PathSources");
    private static readonly Counter<long> Fingerprints = Meter.CreateCounter<long>("path_source.fingerprints");
    private readonly PathSourceFamily _family;
    private readonly JudgementDescription _description;
    private readonly CancellationToken _cancellationToken;
    private readonly string _shared;
    private sealed record ObtainedFingerprint(string Value);
    private readonly ConditionalWeakTable<OwnAccountMembershipAssessment, ObtainedFingerprint> _obtained = new();

    internal PathSourceFingerprints(PathSourceFamily family, JudgementDescription description,
        PathInputs inputs, object shared, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(shared);
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(family) || inputs.JudgementGenerationId != description.GenerationId
            || inputs.Input is { } binding && (binding.EvidenceSeal != description.EvidenceSeal
                || binding.DerivationGenerationId != description.DerivationGenerationId))
            throw Tier0PathStorage.InvalidProof();
        _family = family;
        _description = description;
        _cancellationToken = cancellationToken;
        _shared = Hash(new
        {
            Version, Family = family, Generation = description.GenerationId, Derivation = description.DerivationGenerationId,
            Evidence = description.EvidenceSeal, Inputs = inputs.Input, inputs.Availability, Shared = shared,
        }, "shared");
    }

    internal Target PrepareTarget(ObjectAttributes? target, ObjectPermissions? permissions, IReadOnlyList<ObjectAttributes?> holders)
    {
        _cancellationToken.ThrowIfCancellationRequested();
        var fingerprint = Hash(new { Target = target, Permissions = permissions, Holders = holders }, "target");
        return new(this, fingerprint);
    }

    private string? Obtained(OwnAccountMembershipAssessment? membership)
    {
        if (membership is null) return null;
        if (_obtained.TryGetValue(membership, out var fingerprint)) return fingerprint.Value;
        fingerprint = new(Hash(membership, "obtained-membership"));
        _obtained.Add(membership, fingerprint);
        return fingerprint.Value;
    }

    private string Hash<T>(T value, string component)
    {
        _cancellationToken.ThrowIfCancellationRequested();
        var result = Tier0PathCalculation.Fingerprint(value);
        _cancellationToken.ThrowIfCancellationRequested();
        if (Fingerprints.Enabled)
            Fingerprints.Add(1, new("generation", _description.GenerationId), new("family", _family), new("component", component));
        return result;
    }

    internal sealed class Target(PathSourceFingerprints owner, string fingerprint)
    {
        private ObjectAttributes? _requester;
        private string? _requesterFingerprint;

        internal string OwnAccount(ObjectAttributes? requester)
        {
            RequireFamily(PathSourceFamily.OwnAccountMembership);
            return Finish(new { Version, Shared = owner._shared, Target = fingerprint, Requester = Requester(requester) });
        }

        internal string RequesterDacl(ObjectAttributes? requester, OwnAccountMembershipAssessment? obtained,
            RequesterDaclAssessment assessment) => RequesterDacl(requester, obtained, assessment, null);

        internal string RequesterDacl(ObjectAttributes? requester, OwnAccountMembershipAssessment? obtained,
            RequesterDaclAssessment assessment, string? obtainedFingerprint)
        {
            RequireFamily(PathSourceFamily.RequesterDacl);
            if (assessment.GenerationId != owner._description.GenerationId
                || assessment.DerivationGenerationId != owner._description.DerivationGenerationId
                || assessment.EvidenceSeal != owner._description.EvidenceSeal
                || obtainedFingerprint is not null && (obtained is null || obtainedFingerprint.Length != 64))
                throw Tier0PathStorage.InvalidProof();
            return Finish(new
            {
                Version, Shared = owner._shared, Target = fingerprint, Requester = Requester(requester),
                ObtainedMembership = obtainedFingerprint ?? owner.Obtained(obtained),
                Membership = assessment.Evidence.Select(value => value.Membership).ToArray(),
                ObtainedGroupMembership = assessment.Evidence.Select(value => value.ObtainedGroupMembership).ToArray(),
                ResourceContext = assessment.ResourceContext,
            });
        }

        private void RequireFamily(PathSourceFamily family)
        {
            owner._cancellationToken.ThrowIfCancellationRequested();
            if (owner._family != family) throw Tier0PathStorage.InvalidProof();
        }

        private string Requester(ObjectAttributes? requester)
        {
            if (_requesterFingerprint is null || !ReferenceEquals(requester, _requester))
            {
                var value = owner.Hash(requester, "requester");
                _requester = requester;
                _requesterFingerprint = value;
            }
            return _requesterFingerprint;
        }

        private string Finish<T>(T value)
        {
            return owner.Hash(value, "question");
        }
    }
}

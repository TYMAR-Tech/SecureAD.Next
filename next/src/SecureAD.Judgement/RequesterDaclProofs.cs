using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed record SavedRequesterDaclProof(RequesterDaclAssessment Assessment, string SourceFingerprint);

internal static class RequesterDaclProofs
{
    internal sealed record Question(RequesterDaclRequest Request, OwnAccountMembershipAssessment? ObtainedMembership);

    internal sealed class OriginalPermissions(Func<ControlEdge, IReadOnlyList<PermissionEntry>> read,
        CancellationToken cancellationToken)
    {
        private readonly Dictionary<ControlEdge, HashSet<string>> _originals = new(ReferenceEqualityComparer.Instance);
        private readonly Dictionary<PermissionEntry, string> _fingerprints = new(ReferenceEqualityComparer.Instance);

        internal bool Matches(ControlEdge edge, PermissionEntry grant)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_originals.TryGetValue(edge, out var fingerprints))
            {
                fingerprints = new(StringComparer.Ordinal);
                foreach (var entry in read(edge))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fingerprints.Add(Fingerprint(entry));
                }
                _originals.Add(edge, fingerprints);
            }
            return fingerprints.Contains(Fingerprint(grant));
        }

        private string Fingerprint(PermissionEntry entry)
        {
            if (!_fingerprints.TryGetValue(entry, out var fingerprint))
                _fingerprints.Add(entry, fingerprint = Tier0PathCalculation.Fingerprint(entry));
            return fingerprint;
        }
    }

    internal sealed class Preparation
    {
        private readonly SqliteConnection _connection;
        private readonly JudgementDescription _description;
        private readonly JudgingInputs _sources;
        private readonly IReadOnlyDictionary<string, Tier0Target> _identities;
        private readonly PathInputs _inputs;
        private readonly CancellationToken _token;
        private readonly RequesterMembershipContext? _memberships;
        private readonly IReadOnlyDictionary<string, NamingContextKind> _contexts;
        private readonly PathSourceFingerprints _fingerprints;

        internal Preparation(SqliteConnection connection, JudgementDescription description, JudgingInputs sources,
            IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs, CancellationToken token,
            RequesterMembershipContext? memberships)
        {
            sources.RequireFor(description);
            var contexts = sources.ReadNamingContexts();
            if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
            (_connection, _description, _sources, _identities, _inputs, _token, _memberships, _contexts) =
                (connection, description, sources, identities, inputs, token, memberships, contexts.Value);
            _fingerprints = new(PathSourceFamily.RequesterDacl, description, inputs,
                new { Forest = sources.Bundle.Description.ForestFqdn,
                    Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray() }, token);
        }

        internal Target PrepareTarget(string targetDn)
        {
            _token.ThrowIfCancellationRequested();
            _sources.RequireFor(_description);
            var bundle = _sources.Bundle;
            var permissions = bundle.ReadPermissions(targetDn);
            var target = bundle.ReadObjectAttributes(targetDn);
            using var query = _connection.CreateCommand();
            query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanWriteDacl' ORDER BY id";
            query.Parameters.AddWithValue("$target", targetDn);
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                _token.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            var edges = ids.Select(id => ControlEdgeStorage.ReadEdge(_connection, _description, id)).ToArray();
            var holders = new Dictionary<string, ObjectAttributes?>(StringComparer.Ordinal);
            foreach (var dn in (permissions?.Entries ?? []).Select(entry => entry.Trustee.DistinguishedName)
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            {
                _token.ThrowIfCancellationRequested();
                holders.Add(dn, dn == targetDn ? target : bundle.ReadObjectAttributes(dn));
            }
            return new(this, targetDn, target, permissions, edges, holders,
                _fingerprints.PrepareTarget(target, permissions, holders.Values.ToArray()),
                new(edge => ControlEdgeStorage.ReadExactAces(_connection, edge), _token));
        }

        internal sealed class Target(Preparation owner, string targetDn, ObjectAttributes? target,
            ObjectPermissions? permissions, IReadOnlyList<ControlEdge> edges,
            IReadOnlyDictionary<string, ObjectAttributes?> holders, PathSourceFingerprints.Target fingerprint,
            OriginalPermissions originals)
        {
            private string? _previousRequester;
            private ObjectAttributes? _requester;

            internal SavedRequesterDaclProof Assess(Question question, string? obtainedFingerprint)
            {
                owner._token.ThrowIfCancellationRequested();
                owner._sources.RequireProtectedBinding(owner._description);
                var request = question.Request;
                if (request.TargetDn != targetDn) throw Tier0PathStorage.InvalidProof();
                if (_previousRequester != request.RequesterDn)
                {
                    _requester = request.RequesterDn == targetDn ? target
                        : holders.TryGetValue(request.RequesterDn, out var holder) ? holder
                        : owner._sources.Bundle.ReadObjectAttributes(request.RequesterDn);
                    _previousRequester = request.RequesterDn;
                }
                var assessment = RequesterDaclEvaluator.Assess(request, owner._inputs, owner._description, owner._identities,
                    Attributes, permissions, owner._contexts, edges, owner._sources.Bundle.Description.ForestFqdn, owner._token,
                    question.ObtainedMembership, owner._memberships, originals.Matches);
                var source = fingerprint.RequesterDacl(_requester, question.ObtainedMembership, assessment, obtainedFingerprint);
                return new(assessment, source);

                ObjectAttributes? Attributes(string dn) => dn == request.RequesterDn ? _requester : dn == targetDn ? target
                    : holders.TryGetValue(dn, out var holder) ? holder : owner._sources.Bundle.ReadObjectAttributes(dn);
            }
        }
    }

    internal static void RequireMembershipEvidence(RequesterDaclAssessment assessment, CancellationToken cancellationToken) =>
        RequireMembershipEvidence(assessment, null, cancellationToken);

    internal static void RequireMembershipEvidence(RequesterDaclAssessment assessment,
        OwnAccountMembershipAssessment? obtained, CancellationToken cancellationToken)
    {
        if (assessment.Evidence is null || assessment.Steps is null) throw Tier0PathStorage.InvalidProof();
        var resource = assessment.ResourceContext;
        if (resource is not null && (!resource.IsComplete
            || assessment.Target is not { } targetIdentity || resource.ResourceDomain.NamingContext != targetIdentity.NamingContext
            || resource.ResourceDomain.DomainFqdn != targetIdentity.DomainFqdn
            || assessment.Authorization == ControlEvaluationState.Established
                && (assessment.Requester?.DomainFqdn is not { } domain
                    || !resource.ReadDomains.Contains(domain, StringComparer.OrdinalIgnoreCase)))) throw Tier0PathStorage.InvalidProof();
        if (obtained is not null && (assessment.ObtainedMembership != obtained.Request
            || obtained.Obtainability != ControlEvaluationState.Established || obtained.Requester != assessment.Requester
            || obtained.GenerationId != assessment.GenerationId || obtained.DerivationGenerationId != assessment.DerivationGenerationId
            || obtained.EvidenceSeal != assessment.EvidenceSeal
            || obtained.Target is not { } obtainedTarget || assessment.Requester is not { } obtainedRequester
            || !string.Equals(obtainedTarget.NamingContext, obtainedRequester.NamingContext, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(obtainedTarget.DomainFqdn, obtainedRequester.DomainFqdn, StringComparison.OrdinalIgnoreCase)))
            throw Tier0PathStorage.InvalidProof();
        foreach (var entry in assessment.Evidence)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry is null || entry.Trustee is null || entry.Entry is null) throw Tier0PathStorage.InvalidProof();
            var groupNesting = entry.ObtainedGroupMembership is not null;
            var membership = entry.ObtainedGroupMembership ?? entry.Membership;
            if (membership is null)
            {
                if (entry.Trustee.Reason is RequesterTrusteeReason.NestedGlobalMembership or RequesterTrusteeReason.NestedSecurityMembership)
                    throw Tier0PathStorage.InvalidProof();
                continue;
            }
            if (entry.ObtainedGroupMembership is not null && entry.Membership is not null
                || groupNesting && obtained?.Target is null || !Enum.IsDefined(membership.Verdict)
                || membership.SourceFingerprint is not { Length: 64 } || membership.Links is null
                || membership.Limitations is null || membership.Limitations.Any(value => !Enum.IsDefined(value)))
                throw Tier0PathStorage.InvalidProof();
            if (membership.Links.Count == 0)
            {
                if (entry.Trustee.State == RequesterTrusteeState.Matches) throw Tier0PathStorage.InvalidProof();
                continue;
            }
            var expectedReason = groupNesting && obtained!.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd
                ? RequesterTrusteeReason.ObtainedGlobalMembership : resource is not null && membership.Links.Any(link => link is null || (link.GroupType & 0x0f) != 2)
                    ? RequesterTrusteeReason.NestedSecurityMembership : RequesterTrusteeReason.NestedGlobalMembership;
            if (membership.Links.Count < (groupNesting ? 1 : 2) || entry.Trustee.Reason != expectedReason
                || entry.Trustee.State != RequesterTrusteeState.Matches || assessment.Requester is not { } requester
                || assessment.Target is not { } target) throw Tier0PathStorage.InvalidProof();
            var current = groupNesting ? obtained!.Target! : requester;
            if (groupNesting && obtained!.Basis == OwnAccountMembershipBasis.ExistingMembership
                && !obtained.MembershipEvidence.Any(value => value.Attribute == "member" && value.Object == current
                    && string.Equals(value.Value, requester.DistinguishedName, StringComparison.OrdinalIgnoreCase)))
                throw Tier0PathStorage.InvalidProof();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current.DistinguishedName };
            long? memberType = groupNesting ? -2147483646L : null;
            foreach (var link in membership.Links)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (link is null || link.Group is null || link.Witness is null
                    || link.Member != current || !link.Group.IsValid || link.Group.ObjectGuid is null || link.Group.Sid is null
                    || (resource is null && (!string.Equals(link.Group.NamingContext, target.NamingContext, StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(link.Group.DomainFqdn, requester.DomainFqdn, StringComparison.OrdinalIgnoreCase)
                        || (link.GroupType & 0x8000000fL) != 0x80000002L))
                    || link.SourceFingerprint is not { Length: 64 }
                    || link.Witness.Object != link.Group || link.Witness.Attribute != "member" || link.Witness.Ordinal < 0
                    || !string.Equals(link.Witness.Value, current.DistinguishedName, StringComparison.OrdinalIgnoreCase)
                    || !seen.Add(link.Group.DistinguishedName)) throw Tier0PathStorage.InvalidProof();
                if (resource is not null && (link.Group.DomainFqdn is not { } groupDomain
                    || !resource.ReadDomains.Contains(groupDomain, StringComparer.OrdinalIgnoreCase)
                    || !RequesterTrusteeReading.SupportsSecurityNesting(link.GroupType, memberType,
                        string.Equals(current.DomainFqdn, groupDomain, StringComparison.OrdinalIgnoreCase),
                        SecureAD.Kernel.Security.Sid.IsBuiltinDomain(link.Group.Sid))
                    || (link.GroupType & 0x0f) is 4 or 5
                        && !string.Equals(groupDomain, target.DomainFqdn, StringComparison.OrdinalIgnoreCase)))
                    throw Tier0PathStorage.InvalidProof();
                memberType = link.GroupType;
                current = link.Group;
            }
            if (current.ObjectGuid != entry.Trustee.HolderGuid || current.DistinguishedName != entry.Trustee.HolderDn
                || current.DomainFqdn != entry.Trustee.HolderDomain
                || !string.Equals(current.Sid, entry.Entry.Trustee.Sid == "S-1-5-10" ? target.Sid : entry.Entry.Trustee.Sid,
                    StringComparison.OrdinalIgnoreCase)) throw Tier0PathStorage.InvalidProof();
            if (assessment.Authorization != ControlEvaluationState.Established || entry != assessment.Evidence[^1]) continue;
            var steps = assessment.Steps;
            var offset = groupNesting ? 1 : 0;
            if (steps.Count != membership.Links.Count + 1 + offset
                || groupNesting && steps[0] != OwnAccountMembershipProofs.InitialStep(obtained!)) throw Tier0PathStorage.InvalidProof();
            for (var index = 0; index < membership.Links.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var link = membership.Links[index];
                var step = steps[index + offset];
                if (step.From != link.Member || step.To != link.Group || step.Kind != Tier0PathStepKind.Membership
                    || step.MembershipWitness != link.Witness || step.RequesterRequest != assessment.Request)
                    throw Tier0PathStorage.InvalidProof();
            }
            if (steps[^1].From != current || steps[^1].To != target || steps[^1].Kind != Tier0PathStepKind.WriteDacl)
                throw Tier0PathStorage.InvalidProof();
        }
    }

    internal static string Key(RequesterDaclRequest value) => value.RequesterDn.ToUpperInvariant() + "\0" + value.TargetDn.ToUpperInvariant();
}

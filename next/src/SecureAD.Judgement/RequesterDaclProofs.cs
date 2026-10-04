using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed record SavedRequesterDaclProof(RequesterDaclAssessment Assessment, string SourceFingerprint);

internal static class RequesterDaclProofs
{
    internal static IReadOnlyList<SavedRequesterDaclProof> Create(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
        IReadOnlyList<RequesterDaclRequest> requests, CancellationToken cancellationToken,
        OwnAccountMembershipAssessment? obtainedMembership, RequesterMembershipContext? memberships)
    {
        if (requests.Count == 0) return [];
        sources.RequireFor(description);
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
        var results = new List<SavedRequesterDaclProof>();
        foreach (var request in requests.OrderBy(Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = bundle.ReadPermissions(request.TargetDn);
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanWriteDacl' ORDER BY id";
            query.Parameters.AddWithValue("$target", request.TargetDn);
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            var edges = ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray();
            var assessment = RequesterDaclEvaluator.Assess(request, inputs, description, identities,
                bundle.ReadObjectAttributes, permissions, contexts.Value, edges, bundle.Description.ForestFqdn, cancellationToken,
                obtainedMembership, memberships);
            var holders = new List<ObjectAttributes?>();
            foreach (var dn in (permissions?.Entries ?? []).Select(entry => entry.Trustee.DistinguishedName)
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                holders.Add(bundle.ReadObjectAttributes(dn));
            }
            var source = Tier0PathCalculation.Fingerprint(new
            {
                Requester = bundle.ReadObjectAttributes(request.RequesterDn), Target = bundle.ReadObjectAttributes(request.TargetDn),
                Permissions = permissions, Holders = holders, Forest = bundle.Description.ForestFqdn,
                Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(),
                ObtainedMembership = obtainedMembership,
                Membership = assessment.Evidence.Select(value => value.Membership).ToArray(),
                ObtainedGroupMembership = assessment.Evidence.Select(value => value.ObtainedGroupMembership).ToArray(),
            });
            results.Add(new(assessment, source));
        }
        return results;
    }

    internal static void RequireMembershipEvidence(RequesterDaclAssessment assessment, CancellationToken cancellationToken) =>
        RequireMembershipEvidence(assessment, null, cancellationToken);

    internal static void RequireMembershipEvidence(RequesterDaclAssessment assessment,
        OwnAccountMembershipAssessment? obtained, CancellationToken cancellationToken)
    {
        if (assessment.Evidence is null || assessment.Steps is null) throw Tier0PathStorage.InvalidProof();
        if (obtained is not null && (assessment.ObtainedMembership != obtained.Request
            || obtained.Obtainability != ControlEvaluationState.Established || obtained.Requester != assessment.Requester
            || obtained.GenerationId != assessment.GenerationId || obtained.DerivationGenerationId != assessment.DerivationGenerationId
            || obtained.EvidenceSeal != assessment.EvidenceSeal)) throw Tier0PathStorage.InvalidProof();
        foreach (var entry in assessment.Evidence)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry is null || entry.Trustee is null || entry.Entry is null) throw Tier0PathStorage.InvalidProof();
            var groupNesting = entry.ObtainedGroupMembership is not null;
            var membership = entry.ObtainedGroupMembership ?? entry.Membership;
            if (membership is null)
            {
                if (entry.Trustee.Reason == RequesterTrusteeReason.NestedGlobalMembership) throw Tier0PathStorage.InvalidProof();
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
                ? RequesterTrusteeReason.ObtainedGlobalMembership : RequesterTrusteeReason.NestedGlobalMembership;
            if (membership.Links.Count < (groupNesting ? 1 : 2) || entry.Trustee.Reason != expectedReason
                || entry.Trustee.State != RequesterTrusteeState.Matches || assessment.Requester is not { } requester
                || assessment.Target is not { } target) throw Tier0PathStorage.InvalidProof();
            var current = groupNesting ? obtained!.Target! : requester;
            if (groupNesting && obtained!.Basis == OwnAccountMembershipBasis.ExistingMembership
                && !obtained.MembershipEvidence.Any(value => value.Attribute == "member" && value.Object == current
                    && string.Equals(value.Value, requester.DistinguishedName, StringComparison.OrdinalIgnoreCase)))
                throw Tier0PathStorage.InvalidProof();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { current.DistinguishedName };
            foreach (var link in membership.Links)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (link is null || link.Group is null || link.Witness is null
                    || link.Member != current || !link.Group.IsValid || link.Group.ObjectGuid is null || link.Group.Sid is null
                    || !string.Equals(link.Group.NamingContext, target.NamingContext, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(link.Group.DomainFqdn, requester.DomainFqdn, StringComparison.OrdinalIgnoreCase)
                    || (link.GroupType & 0x8000000fL) != 0x80000002L || link.SourceFingerprint is not { Length: 64 }
                    || link.Witness.Object != link.Group || link.Witness.Attribute != "member" || link.Witness.Ordinal < 0
                    || !string.Equals(link.Witness.Value, current.DistinguishedName, StringComparison.OrdinalIgnoreCase)
                    || !seen.Add(link.Group.DistinguishedName)) throw Tier0PathStorage.InvalidProof();
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

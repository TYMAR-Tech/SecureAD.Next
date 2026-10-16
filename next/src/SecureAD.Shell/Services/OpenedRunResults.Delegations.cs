using System.IO;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

internal sealed partial class OpenedRunResults
{
    internal Result<DelegationPage> ReadDelegations(DelegationQuery query, DelegationPageMark? after, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!query.IncludeGroupHeldPermissions)
            return ReadCapturedDelegations(reader => reader.ReadDelegations(query, after, token), token);
        var read = ReadMembership(reader => reader.ReadContainingGroups(query.Principal.Sid, query.Principal.DomainFqdn, token), token);
        if (!read.IsSuccess) return Result<DelegationPage>.Failure(AuditError.Create(ErrorCategory.Shell,
            "DelegationMembershipUnavailable", ErrorSeverity.Failed,
            DelegationText.Get("MembershipUnavailable") + "\n" + read.Error.Description, Directory));
        return ReadCapturedDelegations(evidence =>
        {
            var membership = read.Value;
            RequireCurrentMembership(membership);
            if (after is not null && (after.Query != query || after.EvidenceFingerprint != membership.EvidenceFingerprint ||
                after.MembershipGenerationId != membership.GenerationId))
                throw new InvalidDataException(DelegationText.Get("MembershipChanged"));
            var nodes = new List<DelegationMemberNode>();
            foreach (var node in membership.Nodes)
            {
                token.ThrowIfCancellationRequested();
                var principal = evidence.ResolveDelegationPrincipal(node.Sid, node.Scope, node.ObjectGuid);
                if (principal is null && (node.ObjectGuid is { } guid && guid != Guid.Empty || node.Scope.Length != 0))
                    throw new InvalidDataException(DelegationText.Get("MembershipIdentityMismatch"));
                nodes.Add(node with { Principal = principal ?? new(null, node.Sid, node.Sid, null, null) });
            }
            membership = membership with { Nodes = nodes };
            var root = nodes.Single(node => node.Id == membership.RootId).Principal!;
            if (root.Sid != query.Principal.Sid ||
                query.Principal.ObjectId is not null && root != query.Principal)
                throw new InvalidDataException(DelegationText.Get("MembershipIdentityMismatch"));
            var holders = new List<(int? Id, DelegationPrincipal Principal)> { (null, query.Principal) };
            holders.AddRange(nodes.Where(node => node.Id != membership.RootId && node.IsGroup is not false && node.IsSecurityEnabled is not false)
                .OrderBy(node => node.Id).Select(node => ((int?)node.Id, node.Principal!)));
            var start = after is null ? 0 : holders.FindIndex(holder => holder.Id == after.HolderMembershipId);
            if (start < 0) throw new InvalidDataException(DelegationText.Get("MembershipChanged"));
            var rows = new List<DelegationEntry>();
            DelegationCoverage? coverage = null;
            for (var index = start; index < holders.Count; index++)
            {
                token.ThrowIfCancellationRequested();
                var holder = holders[index];
                var question = query with { Principal = holder.Principal, IncludeGroupHeldPermissions = false };
                var from = index == start && after is not null
                    ? new DelegationPageMark(after.EvidenceFingerprint, question, after.DescriptorId, after.ObjectId, after.Ordinal)
                    : null;
                var page = evidence.ReadDelegations(question, from, token, DelegationPage.PageSize + 1 - rows.Count);
                coverage = page.Coverage;
                rows.AddRange(page.Entries.Select(entry => entry with { HolderMembershipId = holder.Id }));
                if (rows.Count <= DelegationPage.PageSize) continue;
                var last = rows[DelegationPage.PageSize - 1];
                var next = new DelegationPageMark(membership.EvidenceFingerprint, query, last.DescriptorId,
                    last.ObjectId, last.Entry.Ordinal)
                { MembershipGenerationId = membership.GenerationId, HolderMembershipId = last.HolderMembershipId };
                RequireCurrentMembership(membership);
                return new DelegationPage(rows.Take(DelegationPage.PageSize).ToArray(), next, coverage) { Membership = membership };
            }
            RequireCurrentMembership(membership);
            return new DelegationPage(rows, null, coverage ?? throw new InvalidDataException("No delegation source was read."))
            { Membership = membership };
        }, token);
    }

    private void RequireCurrentMembership(DelegationMembership membership)
    {
        if (_delegations?.Root.EvidenceSeal != membership.EvidenceFingerprint || CurrentDerivation(membership.GenerationId) is not null)
            throw new InvalidDataException(DelegationText.Get("MembershipChanged"));
    }
}

using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    private const string PresentationUser = "CN=Barbara Hernandez,OU=Users,OU=BA Lab,DC=ba,DC=ad,DC=lab";
    private const string PresentationDomain = "DC=ba,DC=ad,DC=lab";
    private const string PresentationGroup = "CN=Tier 0 Delegation,OU=Groups,DC=ba,DC=ad,DC=lab";
    private const string PresentationComputer = "CN=DC01,OU=Domain Controllers,DC=ba,DC=ad,DC=lab";

    private static SavedTier0Path PresentationSaved(bool group = false, bool inherited = false, byte inheritance = 0,
        string targetDn = PresentationDomain, string? targetClass = "domainDNS")
    {
        var saved = Saved(PresentationUser);
        var original = saved.Page.Questions[0];
        var user = original.Requester!.Requester! with
        { NamingContext = PresentationDomain, DomainFqdn = "ba.ad.lab", Sid = "S-1-5-21-10-20-30-1100" };
        var target = new Tier0Target(Guid.NewGuid(), targetDn, PresentationDomain, "ba.ad.lab", "S-1-5-21-10-20-30", null);
        var holder = group ? user with { ObjectGuid = Guid.NewGuid(), DistinguishedName = PresentationGroup, Sid = "S-1-5-21-10-20-30-2100" } : user;
        var holderName = group ? "Tier 0 Delegation" : "Barbara Hernandez";
        var entry = new PermissionEntry(36, "AccessAllowed", new(holder.Sid!, holderName, holder.DistinguishedName, "ba.ad.lab", null, null, null),
            393268, null, null, inherited, inheritance, 0, false, false, []);
        var trustee = new RequesterTrusteeEvidence(holder.Sid!, RequesterTrusteeState.Matches,
            group ? RequesterTrusteeReason.DirectGlobalMembership : RequesterTrusteeReason.DirectIdentity,
            holder.ObjectGuid, holder.DistinguishedName, "ba.ad.lab", group ? 0x80000002L : null,
            saved.Description.CompletedUtc, group ? PresentationUser : null);
        var edge = new ControlEdge(960, target.ObjectGuid, target.DistinguishedName, targetClass, holder.Sid!, holderName, null,
            ControlCapability.CanWriteDacl, ControlEvaluationState.Established, ControlUncertainty.None,
            ControlExpectedness.Unexpected, ControlExpectednessReason.UnexpectedNotControlPlane, PrincipalClassificationRegistry.Version,
            saved.Description.GenerationId, saved.Description.DerivationGenerationId, true, [entry], [], MembershipRouteSummary.NotDerived);
        var steps = new List<Tier0PathStep>();
        if (group) steps.Add(new(user, holder, Tier0PathStepKind.Membership, null, null,
            new(holder, "member", 3, PresentationUser), null));
        steps.Add(new(holder, target, Tier0PathStepKind.WriteDacl, null, null, null, edge.Id));
        var proof = new RequesterDaclAssessment(new(PresentationUser, targetDn), saved.Description.GenerationId,
            saved.Description.DerivationGenerationId, saved.Description.EvidenceSeal, user, target, ControlEvaluationState.Established,
            [], [new(entry, ControlEvaluationState.Established, trustee)], [new(edge.Id, Tier0PathCalculation.Fingerprint(edge))], steps);
        var risk = original.Risk with
        {
            RequesterDn = PresentationUser, TargetDn = targetDn, ReachedTarget = target,
            CurrentAuthority = original.Risk.CurrentAuthority! with { Principal = user },
            SourceProofFingerprint = Tier0PathCalculation.Fingerprint(new SavedRequesterDaclProof(proof, original.SourceFingerprint)),
        };
        var evidence = (Tier0RouteFindingEvidence)saved.Finding!.Evidence;
        return saved with
        {
            Account = new(user.ObjectGuid, PresentationUser, "Barbara Hernandez", "bhernandez", "Barbara"),
            Finding = saved.Finding with { DomainFqdn = "ba.ad.lab", PrincipalName = "bhernandez",
                Evidence = evidence with { RequesterSid = user.Sid!, RequesterDn = PresentationUser } },
            Permissions = [edge],
            Page = saved.Page with { Questions = [original with { Risk = risk, Requester = proof, Steps = steps }] },
        };
    }

    private static SavedTier0Path OwnPresentation(SavedTier0Path saved, OwnAccountMembershipPermissionKind kind,
        bool existing = false, bool primary = false)
    {
        var original = saved.Page.Questions[0];
        var requester = original.Requester!.Requester!;
        var group = original.Steps.FirstOrDefault(value => value.Kind == Tier0PathStepKind.Membership)?.To
            ?? new Tier0Target(Guid.NewGuid(), PresentationGroup, PresentationDomain, "ba.ad.lab", "S-1-5-21-10-20-30-2100", null);
        var request = new OwnAccountMembershipRequest(PresentationUser, PresentationGroup) { PermissionKind = kind };
        var originalEntry = original.Requester.Evidence[0];
        var entry = originalEntry.Entry with
        {
            AccessMask = kind == OwnAccountMembershipPermissionKind.SelfMembership ? 0x20008 : 0x20020,
            ObjectTypeGuid = "bf9679c0-0de6-11d0-a285-00aa003049e2",
            HasObjectType = true,
            Trustee = new(requester.Sid!, "Barbara Hernandez", PresentationUser, "ba.ad.lab", null, null, null),
        };
        var trustee = originalEntry.Trustee with { TrusteeSid = requester.Sid!, HolderGuid = requester.ObjectGuid,
            HolderDn = PresentationUser, GroupType = null, DirectMemberDn = null, Reason = RequesterTrusteeReason.DirectIdentity };
        var edge = saved.Permissions[0] with
        {
            Id = 961, Target = PresentationGroup, TargetGuid = group.ObjectGuid, TargetClass = "group",
            HolderSid = requester.Sid!, HolderName = "Barbara Hernandez",
            Capability = kind == OwnAccountMembershipPermissionKind.SelfMembership ? ControlCapability.CanAddSelfToGroup : ControlCapability.CanModifyGroupMembership,
            Evidence = [entry],
        };
        var permission = new SelfMembershipAssessment(new(PresentationUser, PresentationGroup, SelfMembershipOperation.Add, null),
            saved.Description.GenerationId, saved.Description.DerivationGenerationId, saved.Description.EvidenceSeal,
            requester.ObjectGuid, requester.Sid, group.ObjectGuid, group.Sid, requester.ObjectGuid, requester.Sid,
            kind == OwnAccountMembershipPermissionKind.SelfMembership && !existing ? ControlEvaluationState.Established : ControlEvaluationState.NotEstablished,
            ControlEvaluationState.Established, ControlEvaluationState.Unknown, "Present", saved.Description.CompletedUtc, 512,
            existing ? true : null, [SelfMembershipIssue.MembershipStateUnknown, SelfMembershipIssue.LiveOperationNotEvaluated],
            existing || kind != OwnAccountMembershipPermissionKind.SelfMembership ? [] : [new(entry, ControlEvaluationState.Established, trustee)],
            existing ? [] : [961]);
        var witness = new Tier0Evidence(group, primary ? "primaryGroupID" : "member", 3, primary ? "2100" : PresentationUser);
        var own = new OwnAccountMembershipAssessment(request, saved.Description.GenerationId, saved.Description.DerivationGenerationId,
            saved.Description.EvidenceSeal, requester, group, permission, ControlEvaluationState.Established,
            existing ? OwnAccountMembershipBasis.ExistingMembership : OwnAccountMembershipBasis.ExistingOrAuthorizedAdd,
            [], existing ? [witness] : [], [], existing ? [] : [new(961, Tier0PathCalculation.Fingerprint(edge))])
        {
            MemberWrite = kind == OwnAccountMembershipPermissionKind.WriteMembers
                ? new(existing ? ControlEvaluationState.NotEstablished : ControlEvaluationState.Established, ControlEvaluationState.Unknown,
                    existing ? true : null, [], existing ? [] : [new(entry, ControlEvaluationState.Established, "member", trustee)]) : null,
        };
        Tier0PathStep[] steps = [new(requester, group, existing ? Tier0PathStepKind.Membership : Tier0PathStepKind.OwnAccountMembership,
            null, null, existing ? witness : null, existing ? null : 961) { OwnAccountRequest = request }];
        var risk = original.Risk with { Family = PathRequesterFamily.OwnAccountMembership, TargetDn = PresentationGroup,
            ReachedTarget = group, PermissionKind = kind, CapturedMemberPresent = existing ? true : null,
            OrdinaryAddReadiness = ControlEvaluationState.Unknown,
            SourceProofFingerprint = Tier0PathCalculation.Fingerprint(new SavedOwnAccountMembershipProof(own, original.SourceFingerprint, steps)) };
        return saved with { Permissions = existing ? [] : [edge], Page = saved.Page with
        { Questions = [new(original.Id, risk, original.SourceFingerprint, steps, null, own, null)] } };
    }

    private static SavedTier0Path CombinedPresentation(OwnAccountMembershipPermissionKind kind)
    {
        var saved = PresentationSaved(group: true);
        var original = saved.Page.Questions[0];
        var membership = OwnPresentation(saved, kind);
        var own = membership.Page.Questions[0].OwnAccount!;
        var request = new MembershipDaclRequest(PresentationUser, PresentationGroup, PresentationDomain) { PermissionKind = kind };
        var steps = membership.Page.Questions[0].Steps.Concat(original.Steps.Skip(1)).Select(value => value with
        { OwnAccountRequest = own.Request, MembershipDaclRequest = request }).ToArray();
        var dacl = original.Requester! with { ObtainedMembership = own.Request, Steps = steps,
            Evidence = original.Requester.Evidence.Select(value => value with
            { Trustee = value.Trustee with { Reason = RequesterTrusteeReason.ObtainedGlobalMembership, DirectMemberDn = null } }).ToArray() };
        var combined = new MembershipDaclAssessment(request, own, dacl, ControlEvaluationState.Established, [], steps)
        { AuthorizationContext = MembershipDaclAssessment.Context };
        var risk = original.Risk with { Family = PathRequesterFamily.MembershipDacl, GroupDn = PresentationGroup,
            PermissionKind = kind, OrdinaryAddReadiness = ControlEvaluationState.Unknown, CapturedMemberPresent = null,
            SourceProofFingerprint = Tier0PathCalculation.Fingerprint(new SavedMembershipDaclProof(combined, original.SourceFingerprint)) };
        return saved with { Permissions = saved.Permissions.Concat(membership.Permissions).ToArray(), Page = saved.Page with
        { Questions = [new(original.Id, risk, original.SourceFingerprint, steps, null, null, combined)] } };
    }

    private static SavedPathQuestionViewModel PresentationRow(SavedTier0Path saved) => new(saved.Page.Questions[0], saved);
    private static string Detail(SavedPathQuestionViewModel row, string label) => row.PermissionDetails.Single(value => value.Label == label).Value;
    private static SavedTier0PathSectionViewModel ReadPresentation(SavedTier0Path saved)
    {
        var section = Section();
        section.ConfigureAsync(saved.Page.RequesterDn, (_, _, _) => Task.FromResult(Result<SavedTier0Path?>.Success(saved)));
        section.Read();
        return section;
    }
}

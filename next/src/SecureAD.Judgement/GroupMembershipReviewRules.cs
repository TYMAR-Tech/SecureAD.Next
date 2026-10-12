using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>SEC-050 reviews the saved source-list size, not authorization or a safe member limit.</summary>
public sealed class LargePrivilegedGroupReview : IObjectRule
{
    internal const string Explanation = "The captured Direct member count exceeds this group's membership review threshold. "
        + "Review whether the recorded members still need this privilege. Group size alone does not prove unsafe access.";
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = GroupMembershipReviewRules.Definition("SEC-050", "Large privileged group");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw new InvalidOperationException("SEC-050 requires its declared captured membership inputs.");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        GroupMembershipReviewRules.Judge(subject, context, GroupMembershipReviewKind.PrivilegedGroupSize);

    internal static int ThresholdFor(PrincipalClassification definition) =>
        !CapturedGroupMembershipIndex.IsTarget(definition) ? throw new ArgumentException("Not an administrative group.", nameof(definition))
        : definition.Tier0Scope == Tier0IdentityScope.Domain ? 10
        : definition.Tier0Scope == Tier0IdentityScope.BuiltinDomain ? 15 : 5;
}

/// <summary>SEC-051 records intentional or unintended direct group nesting without inferring authorization.</summary>
public sealed class GroupNestedInDomainAdmins : IObjectRule
{
    internal const string Explanation = "This group is directly nested in Domain Admins. Review its membership and who can change it. "
        + "Nesting may be intentional; this finding does not prove an attack.";
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = GroupMembershipReviewRules.Definition("SEC-051", "Group nested in Domain Admins");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw new InvalidOperationException("SEC-051 requires its declared captured membership inputs.");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) =>
        GroupMembershipReviewRules.Judge(subject, context, GroupMembershipReviewKind.GroupNestedInDomainAdmins);

    internal static string Key(Guid group, Guid target) => group.ToString("D") + ":" + target.ToString("D");
}

/// <summary>SEC-061 reviews broad membership of the scoped legacy group, not object-specific read permission.</summary>
public sealed class BroadPreWindows2000Membership : IObjectRule
{
    internal const int PolicyVersion = 1;
    internal const string Explanation = "Broad identities reach this legacy group through the recorded security-group relationships. "
        + "Review whether this compatibility access is still required. This finding does not establish object-specific read access or a completed attack.";
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-061", "Broad membership of Pre-Windows 2000 Compatible Access", Severity.Medium, 1,
        ["group"], ["objectClass", "objectSid", "groupType", "member", "memberOf"], [nameof(DerivedFactKind.AdministrativeMembership)]);
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) => throw new InvalidOperationException("SEC-061 requires its declared captured membership inputs.");
    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return RuleVerdict.Judged([]);
        if (context.AdministrativeMembership is not { } index)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
        if (CapturedGroupMembershipIndex.ReadSid(subject) is null) return RuleVerdict.CouldNotJudge(["objectSid"]);
        var assessment = index.ForLegacyGroup(subject);
        var findings = new List<Finding>();
        if (assessment.Evidence is { } evidence)
        {
            var target = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.TargetGuid);
            var names = evidence.Principals.ToDictionary(identity => identity.ObjectGuid, identity => identity.DistinguishedName);
            var detail = Explanation + "\n\nBroad identities:\n" + string.Join("\n", evidence.BroadSources.Select(source =>
                source.Name + " (" + source.Sid + (source.SidScope is null ? "" : "; " + source.SidScope) + ")"))
                + "\n\nRecorded membership links:\n" + string.Join("\n", evidence.Links.Select(link =>
                    names[link.GroupGuid] + " contains " + names[link.MemberGuid]
                    + (link.MemberReferenceGuid == link.MemberGuid ? "" : " (recorded through " + names[link.MemberReferenceGuid] + ")")));
            detail = GroupMembershipReviewRules.WithLimitations(detail, evidence.Limitations);
            findings.Add(new("SEC-061", 1, Severity.Medium, new(FindingSubjectKind.DirectoryObject, target.ObjectGuid.ToString("D")),
                target.ObjectGuid, target.DistinguishedName, target.DomainFqdn!, "group", detail, subject.Completeness, evidence)
                { PrincipalName = subject.Find("sAMAccountName")?.OnlyValue?.Text ?? subject.DistinguishedName });
        }
        return new(findings, assessment.Missing, assessment.Unresolved);
    }
}

internal static class GroupMembershipReviewRules
{
    internal const int PolicyVersion = 1;
    internal static RuleDefinition Definition(string id, string name) => new(id, name, Severity.Low, 1,
        ["group"], ["objectClass", "objectSid", "groupType", "member", "isDeleted"], [nameof(DerivedFactKind.AdministrativeMembership)]);

    internal static RuleVerdict Judge(ObjectAttributes subject, JudgingContext context, GroupMembershipReviewKind kind)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return RuleVerdict.Judged([]);
        if (context.AdministrativeMembership is not { } index)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
        var assessment = index.Review(subject, kind);
        var id = kind == GroupMembershipReviewKind.PrivilegedGroupSize ? "SEC-050" : "SEC-051";
        var findings = assessment.Evidence.Select(evidence =>
        {
            var guid = evidence.NestedGroupGuid ?? evidence.TargetGuid;
            var principal = evidence.Principals.Single(identity => identity.ObjectGuid == guid);
            var key = evidence.NestedGroupGuid is not null ? GroupNestedInDomainAdmins.Key(guid, evidence.TargetGuid) : guid.ToString("D");
            return new Finding(id, 1, Severity.Low, new(FindingSubjectKind.DirectoryObject, key), guid, principal.DistinguishedName,
                principal.DomainFqdn!, "group", Detail(evidence), principal.Completeness, evidence)
                { PrincipalName = principal.DistinguishedName };
        }).ToArray();
        return new(findings, assessment.Missing, assessment.Unresolved);
    }

    internal static string Detail(GroupMembershipReviewEvidence evidence)
    {
        var target = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.TargetGuid);
        string detail;
        if (evidence.ReviewKind == GroupMembershipReviewKind.PrivilegedGroupSize)
        {
            detail = LargePrivilegedGroupReview.Explanation + "\n\nDirect count: " + evidence.DirectMembers!.Value.ToString(CultureInfo.InvariantCulture)
                + "\nReview threshold: " + evidence.ReviewThreshold!.Value.ToString(CultureInfo.InvariantCulture);
            if (evidence.KnownTotal is { } total)
                detail += "\nKnown total: " + total.KnownMembers.ToString(CultureInfo.InvariantCulture)
                    + "\nKnown total counts distinct captured objects through member links, including nested groups; primary-group relationships are separate."
                    + (total.Limitations.Count == 0 ? "" : "\nIncomplete membership evidence: " + string.Join(", ", total.Limitations));
        }
        else
        {
            var member = evidence.Principals.Single(identity => identity.ObjectGuid == evidence.NestedGroupGuid);
            detail = GroupNestedInDomainAdmins.Explanation + "\n\n" + target.DistinguishedName + " contains " + member.DistinguishedName
                + "\n\nRecorded membership links:\n" + string.Join("\n", evidence.Links.SelectMany(link => link.Witnesses)
                    .Select(witness => witness.Attribute + "[" + witness.Ordinal.ToString(CultureInfo.InvariantCulture) + "]: " + witness.Value));
        }
        return WithLimitations(detail, evidence.Limitations);
    }

    internal static string WithLimitations(string detail, IReadOnlyList<AdministrativeMembershipLimitation> limitations) =>
        limitations.Count == 0 ? detail : detail + "\n\nAdditional membership could not be fully assessed:\n"
            + string.Join("\n", limitations.Select(limit => CapturedGroupMembershipIndex.Describe(limit.Reason) + ": " + limit.DistinguishedName));
}

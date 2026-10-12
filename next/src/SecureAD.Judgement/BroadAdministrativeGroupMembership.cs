using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>SEC-062 reports source-qualified broad membership, not logon, takeover or a computed Tier 0 path.</summary>
public sealed class BroadAdministrativeGroupMembership : IObjectRule
{
    internal const int PolicyVersion = 1;
    internal const string MembershipSummary = "Broad membership reaches this administrative group through the recorded security-group relationships.";
    internal const string ScopeNote = "This finding does not prove a successful logon or account takeover.";
    internal const string Explanation = MembershipSummary + " " + ScopeNote;
    internal const string Guidance = "Review and remove unintended broad membership paths, replace them with role-specific security groups, "
        + "and check the other recorded routes before concluding the exposure is removed.";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-062", "Broad membership of administrative directory groups", Severity.High, 1,
        ["group"], ["objectClass", "objectSid", "groupType", "member", "memberOf"], [nameof(DerivedFactKind.AdministrativeMembership)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-062 requires its declared saved membership inputs.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return RuleVerdict.Judged([]);
        if (context.AdministrativeMembership is not { } index)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
        if (CapturedGroupMembershipIndex.ReadSid(subject) is null) return RuleVerdict.CouldNotJudge(["objectSid"]);
        var assessment = index.For(subject);
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
            if (!evidence.IsComplete)
                detail += "\n\nAdditional membership could not be fully assessed:\n" + string.Join("\n",
                    evidence.Limitations.Select(limit => CapturedGroupMembershipIndex.Describe(limit.Reason) + ": " + limit.DistinguishedName));
            findings.Add(new("SEC-062", 1, Severity.High, new(FindingSubjectKind.DirectoryObject, target.ObjectGuid.ToString("D")),
                target.ObjectGuid, target.DistinguishedName, target.DomainFqdn!, "group", detail, subject.Completeness, evidence)
                { PrincipalName = subject.Find("sAMAccountName")?.OnlyValue?.Text ?? subject.DistinguishedName });
        }
        return new(findings, assessment.Missing, assessment.Unresolved);
    }
}

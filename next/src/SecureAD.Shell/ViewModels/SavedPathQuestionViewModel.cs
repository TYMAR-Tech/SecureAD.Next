using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Naming;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed class SavedPathQuestionViewModel
{
    private static readonly PermissionVocabulary Vocabulary = PermissionVocabulary.Shipped;
    private readonly bool _qualifyDomains;
    private static string ModifyPermissions => Vocabulary.Words.Describe(0x40000, null).Rights.Single().Name;

    public SavedPathQuestionViewModel(PathRiskQuestion question, SavedTier0Path saved)
    {
        var risk = question.Risk;
        var own = question.OwnAccount ?? question.Membership?.Membership;
        var dacl = question.Requester ?? question.Membership?.Dacl;
        var capturedName = saved.Account?.Name ?? Name(risk.RequesterDn, null);
        var accountName = saved.Account?.AccountName ?? (saved.Finding?.PrincipalName is { } principal
            && !Same(principal, risk.RequesterDn) ? principal : Text("AccountNameNotRecorded"));
        var checks = ReadChecks(question, saved.Permissions);
        _qualifyDomains = dacl?.ResourceContext is not null
            && new[] { dacl.Requester?.DomainFqdn, dacl.Target?.DomainFqdn }
                .Concat(question.Steps.SelectMany(step => new[] { step.From.DomainFqdn, step.To.DomainFqdn }))
                .Concat(checks.Select(check => check.Trustee.HolderDomain)).OfType<string>()
                .Distinct(StringComparer.OrdinalIgnoreCase).Skip(1).Any();
        var name = QualifiedName(capturedName, dacl?.Requester?.DomainFqdn);
        var shortName = saved.Account?.GivenName ?? name;
        var targetClass = checks.FirstOrDefault(value => Same(value.Target, risk.TargetDn))?.TargetClass
            ?? (risk.Family == PathRequesterFamily.OwnAccountMembership ? "group" : null);
        var kind = Kind(targetClass);
        var targetName = QualifiedName(Name(risk.TargetDn, targetClass), dacl?.Target?.DomainFqdn);
        Target = Text("NamedObject", targetName, kind);
        var groupName = Name(risk.GroupDn ?? own?.Request.TargetDn ?? risk.TargetDn, "group");
        var established = risk.Authorization == ControlEvaluationState.Established;
        var existingMembership = own?.Basis == OwnAccountMembershipBasis.ExistingMembership;
        var conditionalMembership = own?.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd;
        RecommendationBoundary = Text(existingMembership && risk.Family == PathRequesterFamily.OwnAccountMembership
            ? "MembershipRecommendationBoundary" : "RecommendationBoundary");
        Heading = !established ? Text("Group" + risk.Verdict) : risk.Family switch
        {
            PathRequesterFamily.RequesterDacl => Text("PermissionHeadline", name, targetName, kind),
            PathRequesterFamily.OwnAccountMembership => Text(existingMembership ? "ExistingMembershipHeadline" : "ObtainableMembershipHeadline",
                name, groupName),
            PathRequesterFamily.MembershipDacl => Text(conditionalMembership ? "ConditionalPermissionHeadline" : "GroupPermissionHeadline",
                name, targetName, kind, groupName),
            _ => throw new InvalidOperationException(Text("InvalidEvidence")),
        };
        var reason = risk.ExpectednessReason is { } expectedness ? Text("Authority" + expectedness)
            : risk.Issue is { } issue ? Text("RiskIssue" + issue) : throw new InvalidOperationException(Text("InvalidEvidence"));
        Explanation = risk.Verdict == PathRiskVerdict.UnexpectedRoute && risk.Family == PathRequesterFamily.RequesterDacl
            && risk.ExpectednessReason == ControlExpectednessReason.UnexpectedNotControlPlane
                ? Text("PermissionWhy", shortName, kind)
                : reason;
        ExplanationHeading = Text(risk.Verdict == PathRiskVerdict.UnexpectedRoute ? "WhyFindingHeading" : "CheckExplanationHeading");
        Membership = own is null ? "" : Text("MembershipStatus",
            Text(risk.CapturedMemberPresent is true ? "MemberPresent" : risk.CapturedMemberPresent is false ? "MemberAbsent" : "MemberUnknown"),
            Text("Add" + (risk.OrdinaryAddReadiness ?? ControlEvaluationState.Unknown))) + "\n" + Text("MembershipBoundary");

        var main = checks.Where(value => Same(value.Target, risk.TargetDn)
            && value.IsGrant && (risk.Family == PathRequesterFamily.OwnAccountMembership
                ? value.Right != ModifyPermissions : value.Right == ModifyPermissions)).ToArray();
        var permission = risk.Family == PathRequesterFamily.OwnAccountMembership
            ? existingMembership ? Text("ExistingMembershipRight") : MembershipRight(own?.Request.PermissionKind ?? risk.PermissionKind)
            : Text("ModifyPermissionsRight", ModifyPermissions);
        var permissionState = dacl?.Authorization ?? (own?.Request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers
            ? own.MemberWrite?.Authorization : own?.Permission.Authorization) ?? risk.Authorization;
        PermissionDetails =
        [
            Field("AccountLabel", Text("AccountWithName", name, accountName)),
            Field("TargetLabel", Text("TargetWithKind", targetName, targetClass is not null && KindKey(targetClass) == "Object"
                ? Text("OtherObjectKind", targetClass) : Text("KindLabel" + KindKey(targetClass)))),
            Field("RelevantPermissionLabel", permission),
            Field("GrantedToLabel", main.Length == 0 ? Text(existingMembership ? "ExistingMembershipGrant" : "GrantNotIdentified")
                : Join(main.Select(value => Grantee(value, name)))),
            Field("AssignmentLabel", main.Length == 0 ? Text("NotApplicable")
                : Join(main.Select(value => Text(value.Entry.IsInherited ? "InheritedAssignment" : "ExplicitAssignment")))),
            Field("AppliesToLabel", main.Length == 0 ? Text("NotApplicable") : Join(main.Select(value => Scope(value.Entry)))),
            Field("PermissionCheckLabel", existingMembership && risk.Family == PathRequesterFamily.OwnAccountMembership
                ? Text("ExistingMembershipCheck") : Text(conditionalMembership && dacl is not null && permissionState == ControlEvaluationState.Established
                    ? "ConditionalAllowed" : "PermissionCheck" + permissionState)),
        ];
        Entries = checks.Select(value => new SavedPathFieldViewModel(
            Text("EntryHeading", Text(EntryKind(value.Entry)), value.Entry.Ordinal,
                QualifiedName(Name(value.Target, value.TargetClass), dacl?.Target?.DomainFqdn), Kind(value.TargetClass)),
            Text("EntryDetails", Holder(value), value.Right, EntryRights(value.Entry),
                Text(value.Entry.IsInherited ? "InheritedAssignment" : "ExplicitAssignment"), Scope(value.Entry),
                Text("EntryScope" + value.Scope), Text("Trustee" + value.Trustee.State))
            + (value.IsGrant ? "\n" + Text("SupportingGrant") : "")
            + (value.Trustee.Reason == RequesterTrusteeReason.ObtainedGlobalMembership ? "\n" + Text("ObtainedTrustee") : ""))).ToArray();
        Steps = !established ? [] : question.Steps.Select(step => Step(step, saved.Permissions, name, risk.RequesterDn)).ToArray();

        HasRecommendation = risk.Verdict == PathRiskVerdict.UnexpectedRoute;
        if (HasRecommendation)
        {
            if (existingMembership && risk.Family == PathRequesterFamily.OwnAccountMembership)
            {
                var witness = own!.MembershipEvidence.FirstOrDefault();
                var removable = witness?.Attribute == "member" && Same(witness.Value, risk.RequesterDn)
                    && Same(witness.Object.DistinguishedName, own.Request.TargetDn);
                RecommendedChange = Text(removable ? "RemoveMembership" : "MembershipOriginUncertain", name, groupName);
                WhereToChange = removable ? Text("EditMembership", groupName, name) : Text("ReviewMembershipSource");
            }
            else
            {
                RecommendedChange = main.Length == 0 ? Text("UnknownGrantChange") : string.Join("\n\n", main.Select(value =>
                    Text(value.Entry.IsInherited ? "RemoveInheritedRight" : "RemoveExplicitRight", value.Right, Holder(value), Target)
                    + (IsGroup(value) ? "\n" + Text("SharedGroupEffect", Holder(value)) : "")
                    + (value.Entry.IsInherited || value.Entry.InheritanceFlags != 0 ? "\n" + Text("DescendantEffect") : "")));
                WhereToChange = main.Length == 0 ? Text("UnknownGrantWhere") : Join(main.Select(value =>
                    value.Entry.IsInherited ? Text("FindInheritedSource", Target, Holder(value))
                        : Text(targetClass == "domainDNS" ? "EditDomainRight" : "EditObjectRight",
                            targetName, Holder(value), value.Right, kind)));
            }
        }
        RecordDetails = Records(question, checks);
    }

    public string Heading { get; }
    public string Target { get; }
    public string Explanation { get; }
    public string ExplanationHeading { get; }
    public string Membership { get; }
    public bool HasRecommendation { get; }
    public string RecommendedChange { get; } = "";
    public string WhereToChange { get; } = "";
    public string RecommendationHeading { get; } = Text("RecommendationHeading");
    public string WhereHeading { get; } = Text("WhereHeading");
    public string RecommendationBoundaryHeading { get; } = Text("RecommendationBoundaryHeading");
    public string RecommendationBoundary { get; }
    public string PermissionDetailsHeading { get; } = Text("PermissionDetailsHeading");
    public IReadOnlyList<SavedPathFieldViewModel> PermissionDetails { get; }
    public IReadOnlyList<SavedPathFieldViewModel> Entries { get; }
    public IReadOnlyList<SavedPathStepViewModel> Steps { get; }
    public IReadOnlyList<SavedPathFieldViewModel> RecordDetails { get; }

    private sealed record EntryCheck(string Target, string? TargetClass, string Right, PermissionEntry Entry,
        ControlEvaluationState Scope, RequesterTrusteeEvidence Trustee, long? PermissionId, string? PermissionFingerprint)
    {
        public bool IsGrant => PermissionId is not null && Scope == ControlEvaluationState.Established
            && Trustee.State == RequesterTrusteeState.Matches && Entry.AceType is "AccessAllowed" or "AccessAllowedObject";
    }

    private static IReadOnlyList<EntryCheck> ReadChecks(PathRiskQuestion question, IReadOnlyList<ControlEdge> permissions)
    {
        var result = new List<EntryCheck>();
        if ((question.Requester ?? question.Membership?.Dacl) is { } dacl)
        {
            var references = dacl.Permissions.Select(value => (value.Id, value.Fingerprint)).ToArray();
            foreach (var entry in dacl.Evidence)
                Add(dacl.Request.TargetDn, null, ModifyPermissions, entry.Entry, entry.Scope, entry.Trustee, references);
        }
        if ((question.OwnAccount ?? question.Membership?.Membership) is { } own)
        {
            var references = own.Permissions.Select(value => (value.Id, value.Fingerprint)).ToArray();
            var right = MembershipRight(own.Request.PermissionKind);
            if (own.Request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers)
            {
                if (own.MemberWrite is { } member)
                    foreach (var entry in member.Evidence)
                        Add(own.Request.TargetDn, "group", right, entry.Entry, entry.Scope, entry.Trustee, references);
            }
            else
                foreach (var entry in own.Permission.Evidence)
                    Add(own.Request.TargetDn, "group", right, entry.Entry, entry.Scope, entry.Trustee, references);
        }
        return result;

        void Add(string target, string? targetClass, string right, PermissionEntry entry, ControlEvaluationState scope,
            RequesterTrusteeEvidence trustee, (long Id, string Fingerprint)[] references)
        {
            var edges = references.Select(reference => (Edge: permissions.Single(value => value.Id == reference.Id
                && Same(value.Target, target)), reference.Fingerprint)).ToArray();
            var granting = edges.Where(value => value.Edge.Evidence.Any(original => original.Ordinal == entry.Ordinal
                && Same(original.Trustee.Sid, entry.Trustee.Sid))).ToArray();
            if (granting.Length > 1) throw new InvalidOperationException(Text("InvalidEvidence"));
            result.Add(new(target, edges.FirstOrDefault().Edge?.TargetClass ?? targetClass, right, entry, scope, trustee,
                granting.FirstOrDefault().Edge?.Id, granting.FirstOrDefault().Fingerprint));
        }
    }

    private SavedPathStepViewModel Step(Tier0PathStep step, IReadOnlyList<ControlEdge> permissions, string account, string accountDn)
    {
        var edge = step.PermissionId is { } id ? permissions.Single(value => value.Id == id && Same(value.Target, step.To.DistinguishedName)) : null;
        var from = Same(step.From.DistinguishedName, accountDn) ? account
            : QualifiedName(Name(step.From.DistinguishedName, null), step.From.DomainFqdn);
        var targetClass = edge?.TargetClass ?? (step.Kind == Tier0PathStepKind.Membership ? "group" : null);
        var description = Text("Relationship" + step.Kind, from,
            QualifiedName(Name(step.To.DistinguishedName, targetClass), step.To.DomainFqdn), Kind(targetClass));
        var evidence = step.MembershipWitness is { } witness
            ? Text(witness.Attribute == "primaryGroupID" ? "PrimaryGroupWitness" : "MembershipEntryWitness", witness.Ordinal)
            : step.Kind == Tier0PathStepKind.OwnAccountMembership ? Text("ObtainableWitness")
            : Text("SavedPermissionWitness");
        return new(description, evidence);
    }

    private string Grantee(EntryCheck value, string account) => Text(
        value.Trustee.Reason == RequesterTrusteeReason.DirectIdentity ? "DirectGrantee"
            : IsGroup(value) ? "GroupGrantee" : "OtherGrantee", Holder(value), account);

    private static bool IsGroup(EntryCheck value) => value.Trustee.GroupType is not null
        || value.Trustee.Reason is RequesterTrusteeReason.DirectGlobalMembership or RequesterTrusteeReason.ObtainedGlobalMembership;

    private string Holder(EntryCheck value) => value.Trustee.HolderDn is { } dn
        ? QualifiedName(Name(dn, null), value.Trustee.HolderDomain)
        : value.Entry.Trustee.DisplayedAgainst(value.Target).Name is { Length: > 0 } name && name != value.Entry.Trustee.Sid
            ? name : Text("HolderUnresolved");

    private string QualifiedName(string name, string? domain) => _qualifyDomains && domain is { Length: > 0 } && !Same(name, domain)
        ? Text("DomainQualifiedName", name, domain) : name;

    private static string MembershipRight(OwnAccountMembershipPermissionKind? kind) => Text(kind switch
    {
        OwnAccountMembershipPermissionKind.SelfMembership => "SelfMembershipRight",
        OwnAccountMembershipPermissionKind.WriteMembers => "WriteMembersRight",
        _ => "PermissionNotRecorded",
    });

    private static string EntryKind(PermissionEntry entry) => entry.AceType switch
    {
        "AccessAllowed" or "AccessAllowedObject" => "Allow",
        "AccessDenied" or "AccessDeniedObject" => "Deny",
        _ => "UnsupportedEntry",
    };

    private static string EntryRights(PermissionEntry entry)
    {
        var wording = Vocabulary.Words.Describe(entry.AccessMask, entry.ObjectTypeGuid);
        var text = string.Join(", ", wording.Rights.Select(value => value.IsNamed ? value.Name : Text("UnnamedRights")));
        return entry.ObjectTypeGuid is { } guid ? text.Replace(guid, Text("RecordedPermissionScope"), StringComparison.OrdinalIgnoreCase) : text;
    }

    private static string Scope(PermissionEntry entry)
    {
        var text = Vocabulary.Scopes.Describe(entry.InheritanceFlags, entry.PropagationFlags, entry.IsInherited,
            entry.InheritedObjectTypeGuid).AppliesTo;
        return entry.InheritedObjectTypeGuid is { } guid
            ? text.Replace(guid, Text("RecordedDescendantClass"), StringComparison.OrdinalIgnoreCase) : text;
    }

    private static string KindKey(string? objectClass) => objectClass switch
    {
        "domainDNS" => "Domain",
        "group" => "Group",
        "computer" => "Computer",
        "user" => "Account",
        "organizationalUnit" => "OrganizationalUnit",
        _ => "Object",
    };

    private static string Kind(string? objectClass) => Text("Kind" + KindKey(objectClass));
    private static string Name(string dn, string? objectClass) =>
        objectClass == "domainDNS" ? DnHelper.DnToFqdn(dn) : DnHelper.ExtractNameFromDn(dn);
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static string Join(IEnumerable<string> values) => string.Join("\n", values.Distinct(StringComparer.Ordinal));
    private static string Text(string key, params object?[] values) => SavedPathText.Get(key, values);
    private static SavedPathFieldViewModel Field(string key, object? value) => new(Text(key), Recorded(value));
    private static string Recorded(object? value) => value switch
    {
        null => Text("NoneRecorded"),
        DateTimeOffset time => time.ToString("O", CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? Text("NoneRecorded"),
    };

    private static IReadOnlyList<SavedPathFieldViewModel> Records(PathRiskQuestion question, IReadOnlyList<EntryCheck> checks)
    {
        var risk = question.Risk;
        var records = new List<SavedPathFieldViewModel>
        {
            Field("RecordQuestion", question.Id), Field("RecordFamily", risk.Family),
            Field("RecordRisk", risk.Verdict), Field("RecordAuthorization", risk.Authorization),
            Field("RecordExpectedness", risk.Expectedness), Field("RecordExpectednessReason", risk.ExpectednessReason),
            Field("RecordIssue", risk.Issue), Field("RecordGeneration", risk.GenerationId),
            Field("RecordDerivation", risk.DerivationGenerationId), Field("RecordEvidenceSeal", risk.EvidenceSeal),
            Field("RecordCalculation", risk.CalculationFingerprint), Field("RecordSourceProof", risk.SourceProofFingerprint),
            Field("RecordSource", question.SourceFingerprint), Field("RecordRequesterDn", risk.RequesterDn),
            Field("RecordTargetDn", risk.TargetDn), Field("RecordGroupDn", risk.GroupDn),
            Field("RecordPermissionKind", risk.PermissionKind), Field("RecordMembership", risk.CapturedMemberPresent),
            Field("RecordAdd", risk.OrdinaryAddReadiness),
        };
        Identity("AccountLabel", question.Requester?.Requester ?? question.OwnAccount?.Requester ?? question.Membership?.Membership.Requester);
        Identity("TargetLabel", question.Requester?.Target ?? question.OwnAccount?.Target ?? question.Membership?.Dacl?.Target);
        Identity("RecordReachedTarget", risk.ReachedTarget);
        if (risk.CurrentAuthority is { } authority)
        {
            Identity("RecordAuthority", authority.Principal);
            records.AddRange([
                Field("RecordAuthorityDerivation", authority.DerivationGenerationId),
                Field("RecordDerivationSeal", authority.DerivationSeal),
                Field("RecordMembershipCatalogue", authority.MembershipCatalogueVersion),
                Field("RecordMembershipSourceAvailable", authority.MembershipSourceAvailable),
                Field("RecordMembershipFingerprint", authority.MembershipFingerprint),
                Field("RecordMembershipLimits", authority.MembershipLimitations),
                Field("RecordAuthorityRoots", authority.CapturedAuthorityRoots.Count == 0 ? Text("NoAuthorityRoots")
                    : string.Join("\n", authority.CapturedAuthorityRoots.Select(value =>
                        Text("AuthorityRootRecord", value.DistinguishedName ?? Text("NoneRecorded"), value.Sid, value.Scope ?? Text("NotUsed"))))),
            ]);
        }
        foreach (var (step, index) in question.Steps.Select((step, index) => (step, index + 1)))
        {
            var prefix = Text("RecordStep", index);
            Add(prefix, "RecordRelationship", step.Kind);
            Add(prefix, "RecordSourceDn", step.From.DistinguishedName);
            Add(prefix, "RecordTargetDn", step.To.DistinguishedName);
            Add(prefix, "RecordPermissionId", step.PermissionId);
            Add(prefix, "RecordMembershipSubject", step.MembershipSubject);
            Add(prefix, "RecordMembershipSupport", step.MembershipSupport);
            if (step.MembershipWitness is { } witness) Witness(prefix, witness);
            Identity("RecordStepSource", step.From);
            Identity("RecordStepTarget", step.To);
        }
        foreach (var check in checks)
        {
            var entry = check.Entry;
            var prefix = Text("RecordEntry", check.Target, entry.Ordinal);
            Add(prefix, "RecordAceType", entry.AceType);
            Add(prefix, "RecordHolderDn", check.Trustee.HolderDn ?? entry.Trustee.DistinguishedName);
            Add(prefix, "RecordSid", entry.Trustee.Sid);
            Add(prefix, "RecordGuid", check.Trustee.HolderGuid);
            Add(prefix, "RecordDomain", check.Trustee.HolderDomain ?? entry.Trustee.DomainFqdn);
            Add(prefix, "RecordMask", Text("AccessMaskRecord", entry.AccessMask, entry.AccessMask.ToString("X8", CultureInfo.InvariantCulture)));
            Add(prefix, "RecordObjectType", entry.ObjectTypeGuid);
            Add(prefix, "RecordHasObjectType", entry.HasObjectType);
            Add(prefix, "RecordInheritedObjectType", entry.InheritedObjectTypeGuid);
            Add(prefix, "RecordHasInheritedObjectType", entry.HasInheritedObjectType);
            Add(prefix, "RecordInherited", entry.IsInherited);
            Add(prefix, "RecordInheritanceFlags", entry.InheritanceFlags);
            Add(prefix, "RecordPropagationFlags", entry.PropagationFlags);
            Add(prefix, "RecordApplicationData", Convert.ToHexString(entry.ApplicationData));
            Add(prefix, "RecordScopeResult", check.Scope);
            Add(prefix, "RecordTrusteeResult", check.Trustee.State);
            Add(prefix, "RecordTrusteeReason", check.Trustee.Reason);
            Add(prefix, "RecordGroupType", check.Trustee.GroupType);
            Add(prefix, "RecordCapturedUtc", check.Trustee.CapturedUtc);
            Add(prefix, "RecordDirectMember", check.Trustee.DirectMemberDn);
            Add(prefix, "RecordPermissionId", check.PermissionId);
            Add(prefix, "RecordPermissionFingerprint", check.PermissionFingerprint);
        }
        if ((question.Requester ?? question.Membership?.Dacl) is { } dacl)
            records.Add(Field("RecordPermissionIssues", Join(dacl.Issues.Select(value => value.ToString()))));
        if ((question.OwnAccount ?? question.Membership?.Membership) is { } own)
        {
            records.AddRange([
                Field("RecordMembershipBasis", own.Basis), Field("RecordObtainability", own.Obtainability),
                Field("RecordMembershipIssues", Join(own.Issues.Select(value => value.ToString()))),
                Field("RecordSelfPermissionIssues", Join(own.Permission.Issues.Select(value => value.ToString()))),
                Field("RecordOperationContext", OwnAccountMembershipAssessment.Context),
                Field("RecordDescriptor", own.Permission.DescriptorOutcome),
                Field("RecordAccountFlags", own.Permission.UserAccountControl),
            ]);
            foreach (var witness in own.MembershipEvidence.Concat(own.OperationEvidence)) Witness(Text("RecordOperationEvidence"), witness);
            if (own.MemberWrite is { } member)
            {
                records.Add(Field("RecordMemberWriteIssues", Join(member.Issues.Select(value => value.ToString()))));
                foreach (var entry in member.Evidence)
                    records.Add(new(Text("RecordMemberWriteScope", own.Request.TargetDn, entry.Entry.Ordinal), entry.ScopeEvidence));
            }
            foreach (var schema in own.SchemaEvidence)
            {
                foreach (var attribute in schema.Attributes)
                    foreach (var value in attribute.Values)
                        records.Add(new(Text("RecordSchemaValue", schema.DistinguishedName, attribute.LdapDisplayName, value.Ordinal), value.Stored));
            }
        }
        if (question.Membership is { } combined)
        {
            records.Add(Field("RecordCombinedContext", combined.AuthorizationContext));
            records.Add(Field("RecordCombinedIssues", Join(combined.Issues.Select(value => value.ToString()))));
        }
        return records;

        void Add(string prefix, string key, object? value) => records.Add(new(Text("RecordField", prefix, Text(key)), Recorded(value)));
        void Identity(string key, Tier0Target? value)
        {
            if (value is null) return;
            var prefix = Text(key);
            Add(prefix, "RecordDn", value.DistinguishedName);
            Add(prefix, "RecordGuid", value.ObjectGuid);
            Add(prefix, "RecordSid", value.Sid);
            Add(prefix, "RecordNamingContext", value.NamingContext);
            Add(prefix, "RecordDomain", value.DomainFqdn);
            Add(prefix, "RecordSidScope", value.SidScope ?? Text("NotUsed"));
        }
        void Witness(string prefix, Tier0Evidence value)
        {
            Add(prefix, "RecordWitnessObject", value.Object.DistinguishedName);
            Add(prefix, "RecordAttribute", value.Attribute);
            Add(prefix, "RecordOrdinal", value.Ordinal);
            Add(prefix, "RecordValue", value.Value);
        }
    }
}

internal sealed record SavedPathFieldViewModel(string Label, string Value);
internal sealed record SavedPathStepViewModel(string Description, string Evidence);

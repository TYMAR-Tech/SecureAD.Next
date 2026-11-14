using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-090: captured broad-identity LAPS permission exposures, not credential retrieval.</summary>
public sealed class LapsPasswordReadAccess : IObjectRule
{
    internal const int RuleVersion = 2;
    public RuleDefinition Definition { get; } = new("SEC-090", LapsPasswordReadMessages.Get("Title"),
        Severity.High, RuleVersion, SubjectClasses: ["computer"], RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts: [nameof(DerivedFactKind.PrincipalExpansion), nameof(DerivedFactKind.AttributeVisibility)]);

    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-090 requires its declared captured permission, schema and membership inputs.");

    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (!LapsAttributes.IsComputer(subject)) return RuleVerdict.Judged([]);
        if (context.SchemaGuids is not { } schema || context.MembersOfPrincipal is not { } expand)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        var attributes = new List<SchemaGuidEntry>();
        var schemaIdentityIncomplete = false;
        foreach (var attributeName in LapsPasswordAttributeCatalogue.All)
        {
            var definition = schema.FindUnambiguousByLdapName(attributeName);
            if (definition is { Kind: SchemaGuidKind.Attribute, Source: SchemaGuidSource.Captured }
                && Guid.TryParse(definition.Guid, out _))
                attributes.Add(definition);
            else if (context.AttributeVisibility?.Find(attributeName) is not null
                || schema.FindByLdapName(attributeName) is { Source: SchemaGuidSource.Captured })
                schemaIdentityIncomplete = true;
        }
        if (attributes.Count == 0)
            return schema.HasCapturedEntries && context.AttributeVisibility is { SchemaAttributesWereAsked: true } visibility
                && LapsPasswordAttributeCatalogue.All.All(name => visibility.Answer(name) == AttributeVisibilityAnswer.NotInSchema)
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions
            || permissions.Availability != DescriptorAvailability.Read
            || permissions.DaclState is DaclState.Unreadable or DaclState.Null)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.SecurityDescriptorUnreadable)]);
        if (!string.Equals(permissions.DistinguishedName, subject.DistinguishedName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The LAPS permission evidence belongs to a different resource.");
        if (permissions.DaclState == DaclState.Empty && permissions.Entries.Count != 0
            || permissions.Entries.Select(entry => entry.Ordinal).Distinct().Count() != permissions.Entries.Count
            || !permissions.Entries.Select(entry => entry.Ordinal).SequenceEqual(permissions.Entries.Select(entry => entry.Ordinal).Order()))
            throw new InvalidDataException("The LAPS descriptor state or original occurrence order is inconsistent.");
        var questions = attributes.Select(attribute => new LapsAttributeReadQuestion(subject, permissions, context, attribute)).ToArray();
        var holders = new Dictionary<string, PermissionTrustee>(StringComparer.OrdinalIgnoreCase);
        var unresolved = new HashSet<UnresolvedInput>();
        if (schemaIdentityIncomplete)
            unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
        foreach (var entry in permissions.Entries)
        {
            if (!FullControlEvaluator.Applies(entry) || (entry.AccessMask & 0x110) == 0
                || FullControlEvaluator.IsDeny(entry)) continue;
            var holder = entry.Trustee;
            if (holder.Sid == "S-1-5-10")
            {
                if (OwnerRightsReading.TargetSid(subject) is not { } sid)
                {
                    unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.IdentityUnreadable));
                    continue;
                }
                holder = holder with { Sid = sid, DistinguishedName = subject.DistinguishedName, WellKnownRole = null };
            }
            if (holder.HoldsThePermission && holder.Sid is not ("S-1-3-0" or "S-1-3-4"))
                holders.TryAdd(holder.Sid, holder);
        }
        var pending = new Dictionary<string, List<LapsReadExposure>>(StringComparer.OrdinalIgnoreCase);
        var membershipComplete = true;
        var checksComplete = true;
        foreach (var holder in holders.Values)
        {
            var expansion = PrincipalExpansionReading.MembersOfTrustee(expand, holder, subject.DomainFqdn);
            if (expansion.Outcome == PrincipalExpansionOutcome.PrincipalDoesNotExist
                && !BroadPrincipalCatalogue.IsBroad(holder.Sid)) continue;
            membershipComplete &= expansion.IsComplete;
            if (!expansion.IsComplete)
                unresolved.Add(new(DerivedFactKind.PrincipalExpansion, expansion.Outcome == PrincipalExpansionOutcome.PrincipalNotFound
                    ? UnresolvedReason.NotDerived : UnresolvedReason.MembershipIncomplete));
            var routes = new Dictionary<string, (IReadOnlyList<string> Path, bool Complete)>(StringComparer.OrdinalIgnoreCase);
            if (BroadPrincipalCatalogue.IsBroad(holder.Sid))
                routes.Add(holder.Sid, ([holder.Sid], expansion.IsComplete));
            foreach (var member in expansion.BroadMembers)
            {
                var complete = expansion.IsComplete && member.IsComplete;
                membershipComplete &= complete;
                if (!routes.TryGetValue(member.Sid, out var earlier) || member.PathFromRoot.Count < earlier.Path.Count)
                    routes[member.Sid] = (member.PathFromRoot, complete);
            }
            foreach (var (broad, route) in routes)
            {
                foreach (var question in questions)
                {
                    var answer = question.Assess(holder, broad, route.Complete,
                        expansion.Outcome != PrincipalExpansionOutcome.PrincipalNotFound);
                    checksComplete &= answer.State != LapsReadState.Unresolved;
                    if (answer.State == LapsReadState.Unresolved)
                        unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.PermissionControlNotEvaluated));
                    if (answer.State == LapsReadState.NotEstablished || !question.HasPossibleGrant(holder.Sid)) continue;
                    if (subject.ObjectGuid is not { } usableGuid || usableGuid == Guid.Empty)
                        return RuleVerdict.CouldNotJudge(["objectGUID"]);
                    var path = route.Path.Select(sid => new PathStep(sid, Name(sid))).ToArray();
                    var exposure = question.Exposure(holder, path, route.Complete, answer.State, answer.ReadProperty, answer.ControlAccess);
                    if (!pending.TryGetValue(broad, out var exposures)) pending.Add(broad, exposures = []);
                    exposures.Add(exposure);
                }
            }
        }
        var descriptorComplete = permissions.DaclCompleteness == DaclCompleteness.Complete;
        if (!descriptorComplete)
            unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.SecurityDescriptorIncomplete));
        var schemaComplete = !schemaIdentityIncomplete && questions.All(question => question.SchemaIsComplete);
        if (pending.Count == 0)
            return unresolved.Count == 0 ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotResolve(unresolved.OrderBy(value => value.Reason).ToArray());
        var limits = unresolved.Select(value => value.Reason.ToString()).Distinct().Order(StringComparer.Ordinal).ToList();
        if (!schemaComplete) limits.Add("CapturedSchemaFlagsIncomplete");
        var findings = pending.Select(pair =>
        {
            var exposures = pair.Value.OrderBy(value => value.TrusteeSid, StringComparer.Ordinal)
                .ThenBy(value => value.TrusteeScope, StringComparer.Ordinal)
                .ThenBy(value => value.Attribute, StringComparer.Ordinal).ToArray();
            var witness = exposures.OrderBy(value => value.State != LapsReadState.Established)
                .ThenBy(value => value.MembershipPath.Count).ThenBy(value => value.TrusteeSid, StringComparer.Ordinal)
                .ThenBy(value => value.Attribute, StringComparer.Ordinal).First();
            var summary = new LapsReadSummary(exposures.Length, exposures.Count(value => value.State == LapsReadState.Established),
                descriptorComplete, schemaComplete, membershipComplete, checksComplete, limits);
            var evidence = new LapsPasswordReaderEvidence(witness.TrusteeSid, witness.TrusteeName,
                pair.Key, Name(pair.Key), witness.MembershipPath, witness.Attribute, witness.Rights, witness.Reach,
                witness.InheritedClassGuids.Count == 1 ? witness.InheritedClassGuids[0] : null, witness.MembershipIsComplete)
            {
                IsInherited = witness.IsInherited,
                Assessment = summary,
                SupportingExposures = exposures,
            };
            return new Finding("SEC-090", RuleVersion, Severity.High,
                new(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(pair.Key)),
                subject.ObjectGuid ?? throw new InvalidOperationException("The evaluated LAPS target lost its identity."),
                subject.DistinguishedName, subject.DomainFqdn ?? "",
                LapsAttributes.ClassOf(subject), Detail(subject, evidence), subject.Completeness, evidence);
        }).ToArray();
        return RuleVerdict.Judged(findings);

        string? Name(string sid) => BroadPrincipalCatalogue.NameOf(sid) ?? context.PrincipalNames?.Invoke(sid);
    }

    private static string Detail(ObjectAttributes subject, LapsPasswordReaderEvidence evidence)
    {
        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var summary = evidence.Assessment;
        var state = summary.EstablishedExposureCount > 0 ? "Read permission established" : "Read permission unresolved";
        var material = (evidence.SupportingExposures ?? throw new InvalidOperationException("Calculated LAPS supports were not retained."))
            .Select(value => value.Attribute == LapsAttributes.WindowsLapsEncryptedPassword ? "EncryptedRead" : "ClearTextRead")
            .Distinct().Select(LapsPasswordReadMessages.Get);
        return $"{name}: {evidence.BroadPrincipalName ?? evidence.BroadPrincipalSid} ({evidence.BroadPrincipalSid}). "
            + $"{state}: {summary.EstablishedExposureCount} established holder/attribute exposure(s); "
            + $"{summary.UnresolvedExposureCount} unresolved. Example permission holder: "
            + $"{evidence.TrusteeName ?? evidence.TrusteeSid}. {string.Join(" ", material)} "
            + "This is named-holder permission evidence and captured membership attribution, not an individual user's authorization. "
            + (evidence.Reach == LapsGrantReach.EveryAttribute ? LapsPasswordReadMessages.Get("EveryAttributeReach") + " " : "")
            + (evidence.IsComplete ? "" : "The captured evidence is incomplete; further access may exist. ")
            + (summary.MembershipIsComplete ? "" : "Not every principal holding this access could be expanded. ")
            + (evidence.IsInherited ? "The entry is inherited. The originating container was not captured. " : "")
            + "Removing one displayed grant or membership route may not remove every way to read these attributes. "
            + "Review all recorded grants and membership routes before changing an intended delegation.";
    }
}

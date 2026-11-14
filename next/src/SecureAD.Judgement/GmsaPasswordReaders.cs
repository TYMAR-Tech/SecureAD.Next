using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>SEC-102: supported broad password-reader exposure, not password retrieval.</summary>
public sealed class BroadGmsaPasswordReader : IObjectRule
{
    public RuleDefinition Definition { get; } = new("SEC-102", GmsaPasswordReaders.Title, Severity.High, 1,
        ["msDS-GroupManagedServiceAccount"],
        ["objectClass", "objectGUID", "objectSid", "sAMAccountName", "userAccountControl", GmsaPasswordReaders.Attribute],
        [nameof(DerivedFactKind.PrincipalExpansion)]);

    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-102 requires its declared captured password-reader and membership inputs.");

    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);
        if (subject.Find("objectClass")?.Values.Any(value => !string.IsNullOrWhiteSpace(value.Text)) != true)
            return RuleVerdict.CouldNotJudge(["objectClass"]);
        if (!Definition.IsAbout(subject)) return RuleVerdict.Judged([]);
        if (context.GmsaReaders is not { } inputs || context.MembersOfPrincipal is null)
            return RuleVerdict.CouldNotResolve([new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        return GmsaPasswordReaders.Assess(subject, context, inputs);
    }
}

internal sealed record GmsaPasswordReaderInputs(Guid GenerationId, Tier0InputBinding Binding, bool CaptureIsComplete,
    CancellationToken CancellationToken);

internal static class GmsaPasswordReaders
{
    internal const int EngineVersion = 1;
    internal const string Attribute = "msDS-GroupMSAMembership";
    internal const string Title = "Broad gMSA password-reader permission";
    internal const string Why = "The captured password-reader configuration grants the named holder password-reading permission "
        + "and includes a widely shared identity. Review whether access extends beyond the intended service hosts.";
    internal const string Guidance = "Confirm which hosts and services need this account. If access is unintended, restrict the "
        + "password-reader list or granting-group membership. Check dependent services before changing access.";
    internal const string Scope = "This is captured permission and membership evidence, not an individual member's authorization. "
        + "No password was collected, no successful retrieval or sign-in was established, and no takeover or path to Tier 0 is proven.";
    internal const string Incomplete = "gMSA password-reader permissions could not be fully assessed from the captured evidence. "
        + "Established findings remain valid; other access may exist.";
    internal const string Reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68";
    // MS-ADTS 3.1.1.4.5.39 checks Read Property on the embedded descriptor, not Control Access on the account.
    internal const int ReadProperty = 0x10;

    internal static RuleVerdict Assess(ObjectAttributes subject, JudgingContext context, GmsaPasswordReaderInputs inputs)
    {
        if (inputs.GenerationId == Guid.Empty || !inputs.Binding.IsSupported)
            throw new InvalidDataException("The gMSA password-reader inputs have no supported fixed generation binding.");
        if (subject.ObjectGuid is not { } guid || guid == Guid.Empty) return RuleVerdict.CouldNotJudge(["objectGUID"]);
        if (string.IsNullOrWhiteSpace(subject.DomainFqdn))
            return RuleVerdict.CouldNotInterpret([new(Attribute, CapturedInputIssueKind.IncompleteValue)]);
        var attribute = subject.Find(Attribute);
        if (attribute is null) return RuleVerdict.CouldNotJudge([Attribute]);
        if (attribute.Values.Count == 0) return RuleVerdict.CouldNotInterpret([new(Attribute, CapturedInputIssueKind.ZeroValue)]);
        if (attribute.Cardinality != AttributeCardinality.SingleValued || attribute.Values.Count != 1
            || attribute.Values[0].Ordinal != 0 || attribute.Values[0].Text is not null)
            return RuleVerdict.CouldNotInterpret([new(Attribute, CapturedInputIssueKind.UnsupportedRepresentation)]);
        if (attribute.Values[0].Bytes is not { Length: > 0 } bytes)
            return RuleVerdict.CouldNotInterpret([new(Attribute, CapturedInputIssueKind.UnusableValue)]);
        var parsed = SecurityDescriptorParser.Parse(bytes);
        if (parsed.DaclState == DaclState.Unreadable || parsed.DaclCompleteness != DaclCompleteness.Complete || parsed.Errors.Count != 0)
            return RuleVerdict.CouldNotInterpret([new(Attribute, CapturedInputIssueKind.IncompleteValue)]);
        var source = new GmsaPasswordReaderSource(guid, subject.DistinguishedName, subject.DomainFqdn,
            AttributeReading.Text(subject, "sAMAccountName"), OwnerRightsReading.TargetSid(subject), subject.CapturedUtc,
            ServiceAccountReading.ReadControl(subject.Find("userAccountControl")?.Values ?? []) is { } control ? (control & 2) != 0 : null,
            bytes.ToArray(), parsed.DaclState, parsed.DaclCompleteness, parsed.DaclWasCanonical, parsed.DaclAces);
        var entries = parsed.DaclAces.Select(entry => Entry(entry, context)).ToArray();
        var holders = entries.Where(entry => FullControlEvaluator.Applies(entry)
                && (entry.AccessMask & ReadProperty) != 0 && entry.AceType.StartsWith("AccessAllowed", StringComparison.Ordinal))
            .Select(entry => EffectiveSid(entry.Trustee.Sid, source.AccountSid))
            .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (parsed.DaclState == DaclState.Null) holders.Add("S-1-1-0");
        var unresolved = new HashSet<UnresolvedInput>();
        var limits = new HashSet<string>(StringComparer.Ordinal);
        if (!inputs.CaptureIsComplete) limits.Add("CaptureIncomplete");
        if (entries.Any(entry => entry.Trustee.Sid == "S-1-5-10") && source.AccountSid is null)
            unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.IdentityUnreadable));
        var grants = new Dictionary<string, List<GmsaPasswordReaderGrant>>(StringComparer.OrdinalIgnoreCase);
        foreach (var holderSid in holders.Order(StringComparer.Ordinal))
        {
            inputs.CancellationToken.ThrowIfCancellationRequested();
            var holder = Trustee(holderSid, context);
            if (!holder.HoldsThePermission) continue;
            var directBroad = BroadPrincipalCatalogue.IsBroad(holderSid);
            PrincipalExpansion? expansion = null;
            if (!directBroad)
            {
                expansion = PrincipalExpansionReading.MembersOfTrustee(context.MembersOfPrincipal!, holder, subject.DomainFqdn);
                if (!string.Equals(expansion.RootSid, holderSid, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("The gMSA password-reader membership answer belongs to another holder.");
                if (!expansion.IsComplete && expansion.Outcome != PrincipalExpansionOutcome.PrincipalDoesNotExist)
                    unresolved.Add(new(DerivedFactKind.PrincipalExpansion, expansion.Outcome switch
                    {
                        PrincipalExpansionOutcome.StoppedAtBudget => UnresolvedReason.MembershipProcessingLimit,
                        PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType => UnresolvedReason.GmsaReaderGroupTypeUnavailable,
                        PrincipalExpansionOutcome.NoNestingDerived or PrincipalExpansionOutcome.PrincipalNotFound => UnresolvedReason.NotDerived,
                        _ => UnresolvedReason.MembershipIncomplete,
                    }));
                if (expansion.Outcome == PrincipalExpansionOutcome.PrincipalDoesNotExist) continue;
            }
            var candidates = directBroad
                ? new[] { new ExpandedPrincipal(holderSid, Sid.IsBuiltinDomain(holderSid) ? subject.DomainFqdn : "", [holderSid], true) }
                : expansion!.BroadMembers;
            foreach (var member in candidates)
            {
                inputs.CancellationToken.ThrowIfCancellationRequested();
                if (member.PathFromRoot.Count == 0 || !Same(member.PathFromRoot[0], holderSid)
                    || !Same(member.PathFromRoot[^1], member.Sid))
                    throw new InvalidDataException("The gMSA password-reader membership witness is inconsistent.");
                if (!member.IsComplete)
                    unresolved.Add(new(DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
                if (expansion?.Outcome == PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
                    || Sid.IsBuiltinDomain(member.Sid) && !Same(member.Scope, subject.DomainFqdn))
                {
                    unresolved.Add(new(DerivedFactKind.PrincipalExpansion,
                        expansion?.Outcome == PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
                            ? UnresolvedReason.GmsaReaderGroupTypeUnavailable : UnresolvedReason.MembershipScopeUnsupported));
                    continue;
                }
                var answer = Permission(source, entries, holder, member.Sid);
                if (!answer.IsComplete)
                {
                    var reasons = new List<UnresolvedReason>();
                    if ((answer.Uncertainty & ControlUncertainty.ConditionalOrUnsupportedAce) != 0)
                        reasons.Add(UnresolvedReason.GmsaReaderConditionalEntryUnsupported);
                    if ((answer.Uncertainty & ControlUncertainty.ObjectSpecificScopeNotEvaluated) != 0)
                        reasons.Add(UnresolvedReason.GmsaReaderScopeUnsupported);
                    if ((answer.Uncertainty & ControlUncertainty.CrossTrusteeDeny) != 0)
                        reasons.Add(UnresolvedReason.GmsaReaderDenialUnassessed);
                    if (reasons.Count == 0) reasons.Add(UnresolvedReason.PermissionControlNotEvaluated);
                    foreach (var reason in reasons) unresolved.Add(new(DerivedFactKind.PrincipalExpansion, reason));
                    continue;
                }
                if (answer.State != ControlEvaluationState.Established) continue;
                if (!grants.TryGetValue(member.Sid, out var supporting)) grants.Add(member.Sid, supporting = []);
                supporting.Add(new(holderSid, Sid.IsBuiltinDomain(holderSid) ? subject.DomainFqdn : null, holder.Name,
                    member.PathFromRoot.Select(sid => new PathStep(sid, Name(sid, context))).ToArray(),
                    (expansion?.IsComplete ?? true) && member.IsComplete, answer.GrantOrdinals, answer.BlockingOrdinals, parsed.DaclState == DaclState.Null));
            }
        }
        foreach (var issue in unresolved) limits.Add(issue.Token);
        var savedLimits = limits.Order(StringComparer.Ordinal).ToArray();
        var findings = grants.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair =>
        {
            var evidence = new GmsaPasswordReaderEvidence(inputs.GenerationId, inputs.Binding.EvidenceSeal,
                inputs.Binding.DerivationGenerationId, inputs.Binding.DerivationSeal, PrincipalClassificationRegistry.Version,
                EngineVersion, source, pair.Key, BroadPrincipalCatalogue.NameOf(pair.Key) ?? pair.Key,
                pair.Value.OrderBy(grant => grant.HolderSid, StringComparer.Ordinal).ToArray(), savedLimits);
            return new Finding("SEC-102", 1, Severity.High,
                new(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(pair.Key)),
                guid, subject.DistinguishedName, subject.DomainFqdn, "msDS-GroupManagedServiceAccount",
                Why, subject.Completeness, evidence) { PrincipalName = evidence.BroadName };
        }).ToArray();
        return new(findings, [], unresolved.OrderBy(issue => issue.Token, StringComparer.Ordinal).ToArray());
    }

    private static FullControlRight Permission(GmsaPasswordReaderSource source, IReadOnlyList<PermissionEntry> entries,
        PermissionTrustee holder, string broadSid)
    {
        var question = new FullControlSource(source.DistinguishedName, source.ObjectGuid, source.AccountSid, source.DomainFqdn,
            ["msDS-GroupManagedServiceAccount"], holder, Sid.IsBuiltinDomain(holder.Sid) ? source.DomainFqdn : null,
            true, false, DescriptorAvailability.Read, source.DaclState, source.DaclCompleteness, source.DaclWasCanonical, entries);
        bool? MatchDeny(PermissionEntry entry)
        {
            var sid = EffectiveSid(entry.Trustee.Sid, source.AccountSid);
            if (Same(sid, broadSid) || Same(sid, "S-1-1-0") && Same(broadSid, "S-1-5-11")) return true;
            return null;
        }
        return FullControlEvaluator.AssessAttributeRight(question, ReadProperty,
            entry => entry.HasObjectType ? ControlEvaluationState.Unknown : ControlEvaluationState.Established,
            MatchDeny, true);
    }

    internal static FullControlRight ReplayPermission(GmsaPasswordReaderSource source, string holderSid, string broadSid)
    {
        var context = JudgingContext.At(source.CapturedUtc);
        return Permission(source, source.Entries.Select(entry => Entry(entry, context)).ToArray(), Trustee(holderSid, context), broadSid);
    }

    private static PermissionEntry Entry(ParsedAce entry, JudgingContext context) => new(entry.Ordinal, entry.AceType.ToString(),
        Trustee(entry.TrusteeSid, context), entry.AccessMask, entry.ObjectTypeGuid, entry.InheritedObjectTypeGuid,
        entry.IsInherited, entry.InheritanceFlags, entry.PropagationFlags, entry.HasObjectType, entry.HasInheritedObjectType,
        entry.ApplicationData);

    private static PermissionTrustee Trustee(string sid, JudgingContext context)
    {
        var wellKnown = WellKnownSidCatalog.FindBySid(sid);
        return new(sid, Name(sid, context), null, null, null, wellKnown?.Role, null);
    }

    private static string? Name(string sid, JudgingContext context) => BroadPrincipalCatalogue.NameOf(sid)
        ?? context.PrincipalNames?.Invoke(sid) ?? WellKnownSidCatalog.FindBySid(sid)?.DisplayName;
    private static string? EffectiveSid(string sid, string? targetSid) => sid == "S-1-5-10" ? targetSid : sid;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

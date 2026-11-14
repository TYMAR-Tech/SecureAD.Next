using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public readonly record struct GpoDirectoryPermissionMark(Guid GenerationId, long FindingId, Guid TargetGuid, int Ordinal);

public sealed record SavedGpoDirectoryOperation(GpoDirectoryOperation Operation, GpoDirectoryPermissionState State)
{
    public string Permission => GpoDirectoryPermissionRules.Operation(Operation).Label;
    public bool IsComplete => State != GpoDirectoryPermissionState.Unresolved;
    public bool IsEstablished => State == GpoDirectoryPermissionState.Established;
}

/// <summary>Selected whole-finding facts, independent of the loaded original-entry page.</summary>
public sealed record GpoDirectoryPermissionContext(FindingReference Reference, string RuleId, GpoDirectoryResource Target,
    string HolderSid, string? HolderScope, string? HolderName, string ExpectednessReason,
    bool EvidenceIsComplete, bool HasNullDacl, int EntryCount, IReadOnlyList<SavedGpoDirectoryOperation> Operations,
    IReadOnlyList<string> Limitations)
{
    public bool IsComplete => EvidenceIsComplete;
    public string PermissionHolder => HolderName ?? HolderSid;
    public string TargetLabel => RuleId == "SEC-080" ? "GPO" : "Link scope";
    public string TargetName => Target.Name ?? Target.DistinguishedName;
    public string WhyUnexpected => SavedPermissionReview.Describe(ExpectednessReason, SavedGpoDirectoryPermission.InvalidDetails);
    public string Caution => GpoDirectoryPermissionRules.Caution;
    public string IncompleteNote => GpoDirectoryPermissionRules.Incomplete;
    public bool Matches(FindingListItem selected) => RuleId is "SEC-080" or "SEC-081"
        && selected.RuleId == RuleId && selected.RuleVersion == 1 && selected.Severity == Severity.High
        && selected.Reference == Reference && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0
        && Target is { IsValid: true } && selected.ObjectGuid == Target.ObjectGuid
        && selected.DistinguishedName == Target.DistinguishedName && selected.DomainFqdn == Target.DomainFqdn
        && selected.ObjectClass == Target.ObjectClass && Sid.ToBytes(HolderSid) is not null
        && selected.Subject == new FindingSubject(FindingSubjectKind.Account, GpoDirectoryPermissionRules.Key(HolderSid, HolderScope))
        && (Sid.IsBuiltinDomain(HolderSid) ? HolderScope == Target.DomainFqdn : HolderScope is null)
        && ExpectednessReason is nameof(ControlExpectednessReason.UnexpectedBroadPrincipal)
            or nameof(ControlExpectednessReason.UnexpectedNotControlPlane) or nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope)
        && Operations is not null && Operations.Select(value => value.Operation)
            .SequenceEqual(GpoDirectoryPermissionRules.For(RuleId).Select(value => value.Operation))
        && Operations.Any(value => value.IsEstablished) && EntryCount >= 0
        && EvidenceIsComplete == selected.EvidenceIsComplete && Limitations is not null
        && EvidenceIsComplete == (Limitations.Count == 0 && Operations.All(value => value.IsComplete))
        && (!HasNullDacl || HolderSid == "S-1-1-0" && EntryCount == 0);

    public bool SameQuestion(GpoDirectoryPermissionContext other) => other.Operations is not null && other.Limitations is not null
        && Operations.SequenceEqual(other.Operations) && Limitations.SequenceEqual(other.Limitations, StringComparer.Ordinal)
        && this == (other with { Operations = Operations, Limitations = Limitations });
}

public sealed record SavedGpoDirectoryEntry(int Ordinal, bool IsDeny, bool IsInherited, string PermissionScope,
    string Operations, bool ScopeIsComplete)
{
    public bool IsComplete => ScopeIsComplete;
    public string EntryType => IsDeny ? "Deny" : "Allow";
    public string Assignment => IsInherited ? "Inherited" : "Explicit";
    public string InheritanceNote => "The original source of this inherited assignment is not established by this finding.";
}

/// <summary>A selected page of saved original occurrences, never an authorization replay.</summary>
public sealed record SavedGpoDirectoryPermission(GpoDirectoryPermissionContext Context,
    IReadOnlyList<SavedGpoDirectoryEntry> Entries, GpoDirectoryPermissionMark? Next)
{
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved GPO-directory permission details are missing, invalid or inconsistent.";
    public const string IncompleteExplanation = GpoDirectoryPermissionRules.Incomplete;
    public bool IsComplete => Context.IsComplete;
    public static bool SupportsRule(string rule) => rule is "SEC-080" or "SEC-081";
    public string NullDaclNote => SavedAttributeWritePermission.NullDaclNote;

    public static string DescribeLimitation(string token) => token switch
    {
        "CaptureIncomplete" => "The capture is incomplete. Other access may exist.",
        "CapturedAttributeSchemaUnavailable" => "The captured schema does not establish every requested policy attribute's identity.",
        "CapturedTargetClassSchemaUnavailable" => "The captured schema does not establish the target object's class.",
        nameof(ControlUncertainty.ResourceContextUnverified) => "The holder's resource-domain context could not be established; a BUILTIN group on a forest-wide site does not identify a single domain.",
        nameof(ControlUncertainty.CrossTrusteeDeny) => "A denial requires a concrete requester authorization context; the named-holder evidence does not settle it.",
        nameof(ControlUncertainty.ConditionalOrUnsupportedAce) => "An original permission entry has an unsupported type or condition.",
        nameof(ControlUncertainty.ObjectSpecificScopeNotEvaluated) => "An original object-specific permission scope could not be fully qualified.",
        nameof(ControlExpectednessReason.UnknownMembershipIncomplete) => "The captured administrative membership could not be followed completely.",
        nameof(ControlExpectednessReason.UnknownAuthorityScope) => "The captured identity does not establish the holder's authority over this target.",
        _ => token + ": this saved input could not be fully assessed.",
    };

    public bool IsExpectedPage(int after)
    {
        if (Context is null || Entries is null || after < -1 || Entries.Count > PageSize) return false;
        if (Context.HasNullDacl) return after == -1 && Entries.Count == 0 && Next is null;
        if (Entries.Count == 0 || Entries.Any(entry => entry.Ordinal <= after || string.IsNullOrWhiteSpace(entry.PermissionScope)
            || string.IsNullOrWhiteSpace(entry.Operations)) || Entries.Select(entry => entry.Ordinal).Distinct().Count() != Entries.Count
            || !Entries.Select(entry => entry.Ordinal).SequenceEqual(Entries.Select(entry => entry.Ordinal).Order())) return false;
        return Next is not { } next || Entries.Count == PageSize && next.GenerationId == Context.Reference.GenerationId
            && next.FindingId == Context.Reference.FindingId && next.TargetGuid == Context.Target.ObjectGuid && next.Ordinal == Entries[^1].Ordinal;
    }
}

using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed record SavedPermissionControl(FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Object, string Name, string HolderSid, string? HolderName,
    string BroadSid, string? BroadName, ObjectTakeoverRight ReportedRight, bool InheritedContext,
    bool ExpansionWasComplete, EvidenceCompleteness Coverage, long ChainCount)
{
    public int RuleVersion { get; init; } = 2;
    public SavedPermissionControlAssessment? Assessment { get; init; }
    public string? HolderObjectClass { get; init; }
    public bool HolderIsWellKnownIdentity => WellKnownSidCatalog.FindBySid(HolderSid)?.Role == WellKnownSidRole.Principal;
    public const string Title = "Broad identity flagged for permission-list control";
    public const string Statement = "The saved assessment flags a broad identity under permission-changing or ownership-related rights on this object.";
    public const string CalculationLimits = "This saved finding uses an older permission calculation with known limitations in deny ordering, conditional entries and permission scope. It must not be treated as independently verified effective access.";
    public const string FullControlNote = "This is not an independently verified full-control proof.";
    public const string ChainNote = "These identifiers are recorded in order from the permission holder towards the broad identity. This is not every possible route or a list of directly removable membership entries.";
    public const string EntryNote = "This describes the entry context recorded by the older calculation. It does not identify the exact entry supporting the reported right or establish an inherited source container.";
    public const string ExpansionNote = "Complete describes the saved membership expansion only, not corrected permission calculation or current access.";
    public const string OwnerNote = "Changing the owner does not by itself establish permission-list control. OWNER RIGHTS entries - permissions specifically for an object's owner - and directory-server restrictions matter. This finding does not save a completed owner-transition assessment. Independently granted Modify permissions rights must be assessed separately.";
    public const string CurrentStateNote = "Established means supported by this saved assessment. Not established does not rule out other access. Unresolved means this assessment could not settle that right.";
    public const string CurrentScopeNote = "These are saved permission conclusions for the named holder, not an individual account's effective access, a successful directory change or a completed path to Tier 0.";
    public const string CurrentOwnerRoute = "Control through changing the owner: Not verified.";
    public const string CurrentOwnerNote = "Change owner permission alone does not prove that an account can become the owner and then change the permission list. OWNER RIGHTS entries - permissions specifically for the object's owner - and directory-server restrictions may matter. Independently established Modify permissions remains separate.";
    public const string CurrentCalculationLimits = "Some relevant permissions or identities remain unresolved. Established rights shown above are retained.";
    public const string CurrentExpansionNote = "Complete describes saved membership expansion only. It does not mean every permission or an individual account's access was established.";
    public const string CurrentEntryNote = "This describes a saved supporting entry. It does not establish the inherited source container.";
    public const string NullDaclNote = "The saved descriptor contains no discretionary permission list (NULL DACL). This grants broad access; it is not an explicit permission entry.";
    public const string Risk = "If an applicable permission can be exercised, it may allow the object's permission list to be changed. Where a broad identity is involved, that possibility warrants review. This saved assessment is not proof of effective access for an individual account, a directory change, successful takeover or a completed path to Tier 0.";
    public const string Action = "Confirm the intended delegation and the actual permission entries on the affected object. When authorised, verify allow/deny ordering, entry scope, conditions and inheritance before acting. If access is unintended, narrow only unnecessary rights or change a confirmed unintended membership after reviewing shared-group impact and service dependencies. Establish the original source before changing inherited permissions. Do not blanket-delete legitimate delegation or assume removing this recorded chain eliminates every route.";
    public const string InvalidDetails = "The selected finding's saved permission-control details are missing, invalid or inconsistent.";
    public const int PageSize = 50;

    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-060" && finding.RuleVersion == RuleVersion
        && (RuleVersion == 2 ? Assessment is null
            : RuleVersion == BroadPrincipalCanTakeOverObject.RuleVersion && Assessment is { } current && current.Matches(this))
        && finding.Severity == Severity.High && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject.Kind == FindingSubjectKind.Account
        && Subject.Key == BroadPrincipalCanTakeOverObject.SubjectKeyFor(BroadSid)
        && Object is { IsValid: true } && Object.ObjectGuid == finding.ObjectGuid
        && Object.DistinguishedName == finding.DistinguishedName && Object.DomainFqdn == finding.DomainFqdn
        && Object.ObjectClass == finding.ObjectClass && Name == finding.PrincipalName && !string.IsNullOrWhiteSpace(Name)
        && Sid.ToBytes(HolderSid) is not null && Sid.ToBytes(BroadSid) is not null
        && (HolderName is null || !string.IsNullOrWhiteSpace(HolderName))
        && (BroadName is null || !string.IsNullOrWhiteSpace(BroadName)) && Enum.IsDefined(ReportedRight)
        && (ExpansionWasComplete && (Assessment?.IsComplete ?? true)) == finding.EvidenceIsComplete
        && Coverage == finding.Coverage && Enum.IsDefined(Coverage)
        && ChainCount > 0;
}

public readonly record struct PermissionControlMark(Guid GenerationId, long FindingId, Guid ObjectGuid, long Ordinal);
public sealed record SavedPermissionControlStep(long Ordinal, string Sid, string? Name)
{
    public string DisplayName => Name ?? "Name not resolved from saved evidence.";
}
public sealed record SavedPermissionControlChain(SavedPermissionControl Context,
    IReadOnlyList<SavedPermissionControlStep> Steps, PermissionControlMark? Next)
{
    public bool IsExpectedPage(PermissionControlMark? after)
    {
        if (Context is null || Steps is null || after is { } mark
            && (mark.GenerationId != Context.Reference.GenerationId || mark.FindingId != Context.Reference.FindingId
                || mark.ObjectGuid != Context.Object.ObjectGuid || mark.Ordinal < 0 || mark.Ordinal >= Context.ChainCount - 1
                || mark.Ordinal % SavedPermissionControl.PageSize != SavedPermissionControl.PageSize - 1)) return false;
        var start = after is { } previous ? previous.Ordinal + 1 : 0;
        return start >= 0 && start < Context.ChainCount
            && Steps.Count == Math.Min(SavedPermissionControl.PageSize, Context.ChainCount - start)
            && Steps.Select((step, index) => step is not null && step.Ordinal == start + index
                && Sid.ToBytes(step.Sid) is not null && (step.Name is null || !string.IsNullOrWhiteSpace(step.Name))
                && (step.Ordinal != 0 || step.Sid == Context.HolderSid)
                && (step.Ordinal != Context.ChainCount - 1 || step.Sid == Context.BroadSid)).All(value => value)
            && (Next is not null) == (start + Steps.Count < Context.ChainCount)
            && (Next is not { } next || next.GenerationId == Context.Reference.GenerationId
                && next.FindingId == Context.Reference.FindingId && next.ObjectGuid == Context.Object.ObjectGuid
                && next.Ordinal == Steps[^1].Ordinal);
    }
}

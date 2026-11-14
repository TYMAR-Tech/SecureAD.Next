using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

public enum DuplicateSpnPageKind { RegisteredObjects, CapturedRegistrations }

public readonly record struct DuplicateSpnMark(Guid GenerationId, long FindingId, Guid SubjectGuid,
    int SpnIndex, DuplicateSpnPageKind Kind, long Offset);

public sealed record DuplicateSpnContext(FindingReference Reference, FindingSubject Subject,
    DuplicateSpnOwner AffectedObject, string ForestFqdn, IReadOnlyList<string> Limitations)
{
    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-026" && finding.RuleVersion == 1
        && finding.Severity == Severity.High && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.DirectoryObject }
        && ValidOwner(AffectedObject) && Subject.Key == AffectedObject.ObjectGuid.ToString("D")
        && AffectedObject.ObjectGuid == finding.ObjectGuid && AffectedObject.DistinguishedName == finding.DistinguishedName
        && AffectedObject.DomainFqdn == finding.DomainFqdn && AffectedObject.ObjectClass == finding.ObjectClass
        && (AffectedObject.AccountName ?? AffectedObject.DistinguishedName) == finding.PrincipalName
        && !string.IsNullOrWhiteSpace(ForestFqdn) && Limitations is not null && Limitations.All(value => !string.IsNullOrWhiteSpace(value));

    public bool SameAs(DuplicateSpnContext other) => other is not null && Reference == other.Reference
        && Subject == other.Subject && AffectedObject == other.AffectedObject && ForestFqdn == other.ForestFqdn
        && Limitations.SequenceEqual(other.Limitations, StringComparer.Ordinal);

    internal static bool ValidOwner(DuplicateSpnOwner? owner) => owner is not null && owner.ObjectGuid != Guid.Empty
        && !string.IsNullOrWhiteSpace(owner.DistinguishedName) && !string.IsNullOrWhiteSpace(owner.DomainFqdn)
        && !string.IsNullOrWhiteSpace(owner.ObjectClass);
}

public sealed record SavedSpnRegistration(DuplicateSpnOwner Owner, int Ordinal, string Value);

public sealed record SavedDuplicateSpn(DuplicateSpnContext Context, int SpnIndex, string MatchKey, int SpnCount,
    DuplicateSpnPageKind Kind, long Offset, long TotalRows, IReadOnlyList<DuplicateSpnOwner> Owners,
    IReadOnlyList<SavedSpnRegistration> Registrations, DuplicateSpnMark? Next)
{
    public const int PageSize = 50;
    public const string Statement = "The same complete service principal name is recorded on more than one captured object in this forest.";
    public const string InvalidDetails = "The selected finding's saved duplicate-SPN details are missing, invalid or inconsistent.";
    public const string ScopeNote = "Matching compares complete captured SPNs without regard to letter case; ports, instance names and suffixes remain part of the name. SPN aliases and other forests were not assessed. Recorded values do not establish complete attribute visibility. SecureAD does not run the suggested commands.";
    public const string LimitationsNote = "The saved assessment has limitations. The recorded duplicates remain findings; this is not assurance of complete forest-wide uniqueness.";

    public DuplicateSpnMark Position => new(Context.Reference.GenerationId, Context.Reference.FindingId,
        Context.AffectedObject.ObjectGuid, SpnIndex, Kind, Offset);
    public DuplicateSpnMark? NextSpn => SpnIndex < SpnCount - 1 ? Position with
        { SpnIndex = SpnIndex + 1, Kind = DuplicateSpnPageKind.RegisteredObjects, Offset = 0 } : null;

    public bool IsExpectedPage(DuplicateSpnMark? requested)
    {
        if (Context is null || SpnIndex < 0 || SpnIndex >= SpnCount || Offset < 0 || Offset % PageSize != 0
            || TotalRows < 2 || Offset >= TotalRows || !Enum.IsDefined(Kind) || !DuplicateServicePrincipalNames.Supports(MatchKey)
            || Owners is null || Registrations is null || requested is { } mark && mark != Position
            || requested is null && (SpnIndex != 0 || Offset != 0 || Kind != DuplicateSpnPageKind.RegisteredObjects)) return false;
        var count = Kind == DuplicateSpnPageKind.RegisteredObjects ? Owners.Count : Registrations.Count;
        if (count != Math.Min(PageSize, TotalRows - Offset)) return false;
        if (Kind == DuplicateSpnPageKind.RegisteredObjects)
        {
            if (Registrations.Count != 0 || Owners.Any(owner => !DuplicateSpnContext.ValidOwner(owner))
                || Owners.Select(owner => owner.ObjectGuid).Distinct().Count() != Owners.Count) return false;
        }
        else if (Owners.Count != 0 || Registrations.Any(value => value is null || !DuplicateSpnContext.ValidOwner(value.Owner)
            || value.Ordinal < 0 || !string.Equals(value.Value, MatchKey, StringComparison.OrdinalIgnoreCase))) return false;
        return Next == (Offset + count < TotalRows ? Position with { Offset = Offset + count } : (DuplicateSpnMark?)null);
    }
}

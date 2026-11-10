using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public enum SidHistoryPageKind { Flagged, Other }
public readonly record struct SidHistoryMark(Guid GenerationId, long FindingId, Guid ObjectGuid, SidHistoryPageKind Kind, int Ordinal);

public sealed record SidHistoryContext(FindingReference Reference, FindingSubject Subject, SavedDelegationIdentity Object,
    string Name, string? ObjectSid, int UnreadableValues, EvidenceCompleteness Coverage)
{
    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-027"     && finding.RuleVersion == PrivilegedSidHistory.RuleVersion
        && finding.Severity == Severity.High && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.Account }
        && Object is { IsValid: true } && Object.ObjectGuid == finding.ObjectGuid && Object.DistinguishedName == finding.DistinguishedName
        && Object.DomainFqdn == finding.DomainFqdn && Object.ObjectClass == finding.ObjectClass && Name == finding.PrincipalName
        && (ObjectSid is null || Sid.ToBytes(ObjectSid) is not null) && UnreadableValues >= 0
        && finding.EvidenceIsComplete == (UnreadableValues == 0) && Coverage == finding.Coverage && Enum.IsDefined(Coverage);
}

public sealed record SavedHistoryValue(int Ordinal, string Sid, string? RecognisedType);

public sealed record SavedSidHistory(SidHistoryContext Context, SidHistoryPageKind Kind,
    IReadOnlyList<SavedHistoryValue> Values, SidHistoryMark? Next)
{
    public const int PageSize = 50;
    public const string Statement = "The captured SID history includes an identifier recognised as privileged by this rule.";
    public const string InvalidDetails = "The selected finding's saved SID-history details are missing, invalid or inconsistent.";
    public const string UnsupportedVersion = "This saved SID-history assessment uses an unsupported calculation version. Re-judge the captured evidence for the corrected assessment.";
    public const string ScopeNote = "A recognised identifier type is not a resolved current group or a confirmed source-domain name. Values not ranked by this rule are not assessed as harmless.";
    public const string UnreadableNote = "Some SID-history values could not be read. The flagged values remain findings; this is not a complete list of what the object may carry.";
    public const string CaptureNote = "The captured evidence for this object may be incomplete. The flagged values remain findings.";

    public SidHistoryMark Start => new(Context.Reference.GenerationId, Context.Reference.FindingId, Context.Object.ObjectGuid, Kind, -1);
    public bool IsExpectedPage(SidHistoryMark? after)
    {
        if (Context is null || !Enum.IsDefined(Kind) || Values is null || Values.Count > PageSize
            || after is null && Kind != SidHistoryPageKind.Flagged) return false;
        var previous = after?.Ordinal ?? -1;
        if (after is { } mark && (mark.GenerationId != Context.Reference.GenerationId || mark.FindingId != Context.Reference.FindingId
            || mark.ObjectGuid != Context.Object.ObjectGuid || mark.Kind != Kind || mark.Ordinal < -1)) return false;
        if (Values.Count == 0 && (Kind != SidHistoryPageKind.Other || previous != -1 || Next is not null)) return false;
        foreach (var value in Values)
        {
            if (value is null || value.Ordinal <= previous || Sid.ToBytes(value.Sid) is null
                || PrivilegedSidCatalogue.PrivilegedName(value.Sid) != value.RecognisedType
                || (Kind == SidHistoryPageKind.Flagged ? string.IsNullOrWhiteSpace(value.RecognisedType) : value.RecognisedType is not null)) return false;
            previous = value.Ordinal;
        }
        return Next is not { } next || Values.Count == PageSize && next == (Start with { Ordinal = previous });
    }
}

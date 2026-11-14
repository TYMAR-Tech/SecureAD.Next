using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public enum ServiceAccountPageKind { EntryMemberships, Links, Values, Names, Limitations }

public sealed record SavedServiceAccountFacts(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string ObjectClass, string Name, DateTimeOffset CapturedUtc, EvidenceCompleteness Coverage,
    ServiceAccountKind Kind, uint? UserAccountControl, string MissingInputs, long ServiceNameCount)
{
    internal bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(DomainFqdn) && !string.IsNullOrWhiteSpace(ObjectClass)
        && !string.IsNullOrWhiteSpace(Name) && Enum.IsDefined(Coverage) && Enum.IsDefined(Kind)
        && MissingInputs is not null && ServiceNameCount >= 0
        && (Kind != ServiceAccountKind.SpnBearingUser || ServiceNameCount > 0);
}

public sealed record SavedServiceAccountIdentity(Guid ObjectGuid, string DistinguishedName, string NamingContext,
    string DomainFqdn, string Sid, string? SidScope, string ObjectClass, long? GroupType,
    DateTimeOffset CapturedUtc, EvidenceCompleteness Coverage)
{
    internal bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(NamingContext) && !string.IsNullOrWhiteSpace(DomainFqdn)
        && GroupMembershipFindingStorage.Within(DistinguishedName, NamingContext)
        && Enum.IsDefined(Coverage) && SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null
        && (SecureAD.Kernel.Security.Sid.IsBuiltinDomain(Sid)
            ? string.Equals(SidScope, DomainFqdn, StringComparison.OrdinalIgnoreCase) : SidScope is null)
        && (ObjectClass == "group"
            ? GroupType is { } type && type is >= int.MinValue and <= uint.MaxValue
                && (type & 0x80000000L) != 0 && (type & 0x0f) is 2 or 4 or 5 or 8
                && ((type & 0x0f) == 5) == SecureAD.Kernel.Security.Sid.IsBuiltinDomain(Sid)
            : ObjectClass is "user" or "computer" or "foreignSecurityPrincipal" && GroupType is null);
}

public sealed record SavedServiceAccountName(int OriginalOrdinal, string? Text, bool HasBinary)
{
    public bool IsReadable => OriginalOrdinal >= 0 && !HasBinary && !string.IsNullOrWhiteSpace(Text);
}
public sealed record SavedServiceAccountLink(long Position, SavedServiceAccountIdentity ContainingGroup,
    SavedServiceAccountIdentity Member, SavedServiceAccountIdentity RecordedThrough, long WitnessCount, bool IsPrimaryGroup);
public sealed record SavedServiceAccountWitness(SavedServiceAccountIdentity Source, string Attribute, int OriginalOrdinal, string Value);

public sealed record SavedServiceAccountContext(FindingReference Reference, string RuleId, FindingSubject Subject,
    SavedServiceAccountFacts Account, SavedServiceAccountIdentity? SourceIdentity, SavedServiceAccountIdentity? Target,
    long EntryMembershipCount, long LinkCount, long LimitationCount, bool InputsComplete,
    MembershipRouteIncompleteReason RouteIncompleteReasons, bool IsComplete)
{
    private static readonly MembershipRouteIncompleteReason KnownReasons = Enum.GetValues<MembershipRouteIncompleteReason>()
        .Aggregate(MembershipRouteIncompleteReason.None, (all, value) => all | value);
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved service-account details are missing, invalid or inconsistent.";
    public const string AssociationNote = "Service association is based on captured account class or service principal names, not observed service use.";
    public const string LimitationsNote = "Recorded positive membership remains a finding. Other routes or administrative destinations may not have been fully assessed.";
    public const string AdministrativeStatement = "The saved assessment records security membership from this service-associated account to the administrative group shown.";
    public const string PasswordStatement = "The captured ordinary user has service principal names and Password never expires set.";
    public const string AdministrativeWhy = "Administrative membership can give a service-associated account more authority than its service needs. "
        + "A managed password does not make excessive membership safe. This finding does not prove effective access to a particular object, "
        + "a successful operation, account takeover or a completed path to Tier 0.";
    public const string AdministrativeAction = "Confirm the account owner, service dependencies and administrative need. "
        + "If membership is unintended, remove only unnecessary memberships under change control and grant only the permissions the service needs. "
        + "For primary-group membership, review the account's primary-group configuration rather than treating it as an ordinary group-member entry. "
        + "Review shared-group effects and other routes, then test dependent services. Removing one link does not establish that all administrative access is gone.";
    public const string PasswordWhy = "Without an appropriate password-management arrangement, a service account may retain a credential longer than intended. "
        + "This setting does not prove that the password has never changed, is old or weak, or lacks external rotation. "
        + "It is not proof of successful authentication, account takeover or a completed path to Tier 0.";
    public const string PasswordAction = "Confirm the account owner, actual service use and password-rotation arrangements, including any external vault or automation. "
        + "For a required service, consider a supported managed service account or a coordinated credential-management plan. "
        + "Check dependencies before changing the setting or credentials, then test dependent services. "
        + "Do not simply enable expiry, reset credentials blindly or remove service principal names merely to suppress this finding.";

    public bool IsAdministrative => RuleId == "SEC-100";
    public static string Statement(string rule) => rule switch
    {
        "SEC-100" => AdministrativeStatement,
        "SEC-101" => PasswordStatement,
        _ => throw new ArgumentOutOfRangeException(nameof(rule), rule, "This rule has no service-account presentation."),
    };

    public bool Matches(FindingListItem finding) => RuleId is "SEC-100" or "SEC-101" && finding.RuleId == RuleId
        && Reference == finding.Reference && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0
        && finding.RuleVersion == 1 && finding.Severity == (IsAdministrative ? Severity.High : Severity.Medium)
        && Subject == finding.Subject && Subject.Kind == FindingSubjectKind.Account && Account is { IsValid: true }
        && Account.ObjectGuid == finding.ObjectGuid && Account.DistinguishedName == finding.DistinguishedName
        && Account.DomainFqdn == finding.DomainFqdn && Account.ObjectClass == finding.ObjectClass
        && Account.Name == finding.PrincipalName && Account.Coverage == finding.Coverage
        && IsComplete == finding.EvidenceIsComplete && EntryMembershipCount >= 0 && LinkCount >= 0 && LimitationCount >= 0
        && (RouteIncompleteReasons & ~KnownReasons) == 0 && !RouteIncompleteReasons.HasFlag(MembershipRouteIncompleteReason.ForestMaskUnreadable)
        && (IsAdministrative
            ? SourceIdentity is { IsValid: true, ObjectClass: "user" or "computer" }
                && SourceIdentity.ObjectGuid == Account.ObjectGuid && SourceIdentity.DistinguishedName == Account.DistinguishedName
                && SourceIdentity.DomainFqdn == Account.DomainFqdn && SourceIdentity.CapturedUtc == Account.CapturedUtc
                && SourceIdentity.Coverage == Account.Coverage && Target is { IsValid: true, ObjectClass: "group" }
                && Target.ObjectGuid != Account.ObjectGuid && Subject.Key == ServiceAccountWithAdministrativeMembership.Key(Account.ObjectGuid, Target.ObjectGuid)
                && EntryMembershipCount > 0 && LinkCount >= EntryMembershipCount
                && IsComplete == (Account.MissingInputs.Length == 0 && InputsComplete
                    && RouteIncompleteReasons == MembershipRouteIncompleteReason.None && LimitationCount == 0)
            : SourceIdentity is null && Target is null && Subject.Key == Account.ObjectGuid.ToString("D")
                && Account.Kind == ServiceAccountKind.SpnBearingUser && Account.UserAccountControl is { } control
                && (control & ServiceAccountWithNonExpiringPassword.DontExpirePassword) != 0
                && EntryMembershipCount == 0 && LinkCount == 0 && LimitationCount == 0 && InputsComplete
                && RouteIncompleteReasons == MembershipRouteIncompleteReason.None && IsComplete == (Account.MissingInputs.Length == 0));

    internal bool Matches(ServiceAccountMark mark, ServiceAccountPageKind kind, long link, long total) =>
        mark.GenerationId == Reference.GenerationId && mark.FindingId == Reference.FindingId
        && mark.AccountGuid == Account.ObjectGuid && mark.TargetGuid == Target?.ObjectGuid
        && mark.Kind == kind && mark.LinkPosition == link && mark.Offset > 0 && mark.Offset < total && mark.Offset % PageSize == 0;
}

public readonly record struct ServiceAccountMark(Guid GenerationId, long FindingId, Guid AccountGuid, Guid? TargetGuid,
    ServiceAccountPageKind Kind, long LinkPosition, long Offset);
public sealed record SavedServiceAccountRow<T>(long Position, T Value);
public sealed record SavedServiceAccountDetails(SavedServiceAccountContext Context,
    SavedServiceAccountPage<SavedServiceAccountLink>? EntryMemberships)
{
    public bool Matches(FindingListItem finding) => Context is not null && Context.Matches(finding)
        && (Context.IsAdministrative
            ? EntryMemberships is { } entries && entries.Context == Context
                && entries.Kind == ServiceAccountPageKind.EntryMemberships && entries.IsExpectedPage(null)
            : EntryMemberships is null);
}

public sealed record SavedServiceAccountPage<T>(SavedServiceAccountContext Context, ServiceAccountPageKind Kind,
    SavedServiceAccountLink? SelectedLink, IReadOnlyList<SavedServiceAccountRow<T>> Rows, ServiceAccountMark? Next)
{
    public bool IsExpectedPage(ServiceAccountMark? after)
    {
        var typeMatches = typeof(T) == typeof(SavedServiceAccountName) ? Kind == ServiceAccountPageKind.Names
            : typeof(T) == typeof(SavedServiceAccountLink) ? Kind is ServiceAccountPageKind.EntryMemberships or ServiceAccountPageKind.Links
            : typeof(T) == typeof(SavedServiceAccountWitness) ? Kind == ServiceAccountPageKind.Values
            : typeof(T) == typeof(AdministrativeMembershipLimitation) && Kind == ServiceAccountPageKind.Limitations;
        if (!typeMatches || Context is null || Rows is null || !Enum.IsDefined(Kind)
            || !Context.IsAdministrative && Kind != ServiceAccountPageKind.Names
            || (Kind == ServiceAccountPageKind.Values) != (SelectedLink is not null)) return false;
        var total = Kind switch
        {
            ServiceAccountPageKind.Names => Context.Account.ServiceNameCount,
            ServiceAccountPageKind.EntryMemberships => Context.EntryMembershipCount,
            ServiceAccountPageKind.Links => Context.LinkCount,
            ServiceAccountPageKind.Values => SelectedLink!.WitnessCount,
            _ => Context.LimitationCount,
        };
        var link = SelectedLink?.Position ?? -1;
        var start = after?.Offset ?? 0;
        return start >= 0 && (start < total || start == 0 && total == 0)
            && (after is not { } previous || Context.Matches(previous, Kind, link, total))
            && Rows.Count == Math.Min(SavedServiceAccountContext.PageSize, total - start)
            && Rows.Select((row, index) => row is not null && row.Position == start + index && ValidValue(row.Value)).All(value => value)
            && (Next is not null) == (start + Rows.Count < total)
            && (Next is not { } next || Context.Matches(next, Kind, link, total) && next.Offset == start + Rows.Count);
    }

    private bool ValidValue(T value) => value switch
    {
        SavedServiceAccountName => true,
        SavedServiceAccountLink link => ValidLink(link)
            && (Kind != ServiceAccountPageKind.EntryMemberships || link.Member.ObjectGuid == Context.Account.ObjectGuid),
        SavedServiceAccountWitness witness => SelectedLink is { } link && ValidLink(link) && witness.OriginalOrdinal >= 0
            && (witness.Attribute switch
            {
                "member" => witness.Source == link.ContainingGroup
                    && Same(witness.Value, link.RecordedThrough.DistinguishedName),
                "memberOf" => witness.Source == link.RecordedThrough
                    && Same(witness.Value, link.ContainingGroup.DistinguishedName),
                "primaryGroupID" => link.IsPrimaryGroup && witness.Source == link.Member && link.Member == link.RecordedThrough
                    && link.Member.ObjectGuid == Context.Account.ObjectGuid && witness.OriginalOrdinal == 0
                    && uint.TryParse(witness.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var rid)
                    && Same(link.Member.DomainFqdn, link.ContainingGroup.DomainFqdn)
                    && Same(link.ContainingGroup.Sid, Sid.IssuingDomain(link.Member.Sid) + "-" + rid.ToString(CultureInfo.InvariantCulture)),
                _ => false,
            }),
        AdministrativeMembershipLimitation limitation => Enum.IsDefined(limitation.Reason)
            && !string.IsNullOrWhiteSpace(limitation.DistinguishedName),
        _ => false,
    };
    private bool ValidLink(SavedServiceAccountLink link) => link.Position >= 0 && link.Position < Context.LinkCount && link.WitnessCount > 0
        && link.ContainingGroup is { IsValid: true, ObjectClass: "group" }
        && link.Member is { IsValid: true, ObjectClass: "group" or "user" or "computer" }
        && link.RecordedThrough is { IsValid: true }
        && (link.Member.ObjectClass == "group" || link.Member == Context.SourceIdentity)
        && Same(link.Member.Sid, link.RecordedThrough.Sid)
        && RequesterTrusteeReading.SupportsSecurityNesting(link.ContainingGroup.GroupType!.Value, link.Member.GroupType,
            Same(link.ContainingGroup.DomainFqdn, link.Member.DomainFqdn), Sid.IsBuiltinDomain(link.ContainingGroup.Sid))
        && ((link.ContainingGroup.GroupType.Value & 0x0f) is not (4 or 5)
            || Same(link.ContainingGroup.DomainFqdn, Context.Target!.DomainFqdn))
        && (link.Member.ObjectGuid == link.RecordedThrough.ObjectGuid
            ? link.Member == link.RecordedThrough
            : link.RecordedThrough.ObjectClass == "foreignSecurityPrincipal"
                && Same(link.RecordedThrough.DomainFqdn, link.ContainingGroup.DomainFqdn)
                && (!Sid.IsBuiltinDomain(link.Member.Sid) || Same(link.RecordedThrough.DomainFqdn, link.Member.DomainFqdn)));
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
}

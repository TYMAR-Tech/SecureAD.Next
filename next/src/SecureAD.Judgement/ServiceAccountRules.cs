using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>SEC-100 reports established administrative security membership, not protection status or takeover.</summary>
public sealed class ServiceAccountWithAdministrativeMembership : IObjectRule
{
    internal const int PolicyVersion = 1;
    internal const string ScopeNote = "Service association is identified from the captured account class or SPN registration, not observed service usage. "
        + "Membership does not prove account takeover or a completed path to Tier 0.";
    internal const string Guidance = "Review the recorded membership links and service dependencies before removing unintended administrative membership. "
        + "Grant only the permissions the service needs, and review other membership routes before concluding the exposure is removed.";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-100", "Service-associated account with administrative membership", Severity.High, 1,
        ["user", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"],
        ["objectClass", "objectGUID", "objectSid", "servicePrincipalName", "userAccountControl", "sAMAccountName",
            "primaryGroupID", "member", "memberOf", "groupType", "sIDHistory"], [nameof(DerivedFactKind.AdministrativeMembership)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException("SEC-100 requires its declared saved membership inputs.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var reading = ServiceAccountReading.Read(subject, includeManaged: true);
        if (reading.Account is not { } account) return new([], reading.Missing, []);
        if (context.AdministrativeMembership is not { } index || context.MembershipRoutes is null)
            return new([], reading.Missing, [new(DerivedFactKind.AdministrativeMembership, UnresolvedReason.NotDerived)]);
        var sid = AdministrativeMembershipIndex.ReadSid(subject);
        if (sid is null) return RuleVerdict.CouldNotJudge([.. reading.Missing, "objectSid"]);
        var assessment = index.ForServiceAccount(subject, context.MembershipRoutes(sid, null));
        var findings = assessment.Memberships.Select(membership =>
        {
            var target = membership.Principals.Single(principal => principal.ObjectGuid == membership.TargetGuid);
            var names = membership.Principals.ToDictionary(principal => principal.ObjectGuid, principal => principal.DistinguishedName);
            var detail = ServiceAccountReading.Name(subject) + " is a " + ServiceAccountReading.Describe(account.Kind)
                + " with an established security-membership route to " + target.DistinguishedName + ". "
                + ScopeNote + ServiceAccountReading.DisabledNote(account)
                + "\n\nRecorded membership links:\n" + string.Join("\n", membership.Links.Select(link =>
                    names[link.GroupGuid] + " contains " + names[link.MemberGuid]
                    + (link.MemberReferenceGuid == link.MemberGuid ? "" : " (recorded through " + names[link.MemberReferenceGuid] + ")")
                    + (link.Witnesses.Any(witness => witness.Attribute == "primaryGroupID") ? " (primary-group membership)" : "")));
            if (!membership.IsComplete)
                detail += "\n\nAdditional administrative membership could not be fully assessed."
                    + (membership.RouteIncompleteReasons == MembershipRouteIncompleteReason.None ? "" : " "
                        + new MembershipRouteSummary([], membership.RouteIncompleteReasons).CompletenessDescription)
                    + string.Concat(membership.Limitations.Select(limit => "\n" + AdministrativeMembershipIndex.Describe(limit.Reason)
                        + ": " + limit.DistinguishedName));
            return new Finding(Definition.Id, Definition.Version, Definition.Severity,
                new(FindingSubjectKind.Account, Key(account.ObjectGuid, target.ObjectGuid)), account.ObjectGuid,
                account.DistinguishedName, account.DomainFqdn, ServiceAccountReading.ObjectClass(account), detail,
                subject.Completeness, new ServiceAccountFindingEvidence(account, membership))
                { PrincipalName = ServiceAccountReading.Name(subject) };
        }).ToArray();
        return new(findings, reading.Missing.Concat(assessment.Missing).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(), assessment.Unresolved);
    }

    internal static string Key(Guid account, Guid target) => account.ToString("D") + ":" + target.ToString("D");
}

/// <summary>SEC-101 reports a captured non-expiring-password setting, never measured password nonrotation.</summary>
public sealed class ServiceAccountWithNonExpiringPassword : IObjectRule
{
    internal const uint DontExpirePassword = 0x00010000;
    internal const string ScopeNote = "A captured SPN associates this ordinary user with a service name, not observed service usage. "
        + "The setting does not prove that its password has never been rotated, account takeover or a completed path to Tier 0.";
    internal const string Guidance = "Review why Password never expires is enabled and how this account's password is managed. "
        + "If it runs a service, check dependencies before changing the setting or moving the service to a managed service account.";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new("SEC-101", "SPN-bearing user with Password never expires", Severity.Medium, 1,
        ["user"], ["objectClass", "objectGUID", "servicePrincipalName", "userAccountControl", "sAMAccountName"], []);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject)
    {
        var reading = ServiceAccountReading.Read(subject, includeManaged: false);
        if (reading.Account is not { } account || account.UserAccountControl is not { } control)
            return new([], reading.Missing, []);
        if ((control & DontExpirePassword) == 0) return new([], reading.Missing, []);
        var finding = new Finding(Definition.Id, Definition.Version, Definition.Severity,
            new(FindingSubjectKind.Account, account.ObjectGuid.ToString("D")), account.ObjectGuid, account.DistinguishedName,
            account.DomainFqdn, ServiceAccountReading.ObjectClass(account),
            ServiceAccountReading.Name(subject) + " is an ordinary user with a captured SPN and Password never expires set. "
                + ScopeNote + ServiceAccountReading.DisabledNote(account),
            subject.Completeness, new ServiceAccountFindingEvidence(account, null))
            { PrincipalName = ServiceAccountReading.Name(subject) };
        return new([finding], reading.Missing, []);
    }
}

internal static class ServiceAccountReading
{
    internal sealed record Reading(ServiceAccountAssociation? Account, IReadOnlyList<string> Missing);

    internal static Reading Read(ObjectAttributes subject, bool includeManaged)
    {
        ArgumentNullException.ThrowIfNull(subject);
        var classes = subject.Find("objectClass")?.Values;
        if (classes is not { Count: > 0 } || !Ordered(classes)
            || classes.Any(value => value.Bytes is not null || string.IsNullOrWhiteSpace(value.Text)))
            return new(null, ["objectClass"]);
        var groupManaged = HasClass("msDS-GroupManagedServiceAccount");
        var managed = groupManaged || HasClass("msDS-ManagedServiceAccount");
        var ordinary = !managed && !HasClass("computer") && !HasClass("group") && Same(classes[^1].Text, "user");
        if (!ordinary && (!includeManaged || !managed)) return new(null, []);
        var missing = new List<string>();
        var services = subject.Find("servicePrincipalName");
        var spns = services?.Values ?? [];
        if (ordinary)
        {
            if (services is null) return new(null, ["servicePrincipalName"]);
            if (spns.Count == 0) return new(null, []);
            if (!Ordered(spns) || spns.Any(value => !ReadableSpn(value))) missing.Add("servicePrincipalName");
            if (!spns.Any(ReadableSpn)) return new(null, ["servicePrincipalName"]);
        }
        if (subject.ObjectGuid is null || subject.ObjectGuid == Guid.Empty) missing.Add("objectGUID");
        if (string.IsNullOrWhiteSpace(subject.DomainFqdn)) missing.Add(nameof(ObjectAttributes.DomainFqdn));
        var controls = subject.Find("userAccountControl")?.Values ?? [];
        var control = ReadControl(controls);
        if (control is null) missing.Add("userAccountControl");
        if (subject.ObjectGuid is not { } guid || guid == Guid.Empty || string.IsNullOrWhiteSpace(subject.DomainFqdn))
            return new(null, missing);
        var kind = groupManaged ? ServiceAccountKind.GroupManagedServiceAccount
            : managed ? ServiceAccountKind.StandaloneManagedServiceAccount : ServiceAccountKind.SpnBearingUser;
        var account = new ServiceAccountAssociation(guid, subject.DistinguishedName, subject.DomainFqdn, subject.CapturedUtc,
            subject.Completeness, kind, Own(classes), Own(spns), Own(controls), control, missing.ToArray());
        return new(account, account.MissingAttributes);

        bool HasClass(string name) => classes.Any(value => Same(value.Text, name));
    }

    internal static uint? ReadControl(IReadOnlyList<AttributeValue> values) => values is { Count: 1 }
        && values[0] is { Ordinal: 0, Bytes: null, Text: { } text }
        && uint.TryParse(text, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var control)
            ? control : null;
    internal static bool ReadableSpn(AttributeValue value) => value.Ordinal >= 0 && value.Bytes is null && !string.IsNullOrWhiteSpace(value.Text);
    internal static bool Ordered(IReadOnlyList<AttributeValue> values) =>
        values.Select(value => value.Ordinal).SequenceEqual(Enumerable.Range(0, values.Count));
    internal static string ObjectClass(ServiceAccountAssociation account) => account.ObjectClasses[^1].Text!;
    internal static string Name(ObjectAttributes subject) => AttributeReading.Text(subject, "sAMAccountName") is { Length: > 0 } name
        ? name : subject.DistinguishedName;
    internal static string Describe(ServiceAccountKind kind) => kind switch
    {
        ServiceAccountKind.SpnBearingUser => "service-associated SPN-bearing user",
        ServiceAccountKind.StandaloneManagedServiceAccount => "standalone managed service account (sMSA)",
        ServiceAccountKind.GroupManagedServiceAccount => "group managed service account (gMSA)",
        _ => throw new InvalidDataException("The service-account association kind is not supported."),
    };
    internal static string DisabledNote(ServiceAccountAssociation account) => account.UserAccountControl is not { } control
        ? " The enabled or disabled state could not be read."
        : (control & 2) != 0 ? " The account is currently disabled; this is dormant exposure that would return if it were re-enabled." : "";
    private static AttributeValue[] Own(IReadOnlyList<AttributeValue> values) =>
        values.Select(value => value with { Bytes = value.Bytes?.ToArray() }).ToArray();
    private static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
}

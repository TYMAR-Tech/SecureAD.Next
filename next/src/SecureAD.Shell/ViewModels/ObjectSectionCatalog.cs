using SecureAD.Evidence;
using SecureAD.Kernel.Capture;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One section of the object view: a heading, and the attributes it is responsible for showing.
/// </summary>
/// <param name="Key">The section's stable name, used to choose its control.</param>
/// <param name="Title">What the section is called on screen.</param>
/// <param name="Attributes">
/// The attributes this section shows. Empty for a section built from something other than
/// attributes - <c>Permissions</c> is built from the security descriptor and <c>Evidence</c> from
/// the run's own record of what it read.
/// </param>
internal sealed record ObjectSectionDefinition(
    string Key,
    string Title,
    IReadOnlyList<string> Attributes)
{
    /// <summary>
    /// A row for each attribute this section is responsible for, in the order it claims them.
    /// </summary>
    /// <remarks>
    /// Built from the section's own attribute list rather than from what arrived, so a section
    /// shows every attribute it is answerable for and an absent value is a row saying so. A
    /// section that listed its rows separately would be free to drift from the list the gate
    /// checks.
    /// </remarks>
    /// <param name="attributes">
    /// What the bundle holds for the object, or null when no attributes were read.
    /// </param>
    public IReadOnlyList<AttributeValueViewModel> Rows(ObjectAttributes? attributes) =>
        [.. Attributes.Select(a => new AttributeValueViewModel(
            a,
            attributes?.Find(a),
            attributes is not null,
            attributes?.CapturedUtc ?? DateTimeOffset.MinValue))];
}

/// <summary>
/// Which sections the object view shows for an object of a given class, and which attribute each
/// section is responsible for.
/// </summary>
/// <remarks>
/// <para>
/// <b>The section list is driven by the object's class, never by whether a value arrived.</b> An
/// attribute that did not arrive and one the object never had are the same emptiness on the wire -
/// Active Directory omits an absent attribute without saying whether the caller was refused
/// (<c>docs/decisions/0022</c>). So hiding a section because it is empty would hide <i>we were
/// refused this</i> behind <i>there is nothing here</i>, which is the failure
/// <c>docs/decisions/0002</c> exists to prevent. Hiding the LAPS section on a user is a different
/// statement: a user is not a thing LAPS applies to, which is a judgement this product owns and can
/// defend.
/// </para>
/// <para>
/// <b>This is not a claim about what capture requested.</b> Capture asks every object for every
/// attribute whatever its class, and cannot do otherwise - an LDAP search names its attributes
/// before any object's class is known. <see cref="CapturedAttributeCatalog.AttributesJustifiedBy"/>
/// answers the different question of which class's needs justify carrying an attribute, and that is
/// the question this type is a presentation of. Reading it as request scope is a mistake that has
/// already cost one session and produced a finding that was wrong.
/// </para>
/// <para>
/// <b>Curation may not hide a captured value.</b> Because the request is unscoped, an object can
/// carry a value its class does not justify. Anything captured that no section for this class
/// claims appears under <see cref="OtherValues"/> - and only when it has a value, so a user never
/// shows an empty computer section. Class decides which sections exist; presence decides only that
/// one.
/// </para>
/// <para>
/// <b>The gate.</b> <c>ObjectSectionCatalogTests</c> asserts that every attribute a class justifies
/// is either claimed by one of that class's sections or named in <see cref="NotShown"/> with a
/// reason. This is the direction <c>CapturedAttributeCatalogDocumentationTests</c> records as
/// missing and calls the one with the one-way door in it (<c>F-S7-24</c>, <c>F-S44-2</c>): the
/// existing check proves an attribute names a consumer in prose, and nothing proved the consumer
/// exists. Three LAPS and operating-system attributes have been captured on every computer in every
/// bundle since 2026-08-13 for rules that were never written, and nothing can show them. That is
/// the state this gate makes impossible to reach silently.
/// </para>
/// </remarks>
internal static class ObjectSectionCatalog
{
    /// <summary>The section every object opens on: who it is, and how this run found it.</summary>
    public const string Overview = "Overview";

    /// <summary>What kind of account it is and what state it is in.</summary>
    public const string Account = "Account";

    /// <summary>The ways this object can act as, or be acted for by, something else.</summary>
    public const string Delegation = "Delegation";

    /// <summary>Whether the local administrator password is managed, and by which product.</summary>
    public const string Laps = "Laps";

    /// <summary>What this object belongs to, and what belongs to it.</summary>
    public const string Membership = "Membership";

    /// <summary>What kind of group it is.</summary>
    public const string Group = "Group";

    /// <summary>Who may retrieve this account's managed password.</summary>
    public const string PasswordReaders = "PasswordReaders";

    /// <summary>The policies linked to this container.</summary>
    public const string PolicyLinks = "PolicyLinks";

    /// <summary>What this policy is and what it carries.</summary>
    public const string Policy = "Policy";

    /// <summary>The domain's own password and lockout policy.</summary>
    public const string PasswordPolicy = "PasswordPolicy";

    /// <summary>A fine-grained policy that overrides the domain's for the principals it names.</summary>
    public const string PasswordSettings = "PasswordSettings";

    /// <summary>Who can do what to this object.</summary>
    public const string Permissions = "Permissions";

    /// <summary>Captured values no section for this class claims. Shown only when there are some.</summary>
    public const string OtherValues = "OtherValues";

    /// <summary>How this run came by this object, and what it could not read.</summary>
    public const string Evidence = "Evidence";

    private static readonly ObjectSectionDefinition OverviewSection = new(
        Overview,
        "Overview",
        [
            "objectClass",
            "objectGUID",
            "objectSid",
            "sAMAccountName",
            "userPrincipalName",
            "description",
            "whenCreated",
            "sIDHistory",
        ]);

    private static readonly ObjectSectionDefinition AccountSection = new(
        Account,
        "Account",
        [
            "userAccountControl",
            "adminCount",
            "pwdLastSet",
            "accountExpires",
            "lastLogonTimestamp",
            "primaryGroupID",
            "operatingSystem",
        ]);

    /// <summary>
    /// The five ways an account can act as something else, or let something else act as it.
    /// </summary>
    /// <remarks>
    /// <c>msDS-AllowedToActOnBehalfOfOtherIdentity</c> is a security descriptor rather than a list,
    /// so it is read and worded by the same machinery as the object's own permissions.
    /// </remarks>
    private static readonly ObjectSectionDefinition DelegationSection = new(
        Delegation,
        "Delegation",
        [
            "servicePrincipalName",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "msDS-KeyCredentialLink",
            "msDS-SupportedEncryptionTypes",
        ]);

    /// <summary>
    /// Which LAPS product is managing this machine's local administrator password, and whether it
    /// is still rotating it.
    /// </summary>
    /// <remarks>
    /// The expiry timestamps only. The passwords themselves sit on the same object and are refused
    /// by <c>CredentialAttributeGuardTests</c>: this product never captures a credential.
    /// </remarks>
    private static readonly ObjectSectionDefinition LapsSection = new(
        Laps,
        "Local administrator password",
        ["ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"]);

    private static readonly ObjectSectionDefinition MembershipSection = new(
        Membership, "Membership", ["memberOf", "member", "primaryGroupID"]);

    private static readonly ObjectSectionDefinition GroupSection = new(
        Group, "Group", ["groupType", "adminCount", "sAMAccountName", "sIDHistory"]);

    /// <summary>
    /// Who may retrieve a group managed service account's password - which is a security
    /// descriptor, and so is read and worded like any other.
    /// </summary>
    private static readonly ObjectSectionDefinition PasswordReadersSection = new(
        PasswordReaders, "Password readers", ["msDS-GroupMSAMembership"]);

    private static readonly ObjectSectionDefinition PolicyLinksSection = new(
        PolicyLinks, "Linked policies", ["gPLink", "gPOptions"]);

    private static readonly ObjectSectionDefinition PolicySection = new(
        Policy,
        "Policy",
        ["displayName", "gPCFileSysPath", "flags", "versionNumber", "gPCMachineExtensionNames"]);

    /// <summary>
    /// The domain's own password and lockout policy, as the directory holds it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Shown, never graded.</b> The owner ruled on 2026-08-25 that SecureAD is not a policy
    /// compliance checker, so no value here carries a verdict and no rule reads any of them. A
    /// threshold of zero is reported as zero, not as weak.
    /// </para>
    /// <para>
    /// <b>This is the baseline a fine-grained policy overrides</b>, which is why the two are
    /// captured and shown together: a policy settings object read without the default it displaces
    /// says nothing about what a given account is actually subject to.
    /// </para>
    /// </remarks>
    private static readonly ObjectSectionDefinition PasswordPolicySection = new(
        PasswordPolicy,
        "Password and lockout policy",
        [
            "minPwdLength",
            "maxPwdAge",
            "minPwdAge",
            "pwdHistoryLength",
            "pwdProperties",
            "lockoutThreshold",
            "lockoutDuration",
            "lockOutObservationWindow",
        ]);

    /// <summary>
    /// A fine-grained password policy: what it sets, who it applies to, and which policy wins.
    /// </summary>
    /// <remarks>
    /// <c>msDS-PasswordSettingsPrecedence</c> leads because it is the only value that answers the
    /// question an operator actually arrives with - several policies can name one principal, and
    /// without precedence a list of them cannot say which is in force.
    /// </remarks>
    private static readonly ObjectSectionDefinition PasswordSettingsSection = new(
        PasswordSettings,
        "Fine-grained password policy",
        [
            "msDS-PasswordSettingsPrecedence",
            "msDS-PSOAppliesTo",
            "msDS-MinimumPasswordLength",
            "msDS-MaximumPasswordAge",
            "msDS-MinimumPasswordAge",
            "msDS-PasswordHistoryLength",
            "msDS-PasswordComplexityEnabled",
            "msDS-PasswordReversibleEncryptionEnabled",
            "msDS-LockoutThreshold",
            "msDS-LockoutDuration",
            "msDS-LockoutObservationWindow",
        ]);

    /// <summary>
    /// The object's own access control list. Built from the security descriptor rather than shown
    /// as an attribute value, which is why it claims <c>nTSecurityDescriptor</c> and lists no
    /// others.
    /// </summary>
    private static readonly ObjectSectionDefinition PermissionsSection = new(
        Permissions, "Permissions", ["nTSecurityDescriptor"]);

    private static readonly ObjectSectionDefinition OtherValuesSection = new(
        OtherValues, "Other captured values", []);

    private static readonly ObjectSectionDefinition EvidenceSection = new(
        Evidence, "Evidence", []);

    /// <summary>The sections an account of any kind gets, in the order they are read in.</summary>
    private static readonly ObjectSectionDefinition[] AccountSections =
    [
        OverviewSection,
        AccountSection,
        DelegationSection,
        MembershipSection,
        PermissionsSection,
    ];

    private static readonly Dictionary<string, ObjectSectionDefinition[]> ByClass =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["user"] = AccountSections,
            ["inetOrgPerson"] = AccountSections,
            ["msDS-ManagedServiceAccount"] = AccountSections,

            ["computer"] =
            [
                OverviewSection,
                AccountSection,
                LapsSection,
                DelegationSection,
                MembershipSection,
                PermissionsSection,
            ],

            ["msDS-GroupManagedServiceAccount"] =
            [
                OverviewSection,
                AccountSection,
                PasswordReadersSection,
                DelegationSection,
                MembershipSection,
                PermissionsSection,
            ],

            ["group"] = [OverviewSection, GroupSection, MembershipSection, PermissionsSection],
            ["organizationalUnit"] = [OverviewSection, PolicyLinksSection, PermissionsSection],
            ["groupPolicyContainer"] = [OverviewSection, PolicySection, PermissionsSection],
            ["domainDNS"] = [OverviewSection, PasswordPolicySection, PermissionsSection],
            ["msDS-PasswordSettings"] = [OverviewSection, PasswordSettingsSection, PermissionsSection],
        };

    /// <summary>
    /// Attributes deliberately not shown, and why. An attribute in neither a section nor here fails
    /// the build.
    /// </summary>
    /// <remarks>
    /// <b>A reason, written down, rather than an omission.</b> The point of the gate is not that
    /// everything captured must reach a screen - some values are only ever inputs to a rule. It is
    /// that the decision is made once, in writing, by somebody who had to think about it, instead
    /// of an attribute quietly riding in every bundle forever with nothing able to show it.
    /// </remarks>
    public static IReadOnlyDictionary<string, string> NotShown { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["objectCategory"] =
                "The same fact as objectClass, in a form an operator does not use. The overview "
                + "shows the class.",
            ["distinguishedName"] =
                "Shown above every section as the object's own heading, in full and selectable, "
                + "because an operator reading any section needs to be certain which object this "
                + "is. A row repeating it inside the overview was on screen 2026-08-18 and read "
                + "as two facts rather than one.",
            ["managedBy"] =
                "Captured but not yet shown. It is the owner of record - a distinguished name the "
                + "directory carries - and it is a different thing from the security owner the "
                + "permissions section already shows. Putting the two side by side without "
                + "wording that distinction would invite an operator to read a contact as a "
                + "controller, which is the wrong answer to who can change this object.",
        };

    /// <summary>
    /// What each attribute is called on screen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Written rather than derived from the name.</b> Splitting <c>sAMAccountName</c> on its
    /// capitals produces <i>S AM Account Name</i>, and no rule turns <c>gPLink</c> into anything an
    /// operator recognises. A label is a small piece of prose and is written as one.
    /// </para>
    /// <para>
    /// The attribute's own name is shown beside the label rather than replaced by it: an operator
    /// checking this product against <c>ldp.exe</c> needs the name the directory uses, and a
    /// friendly label alone would make that impossible.
    /// </para>
    /// </remarks>
    public static IReadOnlyDictionary<string, string> Labels { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["objectClass"] = "Class",
            ["objectGUID"] = "Object identifier",
            ["objectSid"] = "Security identifier",
            ["sAMAccountName"] = "Account name",
            ["userPrincipalName"] = "User principal name",
            ["description"] = "Description",
            ["whenCreated"] = "Created",
            ["accountExpires"] = "Account expires",
            ["lastLogonTimestamp"] = "Last logon (approximate)",
            ["sIDHistory"] = "Former identifiers",
            ["userAccountControl"] = "Account state",
            ["adminCount"] = "Protected by AdminSDHolder",
            ["pwdLastSet"] = "Password last set",
            ["primaryGroupID"] = "Primary group",
            ["operatingSystem"] = "Operating system",
            ["servicePrincipalName"] = "Service principal names",
            ["msDS-AllowedToDelegateTo"] = "May delegate to",
            ["msDS-AllowedToActOnBehalfOfOtherIdentity"] = "May be acted for by",
            ["msDS-KeyCredentialLink"] = "Key credentials",
            ["msDS-SupportedEncryptionTypes"] = "Supported encryption types",
            ["ms-Mcs-AdmPwdExpirationTime"] = "Legacy LAPS password expires",
            ["msLAPS-PasswordExpirationTime"] = "Windows LAPS password expires",
            ["memberOf"] = "Belongs to",
            ["member"] = "Members",
            ["groupType"] = "Group type",
            ["msDS-GroupMSAMembership"] = "Password readers",
            ["minPwdLength"] = "Minimum password length",
            ["maxPwdAge"] = "Maximum password age",
            ["minPwdAge"] = "Minimum password age",
            ["pwdHistoryLength"] = "Passwords remembered",
            ["pwdProperties"] = "Password options",
            ["lockoutThreshold"] = "Lockout after",
            ["lockoutDuration"] = "Lockout lasts",
            ["lockOutObservationWindow"] = "Failed attempts counted within",
            ["msDS-PasswordSettingsPrecedence"] = "Precedence",
            ["msDS-PSOAppliesTo"] = "Applies to",
            ["msDS-MinimumPasswordLength"] = "Minimum password length",
            ["msDS-MaximumPasswordAge"] = "Maximum password age",
            ["msDS-MinimumPasswordAge"] = "Minimum password age",
            ["msDS-PasswordHistoryLength"] = "Passwords remembered",
            ["msDS-PasswordComplexityEnabled"] = "Complexity required",
            ["msDS-PasswordReversibleEncryptionEnabled"] = "Reversible encryption",
            ["msDS-LockoutThreshold"] = "Lockout after",
            ["msDS-LockoutDuration"] = "Lockout lasts",
            ["msDS-LockoutObservationWindow"] = "Failed attempts counted within",
            ["gPLink"] = "Linked policies",
            ["gPOptions"] = "Inheritance blocked",
            ["displayName"] = "Display name",
            ["gPCFileSysPath"] = "Policy files",
            ["flags"] = "Policy flags",
            ["versionNumber"] = "Version",
            ["gPCMachineExtensionNames"] = "Client-side extensions",
            ["nTSecurityDescriptor"] = "Security descriptor",
        };

    /// <summary>
    /// What <paramref name="ldapDisplayName"/> is called on screen, or the attribute's own name
    /// when nothing has written a label for it.
    /// </summary>
    /// <remarks>
    /// The fallback is the directory's name rather than a blank, because a row with no label is
    /// unreadable and an unlabelled row is at worst terse. <c>ObjectSectionCatalogTests</c> keeps
    /// the fallback from being how labels are supplied.
    /// </remarks>
    /// <param name="ldapDisplayName">The attribute, as the catalogue names it.</param>
    public static string LabelFor(string ldapDisplayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        return Labels.TryGetValue(ldapDisplayName, out var label) ? label : ldapDisplayName;
    }

    /// <summary>
    /// The sections shown for an object of <paramref name="objectClass"/>, in reading order.
    /// </summary>
    /// <remarks>
    /// A class nothing here anticipates gets the sections every object has. Its extra values are
    /// not lost: they reach <see cref="OtherValues"/>, which is the reason that section exists.
    /// </remarks>
    /// <param name="objectClass">
    /// The object's most specific class, or null when it did not arrive.
    /// </param>
    public static IReadOnlyList<ObjectSectionDefinition> For(string? objectClass)
    {
        var sections = objectClass is not null && ByClass.TryGetValue(objectClass, out var known)
            ? known
            : [OverviewSection, PermissionsSection];

        // Evidence is last for every class, and is never a class's own business: how this run came
        // by the object is the same question whatever the object is.
        return [.. sections, OtherValuesSection, EvidenceSection];
    }

    /// <summary>
    /// Every attribute claimed by some section shown for <paramref name="objectClass"/>.
    /// </summary>
    /// <param name="objectClass">The class to answer for.</param>
    public static IReadOnlySet<string> AttributesShownFor(string? objectClass) =>
        For(objectClass)
            .SelectMany(s => s.Attributes)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
}

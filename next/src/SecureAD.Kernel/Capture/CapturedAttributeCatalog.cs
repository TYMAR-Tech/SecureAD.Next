namespace SecureAD.Kernel.Capture;

/// <summary>
/// Every attribute the product asks a domain controller for, and the object classes it asks about.
/// </summary>
/// <remarks>
/// <para>
/// This is the ceiling on everything the product can ever say. Inventory row B2 owns it, and
/// <c>docs/layers/audit/the-attribute-catalogue.md</c> is the document that says, for each entry,
/// what reads it and why - bound by <c>CapturedAttributeCatalogDocumentationTests</c>, so an
/// attribute that cannot name a consumer fails the build rather than sitting in every bundle
/// forever.
/// </para>
/// <para>
/// <b>One filter, and it excludes rather than includes.</b> The previous product offered two
/// object-class filters as radio buttons and asked an operator to choose between them. The
/// rebuild has one behaviour: every object in every naming context capture reads is captured,
/// with <see cref="Universal"/> requested for it whatever its class, and the classes enumerated in
/// <see cref="ObjectClasses"/> getting the extra attributes listed for them. Nothing is invisible
/// because nobody thought of its class. The one exclusion is
/// <see cref="UnreadObjectClasses"/>, which is the 2026-08-11 decision that DNS zones and records
/// are out of scope, stated as a named exclusion so a report can say so rather than reporting
/// silence.
/// </para>
/// <para>
/// <b>This type is a table compiled into the assembly.</b> It reads nothing, opens nothing and
/// cannot fail, so an empty answer means one thing only: the class has no extra attributes. That
/// is why gate 4 exempts it from the bare-collection rule, on the same terms as
/// <c>SchemaGuidCatalog</c> and with the same guard against the exemption outliving its reason.
/// </para>
/// </remarks>
public static class CapturedAttributeCatalog
{
    /// <summary>
    /// The version of this catalogue, recorded in every bundle so a bundle can state what it was
    /// allowed to see.
    /// </summary>
    /// <remarks>
    /// Starts at 1. The previous product's catalogue had reached version 10, and that number is not
    /// carried: per <c>docs/decisions/0001</c> there is no backward compatibility to preserve, and
    /// a version number continuing a sequence would imply that a bundle stamped 10 and a bundle
    /// stamped 11 hold comparable evidence. They do not. Increment when an entry is added or
    /// removed.
    /// <para>
    /// <b>2 - 2026-08-13, at S-23.</b> <see cref="ComputerAttributes"/> added, carrying
    /// <c>operatingSystem</c> and the two LAPS expiration timestamps. Without them SEC-091 and
    /// SEC-092 cannot be answered at all, and a bundle stamped 1 therefore cannot support a LAPS
    /// finding however it is analysed later.
    /// </para>
    /// <para>
    /// <b>3 - 2026-08-18, at S-51.</b> <c>whenCreated</c> on every object, and
    /// <c>userPrincipalName</c>, <c>description</c>, <c>accountExpires</c> and
    /// <c>lastLogonTimestamp</c> on accounts. An object view that can say who a principal is and
    /// whether anybody still uses it needs all five, and a bundle stamped 2 cannot answer a
    /// stale-account question at all.
    /// <para>
    /// <b>Two were refused, and for the same reason.</b> <c>lastLogon</c> and <c>whenChanged</c>
    /// are both documented by Microsoft as not replicated, so each controller holds its own value.
    /// This product reads one controller per domain, so reporting either would present one
    /// controller's view as a fact about the domain - and every judgement built on it would be
    /// wrong in a way nothing on screen could reveal. See <see cref="NotCaptured"/>.
    /// </para>
    /// </para>
    /// <para>
    /// <b>4 - 2026-08-25.</b> <see cref="DomainAttributes"/> and
    /// <see cref="PasswordSettingsAttributes"/> added, carrying the domain's password and lockout
    /// policy, the fine-grained policies that override it, and <c>managedBy</c>. A bundle stamped 3
    /// cannot say what a domain's password policy was, and no later analysis can recover it.
    /// <para>
    /// <b>Nothing checks them, and that is deliberate.</b> The owner ruled on 2026-08-25 that
    /// SecureAD is not a policy compliance checker; these are captured so an operator can see a
    /// domain's policy on the domain object and query it, which <c>docs/decisions/0064</c> makes a
    /// sufficient justification on its own. <c>P-97</c> carries the reasoning, including why the
    /// entries were refused when first proposed - there was no consumer to name until the object
    /// view was named.
    /// </para>
    /// </para>
    /// <para>
    /// <b>5 - 2026-08-28.</b> <see cref="DirectoryServiceAttributes"/> added, carrying
    /// <c>dSHeuristics</c> from the forest's one <c>nTDSService</c> object. A bundle stamped 4
    /// cannot say whether its forest removed any group from the set AdminSDHolder protects, so a
    /// derivation reading one can only state that its protected catalogue might not apply. The
    /// object was already captured; only the value was not asked for.
    /// </para>
    /// <para>
    /// <b>6 - 2026-09-03.</b> <c>operatingSystemVersion</c> added to
    /// <see cref="ComputerAttributes"/>. SEC-091 and SEC-094 decide which LAPS product a machine is
    /// capable of running, and the predecessor decided it by matching the operating system
    /// <i>name</i> - <c>LIKE '%2019%'</c>, <c>LIKE '%2016%'</c> - which its own backlog flagged as
    /// brittle and which under-reported twice: it classed Windows 10 as not applicable when
    /// Microsoft supports Windows LAPS on it, and Server 2012 as not applicable when legacy LAPS
    /// runs on it. The build number is numeric and locale-independent and has neither fault.
    /// <para>
    /// <b>The name is still captured, because the version alone is ambiguous.</b> Windows 10 1607
    /// and Windows Server 2016 are both build 14393, so the build cannot tell a client from a
    /// server. The family comes from the name and the generation from the version; either alone
    /// gives a wrong answer.
    /// </para>
    /// <para>
    /// A bundle stamped 5 can still be judged - the capability classifier falls back to the name,
    /// and the finding records that it did so, per <c>docs/decisions/0086</c>.
    /// </para>
    /// </para>
    /// <para>
    /// <b>7 - 2026-09-03.</b> <c>gPCWQLFilter</c> added to
    /// <see cref="GroupPolicyContainerAttributes"/> and <see cref="WmiFilterAttributes"/> added,
    /// carrying the WMI filters a policy requires a machine to satisfy. A bundle stamped 6 cannot
    /// say whether a policy was filtered at all, so a rule reading one can only offer a warning
    /// that some filter might exist - which an operator learns to skip, and a skipped warning
    /// protects nobody. With them the warning names the filter and shows its query.
    /// <para>
    /// <b>Captured, never evaluated</b>, and what that constrains is recorded in
    /// <c>docs/decisions/0094</c>: a rule may use linked scope to raise a finding and never to
    /// suppress one, because a WMI filter can only narrow a policy's reach, so relying on linked
    /// scope to conclude a machine is covered can say <i>safe</i> about something that is not.
    /// </para>
    /// </para>
    /// </remarks>
    public const int Version = 7;

    /// <summary>
    /// Requested for every object, of every class, in every naming context capture reads.
    /// </summary>
    public static IReadOnlyList<CapturedAttribute> Universal { get; } =
    [
        new("distinguishedName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("objectGUID", AttributeCardinality.SingleValued, AttributeStorage.Binary),
        new("objectClass", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("objectCategory", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("objectSid", AttributeCardinality.SingleValued, AttributeStorage.Binary),
        new("nTSecurityDescriptor", AttributeCardinality.SingleValued, AttributeStorage.Binary),

        // Replicated, and in the global catalogue, so one controller's answer is the domain's
        // answer. Its unreplicated counterpart whenChanged is refused - see NotCaptured.
        new("whenCreated", AttributeCardinality.SingleValued, AttributeStorage.Text),

        new("description", AttributeCardinality.MultiValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// Attributes carried by anything that can hold credentials and act - a user, a computer, or a
    /// managed service account. They are one set because they are one kind of thing: the previous
    /// product kept four near-identical lists and they had drifted apart.
    /// </summary>
    private static IReadOnlyList<CapturedAttribute> AccountAttributes { get; } =
    [
        new("sAMAccountName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("userAccountControl", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("adminCount", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("primaryGroupID", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("memberOf", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("sIDHistory", AttributeCardinality.MultiValued, AttributeStorage.Binary),
        new("servicePrincipalName", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("msDS-AllowedToDelegateTo", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("msDS-AllowedToActOnBehalfOfOtherIdentity", AttributeCardinality.SingleValued, AttributeStorage.Binary),
        new("msDS-KeyCredentialLink", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("msDS-SupportedEncryptionTypes", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("pwdLastSet", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("userPrincipalName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("accountExpires", AttributeCardinality.SingleValued, AttributeStorage.Text),

        // Replicated, unlike lastLogon - but deliberately coarse: a controller only updates it
        // when the value it holds is older than msDS-LogonTimeSyncInterval, which defaults to
        // between 9 and 14 days. Anything worded from it must say so.
        new("lastLogonTimestamp", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// A computer is an account plus the things that decide whether its local administrator
    /// password is being managed, by which of the two LAPS products, and which of them it is
    /// capable of running.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Added 2026-08-13 at S-23, on the owner's decision, when the catalogue was re-derived against
    /// all sixty-two rule cards rather than against the rebuild's progress. SEC-091 decides which
    /// LAPS variant a machine <i>should</i> have from <c>operatingSystem</c>, and SEC-092 decides
    /// whether the password is still being rotated from whichever expiration timestamp is present.
    /// Without these three, both rules report a clean forest whatever the forest looks like - which
    /// is the one thing an audit tool must not do.
    /// </para>
    /// <para>
    /// <b>The timestamps only, never a password.</b> <c>ms-Mcs-AdmPwd</c>, <c>msLAPS-Password</c>
    /// and the encrypted forms sit on the same object and are forbidden by
    /// <c>CredentialAttributeGuardTests</c>. Who may <i>read</i> a LAPS password is answered from
    /// the computer's access control list, which arrives with every object.
    /// </para>
    /// <para>
    /// <b>Microsoft ships both expiration timestamps non-confidential, and this was checked rather
    /// than assumed.</b> The Windows LAPS schema reference gives <c>msLAPS-PasswordExpirationTime</c>
    /// a <c>SearchFlags</c> of <b>0</b>, while every attribute carrying a password -
    /// <c>msLAPS-Password</c> and the encrypted forms - carries <b>904</b>, which Microsoft
    /// decomposes as including <c>fCONFIDENTIAL</c>. Read from the <c>ad.lab</c> schema partition on
    /// 2026-09-03, both expiration attributes returned 0 and both password attributes 904. That is a
    /// coherent split: <i>whether</i> a machine is managed is not a secret, and <i>what the
    /// password is</i> is.
    /// </para>
    /// <para>
    /// <b>The rule still asks, because either can be marked confidential by a forest that chooses
    /// to.</b> Both are schema extensions rather than base-schema attributes, so bit 128 is honoured
    /// on them - it is ignored only where <c>systemFlags</c> is <c>0x10</c>. A confidential attribute
    /// is withheld silently, so an unprivileged run cannot tell <i>not deployed</i> from <i>not
    /// allowed to see it</i>. Telling those apart is the absence work <c>docs/decisions/0002</c>
    /// requires, and it is answered per forest from <c>searchFlags</c> in
    /// <see cref="SchemaPartition"/> rather than guessed.
    /// </para>
    /// <para>
    /// <b>The ROADMAP handoff of 2026-09-02 assumed the opposite</b> - that the attributes this rule
    /// reads may be withheld - and building SEC-091 corrected it. The check is kept because the
    /// default is what Microsoft ships, not what a given forest is.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<CapturedAttribute> ComputerAttributes { get; } =
    [
        .. AccountAttributes,
        new("operatingSystem", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("operatingSystemVersion", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("ms-Mcs-AdmPwdExpirationTime", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msLAPS-PasswordExpirationTime", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// A group managed service account is an account plus one thing no other account has: a
    /// security descriptor naming who may retrieve its password.
    /// </summary>
    private static IReadOnlyList<CapturedAttribute> GroupManagedServiceAccountAttributes { get; } =
    [
        .. AccountAttributes,
        new("msDS-GroupMSAMembership", AttributeCardinality.SingleValued, AttributeStorage.Binary),
    ];

    private static IReadOnlyList<CapturedAttribute> GroupAttributes { get; } =
    [
        new("sAMAccountName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("groupType", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("adminCount", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("member", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("memberOf", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("sIDHistory", AttributeCardinality.MultiValued, AttributeStorage.Binary),
    ];

    private static IReadOnlyList<CapturedAttribute> OrganizationalUnitAttributes { get; } =
    [
        new("gPLink", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("gPOptions", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    private static IReadOnlyList<CapturedAttribute> GroupPolicyContainerAttributes { get; } =
    [
        new("displayName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("gPCFileSysPath", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("flags", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("versionNumber", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("gPCMachineExtensionNames", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("gPCWQLFilter", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// A WMI filter: the WQL queries a policy carrying it requires a machine to satisfy before the
    /// policy applies, per <c>docs/decisions/0094</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>These are captured and never evaluated.</b> A WQL query runs on the target machine
    /// against live WMI, and a bundle holds a directory, so answering <i>did this filter pass on
    /// this machine</i> would mean interpreting the query against captured attributes. A partial
    /// interpreter that mostly works is worse than none: it would produce a scoping answer that
    /// reads as authoritative and is wrong, which is the one thing <c>docs/decisions/0086</c> puts
    /// out of bounds.
    /// </para>
    /// <para>
    /// <b>What capturing them buys is that the gap can be named.</b> Without them a finding can
    /// only warn that some filter might exist; with them it can say which filter, and show the
    /// query, so an operator settles in seconds what they would otherwise have to go and look up.
    /// It also means silence about a filter is a fact rather than an omission - <c>0002</c>.
    /// </para>
    /// <para>
    /// <b>Not hypothetical.</b> The lab forest carries four of these, splitting servers at the
    /// Server 2019 build boundary, and two of them are attached to the LAPS policies that SEC-091
    /// and SEC-092 judge. A session had already concluded twice that WMI filters were unreadable
    /// and then that they were rare on security policies; the owner corrected both, and the
    /// directory settled it.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<CapturedAttribute> WmiFilterAttributes { get; } =
    [
        new("msWMI-Name", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msWMI-ID", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msWMI-Parm2", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// The domain object's own password and lockout policy, and who the directory records as
    /// responsible for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>None of these is checked against a standard, and that is the point of them.</b> SecureAD
    /// does not measure password strength - the owner's ruling of 2026-08-25 is that plenty of
    /// software does, and this is not that product. No rule card reads any of them. They are here
    /// because an operator looking at a domain should be able to see its policy, which is the
    /// object-view justification <c>docs/decisions/0064</c> makes sufficient on its own.
    /// </para>
    /// <para>
    /// <b>They live on the domain object by inheritance.</b> Microsoft places them on
    /// <c>Sam-Domain</c>, which <c>Domain-DNS</c> carries as an auxiliary class, and groups them as
    /// the
    /// <see href="https://learn.microsoft.com/windows/win32/adschema/r-domain-password">Domain-Password</see>
    /// property set that applies to <c>Domain-DNS</c>. So no separate read is needed: the domain
    /// object is already captured, and this list only widens what is asked for it.
    /// </para>
    /// <para>
    /// <b>Stored as text like every other number here.</b> <c>maxPwdAge</c>, <c>minPwdAge</c>,
    /// <c>lockoutDuration</c> and <c>lockOutObservationWindow</c> are <c>Interval</c> values - the
    /// negative count of 100-nanosecond units - and the rest are enumerations. Following
    /// <c>userAccountControl</c> and <c>pwdLastSet</c>, the catalogue keeps the controller's own
    /// representation and leaves interpretation to a reader.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<CapturedAttribute> DomainAttributes { get; } =
    [
        new("minPwdLength", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("maxPwdAge", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("minPwdAge", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("pwdHistoryLength", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("pwdProperties", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("lockoutThreshold", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("lockoutDuration", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("lockOutObservationWindow", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("managedBy", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// A fine-grained password policy - the settings it carries and the principals it applies to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Read together with <see cref="DomainAttributes"/> or not at all.</b> A policy settings
    /// object overrides the domain default for the principals it names, so a list of these without
    /// the default they override says nothing about what is actually enforced.
    /// </para>
    /// <para>
    /// <b>Absence of a policy is a fact only because preflight proved it.</b> These objects carry a
    /// restrictive default access control list, and an account without access reads the Password
    /// Settings Container as <i>empty</i> rather than as <i>denied</i>. That is why
    /// <c>ForPasswordSettingsContainer</c> proves the container readable before a run commits, per
    /// <c>docs/decisions/0048</c>. Without that proof a bundle holding no policy would be
    /// indistinguishable from a bundle whose reader was not allowed to see one.
    /// </para>
    /// <para>
    /// <b><c>msDS-PSOAppliesTo</c> is the only range-liable entry here.</b> Microsoft records it as
    /// <c>Is-Single-Valued: False</c> with syntax <c>Object(DS-DN)</c>
    /// (<see href="https://learn.microsoft.com/windows/win32/adschema/a-msds-psoappliesto">ms-DS-PSO-Applies-To</see>);
    /// every other entry is a scalar setting. Marking it single-valued would truncate a policy that
    /// applies to more principals than the server returns at once, and nothing on screen would say
    /// so.
    /// </para>
    /// <para>
    /// As with the domain policy, <b>nothing here is checked</b> and no rule card reads it.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<CapturedAttribute> PasswordSettingsAttributes { get; } =
    [
        new("msDS-PasswordSettingsPrecedence", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-PSOAppliesTo", AttributeCardinality.MultiValued, AttributeStorage.Text),
        new("msDS-MinimumPasswordLength", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-MaximumPasswordAge", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-MinimumPasswordAge", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-PasswordHistoryLength", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-PasswordComplexityEnabled", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-PasswordReversibleEncryptionEnabled", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-LockoutThreshold", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-LockoutDuration", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("msDS-LockoutObservationWindow", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// Attributes carried by the forest's one <c>nTDSService</c> object, at
    /// <c>CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>One object in a forest, and what it says applies to all of it.</b> <c>dSHeuristics</c> is
    /// a string in which each character position is a separate setting
    /// (<see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5">MS-ADTS
    /// 6.1.1.2.4.1.2</see>), and several of them change what other evidence in a bundle
    /// <i>means</i> rather than adding a fact of their own.
    /// </para>
    /// <para>
    /// <b>Character 16, <c>dwAdminSDExMask</c>, is why it is captured now.</b> It can remove
    /// Account, Server, Print and Backup Operators from the set AdminSDHolder protects, so without
    /// it the protected-principal derivation can only state that its catalogue might not apply.
    /// Two others are already named as gaps elsewhere: <c>fDontStandardizeSDs</c> at character 12,
    /// in <c>docs/decisions/0038</c>, and <c>BlockOwnerImplicitRights</c> at character 29, which
    /// the judgement-half specification needs.
    /// </para>
    /// <para>
    /// <b>The object was always captured; only the attribute was missing.</b> It sits in the
    /// configuration partition, which capture reads in full, so this entry adds a column to the
    /// request rather than a new thing to go and read.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<CapturedAttribute> DirectoryServiceAttributes { get; } =
    [
        new("dSHeuristics", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// The object classes that get attributes beyond <see cref="Universal"/>, keyed by
    /// <c>lDAPDisplayName</c>. Matched without regard to case, because an LDAP class name is.
    /// </summary>
    private static readonly Dictionary<string, IReadOnlyList<CapturedAttribute>> ClassSpecific =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["user"] = AccountAttributes,
            ["inetOrgPerson"] = AccountAttributes,
            ["computer"] = ComputerAttributes,
            ["msDS-ManagedServiceAccount"] = AccountAttributes,
            ["msDS-GroupManagedServiceAccount"] = GroupManagedServiceAccountAttributes,
            ["group"] = GroupAttributes,
            ["organizationalUnit"] = OrganizationalUnitAttributes,
            ["groupPolicyContainer"] = GroupPolicyContainerAttributes,
            ["msWMI-Som"] = WmiFilterAttributes,
            ["domainDNS"] = DomainAttributes,
            ["msDS-PasswordSettings"] = PasswordSettingsAttributes,
            ["nTDSService"] = DirectoryServiceAttributes,
        };

    /// <summary>
    /// Requested for each <c>attributeSchema</c> and <c>classSchema</c> object in the schema
    /// partition, per <c>docs/decisions/0014</c>.
    /// </summary>
    /// <remarks>
    /// <c>attributeSecurityGUID</c> is the join that turns a property-set permission into the
    /// attributes it really grants: the property set is a <c>controlAccessRight</c> object, it names
    /// no attributes, and each attribute instead points back at the set through this value
    /// (<see href="https://learn.microsoft.com/windows/win32/ad/creating-a-control-access-right">Creating
    /// a Control Access Right</see>). It is an octet string, and <c>rightsGuid</c> on the other side
    /// of the join is a 36-character string, so the two are the same GUID in two different
    /// representations and comparing them as they arrive never matches.
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> SchemaPartition { get; } =
    [
        new("lDAPDisplayName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("cn", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("schemaIDGUID", AttributeCardinality.SingleValued, AttributeStorage.Binary),
        new("attributeSecurityGUID", AttributeCardinality.SingleValued, AttributeStorage.Binary),
        new("isSingleValued", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("searchFlags", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("systemFlags", AttributeCardinality.SingleValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// Requested for each <c>controlAccessRight</c> object in the extended-rights container, per
    /// <c>docs/decisions/0014</c>.
    /// </summary>
    /// <remarks>
    /// One container read resolves three of the five things a GUID in an access control entry can
    /// mean. Extended rights, property sets and validated writes all live here - Microsoft says
    /// outright that the last two are stored there "for convenience" despite not being extended
    /// rights - and <c>validAccesses</c> is what tells them apart: 256 for an extended right, 48 for
    /// a property set, 8 for a validated write
    /// (<see href="https://learn.microsoft.com/windows/win32/ad/control-access-rights">Control
    /// Access Rights</see>).
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> ExtendedRights { get; } =
    [
        new("cn", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("displayName", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("rightsGuid", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("validAccesses", AttributeCardinality.SingleValued, AttributeStorage.Text),
        new("appliesTo", AttributeCardinality.MultiValued, AttributeStorage.Text),
    ];

    /// <summary>
    /// The object classes that get more than <see cref="Universal"/>, in the spelling the schema
    /// uses.
    /// </summary>
    public static IReadOnlyList<string> ObjectClasses { get; } =
        ClassSpecific.Keys.OrderBy(name => name, StringComparer.Ordinal).ToArray();

    /// <summary>
    /// The only object classes capture does not read at all.
    /// </summary>
    /// <remarks>
    /// The DNS scope decision of 2026-08-11, recorded at
    /// <c>docs/decisions/0042-dns-zones-and-records-are-out-of-scope.md</c>, puts DNS zones and
    /// records out of scope. They are
    /// excluded here by name rather than left out of an inclusion list, because the two are not the
    /// same thing: an exclusion is a statement the product can put in a report, and a large forest
    /// holds hundreds of thousands of <c>dnsNode</c> objects whose records are values of
    /// <c>dnsRecord</c>
    /// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/networking/event-4015-dns-server-encounters-critical-error">Event
    /// ID 4015</see>). What the product must say is precise: DNS zone and record permissions are not
    /// assessed, and DNS administrative group membership is.
    ///
    /// <para>
    /// This is one of two places the decision is enforced. The other is the partition skip in
    /// <c>ForestPartitions</c>, and <c>0042</c> asks that they be changed together.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> UnreadObjectClasses { get; } = ["dnsNode", "dnsZone"];

    /// <summary>
    /// Every distinct attribute the catalogue asks for anywhere, ordered so the list reads the same
    /// on every run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the request.</b> Capture adds every entry here to every search, and asks every
    /// object for all of them whatever its class. The per-class lists this is built from group the
    /// attributes by the reason they are captured; they do not scope anything.
    /// </para>
    /// <para>
    /// <b>A per-class request is not possible in one pass.</b> An LDAP search names its attributes in
    /// the request, and an object's class is not known until the response arrives, so there is no
    /// query meaning <i>send each object the attributes suited to its class</i>. Scoping by class
    /// would mean one paged search per class over every partition - each with its own paging
    /// bookmark, retry handling and referral exposure - to save absent attributes on the wire, which
    /// cost nothing. The union is therefore the cheap option and not the lazy one.
    /// </para>
    /// <para>
    /// It also means a value missing from a captured object has exactly two possible causes, which
    /// the directory does not distinguish: the object has no value, or the reader was not permitted
    /// to see it. It can never mean <i>this class was not asked</i>. See
    /// <c>docs/decisions/0022</c>.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> All { get; } =
        Universal
            .Concat(ClassSpecific.Values.SelectMany(a => a))
            .Concat(SchemaPartition)
            .Concat(ExtendedRights)
            .DistinctBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    /// <summary>
    /// Every attribute that can exceed the server's value limit, and therefore every attribute a
    /// reader must range-retrieve.
    /// </summary>
    /// <remarks>
    /// Derived rather than listed. A hand-maintained second list is the shape of the defect gate 2
    /// exists for: it agrees with the catalogue on the day it is written and silently stops
    /// agreeing when somebody adds a multi-valued entry. B8 reads this and never tests an attribute
    /// name.
    /// </remarks>
    public static IReadOnlyList<CapturedAttribute> RangeLiable { get; } =
        All.Where(a => a.Cardinality == AttributeCardinality.MultiValued).ToArray();

    /// <summary>
    /// Attributes an audit of this kind would obviously want, and that this product refuses to
    /// capture, with the reason for each.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A refusal that is not written down is indistinguishable from an oversight.</b> Every one
    /// of these will be proposed again - they are the obvious things to want - and without a record
    /// the argument is had from scratch each time, by somebody who does not know it was already
    /// settled and against what evidence.
    /// </para>
    /// <para>
    /// Both entries fail the same test, which is the test that matters for a product reading one
    /// controller per domain: <b>is this value replicated?</b> An unreplicated attribute is one
    /// controller's opinion, and printing it as the domain's answer produces a finding that is
    /// wrong in a way nothing on screen can reveal.
    /// </para>
    /// </remarks>
    public static IReadOnlyDictionary<string, string> NotCaptured { get; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["lastLogon"] =
                "Not replicated. Each controller holds only the logons it served, so the value on "
                + "the one controller this product reads is not the account's last logon - it is "
                + "the last logon that controller saw. An account logging on daily elsewhere would "
                + "be reported as dormant. lastLogonTimestamp is captured instead: it is "
                + "replicated, and coarse in a way that can be stated.",
            ["whenChanged"] =
                "Not replicated, on Microsoft's own statement, though it is in the global "
                + "catalogue. Two controllers can disagree about when an object last changed, so a "
                + "run reading one of them cannot report it as a fact about the object. "
                + "whenCreated is replicated and is captured.",
        };

    /// <summary>
    /// Which attributes an object of <paramref name="ldapObjectClass"/> is the reason for capturing:
    /// <see cref="Universal"/> plus whatever that class adds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is not what capture requests, and nothing about a request is decided here.</b> Capture
    /// asks every object for <see cref="All"/> whatever its class - see that member for why the
    /// request cannot be scoped by class at all. This answers the different question <i>which class's
    /// needs justify carrying this attribute in the catalogue</i>, which is what
    /// <c>docs/layers/audit/the-attribute-catalogue.md</c> records and what
    /// <c>CredentialAttributeGuardTests</c> asks when it checks that computers justify the LAPS
    /// expiry timestamp and never the LAPS password.
    /// </para>
    /// <para>
    /// It was called <c>AttributesFor</c> until 2026-08-13, and that name cost real time: a session
    /// read it as the request scope, concluded that a null column could mean <i>this class was never
    /// asked</i>, and raised a finding that reading the capture pipeline disproved. The shape of the
    /// catalogue suggests a per-class request and there has never been one.
    /// </para>
    /// <para>
    /// A class the catalogue has never heard of yields <see cref="Universal"/>, which includes the
    /// security descriptor - so a vendor object nobody anticipated is still justified in full for the
    /// thing this product assesses, and only the extra attributes are absent. It is never empty, so
    /// an empty answer is not a state a caller has to handle.
    /// </para>
    /// </remarks>
    /// <param name="ldapObjectClass">The class's <c>lDAPDisplayName</c>. Matched without case.</param>
    public static IReadOnlyList<CapturedAttribute> AttributesJustifiedBy(string ldapObjectClass)
    {
        ArgumentNullException.ThrowIfNull(ldapObjectClass);

        if (!ClassSpecific.TryGetValue(ldapObjectClass, out var specific))
        {
            return Universal;
        }

        return Universal
            .Concat(specific)
            .DistinctBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .OrderBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

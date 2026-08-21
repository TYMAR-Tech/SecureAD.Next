using System.Collections.Frozen;

namespace SecureAD.Kernel.Security;

/// <summary>
/// Who a SID is, when the answer is the same in every forest.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is consulted before the captured objects.</b> A SID used to be named only by
/// searching the run's own objects for a matching <c>objectSid</c>. That is the right question for
/// an account and the wrong one for a well-known SID, in two ways. It gives a confident answer for
/// SIDs that are not principals, because Active Directory keeps objects for them under
/// <c>CN=WellKnown Security Principals</c>. And it gives an <i>arbitrary</i> answer where several
/// captured objects carry one SID: in one lab bundle <c>S-1-5-11</c> matched four objects - the
/// well-known principal and three <c>ForeignSecurityPrincipals</c> entries in different domains -
/// and the query that picked between them had no <c>ORDER BY</c>, so which domain an operator saw
/// beside <i>Authenticated Users</i> was decided by row order.
/// </para>
/// <para>
/// <b>Where these values came from.</b> <c>next/tools/harvest-ms-dtyp-well-known-sids.ps1</c>
/// fetches MS-DTYP 2.4.2.4 and extracts the table. The same section was read independently through
/// the Microsoft Learn documentation service and the two agreed on every value.
/// <c>WellKnownSidCatalogMicrosoftAnchorTests</c> is the gate.
/// </para>
/// <para>
/// <b>What is deliberately absent.</b> The integrity levels (<c>S-1-16-*</c>) belong to the
/// mandatory label in a SACL, and <c>docs/decisions/0036</c> says capture never requests one. The
/// asserted-identity range (<c>S-1-18-*</c>) exists in a token and not in a DACL. The bare
/// authority prefixes <c>S-1-3</c> and <c>S-1-5</c> are not SIDs a trustee can be. Including any
/// of them would invite code that pretends to handle a case the product never sees.
/// </para>
/// </remarks>
public static class WellKnownSidCatalog
{
    /// <summary>The specification every value here is taken from.</summary>
    public const string SourceSpecification = "MS-DTYP 2.4.2.4";

    /// <summary>
    /// The well-known SID with this value, or null when it is not one.
    /// </summary>
    /// <remarks>
    /// Null rather than a guess. A SID this catalogue does not know is an ordinary principal, and
    /// the caller goes on to look for it among the captured objects.
    /// </remarks>
    /// <param name="sid">The SID in written form.</param>
    public static WellKnownSid? FindBySid(string? sid) =>
        string.IsNullOrWhiteSpace(sid) ? null : BySid.GetValueOrDefault(sid);

    /// <summary>
    /// The meaning of a relative identifier, or null when it is not a well-known one.
    /// </summary>
    /// <remarks>
    /// The caller supplies the RID because deciding whether a SID is domain-relative at all needs
    /// the domain SID, which this catalogue does not hold and must not guess at.
    /// </remarks>
    /// <param name="rid">The last sub-authority of a domain SID.</param>
    public static DomainRelativeSid? FindByRid(int rid) => ByRid.GetValueOrDefault(rid);

    /// <summary>Every well-known SID this build knows.</summary>
    public static IReadOnlyList<WellKnownSid> AllSids => Universal;

    /// <summary>Every relative identifier this build knows.</summary>
    public static IReadOnlyList<DomainRelativeSid> AllRelativeIdentifiers => Relative;

    private static readonly WellKnownSid[] Universal =
    [
        new("S-1-0-0", "NULL", "Nobody", WellKnownSidRole.LogonContext,
            "No security principal. Used when the SID is unknown."),
        new("S-1-1-0", "EVERYONE", "Everyone", WellKnownSidRole.Principal,
            "A group that includes all users."),
        new("S-1-2-0", "LOCAL", "Local", WellKnownSidRole.LogonContext,
            "Everyone who has physically logged on locally."),
        new("S-1-2-1", "CONSOLE_LOGON", "Console Logon", WellKnownSidRole.LogonContext,
            "Everyone logged on to the physical console."),

        new("S-1-3-0", "CREATOR_OWNER", "Creator Owner", WellKnownSidRole.Placeholder,
            "A placeholder in an inheritable entry. When the entry is inherited the system "
            + "replaces this with the SID of the object's creator."),
        new("S-1-3-1", "CREATOR_GROUP", "Creator Group", WellKnownSidRole.Placeholder,
            "A placeholder in an inheritable entry, replaced with the primary group of the "
            + "object's creator."),
        new("S-1-3-2", "OWNER_SERVER", "Owner Server", WellKnownSidRole.Placeholder,
            "A placeholder in an inheritable entry, replaced with the object's owner server."),
        new("S-1-3-3", "GROUP_SERVER", "Group Server", WellKnownSidRole.Placeholder,
            "A placeholder in an inheritable entry, replaced with the object's group server."),
        new("S-1-3-4", "OWNER_RIGHTS", "Owner Rights", WellKnownSidRole.OwnerRightsQualifier,
            "Represents the object's current owner. Where an entry carries this SID the system "
            + "ignores the owner's implicit Read Permissions and Modify Permissions."),

        new("S-1-5-1", "DIALUP", "Dialup", WellKnownSidRole.LogonContext,
            "Everyone logged on through a dial-up connection."),
        new("S-1-5-2", "NETWORK", "Network", WellKnownSidRole.LogonContext,
            "Everyone logged on through a network connection."),
        new("S-1-5-3", "BATCH", "Batch", WellKnownSidRole.LogonContext,
            "Everyone logged on through a batch queue facility."),
        new("S-1-5-4", "INTERACTIVE", "Interactive", WellKnownSidRole.LogonContext,
            "Everyone logged on interactively."),
        new("S-1-5-6", "SERVICE", "Service", WellKnownSidRole.LogonContext,
            "Every security principal logged on as a service."),
        new("S-1-5-7", "ANONYMOUS", "Anonymous Logon", WellKnownSidRole.Principal,
            "An anonymous logon."),
        new("S-1-5-8", "PROXY", "Proxy", WellKnownSidRole.LogonContext,
            "Identifies a proxy."),
        new("S-1-5-9", "ENTERPRISE_DOMAIN_CONTROLLERS", "Enterprise Domain Controllers",
            WellKnownSidRole.Principal,
            "Every domain controller in the forest."),
        new("S-1-5-10", "PRINCIPAL_SELF", "Principal Self", WellKnownSidRole.Placeholder,
            "A placeholder meaning the object the entry sits on. The system replaces it with the "
            + "SID of the principal that holds the account."),
        new("S-1-5-11", "AUTHENTICATED_USERS", "Authenticated Users", WellKnownSidRole.Principal,
            "Everyone whose identity was authenticated at logon. Guest and anonymous logons are "
            + "not members."),
        new("S-1-5-12", "RESTRICTED_CODE", "Restricted Code", WellKnownSidRole.LogonContext,
            "Used to control access by untrusted code."),
        new("S-1-5-13", "TERMINAL_SERVER_USER", "Terminal Server User", WellKnownSidRole.LogonContext,
            "Everyone logged on to a Terminal Services server."),
        new("S-1-5-14", "REMOTE_INTERACTIVE_LOGON", "Remote Interactive Logon",
            WellKnownSidRole.LogonContext,
            "Everyone logged on through a terminal services logon."),
        new("S-1-5-15", "THIS_ORGANIZATION", "This Organization", WellKnownSidRole.Principal,
            "Everyone from the same organization."),
        new("S-1-5-17", "IUSR", "IUSR", WellKnownSidRole.Principal,
            "The account used by the default Internet Information Services user."),
        new("S-1-5-18", "LOCAL_SYSTEM", "Local System", WellKnownSidRole.Principal,
            "The account used by the operating system."),
        new("S-1-5-19", "LOCAL_SERVICE", "Local Service", WellKnownSidRole.Principal,
            "A local service account."),
        new("S-1-5-20", "NETWORK_SERVICE", "Network Service", WellKnownSidRole.Principal,
            "A network service account."),
        new("S-1-5-33", "WRITE_RESTRICTED_CODE", "Write Restricted Code",
            WellKnownSidRole.LogonContext,
            "Lets any service process with a write-restricted token write to the object."),
        new("S-1-5-64-10", "NTLM_AUTHENTICATION", "NTLM Authentication",
            WellKnownSidRole.LogonContext,
            "Used when the NTLM authentication package authenticated the client."),
        new("S-1-5-64-14", "SCHANNEL_AUTHENTICATION", "SChannel Authentication",
            WellKnownSidRole.LogonContext,
            "Used when the SChannel authentication package authenticated the client."),
        new("S-1-5-64-21", "DIGEST_AUTHENTICATION", "Digest Authentication",
            WellKnownSidRole.LogonContext,
            "Used when the Digest authentication package authenticated the client."),
        new("S-1-5-65-1", "THIS_ORGANIZATION_CERTIFICATE", "This Organization Certificate",
            WellKnownSidRole.LogonContext,
            "Indicates the client's Kerberos service ticket carried a supplemental credential."),
        new("S-1-5-80", "NT_SERVICE", "NT Service", WellKnownSidRole.LogonContext,
            "An NT Service account prefix."),
        new("S-1-5-80-0", "NT_SERVICE_ALL_SERVICES", "NT Service\\ALL SERVICES",
            WellKnownSidRole.Principal,
            "Every service process configured on the system."),
        new("S-1-5-113", "LOCAL_ACCOUNT", "Local Account", WellKnownSidRole.Principal,
            "Everyone who is a local account."),
        new("S-1-5-114", "LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP",
            "Local Account And Member Of Administrators Group", WellKnownSidRole.Principal,
            "Everyone who is a local account and a member of the administrators group."),
        new("S-1-5-1000", "OTHER_ORGANIZATION", "Other Organization", WellKnownSidRole.Principal,
            "Everyone from another organization."),
        new("S-1-15-2-1", "ALL_APP_PACKAGES", "All Application Packages",
            WellKnownSidRole.LogonContext,
            "All applications running in an app package context."),

        // BUILTIN aliases. Absolute rather than domain-relative - S-1-5-32 is its own domain, the
        // same in every forest - which is why they belong in this list and not the one below.
        new("S-1-5-32-544", "BUILTIN_ADMINISTRATORS", "BUILTIN\\Administrators",
            WellKnownSidRole.Principal,
            "The built-in Administrators group."),
        new("S-1-5-32-545", "BUILTIN_USERS", "BUILTIN\\Users", WellKnownSidRole.Principal,
            "The built-in Users group."),
        new("S-1-5-32-546", "BUILTIN_GUESTS", "BUILTIN\\Guests", WellKnownSidRole.Principal,
            "The built-in Guests group."),
        new("S-1-5-32-547", "POWER_USERS", "BUILTIN\\Power Users", WellKnownSidRole.Principal,
            "The built-in Power Users group."),
        new("S-1-5-32-548", "ACCOUNT_OPERATORS", "BUILTIN\\Account Operators",
            WellKnownSidRole.Principal,
            "Can create, modify and delete accounts in most containers, on domain controllers."),
        new("S-1-5-32-549", "SERVER_OPERATORS", "BUILTIN\\Server Operators",
            WellKnownSidRole.Principal,
            "Can log on to, back up, restore and shut down domain controllers."),
        new("S-1-5-32-550", "PRINTER_OPERATORS", "BUILTIN\\Print Operators",
            WellKnownSidRole.Principal,
            "Can manage printers and document queues on domain controllers."),
        new("S-1-5-32-551", "BACKUP_OPERATORS", "BUILTIN\\Backup Operators",
            WellKnownSidRole.Principal,
            "Can back up and restore all files regardless of the permissions protecting them."),
        new("S-1-5-32-552", "REPLICATOR", "BUILTIN\\Replicator", WellKnownSidRole.Principal,
            "Used by the File Replication Service on domain controllers."),
        new("S-1-5-32-554", "ALIAS_PREW2KCOMPACC", "BUILTIN\\Pre-Windows 2000 Compatible Access",
            WellKnownSidRole.Principal,
            "A backward compatibility group allowing read access on all users and groups."),
        new("S-1-5-32-555", "REMOTE_DESKTOP", "BUILTIN\\Remote Desktop Users",
            WellKnownSidRole.Principal,
            "Granted the right to log on remotely."),
        new("S-1-5-32-556", "NETWORK_CONFIGURATION_OPS",
            "BUILTIN\\Network Configuration Operators", WellKnownSidRole.Principal,
            "Can manage configuration of networking features."),
        new("S-1-5-32-557", "INCOMING_FOREST_TRUST_BUILDERS",
            "BUILTIN\\Incoming Forest Trust Builders", WellKnownSidRole.Principal,
            "Can create incoming one-way trusts to this forest."),
        new("S-1-5-32-558", "PERFMON_USERS", "BUILTIN\\Performance Monitor Users",
            WellKnownSidRole.Principal,
            "Have remote access to monitor this computer."),
        new("S-1-5-32-559", "PERFLOG_USERS", "BUILTIN\\Performance Log Users",
            WellKnownSidRole.Principal,
            "Have remote access to schedule performance counter logging."),
        new("S-1-5-32-560", "WINDOWS_AUTHORIZATION_ACCESS_GROUP",
            "BUILTIN\\Windows Authorization Access Group", WellKnownSidRole.Principal,
            "Have access to the computed tokenGroupsGlobalAndUniversal attribute on user objects."),
        new("S-1-5-32-561", "TERMINAL_SERVER_LICENSE_SERVERS",
            "BUILTIN\\Terminal Server License Servers", WellKnownSidRole.Principal,
            "A group for Terminal Server license servers."),
        new("S-1-5-32-562", "DISTRIBUTED_COM_USERS", "BUILTIN\\Distributed COM Users",
            WellKnownSidRole.Principal,
            "Governs access to call, activation and launch requests on the computer."),
        new("S-1-5-32-568", "IIS_IUSRS", "BUILTIN\\IIS_IUSRS", WellKnownSidRole.Principal,
            "A built-in group account for IIS users."),
        new("S-1-5-32-569", "CRYPTOGRAPHIC_OPERATORS", "BUILTIN\\Cryptographic Operators",
            WellKnownSidRole.Principal,
            "A built-in group account for cryptographic operators."),
        new("S-1-5-32-573", "EVENT_LOG_READERS", "BUILTIN\\Event Log Readers",
            WellKnownSidRole.Principal,
            "Can read event logs from the local machine."),
        new("S-1-5-32-574", "CERTIFICATE_SERVICE_DCOM_ACCESS",
            "BUILTIN\\Certificate Service DCOM Access", WellKnownSidRole.Principal,
            "Allowed to connect to certification authorities in the enterprise."),
        new("S-1-5-32-575", "RDS_REMOTE_ACCESS_SERVERS", "BUILTIN\\RDS Remote Access Servers",
            WellKnownSidRole.Principal,
            "Enable users of RemoteApp programs and personal virtual desktops to reach them."),
        new("S-1-5-32-576", "RDS_ENDPOINT_SERVERS", "BUILTIN\\RDS Endpoint Servers",
            WellKnownSidRole.Principal,
            "Member servers run virtual machines and host sessions."),
        new("S-1-5-32-577", "RDS_MANAGEMENT_SERVERS", "BUILTIN\\RDS Management Servers",
            WellKnownSidRole.Principal,
            "Members can access WMI resources over management protocols."),
        new("S-1-5-32-578", "HYPER_V_ADMINS", "BUILTIN\\Hyper-V Administrators",
            WellKnownSidRole.Principal,
            "Members have access to all administrative features of Hyper-V."),
        new("S-1-5-32-579", "ACCESS_CONTROL_ASSISTANCE_OPS",
            "BUILTIN\\Access Control Assistance Operators", WellKnownSidRole.Principal,
            "Can remotely query authorization attributes and permissions for local resources."),
        new("S-1-5-32-580", "REMOTE_MANAGEMENT_USERS", "BUILTIN\\Remote Management Users",
            WellKnownSidRole.Principal,
            "Can access WMI resources over management protocols."),
        new("S-1-5-32-582", "STORAGE_REPLICA_ADMINS", "BUILTIN\\Storage Replica Administrators",
            WellKnownSidRole.Principal,
            "Represents storage replica admins."),
    ];

    private static readonly DomainRelativeSid[] Relative =
    [
        new(498, "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS",
            "Enterprise Read-Only Domain Controllers", DomainRelativeScope.RootDomain,
            "Every read-only domain controller in the forest."),
        new(500, "ADMINISTRATOR", "Administrator", DomainRelativeScope.Machine,
            "The built-in system administrator account."),
        new(501, "GUEST", "Guest", DomainRelativeScope.Machine,
            "The built-in account for people without individual accounts."),
        new(502, "KRBTGT", "krbtgt", DomainRelativeScope.Domain,
            "The service account used by the Key Distribution Center."),
        new(512, "DOMAIN_ADMINS", "Domain Admins", DomainRelativeScope.Domain,
            "Members are authorized to administer the domain, and are the default owner of "
            + "anything a member creates."),
        new(513, "DOMAIN_USERS", "Domain Users", DomainRelativeScope.Domain,
            "Every user account in the domain."),
        new(514, "DOMAIN_GUESTS", "Domain Guests", DomainRelativeScope.Domain,
            "Has one member, the domain's built-in Guest account."),
        new(515, "DOMAIN_COMPUTERS", "Domain Computers", DomainRelativeScope.Domain,
            "Every client and server that has joined the domain."),
        new(516, "DOMAIN_DOMAIN_CONTROLLERS", "Domain Controllers", DomainRelativeScope.Domain,
            "Every domain controller in the domain."),
        new(517, "CERT_PUBLISHERS", "Cert Publishers", DomainRelativeScope.Domain,
            "Every computer running an enterprise certification authority."),
        new(518, "SCHEMA_ADMINISTRATORS", "Schema Admins", DomainRelativeScope.RootDomain,
            "Authorized to make schema changes."),
        new(519, "ENTERPRISE_ADMINS", "Enterprise Admins", DomainRelativeScope.RootDomain,
            "Authorized to make forest-wide changes, such as adding child domains."),
        new(520, "GROUP_POLICY_CREATOR_OWNERS", "Group Policy Creator Owners",
            DomainRelativeScope.Domain,
            "Authorized to create new Group Policy Objects."),
        new(521, "READONLY_DOMAIN_CONTROLLERS", "Read-Only Domain Controllers",
            DomainRelativeScope.Domain,
            "Every read-only domain controller in the domain."),
        new(522, "CLONEABLE_CONTROLLERS", "Cloneable Domain Controllers",
            DomainRelativeScope.Domain,
            "Domain controllers in the domain that can be cloned."),
        new(525, "PROTECTED_USERS", "Protected Users", DomainRelativeScope.Domain,
            "Afforded additional protections against authentication security threats."),
        new(526, "KEY_ADMINS", "Key Admins", DomainRelativeScope.Domain,
            "Delegated write access on the msDS-KeyCredentialLink attribute only."),
        new(527, "ENTERPRISE_KEY_ADMINS", "Enterprise Key Admins", DomainRelativeScope.Domain,
            "Delegated write access on the msDS-KeyCredentialLink attribute only, enterprise-wide."),
        new(553, "RAS_SERVERS", "RAS and IAS Servers", DomainRelativeScope.Domain,
            "Servers with read access to account restrictions and logon information on users."),
        new(571, "ALLOWED_RODC_PASSWORD_REPLICATION_GROUP",
            "Allowed RODC Password Replication Group", DomainRelativeScope.Domain,
            "Members can have their passwords replicated to read-only domain controllers."),
        new(572, "DENIED_RODC_PASSWORD_REPLICATION_GROUP",
            "Denied RODC Password Replication Group", DomainRelativeScope.Domain,
            "Members cannot have their passwords replicated to read-only domain controllers."),
    ];

    private static readonly FrozenDictionary<string, WellKnownSid> BySid =
        Universal.ToFrozenDictionary(e => e.Sid, StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenDictionary<int, DomainRelativeSid> ByRid =
        Relative.ToFrozenDictionary(e => e.Rid);
}

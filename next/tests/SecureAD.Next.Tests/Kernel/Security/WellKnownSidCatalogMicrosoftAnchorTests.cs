using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Every <see cref="WellKnownSidCatalog"/> value, pinned to MS-DTYP 2.4.2.4.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this matters.</b> This catalogue is consulted before the captured objects, so it decides
/// two things a customer acts on: who a permission is credited to, and whether it is credited to
/// anybody at all. A wrong SID puts the wrong name against a permission. A wrong
/// <see cref="WellKnownSidRole"/> is worse, because it is the difference between reporting that
/// somebody holds a right and reporting that a placeholder does - and nothing else in the product
/// can catch either. The bytes still parse, the counts still add up, every other test still passes.
/// </para>
/// <para>
/// <b>Where these values came from.</b> <c>next/tools/harvest-ms-dtyp-well-known-sids.ps1</c>
/// fetches MS-DTYP 2.4.2.4 and extracts 84 absolute and 21 domain-relative entries. The same
/// section was read independently through the Microsoft Learn documentation service and the two
/// agreed on every value both extracted.
/// </para>
/// <para>
/// <b>The two values that prove this was worth doing.</b> The predecessor's hand-assembled
/// catalogue had <c>S-1-5-17</c> as <i>This Organization</i> and <c>S-1-5-32-581</c> as
/// <i>Storage Replica Administrators</i>. Microsoft publishes <c>S-1-5-17</c> as <c>IUSR</c>,
/// <c>S-1-5-15</c> as <c>THIS_ORGANIZATION</c>, and <c>S-1-5-32-582</c> as
/// <c>STORAGE_REPLICA_ADMINS</c> with no 581 at all. Both errors were internally consistent and
/// would have survived any test written from that file, which is why the values here were
/// harvested rather than carried across.
/// </para>
/// </remarks>
public sealed class WellKnownSidCatalogMicrosoftAnchorTests
{
    /// <summary>
    /// Each row is a constant Microsoft publishes, with the SID it publishes for it.
    /// </summary>
    [Theory]
    [InlineData("NULL", "S-1-0-0")]
    [InlineData("EVERYONE", "S-1-1-0")]
    [InlineData("LOCAL", "S-1-2-0")]
    [InlineData("CONSOLE_LOGON", "S-1-2-1")]
    [InlineData("CREATOR_OWNER", "S-1-3-0")]
    [InlineData("CREATOR_GROUP", "S-1-3-1")]
    [InlineData("OWNER_SERVER", "S-1-3-2")]
    [InlineData("GROUP_SERVER", "S-1-3-3")]
    [InlineData("OWNER_RIGHTS", "S-1-3-4")]
    [InlineData("DIALUP", "S-1-5-1")]
    [InlineData("NETWORK", "S-1-5-2")]
    [InlineData("BATCH", "S-1-5-3")]
    [InlineData("INTERACTIVE", "S-1-5-4")]
    [InlineData("SERVICE", "S-1-5-6")]
    [InlineData("ANONYMOUS", "S-1-5-7")]
    [InlineData("PROXY", "S-1-5-8")]
    [InlineData("ENTERPRISE_DOMAIN_CONTROLLERS", "S-1-5-9")]
    [InlineData("PRINCIPAL_SELF", "S-1-5-10")]
    [InlineData("AUTHENTICATED_USERS", "S-1-5-11")]
    [InlineData("RESTRICTED_CODE", "S-1-5-12")]
    [InlineData("TERMINAL_SERVER_USER", "S-1-5-13")]
    [InlineData("REMOTE_INTERACTIVE_LOGON", "S-1-5-14")]
    [InlineData("THIS_ORGANIZATION", "S-1-5-15")]
    [InlineData("IUSR", "S-1-5-17")]
    [InlineData("LOCAL_SYSTEM", "S-1-5-18")]
    [InlineData("LOCAL_SERVICE", "S-1-5-19")]
    [InlineData("NETWORK_SERVICE", "S-1-5-20")]
    [InlineData("WRITE_RESTRICTED_CODE", "S-1-5-33")]
    [InlineData("NTLM_AUTHENTICATION", "S-1-5-64-10")]
    [InlineData("SCHANNEL_AUTHENTICATION", "S-1-5-64-14")]
    [InlineData("DIGEST_AUTHENTICATION", "S-1-5-64-21")]
    [InlineData("THIS_ORGANIZATION_CERTIFICATE", "S-1-5-65-1")]
    [InlineData("NT_SERVICE", "S-1-5-80")]
    [InlineData("LOCAL_ACCOUNT", "S-1-5-113")]
    [InlineData("LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP", "S-1-5-114")]
    [InlineData("OTHER_ORGANIZATION", "S-1-5-1000")]
    [InlineData("ALL_APP_PACKAGES", "S-1-15-2-1")]
    [InlineData("BUILTIN_ADMINISTRATORS", "S-1-5-32-544")]
    [InlineData("BUILTIN_USERS", "S-1-5-32-545")]
    [InlineData("BUILTIN_GUESTS", "S-1-5-32-546")]
    [InlineData("POWER_USERS", "S-1-5-32-547")]
    [InlineData("ACCOUNT_OPERATORS", "S-1-5-32-548")]
    [InlineData("SERVER_OPERATORS", "S-1-5-32-549")]
    [InlineData("PRINTER_OPERATORS", "S-1-5-32-550")]
    [InlineData("BACKUP_OPERATORS", "S-1-5-32-551")]
    [InlineData("REPLICATOR", "S-1-5-32-552")]
    [InlineData("ALIAS_PREW2KCOMPACC", "S-1-5-32-554")]
    [InlineData("REMOTE_DESKTOP", "S-1-5-32-555")]
    [InlineData("NETWORK_CONFIGURATION_OPS", "S-1-5-32-556")]
    [InlineData("INCOMING_FOREST_TRUST_BUILDERS", "S-1-5-32-557")]
    [InlineData("PERFMON_USERS", "S-1-5-32-558")]
    [InlineData("PERFLOG_USERS", "S-1-5-32-559")]
    [InlineData("WINDOWS_AUTHORIZATION_ACCESS_GROUP", "S-1-5-32-560")]
    [InlineData("TERMINAL_SERVER_LICENSE_SERVERS", "S-1-5-32-561")]
    [InlineData("DISTRIBUTED_COM_USERS", "S-1-5-32-562")]
    [InlineData("IIS_IUSRS", "S-1-5-32-568")]
    [InlineData("CRYPTOGRAPHIC_OPERATORS", "S-1-5-32-569")]
    [InlineData("EVENT_LOG_READERS", "S-1-5-32-573")]
    [InlineData("CERTIFICATE_SERVICE_DCOM_ACCESS", "S-1-5-32-574")]
    [InlineData("RDS_REMOTE_ACCESS_SERVERS", "S-1-5-32-575")]
    [InlineData("RDS_ENDPOINT_SERVERS", "S-1-5-32-576")]
    [InlineData("RDS_MANAGEMENT_SERVERS", "S-1-5-32-577")]
    [InlineData("HYPER_V_ADMINS", "S-1-5-32-578")]
    [InlineData("ACCESS_CONTROL_ASSISTANCE_OPS", "S-1-5-32-579")]
    [InlineData("REMOTE_MANAGEMENT_USERS", "S-1-5-32-580")]
    [InlineData("STORAGE_REPLICA_ADMINS", "S-1-5-32-582")]
    public void WhenMicrosoftPublishesAWellKnownSid_ThenTheCatalogueCarriesThatValue(
        string constantName,
        string sid)
    {
        var entry = WellKnownSidCatalog.FindBySid(sid);

        Assert.NotNull(entry);
        Assert.Equal(constantName, entry.ConstantName);
    }

    /// <summary>
    /// The three values the predecessor had wrong, named individually so a future edit that
    /// reintroduces one fails on a test that says what it is.
    /// </summary>
    [Theory]
    [InlineData("S-1-5-15", "THIS_ORGANIZATION")]
    [InlineData("S-1-5-17", "IUSR")]
    [InlineData("S-1-5-32-582", "STORAGE_REPLICA_ADMINS")]
    public void WhenASidWasCarriedWrongBefore_ThenTheCatalogueCarriesMicrosoftsValue(
        string sid,
        string constantName)
    {
        Assert.Equal(constantName, WellKnownSidCatalog.FindBySid(sid)?.ConstantName);
    }

    /// <summary>
    /// <c>S-1-5-32-581</c> is not in Microsoft's table. The predecessor used it for Storage Replica
    /// Administrators, so resolving it would mean the wrong catalogue had been copied across.
    /// </summary>
    [Fact]
    public void TheCatalogueDoesNotResolveASidMicrosoftDoesNotPublish()
    {
        Assert.Null(WellKnownSidCatalog.FindBySid("S-1-5-32-581"));
    }

    /// <summary>
    /// The roles, which are the part that changes what the product says rather than what it shows.
    /// A placeholder reported as a principal credits a permission to somebody who does not hold it.
    /// </summary>
    [Theory]
    [InlineData("S-1-3-0", WellKnownSidRole.Placeholder)]          // CREATOR_OWNER
    [InlineData("S-1-3-1", WellKnownSidRole.Placeholder)]          // CREATOR_GROUP
    [InlineData("S-1-3-2", WellKnownSidRole.Placeholder)]          // OWNER_SERVER
    [InlineData("S-1-3-3", WellKnownSidRole.Placeholder)]          // GROUP_SERVER
    [InlineData("S-1-5-10", WellKnownSidRole.Placeholder)]         // PRINCIPAL_SELF
    [InlineData("S-1-3-4", WellKnownSidRole.OwnerRightsQualifier)] // OWNER_RIGHTS
    [InlineData("S-1-1-0", WellKnownSidRole.Principal)]            // EVERYONE
    [InlineData("S-1-5-11", WellKnownSidRole.Principal)]           // AUTHENTICATED_USERS
    [InlineData("S-1-5-18", WellKnownSidRole.Principal)]           // LOCAL_SYSTEM
    [InlineData("S-1-5-32-544", WellKnownSidRole.Principal)]       // BUILTIN_ADMINISTRATORS
    public void WhenASidHasARole_ThenItIsTheOneMicrosoftsDescriptionSupports(
        string sid,
        WellKnownSidRole role)
    {
        Assert.Equal(role, WellKnownSidCatalog.FindBySid(sid)?.Role);
    }

    /// <summary>
    /// Only a principal is credited with holding a permission. This is the single question the
    /// permission display asks, so it is asserted directly rather than inferred from the role.
    /// </summary>
    [Theory]
    [InlineData("S-1-3-0", false)]     // CREATOR_OWNER - a template
    [InlineData("S-1-5-10", false)]    // PRINCIPAL_SELF - the object itself
    [InlineData("S-1-3-4", false)]     // OWNER_RIGHTS - a qualifier, not a holder
    [InlineData("S-1-1-0", true)]      // EVERYONE
    [InlineData("S-1-5-11", true)]     // AUTHENTICATED_USERS
    public void WhetherASidNamesAPrincipalFollowsItsRole(string sid, bool namesAPrincipal)
    {
        Assert.Equal(namesAPrincipal, WellKnownSidCatalog.FindBySid(sid)?.NamesAPrincipal);
    }

    /// <summary>
    /// Each domain-relative identifier, with the RID Microsoft publishes and the SID it is counted
    /// from. The scope is not decoration: matching RID 519 under a child domain would name a group
    /// as <i>Enterprise Admins</i> that exists only in the forest root.
    /// </summary>
    [Theory]
    [InlineData(498, "ENTERPRISE_READONLY_DOMAIN_CONTROLLERS", DomainRelativeScope.RootDomain)]
    [InlineData(500, "ADMINISTRATOR", DomainRelativeScope.Machine)]
    [InlineData(501, "GUEST", DomainRelativeScope.Machine)]
    [InlineData(502, "KRBTGT", DomainRelativeScope.Domain)]
    [InlineData(512, "DOMAIN_ADMINS", DomainRelativeScope.Domain)]
    [InlineData(513, "DOMAIN_USERS", DomainRelativeScope.Domain)]
    [InlineData(514, "DOMAIN_GUESTS", DomainRelativeScope.Domain)]
    [InlineData(515, "DOMAIN_COMPUTERS", DomainRelativeScope.Domain)]
    [InlineData(516, "DOMAIN_DOMAIN_CONTROLLERS", DomainRelativeScope.Domain)]
    [InlineData(517, "CERT_PUBLISHERS", DomainRelativeScope.Domain)]
    [InlineData(518, "SCHEMA_ADMINISTRATORS", DomainRelativeScope.RootDomain)]
    [InlineData(519, "ENTERPRISE_ADMINS", DomainRelativeScope.RootDomain)]
    [InlineData(520, "GROUP_POLICY_CREATOR_OWNERS", DomainRelativeScope.Domain)]
    [InlineData(521, "READONLY_DOMAIN_CONTROLLERS", DomainRelativeScope.Domain)]
    [InlineData(522, "CLONEABLE_CONTROLLERS", DomainRelativeScope.Domain)]
    [InlineData(525, "PROTECTED_USERS", DomainRelativeScope.Domain)]
    [InlineData(526, "KEY_ADMINS", DomainRelativeScope.Domain)]
    [InlineData(527, "ENTERPRISE_KEY_ADMINS", DomainRelativeScope.Domain)]
    [InlineData(553, "RAS_SERVERS", DomainRelativeScope.Domain)]
    [InlineData(571, "ALLOWED_RODC_PASSWORD_REPLICATION_GROUP", DomainRelativeScope.Domain)]
    [InlineData(572, "DENIED_RODC_PASSWORD_REPLICATION_GROUP", DomainRelativeScope.Domain)]
    public void WhenMicrosoftPublishesARelativeIdentifier_ThenTheCatalogueCarriesIt(
        int rid,
        string constantName,
        DomainRelativeScope scope)
    {
        var entry = WellKnownSidCatalog.FindByRid(rid);

        Assert.NotNull(entry);
        Assert.Equal(constantName, entry.ConstantName);
        Assert.Equal(scope, entry.Scope);
    }

    /// <summary>
    /// The catalogue invents nothing. A SID not in Microsoft's table would be one no directory
    /// sends, and a name for it invites code that pretends to handle it.
    /// </summary>
    [Fact]
    public void TheCatalogueCarriesNoSidMicrosoftDoesNotPublish()
    {
        string[] published =
        [
            "S-1-0-0", "S-1-1-0", "S-1-2-0", "S-1-2-1",
            "S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3", "S-1-3-4",
            "S-1-5-1", "S-1-5-2", "S-1-5-3", "S-1-5-4", "S-1-5-6", "S-1-5-7", "S-1-5-8",
            "S-1-5-9", "S-1-5-10", "S-1-5-11", "S-1-5-12", "S-1-5-13", "S-1-5-14", "S-1-5-15",
            "S-1-5-17", "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-33",
            "S-1-5-64-10", "S-1-5-64-14", "S-1-5-64-21", "S-1-5-65-1",
            "S-1-5-80", "S-1-5-80-0", "S-1-5-113", "S-1-5-114", "S-1-5-1000", "S-1-15-2-1",
            "S-1-5-32-544", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-32-547", "S-1-5-32-548",
            "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552", "S-1-5-32-554",
            "S-1-5-32-555", "S-1-5-32-556", "S-1-5-32-557", "S-1-5-32-558", "S-1-5-32-559",
            "S-1-5-32-560", "S-1-5-32-561", "S-1-5-32-562", "S-1-5-32-568", "S-1-5-32-569",
            "S-1-5-32-573", "S-1-5-32-574", "S-1-5-32-575", "S-1-5-32-576", "S-1-5-32-577",
            "S-1-5-32-578", "S-1-5-32-579", "S-1-5-32-580", "S-1-5-32-582",
        ];

        var invented = WellKnownSidCatalog.AllSids
            .Where(e => !published.Contains(e.Sid, StringComparer.Ordinal))
            .Select(e => $"{e.ConstantName} = {e.Sid}")
            .ToArray();

        Assert.True(
            invented.Length == 0,
            "The catalogue carries SIDs MS-DTYP 2.4.2.4 does not publish: "
            + string.Join(", ", invented));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes over an empty catalogue and
    /// reports that nothing is wrong with it.
    /// </summary>
    [Fact]
    public void TheCatalogueIsPopulated()
    {
        Assert.Equal(67, WellKnownSidCatalog.AllSids.Count);
        Assert.Equal(21, WellKnownSidCatalog.AllRelativeIdentifiers.Count);
    }

    /// <summary>
    /// A SID that is not well-known returns null rather than a guess, because the caller goes on to
    /// look for it among the objects the run captured. A catalogue that answered here would stop
    /// real accounts being resolved.
    /// </summary>
    [Theory]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-1001")]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-512")]
    [InlineData("")]
    [InlineData(null)]
    public void WhenASidIsNotWellKnown_ThenTheCatalogueSaysSoRatherThanGuessing(string? sid)
    {
        Assert.Null(WellKnownSidCatalog.FindBySid(sid));
    }

    /// <summary>
    /// A relative identifier that is not well-known returns null for the same reason.
    /// </summary>
    [Fact]
    public void WhenARelativeIdentifierIsNotWellKnown_ThenTheCatalogueSaysSo()
    {
        Assert.Null(WellKnownSidCatalog.FindByRid(1001));
    }

    /// <summary>
    /// The catalogue says which specification it is taken from, so a reader can check it.
    /// </summary>
    [Fact]
    public void TheCatalogueNamesItsSource()
    {
        Assert.Equal("MS-DTYP 2.4.2.4", WellKnownSidCatalog.SourceSpecification);
    }
}

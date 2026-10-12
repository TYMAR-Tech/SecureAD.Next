using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>SEC-012 reports captured constrained delegation to a supported Tier-0-relevant resource.</summary>
public sealed class ConstrainedDelegationToRelevantService : IRule
{
    internal const string Summary = "The captured settings configure this account for constrained delegation to the recorded services on a Tier 0-relevant resource. "
        + "Review whether this delegation is required.";
    internal const string ScopeNote = "This finding does not establish successful impersonation, credential extraction or a completed Tier 0 path.";
    internal const string Explanation = Summary + " " + ScopeNote;
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = DelegationConfigurationRules.Definition("SEC-012", "Constrained delegation to a Tier 0-relevant service");
}

/// <summary>SEC-013 reports supported captured RBCD grants, not concrete-requester authorization.</summary>
public sealed class ResourceBasedDelegationOnRelevantResource : IRule
{
    internal const string Summary = "The captured RBCD settings contain a supported delegation grant on this Tier 0-relevant resource. "
        + "Review the recorded grants and whether this delegation is required.";
    internal const string ScopeNote = "This finding does not establish authorization for a particular requester, successful impersonation or a completed Tier 0 path.";
    internal const string Explanation = Summary + " " + ScopeNote;
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = DelegationConfigurationRules.Definition("SEC-013", "RBCD delegation grant on a Tier 0-relevant resource");
}

internal static class DelegationConfigurationRules
{
    internal const int PolicyVersion = 1;
    internal const string ConstrainedAttribute = "msDS-AllowedToDelegateTo";
    internal const string ResourceAttribute = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    internal static readonly string[] IdentityAttributes =
        ["objectClass", "objectSid", "isDeleted", "userAccountControl", "primaryGroupID", "sAMAccountName",
            "dNSHostName", "servicePrincipalName", ConstrainedAttribute, ResourceAttribute];
    internal static RuleDefinition Definition(string id, string name) => new(id, name, Severity.High, 1,
        ["user", "computer", "inetOrgPerson", "msDS-ManagedServiceAccount", "msDS-GroupManagedServiceAccount"],
        IdentityAttributes, [nameof(DerivedFactKind.AdministrativeMembership)]);
    internal static string Key(Guid account, Guid resource) => account.ToString("D") + ":" + resource.ToString("D");
}

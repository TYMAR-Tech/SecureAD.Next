namespace SecureAD.Judgement;

/// <summary>Explains saved delegation-assessment gaps without presenting an unassessed resource as safe.</summary>
public static class DelegationConfigurationLimitations
{
    /// <summary>Describes a saved reason; an unknown reason remains explicit rather than hidden.</summary>
    public static string Describe(string reason) => reason switch
    {
        "CaptureIncomplete" => "Not all declared capture scope was read.",
        "AccountClassUnreadable" => "The captured object-class values are unusable, so the rule cannot decide whether the object is within its account scope.",
        "AccountIdentityUnavailable" or "AccountIdentityAmbiguous" => "A captured account or its issuing domain could not be uniquely verified.",
        "AccountSourceIncomplete" or "AccountIdentity.SourceIncomplete" or "Resource.AccountIdentity.SourceIncomplete" =>
            "A captured account, resource or issuing-domain source has limited completeness.",
        "ConfigurationOrdinalsUnusable" => "The original configuration value positions do not establish a complete ordered list.",
        "ConfiguredServiceUnsupported" => "A configured service value is unreadable or uses unsupported syntax.",
        "ServiceRegistrationUnsupported" => "Some captured service registrations could not be interpreted.",
        "ServiceResourceUnresolved" => "The configured service has no unique supported captured registration; HOST aliases and live DNS are not inferred.",
        "ServiceResourceAmbiguous" => "The configured service registration has conflicting or unqualified captured owners.",
        "ResourceRelevanceUnassessed" => "The resource is not positively identified within the existing Tier 0-relevant assessment scope; it is not declared safe.",
        "ResourceDescriptorUnavailable" => "The RBCD security descriptor was not captured as one readable binary value.",
        "ResourceDescriptorIncomplete" => "The RBCD security descriptor could not be parsed completely; no definite delegation grant is inferred.",
        "ResourceDelegationEntryUnsupported" => "An RBCD entry requires unsupported conditional, object-scope or trustee interpretation.",
        "StoredGenericRightUnsupported" => "A stored generic access bit is not expanded into an already-granted delegation right.",
        "OtherRequesterDenyMembershipUnassessed" => "Other denial entries may apply through a requester's membership; individual requester authorization was not assessed.",
        "ResourceAnalysis.InputIncomplete" => "Some captured inputs supporting the resource's relevance are incomplete.",
        "ResourceAnalysis.MembershipIncomplete" or "ResourceAnalysis.MembershipUnqualified" =>
            "Additional resource memberships could not be fully assessed.",
        "ResourceAnalysis.AssetQualificationUnsupported" => "The shared model does not implement every possible identity-control-system classification.",
        "ResourceAnalysis.ControlQualificationUnsupported" => "The shared model does not establish every controller's operational Tier 0 classification.",
        "ResourceAnalysis.DependencyQualificationUnsupported" => "Additional dependency interpretation is not implemented by the shared model.",
        "ResourceAnalysis.IdentityUnverified" or "ResourceAnalysis.SourceMismatch" => "The shared resource identity or source binding could not be fully verified.",
        "ResourceAnalysis.ConditionalOperation" => "The named permission does not establish a completed operation.",
        "ResourceAnalysis.ProcessingIncomplete" => "The shared scope calculation did not complete its recorded processing.",
        "ResourceAnalysis.AssetHostEvidenceMissing" or "ResourceAnalysis.AssetHostIdentityUnresolved" =>
            "An identity-control-system host could not be uniquely qualified from captured evidence.",
        _ => reason + " remains explicitly unassessed.",
    };
}

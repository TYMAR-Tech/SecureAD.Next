using System.Collections.Frozen;
using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>The boundary of a catalogue claim, not proof that the principal holds a permission.</summary>
public enum PrincipalAuthorityScope
{
    /// <summary>No administrative authority conferred by this catalogue entry.</summary>
    None,
    /// <summary>The verified issuing domain only.</summary>
    Domain,
    /// <summary>The verified forest-root identity's forest.</summary>
    Forest,
    /// <summary>The captured forest's schema partition only.</summary>
    Schema,
    /// <summary>A platform/placeholder ownership treatment or a directly evidenced SYSTEM ACE, depending on the predicate.</summary>
    Descriptor,
    /// <summary>Only independently verified operations required by domain controllers.</summary>
    RequiredDomainControllerOperations,
}

/// <summary>Independent, versioned catalogue answers. Object classification can require evidence beyond a SID.</summary>
public sealed record PrincipalClassification(
    string Sid,
    string? MicrosoftName,
    bool IdentityIsValid,
    bool IsBroad,
    bool IsSensitiveSidHistory,
    PrincipalAuthorityScope OwnerScope,
    PrincipalAuthorityScope ControlPlaneScope,
    string CapabilityScope,
    bool? IsTier0Asset,
    int CatalogueVersion)
{
    /// <summary>The SID syntax was readable. Nullable asset classification still needs object evidence.</summary>
    public bool IsComplete => IdentityIsValid;
    /// <summary>The Microsoft identifier catalogue used for recognition.</summary>
    public string RecognitionSource => "MS-DTYP-2.4.2.4";
    /// <summary>The independently accepted broad-principal policy.</summary>
    public string BroadSource => "0098;BroadPrincipalCatalogue";
    /// <summary>The existing SID-history selection and identifier anchor.</summary>
    public string SidHistorySource => "SEC-027;MS-DTYP-2.4.2.4";
    /// <summary>The owner policy, independent of protection and expectedness.</summary>
    public string OwnershipSource => "0095;0107;0109";
    /// <summary>The scoped control-plane and SYSTEM policies.</summary>
    public string ControlPlaneSource => "0099;0100";
    /// <summary>Asset classification must not be inferred from expectedness.</summary>
    public string Tier0Source => "0006;0099;object evidence required for computer accounts";
}

/// <summary>Shared data with separate predicates under 0101. Membership, protection and authorization are not inferred here.</summary>
public static class PrincipalClassificationRegistry
{
    /// <summary>The semantic version recorded on control-edge classifications.</summary>
    public const int Version = 2;

    /// <summary>Absolute broad identifiers, not discovered directory members.</summary>
    public static readonly FrozenSet<string> BroadSids = new[]
    {
        "S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-32-554",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    /// <summary>Broad domain-relative identifiers, requiring a domain-principal SID shape.</summary>
    public static readonly FrozenSet<int> BroadRids = new[] { 513, 514, 515 }.ToFrozenSet();
    /// <summary>SEC-027's existing domain-relative sensitivity selection.</summary>
    public static readonly FrozenSet<int> SensitiveHistoryRids = new[]
    {
        500, 502, 512, 516, 518, 519, 520, 521,
    }.ToFrozenSet();
    /// <summary>SEC-027's existing absolute sensitivity selection.</summary>
    public static readonly FrozenSet<string> SensitiveHistorySids = new[]
    {
        "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    /// <summary>Independent owner-acceptance closure roots; Schema Admins is deliberately separate.</summary>
    public static readonly FrozenSet<int> AcceptedOwnerRootRids = new[] { 500, 512, 519, 544 }.ToFrozenSet();
    /// <summary>The existing ownership predicate's domain-relative identifier selection.</summary>
    public static readonly FrozenSet<int> AcceptedOwnerIdentifierRids = new[] { 500, 512, 519 }.ToFrozenSet();
    /// <summary>The existing ownership predicate's absolute and artifact identifiers.</summary>
    public static readonly FrozenSet<string> AcceptedOwnerSids = new[]
    {
        "S-1-5-32-544", "S-1-5-18", "S-1-5-9", "S-1-3-0",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Returns separate identifier-level answers. Authority scopes still require captured identity validation.</summary>
    public static PrincipalClassification For(string sid)
    {
        ArgumentNullException.ThrowIfNull(sid);
        var valid = Sid.ToBytes(sid) is not null;
        var rid = DomainRid(sid);
        var normalized = sid.ToUpperInvariant();
        var owner = normalized switch
        {
            "S-1-5-32-544" => PrincipalAuthorityScope.Domain,
            "S-1-5-18" or "S-1-5-9" or "S-1-3-0" => PrincipalAuthorityScope.Descriptor,
            _ => rid switch
            {
                500 or 512 => PrincipalAuthorityScope.Domain,
                519 => PrincipalAuthorityScope.Forest,
                518 => PrincipalAuthorityScope.Schema,
                _ => PrincipalAuthorityScope.None,
            },
        };
        // Deliberately not computed from owner acceptance or the SID-history set.
        var control = normalized switch
        {
            "S-1-5-32-544" => PrincipalAuthorityScope.Domain,
            "S-1-5-18" => PrincipalAuthorityScope.Descriptor,
            "S-1-5-9" => PrincipalAuthorityScope.RequiredDomainControllerOperations,
            _ => rid switch
            {
                500 or 512 => PrincipalAuthorityScope.Domain,
                519 => PrincipalAuthorityScope.Forest,
                518 => PrincipalAuthorityScope.Schema,
                _ => PrincipalAuthorityScope.None,
            },
        };
        bool? tier0 = normalized switch
        {
            "S-1-5-32-544" or "S-1-5-32-549" or "S-1-5-32-551" => true,
            _ => rid switch
            {
                500 or 502 or 512 => true,
                // A SID alone does not establish that 518/519 is the actual forest-root group.
                518 or 519 => null,
                516 or 521 or 498 => false,
                _ => null,
            },
        };
        return new PrincipalClassification(sid,
            WellKnownSidCatalog.FindBySid(sid)?.DisplayName
                ?? (rid is { } relative ? WellKnownSidCatalog.FindByRid(relative)?.DisplayName : null),
            valid, BroadSids.Contains(sid) || rid is { } broad && BroadRids.Contains(broad),
            SensitiveHistorySids.Contains(sid) || rid is { } sensitive && SensitiveHistoryRids.Contains(sensitive),
            owner, control, control switch
            {
                PrincipalAuthorityScope.Domain or PrincipalAuthorityScope.Forest => "UnrestrictedWithinAuthority",
                PrincipalAuthorityScope.Schema => "SchemaAdministrationOnly",
                PrincipalAuthorityScope.Descriptor => "ApplicableSystemAceOnly",
                PrincipalAuthorityScope.RequiredDomainControllerOperations => "VerifiedRequiredOperationsOnly",
                _ => "None",
            }, tier0, Version);
    }

    /// <summary>Reads a RID only from a structurally valid domain-principal SID.</summary>
    public static int? DomainRid(string sid) =>
        sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase)
        && sid.Split('-').Length == 8 && Sid.ToBytes(sid) is not null
            ? Sid.RelativeIdentifier(sid) : null;
}

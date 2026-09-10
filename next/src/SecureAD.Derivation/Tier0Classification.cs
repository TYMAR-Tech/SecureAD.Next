using System.Collections.Immutable;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>A classification conclusion, never an expectedness or protection answer.</summary>
public enum Tier0State
{
    /// <summary>No supported positive or complete negative conclusion is available.</summary>
    Unknown,
    /// <summary>At least one independently qualified basis is established.</summary>
    Established,
    /// <summary>A complete evaluation did not establish classification within its stated model.</summary>
    NotEstablished,
}

/// <summary>Why an object qualifies, separate from longer or conditional relevance.</summary>
/// <remarks>
/// <b><c>DirectControl</c> was removed on 2026-09-11, and its absence is the point.</b> It belonged
/// to the design where every object was assessed and a controller could be classified Tier 0 for
/// holding a qualified capability. Discovery-first admission replaced that: a controller is a
/// candidate to be assessed, not a member of the set, so the classifier never produced the value and
/// a reader seeing it would have looked for a basis nothing can emit. Removal was safe only once
/// <see cref="SecureAD.Evidence.ProofSerialization"/> stopped writing enums as ordinals - before
/// that, deleting a member from the middle would have renumbered <see cref="PartitionRoot"/> and
/// changed the meaning of fingerprints already written. Decision 0119.
/// </remarks>
public enum Tier0Basis
{
    /// <summary>The canonical Tier-0 policy identifies the captured object.</summary>
    Core,
    /// <summary>Captured security membership establishes authority through a canonical core group.</summary>
    EffectiveMembership,
    /// <summary>
    /// The captured object is the head of a directory partition.
    /// </summary>
    /// <remarks>
    /// <b>What the object is, rather than a SID it holds.</b> A naming-context root carries no
    /// <c>objectSid</c>, so it can never hold a permission or own an object and no controller route
    /// can reach it. Replication rights are granted on the partition root, and on a domain root that
    /// is every credential in the domain, so a root that nothing assessed is the most consequential
    /// silence the product could produce. Decision 0117.
    /// </remarks>
    PartitionRoot,
}

/// <summary>Limits retained alongside any established positive witnesses.</summary>
[Flags]
public enum Tier0Limitations
{
    /// <summary>No recorded limit.</summary>
    None = 0,
    /// <summary>The supplied captured input belongs to another source generation.</summary>
    SourceMismatch = 1,
    /// <summary>The captured identity or resource context is missing or ambiguous.</summary>
    IdentityUnverified = 2,
    /// <summary>Capture or attribute evidence is incomplete.</summary>
    InputIncomplete = 4,
    /// <summary>Existing membership witnesses do not enumerate all relevant memberships.</summary>
    MembershipIncomplete = 8,
    /// <summary>A membership witness cannot establish effective authority in this slice.</summary>
    MembershipUnqualified = 16,
    /// <summary>Evidence-backed asset qualification is not implemented by this producer.</summary>
    AssetQualificationUnsupported = 32,
    /// <summary>Operational direct-control qualification is not implemented by this producer.</summary>
    ControlQualificationUnsupported = 64,
    /// <summary>The dependency relationship requires unsupported interpretation.</summary>
    DependencyQualificationUnsupported = 128,
    /// <summary>The named permission does not establish the proposed operation.</summary>
    ConditionalOperation = 256,
    /// <summary>Processing stopped before completing the supported work.</summary>
    ProcessingIncomplete = 512,
}

/// <summary>Exact source and semantic identities; validation is not a substitute for verifying file seals.</summary>
public sealed record Tier0InputBinding(string EvidenceSeal, Guid DerivationGenerationId, string DerivationSeal,
    int PrincipalCatalogueVersion = PrincipalClassificationRegistry.Version, int PolicyVersion = 1, int ContractVersion = 1,
    string? ForestRootNamingContext = null)
{
    /// <summary>Whether source identities are structurally usable.</summary>
    public bool IsValid => IsSeal(EvidenceSeal) && DerivationGenerationId != Guid.Empty && IsSeal(DerivationSeal)
        && PrincipalCatalogueVersion > 0 && PolicyVersion > 0 && ContractVersion > 0
        && (ForestRootNamingContext is null || !string.IsNullOrWhiteSpace(ForestRootNamingContext));

    /// <summary>The only semantic versions produced by the current shared foundation.</summary>
    public bool IsSupported => IsValid && PrincipalCatalogueVersion == PrincipalClassificationRegistry.Version
        && PolicyVersion == 1 && ContractVersion == 1;

    internal static bool IsSeal(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
}

/// <summary>A capture-local identity, preserving the resource scope of non-unique BUILTIN SIDs.</summary>
public sealed record Tier0Target(Guid? ObjectGuid, string DistinguishedName, string NamingContext,
    string? DomainFqdn, string? Sid, string? SidScope)
{
    /// <summary>Whether the identity is usable within a validated capture.</summary>
    public bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(NamingContext) && Within(DistinguishedName, NamingContext)
        && (Sid is null ? SidScope is null : SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null
            && (SecureAD.Kernel.Security.Sid.IsBuiltinDomain(Sid)
                ? !string.IsNullOrWhiteSpace(DomainFqdn) && Same(SidScope, DomainFqdn)
                : SidScope is null));

    /// <summary>Reads an identity without treating its captured domain as verified authority.</summary>
    public static Tier0Target From(ObjectAttributes subject, string namingContext)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContext);
        var sid = ReadSid(subject);
        return new(subject.ObjectGuid, subject.DistinguishedName, namingContext, subject.DomainFqdn, sid,
            sid is not null && SecureAD.Kernel.Security.Sid.IsBuiltinDomain(sid) ? subject.DomainFqdn : null);
    }

    internal static string? ReadSid(ObjectAttributes subject)
    {
        var values = subject.Find("objectSid")?.Values;
        return values is { Count: 1 } ? values[0].Bytes is { } bytes
            ? SecureAD.Kernel.Security.Sid.ToText(bytes) : values[0].Text : null;
    }

    internal static bool Same(string? first, string? second) => string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    internal static bool Within(string dn, string namingContext)
    {
        for (string? current = dn; current is not null; current = DnHelper.GetParentDn(current))
            if (Same(current, namingContext)) return true;
        return false;
    }
}

/// <summary>An original attribute value used as a witness; the containing result supplies its source binding.</summary>
public sealed record Tier0Evidence(Tier0Target Object, string Attribute, int Ordinal, string Value);

/// <summary>An independently qualified classification support, not a flattened privileged flag.</summary>
public sealed record Tier0Support
{
    internal Tier0Support(Tier0Basis basis, Tier0Target root, ImmutableArray<Tier0Evidence> evidence)
    {
        Basis = basis;
        Root = root;
        Evidence = evidence;
    }

    /// <summary>The claim established by these witnesses.</summary>
    public Tier0Basis Basis { get; }
    /// <summary>The canonical core object supporting the classification.</summary>
    public Tier0Target Root { get; }
    /// <summary>Original attribute witnesses, retained independently for each support.</summary>
    public ImmutableArray<Tier0Evidence> Evidence { get; }
}

/// <summary>Capture coverage, supported analysis and processing completion are independent.</summary>
public sealed record Tier0Coverage(bool InputsComplete, bool AnalysisComplete, bool ProcessingComplete, Tier0Limitations Limitations)
{
    /// <summary>True only when none of the three boundaries is incomplete.</summary>
    public bool IsComplete => InputsComplete && AnalysisComplete && ProcessingComplete && Limitations == Tier0Limitations.None;
}

/// <summary>A shared evidence-backed answer; only the classifier creates qualified supports.</summary>
public sealed record Tier0Classification
{
    internal Tier0Classification(Tier0InputBinding input, Tier0Target target,
        ImmutableArray<Tier0Support> supports, Tier0Coverage coverage)
    {
        Input = input;
        Target = target;
        Supports = supports;
        Coverage = coverage;
    }

    /// <summary>The capture, derivation and semantics consumed by this result.</summary>
    public Tier0InputBinding Input { get; }
    /// <summary>The object classified, not a display name or bare SID.</summary>
    public Tier0Target Target { get; }
    /// <summary>Each qualifying independent basis, without route-count multiplication.</summary>
    public ImmutableArray<Tier0Support> Supports { get; }
    /// <summary>Limitations remain visible even when a positive support is established.</summary>
    public Tier0Coverage Coverage { get; }
    /// <summary>The bounded producer does not infer a negative from absent witnesses.</summary>
    public Tier0State State => Supports.Length != 0 ? Tier0State.Established : Tier0State.Unknown;
}

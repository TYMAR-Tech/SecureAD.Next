using System.Security.Cryptography;
using System.Text.Json;

namespace SecureAD.Evidence;

/// <summary>The immutable product selected by a publication root.</summary>
public enum StoreSegmentRole { Evidence, Navigation, Derivation, Judgement, PermissionProof, PathProof, JudgementFacts, Overview }

/// <summary>Exact sealed bytes, schema and generation for one independently readable product.</summary>
public sealed record SealedStoreSegment(StoreSegmentRole Role, int SchemaVersion, Guid GenerationId,
    string FileName, long ByteLength, string Hash);

/// <summary>A saved derivation counter, not a request to expand membership while browsing.</summary>
public sealed record DerivationBrowseSummary(int Version, string EvidenceSeal, Guid GenerationId,
    bool NestingWasDerived, int? GroupsWithUnidentifiedMembers);

/// <summary>One atomic selection of complete immutable products and their source identity.</summary>
public sealed record StoreRootManifest(int Version, Guid GenerationId, string EvidenceSeal,
    IReadOnlyList<SealedStoreSegment> Segments, DerivationBrowseSummary? DerivationSummary, string Hash)
{
    [System.Text.Json.Serialization.JsonInclude]
    internal IReadOnlyList<SealedStoreSegment> Segments { get; init; } = Segments;

    internal const int CurrentVersion = 3;
    /// <summary>The captured-object count maintained by the capture projection write, not by a loaded page.</summary>
    public long? CapturedObjects { get; init; }

    internal string ComputeHash() => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
        new { Version, GenerationId, EvidenceSeal, Segments, DerivationSummary, CapturedObjects }))).ToLowerInvariant();

    /// <summary>Returns the single declared role; duplicate or missing roles are never guessed.</summary>
    public SealedStoreSegment Segment(StoreSegmentRole role) => Segments.Single(segment => segment.Role == role);
}

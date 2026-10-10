using System.Collections.ObjectModel;
using System.Diagnostics.Metrics;
using SecureAD.Evidence;

namespace SecureAD.Derivation;

/// <summary>Source-linked membership inputs from one sealed capture and selected derivation.</summary>
/// <param name="DerivationGenerationId">The immutable derivation that collected these sources.</param>
/// <param name="IsComplete">Whether all declared capture units were read; not an attribute-visibility guarantee.</param>
/// <param name="Objects">Captured principal identities and membership attributes, including unresolved DN values.</param>
public sealed record CapturedMembershipInput(
    Guid DerivationGenerationId,
    bool IsComplete,
    IReadOnlyList<ObjectAttributes> Objects)
{
    internal const string MeterName = "SecureAD.Derivation.MembershipPreparation";
    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> Snapshots = Meter.CreateCounter<long>("membership.source_snapshots");
    private static readonly Counter<long> Indexes = Meter.CreateCounter<long>("membership.captured_index_builds");
    private static readonly Counter<long> CompactPaths = Meter.CreateCounter<long>("membership.compact_paths");
    private static readonly Counter<long> MaterializedPaths = Meter.CreateCounter<long>("membership.materialized_paths");

    /// <summary>Owns the source once, retaining ordered values and one reusable captured-identity index.</summary>
    public CapturedMembershipInput Prepare(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Objects is PreparedObjects) return this;
        return this with { Objects = new PreparedObjects(Objects, DerivationGenerationId, cancellationToken) };
    }

    /// <summary>Returns a unique captured DN; conflicting occurrences remain unresolved rather than selecting one.</summary>
    public ObjectAttributes? FindUnique(string distinguishedName, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        return Index(cancellationToken).Find(distinguishedName);
    }

    internal Tier0Classifier.CapturedIndex Index(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Objects is PreparedObjects prepared ? prepared.Index(DerivationGenerationId, cancellationToken)
            : CreateIndex(Objects, DerivationGenerationId, cancellationToken);
    }

    private static Tier0Classifier.CapturedIndex CreateIndex(IEnumerable<ObjectAttributes> objects, Guid generation,
        CancellationToken cancellationToken)
    {
        var result = new Tier0Classifier.CapturedIndex(objects, cancellationToken);
        Indexes.Add(1, Tag(generation));
        return result;
    }

    internal static void RecordCompactPath(Guid generation) => CompactPaths.Add(1, Tag(generation));
    internal static void RecordMaterializedPath(Guid generation) => MaterializedPaths.Add(1, Tag(generation));
    private static KeyValuePair<string, object?> Tag(Guid generation) => new("derivation", generation.ToString("D"));

    private sealed class PreparedObjects : ReadOnlyCollection<ObjectAttributes>
    {
        private Tier0Classifier.CapturedIndex? _index;

        internal PreparedObjects(IReadOnlyList<ObjectAttributes> objects, Guid generation, CancellationToken token)
            : base(Own(objects, token))
        {
            Snapshots.Add(1, Tag(generation));
        }

        internal Tier0Classifier.CapturedIndex Index(Guid generation, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return _index ??= CreateIndex(this, generation, token);
        }

        private static ObjectAttributes[] Own(IReadOnlyList<ObjectAttributes> objects, CancellationToken token)
        {
            var result = new List<ObjectAttributes>(objects.Count);
            foreach (var source in objects)
            {
                token.ThrowIfCancellationRequested();
                result.Add(source.Snapshot());
            }
            return result.ToArray();
        }
    }

    internal static readonly string[] AttributeNames =
    [
        "objectSid", "objectClass", "groupType", "primaryGroupID", "member", "memberOf",
        "sIDHistory", "userAccountControl", "isDeleted", "sAMAccountName", "dNSHostName",
    ];

    internal static ObjectAttributes? Project(ObjectAttributes source)
    {
        var classes = source.Find("objectClass")?.Values;

        // Naming-context heads are retained even though they are not principals. A partition root
        // holds no SID and no membership, so every other test here rejects it, but decision 0117
        // makes it a Tier-0 seed in its own right and the classifier cannot qualify what the index
        // does not contain. Its objectClass is the qualifying witness and is already projected.
        if (classes?.Any(value => value.Text is "domainDNS" or "configuration" or "dMD") == true) return Projected(source);
        // A CA registration is a target, not a principal; dropping it would lose the host's source witness.
        if (classes?.Any(value => string.Equals(value.Text, "pKIEnrollmentService", StringComparison.OrdinalIgnoreCase)) == true)
            return Projected(source);
        if (source.Find("objectSid")?.HasValue != true
            && classes?.Any(value => value.Text is "group" or "user" or "computer" or "foreignSecurityPrincipal") != true
            && source.Find("member")?.HasValue != true && source.Find("memberOf")?.HasValue != true)
            return null;
        return Projected(source);
    }

    private static ObjectAttributes Projected(ObjectAttributes source) => source with
    {
        Attributes = source.Attributes.Where(attribute => AttributeNames.Contains(attribute.LdapDisplayName,
            StringComparer.OrdinalIgnoreCase)).ToArray(),
    };
}

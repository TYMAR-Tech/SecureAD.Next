using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureAD.Judgement;

/// <summary>
/// What the permission writer has already stored once and need not store again this run.
/// </summary>
/// <remarks>
/// <para>
/// <b>Readings repeat, overwhelmingly.</b> The P-251 comparison found 209,032 stored entries carrying
/// only <b>240 distinct readings</b> between them - each one written out, on average, 871 times. The
/// same comparison measured the result file falling from 352,264,192 to 187,617,280 bytes when they
/// were shared, and found no judging gain on an NVMe laptop, where writing bytes is nearly free. The
/// 2026-09-22 laboratory run is where that stops being free: 18,463 ms of a 49,919 ms object pass
/// went to commits on standard SSD, against 1,979 ms for the same work on the laptop.
/// </para>
/// <para>
/// <b>Access control entries repeat far harder still.</b> P-279 measured 24,098 distinct entries
/// behind 17,164,866 stored positions - 712 copies of each - because the shared table deduplicated
/// only within one object. They are shared here for the same reason and under the same rules.
/// </para>
/// <para>
/// <b>Nothing is trusted until its transaction commits.</b> Rows written inside an open batch do not
/// exist yet, so they stay in the pending maps; a record claiming otherwise would let a later object
/// reference an identifier that was rolled back. <see cref="Promote"/> runs after the commit and
/// <see cref="Discard"/> after a rollback.
/// </para>
/// </remarks>
internal sealed class PermissionWriteSession
{
    private readonly Dictionary<string, string> _schema = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _pendingSchema = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _readings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _pendingReadings = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _entries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _pendingEntries = new(StringComparer.Ordinal);
    private readonly Dictionary<long, byte[]> _descriptors = [];
    private readonly Dictionary<long, byte[]> _pendingDescriptors = [];
    private readonly HashSet<long> _values = [];
    private readonly HashSet<long> _pendingValues = [];
    private readonly Dictionary<string, long> _proofs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _pendingProofs = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SchemaPayload> _schemaPayloads = new(StringComparer.Ordinal);

    private sealed record SchemaPayload(PermissionSchemaSupport Snapshot, string Json);

    /// <summary>Reuses schema JSON only while every value still matches an owned snapshot.</summary>
    internal string SerializeSchema(PermissionSchemaSupport support)
    {
        // IReadOnlyList does not make the caller's arrays immutable. Never accept a previously
        // seen reference (or GUID) without comparing it to the contents that were serialized.
        if (_schemaPayloads.TryGetValue(support.Guid, out var saved)
            && saved.Snapshot.Definitions.SequenceEqual(support.Definitions)
            && saved.Snapshot.AmbiguousNames.SequenceEqual(support.AmbiguousNames)
            && (saved.Snapshot.PropertySetMembers is null
                ? support.PropertySetMembers is null
                : support.PropertySetMembers is not null
                    && saved.Snapshot.PropertySetMembers.SequenceEqual(support.PropertySetMembers)))
            return saved.Json;

        var snapshot = support with
        {
            Definitions = support.Definitions.ToArray(),
            AmbiguousNames = support.AmbiguousNames.ToArray(),
            PropertySetMembers = support.PropertySetMembers?.ToArray(),
        };
        var json = JsonSerializer.Serialize(snapshot);
        _schemaPayloads[support.Guid] = new(snapshot, json);
        return json;
    }

    /// <summary>The payload already stored for a schema GUID, when there is one.</summary>
    /// <param name="guid">The schema GUID.</param>
    /// <param name="payload">The payload stored for it.</param>
    /// <returns>Whether this run has already written and verified a payload for that GUID.</returns>
    internal bool TryGetSchema(string guid, out string? payload) =>
        _schema.TryGetValue(guid, out payload) || _pendingSchema.TryGetValue(guid, out payload);

    /// <summary>Records a schema payload written in the open transaction.</summary>
    /// <param name="guid">The schema GUID.</param>
    /// <param name="payload">The payload written for it.</param>
    internal void AddSchema(string guid, string payload) => _pendingSchema[guid] = payload;

    /// <summary>The row already holding this reading, when there is one.</summary>
    /// <param name="key">The reading's fingerprint, as text.</param>
    /// <param name="id">The row holding it.</param>
    /// <returns>Whether this run has already stored that reading.</returns>
    internal bool TryGetReading(string key, out long id) =>
        _readings.TryGetValue(key, out id) || _pendingReadings.TryGetValue(key, out id);

    /// <summary>Records a reading written in the open transaction.</summary>
    /// <param name="key">The reading's fingerprint, as text.</param>
    /// <param name="id">The row holding it.</param>
    internal void AddReading(string key, long id) => _pendingReadings[key] = id;

    /// <summary>The row already holding this access control entry, when there is one.</summary>
    /// <param name="hash">The entry's content hash, as text.</param>
    /// <param name="id">The row holding it.</param>
    /// <returns>Whether this run has already stored that entry.</returns>
    /// <remarks>
    /// A miss is not an answer, only an absence of one: the caller still asks the table, because an
    /// on-demand assessment writes in a transaction no session ever saw.
    /// </remarks>
    internal bool TryGetEntry(string hash, out long id) =>
        _entries.TryGetValue(hash, out id) || _pendingEntries.TryGetValue(hash, out id);

    /// <summary>Records an access control entry written in the open transaction.</summary>
    /// <param name="hash">The entry's content hash, as text.</param>
    /// <param name="id">The row holding it.</param>
    internal void AddEntry(string hash, long id) => _pendingEntries[hash] = id;

    /// <summary>The fingerprint already stored for this descriptor, when there is one.</summary>
    /// <param name="descriptorId">The descriptor, as the evidence numbers it.</param>
    /// <param name="fingerprint">The fingerprint stored over its ordered entry list.</param>
    /// <returns>Whether this run has already stored that descriptor's classification.</returns>
    /// <remarks>
    /// <b>This is where <c>P-280</c>'s saving is actually taken.</b> On the production capture
    /// 940,067 objects carry 267,550 distinct descriptors, so 71.5% of objects find their
    /// descriptor already written and store no occurrences at all. The fingerprint is handed back
    /// rather than a bare yes, because the caller recomputes it from what this object read and
    /// refuses a disagreement — a descriptor identity that has been seen before is not on its own a
    /// promise that the entries behind it are the same ones.
    /// </remarks>
    internal bool TryGetDescriptor(long descriptorId, out byte[] fingerprint) =>
        _descriptors.TryGetValue(descriptorId, out fingerprint!)
        || _pendingDescriptors.TryGetValue(descriptorId, out fingerprint!);

    /// <summary>Records a descriptor classification written in the open transaction.</summary>
    /// <param name="descriptorId">The descriptor, as the evidence numbers it.</param>
    /// <param name="fingerprint">The fingerprint stored over its ordered entry list.</param>
    internal void AddDescriptor(long descriptorId, byte[] fingerprint) =>
        _pendingDescriptors[descriptorId] = fingerprint;

    /// <summary>Whether the interpretation of this entry has already been stored.</summary>
    /// <param name="entryId">The shared entry row.</param>
    /// <remarks>
    /// One row per distinct entry rather than one per occurrence, so the same entry appearing on a
    /// second descriptor writes nothing. The identity is the shared row, which was reached through
    /// <see cref="TryGetEntry"/> over the entry's own content hash.
    /// </remarks>
    internal bool HasValue(long entryId) =>
        _values.Contains(entryId) || _pendingValues.Contains(entryId);

    /// <summary>Records an entry interpretation written in the open transaction.</summary>
    /// <param name="entryId">The shared entry row it was written for.</param>
    internal void AddValue(long entryId) => _pendingValues.Add(entryId);

    internal bool TryGetProof(string key, out long id) =>
        _proofs.TryGetValue(key, out id) || _pendingProofs.TryGetValue(key, out id);

    internal void AddProof(string key, long id) => _pendingProofs[key] = id;

    /// <summary>Trusts everything written in the transaction that has just committed.</summary>
    internal void Promote()
    {
        foreach (var (guid, payload) in _pendingSchema) _schema[guid] = payload;
        foreach (var (key, id) in _pendingReadings) _readings[key] = id;
        foreach (var (hash, id) in _pendingEntries) _entries[hash] = id;
        foreach (var (id, fingerprint) in _pendingDescriptors) _descriptors[id] = fingerprint;
        foreach (var id in _pendingValues) _values.Add(id);
        foreach (var (key, id) in _pendingProofs) _proofs[key] = id;
        Discard();
    }

    /// <summary>Forgets everything written in a transaction that did not commit.</summary>
    internal void Discard()
    {
        _pendingSchema.Clear();
        _pendingReadings.Clear();
        _pendingEntries.Clear();
        _pendingDescriptors.Clear();
        _pendingValues.Clear();
        _pendingProofs.Clear();
    }

    /// <summary>The fingerprint that identifies a reading, as a dictionary key.</summary>
    /// <param name="payload">The serialised reading.</param>
    /// <returns>The fingerprint bytes and their text form.</returns>
    internal static (byte[] Bytes, string Key) Fingerprint(string payload)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        return (bytes, Convert.ToHexString(bytes));
    }

    /// <summary>How many distinct readings this run has stored, for the run log.</summary>
    internal string SharedReadings =>
        (_readings.Count + _pendingReadings.Count).ToString(CultureInfo.InvariantCulture);

    /// <summary>How many distinct access control entries this run has stored, for the run log.</summary>
    /// <remarks>
    /// Read against the number of entries written, this is the ratio P-279 was opened for: the
    /// before-measurement put it at 24,098 distinct entries behind 17,164,866 stored positions.
    /// </remarks>
    internal string SharedEntries =>
        (_entries.Count + _pendingEntries.Count).ToString(CultureInfo.InvariantCulture);
}

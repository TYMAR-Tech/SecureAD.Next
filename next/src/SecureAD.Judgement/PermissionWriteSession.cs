using System.Globalization;
using System.Security.Cryptography;
using System.Text;

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

    /// <summary>Trusts everything written in the transaction that has just committed.</summary>
    internal void Promote()
    {
        foreach (var (guid, payload) in _pendingSchema) _schema[guid] = payload;
        foreach (var (key, id) in _pendingReadings) _readings[key] = id;
        Discard();
    }

    /// <summary>Forgets everything written in a transaction that did not commit.</summary>
    internal void Discard()
    {
        _pendingSchema.Clear();
        _pendingReadings.Clear();
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
}

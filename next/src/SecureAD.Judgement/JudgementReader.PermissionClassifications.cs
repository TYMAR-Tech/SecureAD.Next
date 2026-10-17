using SecureAD.Evidence;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one object's saved per-right interpretations without invoking permission analysis.</summary>
    /// <param name="distinguishedName">The object to read.</param>
    /// <param name="carriedDescriptor">
    /// Which stored descriptor the <b>evidence</b> says this object carries, or <c>null</c> when it
    /// kept none. <see cref="Evidence.ObjectPermissions.DescriptorId"/> is where it comes from.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <remarks>
    /// <b>The descriptor is a parameter and not something this reader looks up</b> (<c>P-280</c>).
    /// The saved interpretations are stored once per descriptor, so an object reaches its own
    /// permissions through a descriptor identity — and this reader holds only the judgement
    /// connection, by design, so it cannot reach the evidence that is entitled to state which
    /// descriptor that is. Were the judgement allowed to answer it, a store saying <i>X uses D2</i>
    /// where the evidence says <i>X uses D1</i> would validate every fingerprint it holds and
    /// attribute D2's permissions to X. The caller brings the answer across; this refuses any
    /// disagreement.
    /// </remarks>
    public SavedPermissionClassification ReadPermissionClassification(string distinguishedName,
        long? carriedDescriptor, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (Description.State is not (JudgementRunState.Completed or JudgementRunState.CompletedDegraded))
            throw new InvalidOperationException(PermissionClassificationStorage.Message("Unavailable"));
        VerifyRequestedClassification(distinguishedName, carriedDescriptor);
        return PermissionClassificationStorage.Read(_connection, Description, distinguishedName, carriedDescriptor, cancellationToken);
    }

    private void VerifyRequestedClassification(string target, long? carriedDescriptor)
    {
        var facts = RequestedPart(StoreSegmentRole.JudgementFacts);
        RequestedPart(StoreSegmentRole.PermissionProof);
        var product = facts.ReadSingle("permission_classification_product", 1L)
            ?? throw new InvalidOperationException(PermissionClassificationStorage.Message("Unavailable"));
        product.VerifyValues();
        var selected = Required(facts, "permission_classification_object", target);
        var descriptor = selected.IsNull("descriptor_id") ? null : (long?)selected.Integer("descriptor_id");
        if (descriptor != carriedDescriptor) throw new InvalidDataException(PermissionClassificationStorage.Message("Invalid"));
        if (descriptor is null) return;
        Required(facts, "permission_classification_descriptor", descriptor.Value);
        var entries = new HashSet<long>();
        var readings = new HashSet<long>();
        var schema = new HashSet<string>(StringComparer.Ordinal);
        foreach (var occurrence in facts.ReadCompleteScope("permission_classification_entry", descriptor.Value))
        {
            occurrence.VerifyValues();
            var id = occurrence.Integer("entry_id");
            if (!entries.Add(id)) continue;
            try { JudgementStoreLayout.VerifyPermission(_connection, id); }
            catch (InvalidOperationException error)
            {
                throw new InvalidDataException(PermissionClassificationStorage.Message("Invalid"), error);
            }
            var value = Required(facts, "permission_classification_value", id);
            var reading = value.Integer("reading_id");
            if (readings.Add(reading)) Required(facts, "permission_classification_reading", reading);
            Support("object_schema");
            Support("inherited_schema");

            void Support(string column)
            {
                if (value.IsNull(column)) return;
                var guid = value.CompleteText(column);
                if (schema.Add(guid)) Required(facts, "permission_classification_schema", guid);
            }
        }

    }

    private static RequestedDetailRow Required(RequestedDetailReader reader, string table, object owner)
    {
        var row = reader.ReadSingle(table, owner)
            ?? throw new InvalidDataException("The selected saved proof has a missing source record.");
        row.VerifyValues();
        return row;
    }
}

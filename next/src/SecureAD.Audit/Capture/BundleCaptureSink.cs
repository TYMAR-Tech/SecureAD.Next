using SecureAD.Audit.Sysvol;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;

namespace SecureAD.Audit.Capture;

/// <summary>
/// Where a capture pass's objects go: the bundle.
/// </summary>
/// <remarks>
/// <para>
/// This is the join between capture and storage - inventory row C15's other half. Connect, capture,
/// the schema and run identity were each finished and none of them called another, so until this
/// existed the product had never run end to end. It is deliberately thin: it maps what capture
/// produces onto what the bundle expects and decides nothing.
/// </para>
/// <para>
/// <b>It is not thread-safe and holds one partition at a time</b>, because
/// <see cref="BundleWriter"/> is one connection held for the run and a capture reads one naming
/// context at a time into one store. A second partition opened before the first completes is a
/// defect in the caller and is refused rather than interleaved.
/// </para>
/// <para>
/// <b>A security descriptor the forest holds and this product could not parse is stored as an
/// unreadable one, not dropped and not fatal.</b> That is the distinction inventory row B9 draws and
/// it is the one that matters most here: a value <i>this product</i> cannot represent is a defect
/// in this product and ends the run, while a descriptor <i>the forest holds</i> that could not be
/// read is a fact about the customer's directory and belongs in the evidence. Conflating them is
/// how a real finding gets discarded as a bug in the reader.
/// </para>
/// </remarks>
public sealed class BundleCaptureSink : ICapturedObjectSink
{
    /// <summary>
    /// The attribute the security descriptor arrives on. Named here rather than matched loosely,
    /// because the whole security half of the bundle hangs off recognising it.
    /// </summary>
    private const string SecurityDescriptorAttribute = "nTSecurityDescriptor";

    private readonly BundleWriter _writer;
    private readonly TimeProvider _time;

    private PartitionCoverage? _openPartition;
    private GpoInventory.Checkpoint? _policyCheckpoint;

    /// <summary>
    /// Creates a sink writing into <paramref name="writer"/>.
    /// </summary>
    /// <param name="writer">The bundle being written.</param>
    /// <param name="time">
    /// The clock each object's capture time is read from. Named rather than taken from the ambient
    /// one because a bundle written in a test has to come out the same twice.
    /// </param>
    public BundleCaptureSink(BundleWriter writer, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(time);

        _writer = writer;
        _time = time;
    }

    /// <summary>How many descriptors the forest held that could not be parsed.</summary>
    /// <remarks>
    /// Counted so a run can report it rather than a reader having to notice. It is a fact about the
    /// customer's directory, and a run where it is not zero is worth saying so out loud.
    /// </remarks>
    public int UnreadableDescriptors { get; private set; }

    /// <summary>
    /// The Group Policy objects seen while reading the directory.
    /// </summary>
    /// <remarks>
    /// Collected here because this is the one place every captured object passes, and it must be
    /// collected from the directory rather than from the share: per <c>docs/decisions/0044</c> the
    /// SYSVOL coverage record is only permitted because its denominator comes from LDAP before any
    /// file is opened.
    /// </remarks>
    public GpoInventory Policies { get; } = new();

    /// <inheritdoc/>
    public void BeginPartition(
        CaptureUnit unit, ConnectionSecurityLevel connectionSecurity, bool referralsSuppressed)
    {
        ArgumentNullException.ThrowIfNull(unit);

        if (_openPartition is not null)
        {
            throw new InvalidOperationException(
                $"'{unit.NamingContext}' is being opened while '{_openPartition.NamingContextDn}' "
                + "is still open. One partition is read at a time into one store, so two open at "
                + "once means objects could be attributed to the wrong one.");
        }

        // Everything except the counts is known now, and the one derived answer - whether the
        // continuation references will be a complete statement of what lies below - depends only
        // on whether the domain-scope control was sent. So this carries the right answer to the
        // question an object asks of its partition, while the counts wait for the pass to end.
        _openPartition = new PartitionCoverage(
            unit.NamingContext,
            unit.Kind,
            unit.DomainController,
            connectionSecurity,
            PagesRead: 0,
            ObjectsRead: 0,
            AttributeBlocksFetched: 0,
            ContinuationReferences: [],
            referralsSuppressed);

        _policyCheckpoint = Policies.Mark();

        _writer.BeginPartition(
            unit.NamingContext, unit.Kind, unit.DomainController, connectionSecurity);
    }

    /// <inheritdoc/>
    public void Receive(CapturedObject capturedObject)
    {
        ArgumentNullException.ThrowIfNull(capturedObject);

        var partition = _openPartition
            ?? throw new InvalidOperationException(
                $"'{capturedObject.DistinguishedName}' arrived with no partition open. An object "
                + "that cannot be attributed to the pass that read it is an object whose absence "
                + "means nothing, so it is refused rather than filed under a guess.");

        var attributes = new List<EvidenceAttribute>();
        AttributeValues? descriptor = null;

        foreach (var attribute in capturedObject.Attributes)
        {
            if (string.Equals(
                    attribute.LdapDisplayName,
                    SecurityDescriptorAttribute,
                    StringComparison.OrdinalIgnoreCase))
            {
                descriptor = attribute;
                continue;
            }

            attributes.Add(ToEvidenceAttribute(capturedObject.DistinguishedName, attribute));
        }

        var evidenceObject = new EvidenceObject(
            partition,
            capturedObject.DistinguishedName,
            ObjectGuidOf(capturedObject),
            attributes,
            _time.GetUtcNow());

        var objectId = _writer.WriteObject(evidenceObject);

        Policies.Observe(capturedObject, evidenceObject.ObjectGuid);

        if (descriptor is not null)
        {
            WriteDescriptor(objectId, evidenceObject.ObjectGuid, descriptor);
        }
    }

    /// <inheritdoc/>
    public void CompletePartition(PartitionCoverage coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);

        if (_openPartition is null)
        {
            throw new InvalidOperationException(
                $"'{coverage.NamingContextDn}' is being completed with no partition open.");
        }

        _writer.CompletePartition(coverage);
        _openPartition = null;
        _policyCheckpoint = null;
    }

    /// <inheritdoc/>
    public void AbortPartition()
    {
        if (_openPartition is null || _policyCheckpoint is not { } checkpoint)
            throw new InvalidOperationException("There is no partition attempt to abort.");

        _writer.AbortPartition();
        Policies.Restore(checkpoint);
        _openPartition = null;
        _policyCheckpoint = null;
    }

    /// <summary>
    /// Stores one object's security descriptor, or the fact that it never arrived.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two different failures, and only one of them is about parsing.</b> A descriptor that did
    /// not come back at all is recorded with
    /// <see cref="BundleWriter.WriteUnreadableSecurityDescriptor"/> and counted against the
    /// partition. That is not hypothetical: a Windows Server 2025 controller strips confidential
    /// attributes from an unencrypted search and returns no error to the client, so a partition
    /// read on a low rung can be missing descriptors with nothing else in the bundle recording
    /// their absence - which is <c>F-S24-1</c>, and is why the rung is stored per partition.
    /// </para>
    /// <para>
    /// A descriptor that <i>did</i> arrive goes to the parser whatever the parser makes of it.
    /// <see cref="SecurityDescriptorParser.Parse"/> does not throw - it records what it could not
    /// read in its errors, and answers <see cref="DaclState.Unreadable"/> where a DACL declared
    /// entries and none of them parsed. All of that is stored, because a descriptor the forest
    /// holds is a fact about the customer's directory even where this product cannot make sense of
    /// it. An earlier draft of this method wrapped the parse in a <c>catch</c>, which would never
    /// have fired and would have made every malformed descriptor look well-formed.
    /// </para>
    /// </remarks>
    private void WriteDescriptor(long objectId, Guid? objectGuid, AttributeValues descriptor)
    {
        if (descriptor.Completeness != AttributeCompleteness.Complete)
        {
            _writer.WriteUnreadableSecurityDescriptor(
                objectId,
                "The controller did not return nTSecurityDescriptor. It is withheld silently from "
                + "a reader without permission, and stripped from an unencrypted search by a "
                + "controller that reports no error, so this records that it did not arrive and "
                + "makes no claim about why.");
            UnreadableDescriptors++;
            return;
        }

        if (descriptor.Values.OfType<byte[]>().FirstOrDefault() is not { } descriptorBytes)
        {
            _writer.WriteUnreadableSecurityDescriptor(
                objectId,
                "nTSecurityDescriptor came back as something other than bytes, so there is nothing "
                + "to parse and nothing that may be presented as this object's permissions.");
            UnreadableDescriptors++;
            return;
        }

        var parsed = SecurityDescriptorParser.Parse(descriptorBytes);
        var normalization = AceNormalizer.Normalize(objectGuid ?? Guid.Empty, parsed);

        _writer.WriteSecurityDescriptor(objectId, descriptorBytes, normalization);
    }

    /// <summary>
    /// The object's identity, if it arrived.
    /// </summary>
    /// <remarks>
    /// Null rather than defaulted when it did not, per <c>docs/decisions/0002</c>: an object with
    /// no identity cannot take part in a comparison between two runs, and a reader has to be able
    /// to see that rather than be handed a placeholder that silently joins to nothing.
    /// </remarks>
    private static Guid? ObjectGuidOf(CapturedObject capturedObject)
    {
        var attribute = capturedObject.Attributes.FirstOrDefault(a =>
            string.Equals(a.LdapDisplayName, "objectGUID", StringComparison.OrdinalIgnoreCase));

        if (attribute is null || attribute.Completeness != AttributeCompleteness.Complete)
            return null;

        var bytes = attribute.Values.OfType<byte[]>().FirstOrDefault();

        return bytes is { Length: 16 } ? new Guid(bytes) : null;
    }

    /// <summary>
    /// Turns one captured attribute into the shape the bundle stores.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An attribute that did not arrive is carried across as
    /// <see cref="StoredAttributeCompleteness.NotReturned"/> with no values rather than being
    /// dropped, because omitting it makes <i>the reader was not permitted to see this</i> and
    /// <i>the object has no value for this</i> the same row.
    /// </para>
    /// <para>
    /// <b>An unfinished attribute ends the run.</b> <see cref="CapturedObject.Create"/> already
    /// refuses one, and this refuses it again: a prefix of a group's membership stored as its
    /// membership is silent, and two walls is what B9 asked for.
    /// </para>
    /// </remarks>
    private static EvidenceAttribute ToEvidenceAttribute(
        string distinguishedName, AttributeValues attribute)
    {
        if (attribute.Completeness == AttributeCompleteness.MoreToFetch)
        {
            throw new InvalidOperationException(
                $"'{attribute.LdapDisplayName}' on '{distinguishedName}' is being stored while the "
                + "controller still has more of it. A prefix of a group's members presented as its "
                + "members is the defect range retrieval exists to remove.");
        }

        if (attribute.Completeness == AttributeCompleteness.NotReturned)
        {
            return new EvidenceAttribute(
                attribute.LdapDisplayName, StoredAttributeCompleteness.NotReturned, []);
        }

        var values = new List<EvidenceValue>(attribute.Values.Count);

        var declared = DeclaredStorageOf(attribute.LdapDisplayName, distinguishedName);

        foreach (var value in attribute.Values)
        {
            values.Add(declared == AttributeStorage.Text
                ? EvidenceValue.OfText(Text(value, attribute, distinguishedName))
                : EvidenceValue.OfBytes(Bytes(value, attribute, distinguishedName)));
        }

        return new EvidenceAttribute(
            attribute.LdapDisplayName, StoredAttributeCompleteness.Complete, values);
    }

    /// <summary>
    /// How the catalogue says this attribute is stored.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The catalogue decides, not the runtime type of the value.</b> This once chose by
    /// inspecting whether the value happened to be a <c>string</c> or a <c>byte[]</c>, which meant
    /// the shape of the wire decided the shape of the evidence. A live directory sends text as
    /// bytes, so every text attribute in the forest was about to be stored as binary - and the
    /// first real capture died on <c>cn</c>, three objects in, against the writer's own guard that
    /// storage must match what was declared. That guard was right; this was wrong.
    /// </para>
    /// <para>
    /// An attribute that is not in the catalogue was never asked for, so it arriving here is a
    /// defect in this product rather than anything a controller did.
    /// </para>
    /// </remarks>
    private static AttributeStorage DeclaredStorageOf(
        string ldapDisplayName, string distinguishedName)
    {
        if (Declared.TryGetValue(ldapDisplayName, out var storage))
            return storage;

        throw new InvalidOperationException(
            $"'{ldapDisplayName}' on '{distinguishedName}' is not in the captured attribute "
            + "catalogue, so nothing declares how it is stored. Capture asks for the attributes "
            + "the catalogue names and no others, so this is a fault in this product rather than "
            + "anything the directory did.");
    }

    /// <summary>Every attribute the catalogue names, and how it is stored.</summary>
    private static readonly Dictionary<string, AttributeStorage> Declared =
        CapturedAttributeCatalog.All
            .GroupBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First().Storage, StringComparer.OrdinalIgnoreCase);

    private static string Text(
        object value, AttributeValues attribute, string distinguishedName)
    {
        var text = LdapEntryReader.AsText(value);

        return text.IsSuccess
            ? text.Value!
            : throw new InvalidOperationException(
                $"'{attribute.LdapDisplayName}' on '{distinguishedName}' is declared as text and "
                + $"could not be read as text: {text.Error!.Description}");
    }

    private static byte[] Bytes(
        object value, AttributeValues attribute, string distinguishedName)
    {
        var bytes = LdapEntryReader.AsBytes(value);

        return bytes.IsSuccess
            ? bytes.Value!
            : throw new InvalidOperationException(
                $"'{attribute.LdapDisplayName}' on '{distinguishedName}' is declared as binary and "
                + $"could not be read as bytes: {bytes.Error!.Description}");
    }
}

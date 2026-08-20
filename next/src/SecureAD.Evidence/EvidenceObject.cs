namespace SecureAD.Evidence;

/// <summary>
/// Whether the stored values of one attribute are all of the values.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two states, where the reader that produced them has three.</b> That is the point of this
/// type, not an oversight. A capture-side attribute can also be part-way through a range
/// retrieval - a prefix of a group's membership, with more to fetch - and <b>that state has no
/// spelling here</b>, so an unfinished attribute cannot be written into a bundle at all. It is
/// unrepresentable rather than merely rejected, which is the strongest form the refusal can take:
/// a check can be forgotten and a missing enum member cannot.
/// </para>
/// <para>
/// <b>This is a write-side vocabulary and not a stored fact.</b> Nothing in the schema records it.
/// Per <c>docs/decisions/0022</c> an attribute that did not arrive and one the object never had are
/// the same emptiness - Active Directory omits an absent attribute without saying which - so a
/// column claiming to tell them apart would record a guess. What
/// <see cref="NotReturned"/> means here is therefore an instruction to the writer, <i>store
/// nothing for this</i>, rather than a claim to be written down. See <c>docs/next/S-24</c>
/// <c>F-S24-3</c>.
/// </para>
/// <para>
/// The schema used to say the same thing a second time with a constraint. It no longer can, having
/// no column left to constrain, and that reduction is recorded as <c>F-S24-6</c> rather than left
/// to be noticed.
/// </para>
/// </remarks>
public enum StoredAttributeCompleteness
{
    /// <summary>Every value the controller holds for this attribute is stored.</summary>
    Complete,

    /// <summary>
    /// The response did not carry this attribute at all, so nothing is stored for it: the column
    /// stays null, or the value table gets no rows. Indistinguishable, once written, from an
    /// object that simply has no value - which is correct, because the two are indistinguishable
    /// on the wire.
    /// </summary>
    NotReturned,
}

/// <summary>
/// One value of one attribute: text or bytes, and never both or neither.
/// </summary>
/// <remarks>
/// Constructed only through <see cref="OfText"/> and <see cref="OfBytes"/>, so a value that is
/// neither is unrepresentable. A value that is bytes and gets stored as text is not an error that
/// surfaces - it is a mangled string that looks like data, and <c>objectSid</c>, <c>objectGUID</c>
/// and the two security descriptors deciding who can take an identity over are all bytes.
/// </remarks>
public sealed record EvidenceValue
{
    private EvidenceValue(string? text, byte[]? bytes)
    {
        Text = text;
        Bytes = bytes;
    }

    /// <summary>The value as text, or null when this is a byte value.</summary>
    public string? Text { get; }

    /// <summary>The value as bytes, or null when this is a text value.</summary>
    public byte[]? Bytes { get; }

    /// <summary>A text value.</summary>
    /// <param name="text">The text, as the controller sent it.</param>
    public static EvidenceValue OfText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return new EvidenceValue(text, null);
    }

    /// <summary>A byte value.</summary>
    /// <param name="bytes">The bytes, as the controller sent them.</param>
    public static EvidenceValue OfBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return new EvidenceValue(null, bytes);
    }
}

/// <summary>
/// One attribute of one object, as it will be stored.
/// </summary>
/// <param name="LdapDisplayName">The attribute, under the name the catalogue asked for.</param>
/// <param name="Completeness">Whether these are all of the values.</param>
/// <param name="Values">
/// The values, in the order the controller sent them. Empty when
/// <paramref name="Completeness"/> is <see cref="StoredAttributeCompleteness.NotReturned"/>.
/// </param>
public sealed record EvidenceAttribute(
    string LdapDisplayName,
    StoredAttributeCompleteness Completeness,
    IReadOnlyList<EvidenceValue> Values);

/// <summary>
/// One object as it will be stored: the partition it was read from, its distinguished name, and
/// every attribute the controller had something to say about, including the ones where what it
/// said was nothing.
/// </summary>
/// <param name="Coverage">
/// The pass this object was read by.
/// <para>
/// <b>Carried on the object rather than passed beside it.</b> The writer used to take the coverage
/// handle as a separate argument, which meant an object and the partition it was attributed to
/// could disagree - and nothing would have noticed, because a row that names the wrong partition is
/// still a valid row. Holding the two together makes that disagreement unrepresentable rather than
/// merely guarded against, which is the stronger form: a guard can be forgotten and a missing
/// argument cannot. See <c>F-S24-7</c>, option A.
/// </para>
/// </param>
/// <param name="DistinguishedName">The object's distinguished name, as the controller gave it.</param>
/// <param name="ObjectGuid">
/// The object's identity, and the only one that survives a rename or a move.
/// <para>
/// Null when it did not arrive, rather than defaulted, because per <c>docs/decisions/0002</c> a
/// value that did not arrive is not invented. An object with no identity cannot take part in a
/// comparison between two runs, and a reader has to be able to see that rather than be handed a
/// placeholder that silently joins to nothing.
/// </para>
/// </param>
/// <param name="Attributes">Its attributes, each with the answer to "are these all of them".</param>
/// <param name="CapturedUtc">
/// When this object was read.
/// <para>
/// Per object rather than once per run, because a capture of a large forest is not an instant - it
/// is hours - and two objects in the same bundle can have been read far enough apart for one to
/// have changed after the other was seen. A single run-level timestamp would quietly claim they
/// were a snapshot.
/// </para>
/// <para>
/// Supplied by the caller rather than read from a clock inside the writer, which is what the
/// predecessor did too. The writer records what happened; it does not decide when it happened, and
/// a writer that stamps its own times cannot be tested deterministically.
/// </para>
/// </param>
public sealed record EvidenceObject(
    PartitionCoverage Coverage,
    string DistinguishedName,
    Guid? ObjectGuid,
    IReadOnlyList<EvidenceAttribute> Attributes,
    DateTimeOffset CapturedUtc)
{
    /// <summary>
    /// What the connection this object was read over could have withheld without saying so.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>It answered a different question until <c>F-S29-3</c>, and that question had one answer.</b>
    /// It forwarded to the partition's completeness, which is a statement about whether the list of
    /// continuation references is exhaustive - so every domain object in a bundle reported that we
    /// could not say whether we had looked properly, while configuration and schema objects reported
    /// that we could. It was the wrong answer on nearly half of a real capture, and the question it
    /// was reaching for is unanswerable anyway: capture is fail-fast per
    /// <c>docs/decisions/0003</c>, so "was this partition read to the end" is true of every object in
    /// every sealed bundle.
    /// </para>
    /// <para>
    /// <b>What it asks instead is reachable.</b> A controller serving an unencrypted search may
    /// strip confidential attributes and return no error, so the rung the connection reached decides
    /// whether an absent value is evidence. That varies between runs with nothing an operator did.
    /// </para>
    /// <para>
    /// <b>It is also what makes the type vouched under gate 4</b>, and that is worth stating
    /// plainly so a later reader does not mistake it for a member added to quieten a check.
    /// <see cref="Attributes"/> is a collection handed back in public, and the gate asks that the
    /// type carrying it be able to say whether it managed to look - otherwise an empty list reads
    /// the same whether capture found nothing or never ran. Until S-24 the answer came from a
    /// per-attribute completeness marker, which was removed because it recorded a distinction the
    /// LDAP protocol does not provide. This answers a narrower question from the level at which it
    /// is observable. The alternative on offer was a fifth entry in the gate's allowlist, whose own
    /// comment says that widening it is how a gate dies.
    /// </para>
    /// </remarks>
    public EvidenceCompleteness Completeness => Coverage.ConnectionSecurity switch
    {
        ConnectionSecurityLevel.Ldaps or ConnectionSecurityLevel.SignedAndSealed =>
            EvidenceCompleteness.Complete,
        _ => EvidenceCompleteness.MayBeMissingConfidentialValues,
    };
}

// PartitionCoverageRecord used to live here, twinned with PartitionCoverage in SecureAD.Audit.
// The pair is now one type in PartitionCoverage.cs, per docs/decisions/0035.

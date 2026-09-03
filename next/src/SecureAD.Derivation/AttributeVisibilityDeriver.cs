using SecureAD.Evidence;
using SecureAD.Kernel.Schema;

namespace SecureAD.Derivation;

/// <summary>
/// What this forest's schema says about whether one attribute can be read.
/// </summary>
/// <remarks>
/// <b>Four answers, and collapsing any two of them loses a rule.</b> A rule reading a LAPS
/// timestamp needs <see cref="Readable"/> before it may treat an absent value as a fact about a
/// machine. Every other answer means silence is a statement about the capture instead, and
/// <c>docs/decisions/0002</c> forbids rendering one as the other.
/// </remarks>
public enum AttributeVisibilityAnswer
{
    /// <summary>
    /// The run was refused the schema partition, so nothing is known about any attribute. Not the
    /// same as a forest that withholds nothing.
    /// </summary>
    SchemaNotRead,

    /// <summary>
    /// The forest's schema carries no such attribute. <b>No object in it can hold a value</b>, so
    /// absence is not evidence about any individual object - which is why a rule reading only this
    /// attribute must stay silent rather than report every object in the forest.
    /// </summary>
    NotInSchema,

    /// <summary>
    /// The attribute is defined and its flags were not captured. <b>Answered cautiously</b>: an
    /// attribute not known to be readable is not an attribute known to be readable, and guessing
    /// the Microsoft default here is the shape of mistake that produced the <c>krbtgt</c> defect.
    /// </summary>
    FlagsNotCaptured,

    /// <summary>
    /// The attribute is defined and this forest does not withhold it. <b>Absence is now a fact
    /// about the object</b> and may be reported.
    /// </summary>
    Readable,

    /// <summary>
    /// This forest has marked the attribute confidential. It is withheld silently, so a privileged
    /// run and an unprivileged one are indistinguishable per object and absence proves nothing.
    /// </summary>
    Confidential,
}

/// <summary>
/// One attribute's visibility, as the schema partition stated it.
/// </summary>
/// <param name="LdapDisplayName">The attribute.</param>
/// <param name="SearchFlags">Its <c>searchFlags</c>, or null where none was captured.</param>
/// <param name="SystemFlags">Its <c>systemFlags</c>, or null where none was captured.</param>
public sealed record AttributeVisibilityFact(
    string LdapDisplayName,
    int? SearchFlags,
    int? SystemFlags)
{
    /// <summary>What this means for a rule that reads the attribute.</summary>
    /// <remarks>
    /// Recomputed from the two flags rather than stored beside them, so the answer and the values it
    /// came from cannot drift apart.
    /// </remarks>
    public AttributeVisibilityAnswer Answer =>
        SearchFlags is null
            ? AttributeVisibilityAnswer.FlagsNotCaptured
            : SchemaAttributeFlags.IsConfidential(SearchFlags, SystemFlags)
                ? AttributeVisibilityAnswer.Confidential
                : AttributeVisibilityAnswer.Readable;
}

/// <summary>
/// Which attributes this forest withholds, derived once and consulted by every rule that reads one.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a derived product and not a lookup a rule performs itself.</b> A rule judges one object
/// and nothing else - no sibling lookup, no second pass - so a rule holding a computer object
/// cannot go and read the schema partition. The answer has to be handed to it, and
/// <c>JudgingContext</c> is the only channel there is.
/// </para>
/// <para>
/// <b>What declaring it buys is the whole-run refusal.</b> Per <c>docs/decisions/0091</c> a judging
/// missing a derivation a scheduled rule declared is refused before it starts, rather than
/// reporting an unanswerable question against every computer in the forest. For SEC-094 that
/// matters more than for most: if the modern LAPS timestamp were confidential in a forest, every
/// modern-capable machine carrying a legacy value would be reported and every one of those findings
/// would be false.
/// </para>
/// </remarks>
/// <param name="Attributes">Every schema definition captured, in the order read.</param>
public sealed record StoredAttributeVisibility(IReadOnlyList<AttributeVisibilityFact> Attributes)
{
    private Dictionary<string, AttributeVisibilityFact>? _byName;

    /// <summary>
    /// Whether this capture was given the schema partition at all.
    /// </summary>
    /// <remarks>
    /// <b>Gate 4's requirement, and the rule's as well.</b> A product with no attributes in it is
    /// not a forest that withholds nothing - it is a run nobody asked - and
    /// <see cref="Answer"/> returns <see cref="AttributeVisibilityAnswer.SchemaNotRead"/> for every
    /// question in that case rather than letting the emptiness read as an answer.
    /// </remarks>
    public bool SchemaAttributesWereAsked => Attributes.Count > 0;

    /// <summary>
    /// What the schema says about one attribute.
    /// </summary>
    /// <remarks>
    /// <b>An empty product answers <see cref="AttributeVisibilityAnswer.SchemaNotRead"/>, not
    /// <see cref="AttributeVisibilityAnswer.NotInSchema"/>.</b> No forest has zero attribute
    /// definitions, so emptiness is a fact about the run rather than about the schema, and the two
    /// lead a rule to opposite behaviour: one is silence, the other is a reported gap.
    /// </remarks>
    /// <param name="ldapDisplayName">The attribute, matched without regard to case.</param>
    public AttributeVisibilityAnswer Answer(string ldapDisplayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        if (!SchemaAttributesWereAsked)
            return AttributeVisibilityAnswer.SchemaNotRead;

        _byName ??= Attributes
            .GroupBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return _byName.TryGetValue(ldapDisplayName, out var fact)
            ? fact.Answer
            : AttributeVisibilityAnswer.NotInSchema;
    }
}

/// <summary>
/// Whether the attribute-visibility derivation is there to be read.
/// </summary>
/// <remarks>
/// Separate from the product itself for the reason
/// <see cref="ProtectedPrincipalProductAvailability"/> gives: a phase that did not run and a phase
/// that ran and found nothing are opposite answers, and a null product cannot say which happened.
/// </remarks>
public enum AttributeVisibilityAvailability
{
    /// <summary>The phase ran and its product is here.</summary>
    Available,

    /// <summary>The phase was never attempted, because something it needed was absent.</summary>
    DidNotRun,

    /// <summary>The phase threw. Its fault is recorded against it rather than blamed on the store.</summary>
    Failed,

    /// <summary>The store has no product and no phase row explaining why. A store to distrust.</summary>
    Missing,
}

/// <summary>
/// The stored attribute-visibility product, with whether there is one.
/// </summary>
/// <param name="Availability">Whether the product is here, and why not when it is not.</param>
/// <param name="Value">The product, or null when <paramref name="Availability"/> is not Available.</param>
public sealed record StoredAttributeVisibilityProduct(
    AttributeVisibilityAvailability Availability,
    StoredAttributeVisibility? Value);

/// <summary>
/// Derives which attributes this forest withholds, from the schema partition inside the seal.
/// </summary>
/// <remarks>
/// <para>
/// <b>The cheapest phase in the derivation, and deliberately so.</b> It reads rows capture already
/// took - <c>CapturedAttributeCatalog.SchemaPartition</c> requests <c>searchFlags</c> and
/// <c>systemFlags</c> on every <c>attributeSchema</c> object - and turns them into a lookup. There
/// is no graph, no closure and no budget, so it cannot degrade for any reason except the schema
/// partition being absent from the capture.
/// </para>
/// <para>
/// <b>It records every attribute, not only the ones a rule names.</b> A product scoped to LAPS
/// would have to be rewritten by the next rule that needs to know whether an attribute is withheld,
/// and a derivation phase is not a cheap thing to rewrite. The whole schema is a few thousand rows.
/// </para>
/// </remarks>
public static class AttributeVisibilityDeriver
{
    /// <summary>The name this phase is recorded under.</summary>
    public const string PhaseName = "AttributeVisibility";

    /// <summary>
    /// Turns the captured schema definitions into the product rules consult.
    /// </summary>
    /// <param name="reading">What the schema partition held, and whether it was read.</param>
    public static StoredAttributeVisibility Derive(SchemaAttributeReading reading)
    {
        ArgumentNullException.ThrowIfNull(reading);

        return new StoredAttributeVisibility(
            [.. reading.Attributes.Select(d =>
                new AttributeVisibilityFact(d.LdapDisplayName, d.SearchFlags, d.SystemFlags))]);
    }
}

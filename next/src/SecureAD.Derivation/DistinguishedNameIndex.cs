namespace SecureAD.Derivation;

/// <summary>
/// Maps distinguished names to small integers, and remembers which SID each one turned out to
/// belong to.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because membership is written in distinguished names and stored in SIDs.</b> A
/// group's <c>member</c> and an account's <c>memberOf</c> both name the other side by distinguished
/// name, while <see cref="NestingEdge"/> names both sides by the SID dictionary's ids. The two
/// cannot be reconciled as the bundle is read, because the object a name refers to may not have
/// been streamed yet - so names are interned on the way past and resolved once, at the end.
/// </para>
/// <para>
/// <b>Interning rather than keeping the strings on the edges.</b> One distinguished name appears at
/// least twice - once as an object's own name and once inside the containing group's
/// <c>member</c> - and in a forest of any size a great deal more often than that. Held as ids, an
/// edge is two integers and each name is stored once.
/// </para>
/// <para>
/// <b>Comparison is case-insensitive, which is close to right rather than exactly right.</b> LDAP
/// treats a distinguished name's attribute types and most of its values case-insensitively, so
/// ordinal comparison would split one object across two ids. Full equivalence would also normalise
/// escaping and whitespace around the separators; this does not, so two spellings of one name that
/// differ in those ways resolve as two, and the second becomes an unresolved trustee rather than a
/// wrong edge. That is the safe direction to be imprecise in: a missing edge is recorded as a gap,
/// where an invented one would not be.
/// </para>
/// </remarks>
internal sealed class DistinguishedNameIndex
{
    private const int Unresolved = -1;

    private readonly Dictionary<string, int> _ids = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _text = [];
    private readonly List<int> _sidIdByDnId = [];

    /// <summary>How many distinct names have been seen.</summary>
    internal int Count => _sidIdByDnId.Count;

    /// <summary>
    /// The id for a name, assigning one if this is the first time it has been seen.
    /// </summary>
    /// <param name="distinguishedName">The name, as the controller gave it.</param>
    internal int IdOf(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        if (_ids.TryGetValue(distinguishedName, out var existing))
            return existing;

        var id = _sidIdByDnId.Count;
        _ids.Add(distinguishedName, id);
        _text.Add(distinguishedName);
        _sidIdByDnId.Add(Unresolved);
        return id;
    }

    /// <summary>
    /// Records which SID the object with this name turned out to have.
    /// </summary>
    /// <remarks>
    /// Called when the named object is streamed, which may be long after something referred to it.
    /// </remarks>
    /// <param name="distinguishedNameId">The name's id.</param>
    /// <param name="sidId">The SID dictionary id for that object.</param>
    internal void BindSid(int distinguishedNameId, int sidId) =>
        _sidIdByDnId[distinguishedNameId] = sidId;

    /// <summary>
    /// The SID of the object with this name, when the capture contained it.
    /// </summary>
    /// <remarks>
    /// <b>False is an ordinary answer, not a fault.</b> A group can hold a member from a domain the
    /// run did not cover, or one that has since been deleted, and neither is a defect in this
    /// product. What must not happen is the edge being dropped silently: the caller records it as an
    /// unresolved trustee so the closure can say its coverage was incomplete.
    /// </remarks>
    /// <param name="distinguishedNameId">The name's id.</param>
    /// <param name="sidId">The SID dictionary id, when the name resolved.</param>
    /// <returns>Whether an object with that name was captured and carried a SID.</returns>
    internal bool TryResolve(int distinguishedNameId, out int sidId)
    {
        sidId = _sidIdByDnId[distinguishedNameId];
        return sidId != Unresolved;
    }

    /// <summary>The name an id stands for, for reporting an unresolved trustee.</summary>
    /// <remarks>
    /// Indexed rather than searched. A forest can leave a great many trustees unresolved - every
    /// member from an uncovered domain is one - and a scan per name would turn reporting the gap
    /// into a cost proportional to the square of it.
    /// </remarks>
    /// <param name="distinguishedNameId">The name's id.</param>
    internal string TextOf(int distinguishedNameId) => _text[distinguishedNameId];
}

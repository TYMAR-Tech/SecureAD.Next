using SecureAD.Kernel.Security;

namespace SecureAD.Derivation;

/// <summary>
/// How a SID identifies the principal it resolves to.
/// </summary>
/// <remarks>
/// Kept apart so a finding can say which sentence is true of it. "Matched current SID" and
/// "matched SIDHistory" are both matches and they mean different things to whoever is reading:
/// the second one says the access came through a migration nobody has cleaned up.
/// </remarks>
public enum SidIdentityKind
{
    /// <summary>The principal's own <c>objectSid</c>.</summary>
    Current,

    /// <summary>A SID the principal carries from a migration, through <c>sIDHistory</c>.</summary>
    History,
}

/// <summary>
/// Assigns a small integer to every SID the derivation touches, so nothing else has to store the
/// text.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the store's largest single economy.</b> Everything derived from group nesting is a
/// list of pairs of principals, and there are more of those rows than of anything else the product
/// writes outside the capture. Naming principals by integer rather than by a forty-five character
/// SID shrinks those tables several-fold, and shrinks the indexes over them by the same factor,
/// which is what decides how many rows fit in a page and therefore how deep the B-tree is.
/// </para>
/// <para>
/// <b>It also makes the graph fit in memory, which is what lets the closure be computed at all.</b>
/// The predecessor held its membership graph as a dictionary of lists of SID strings, and because
/// it re-read each group's members from the database the same SID existed as a separate string
/// object in every list that contained it. As integers the same graph is a pair of arrays.
/// </para>
/// <para>
/// <b>Ids are assigned in first-seen order and mean nothing outside one store.</b> They are not
/// stable across derivations and nothing may persist one anywhere but here. A reader that wants to
/// name a principal reads the text back out of the dictionary.
/// </para>
/// </remarks>
public sealed class SidInterner
{
    /// <summary>
    /// Separates a scope from a SID in a key. A null character because no domain name and no SID
    /// may contain one, so no pair of legitimate values can collide by concatenation.
    /// </summary>
    private const char ScopeSeparator = '\0';

    private readonly Dictionary<string, int> _ids = new(StringComparer.Ordinal);
    private readonly List<string> _text = [];
    private readonly List<string?> _scopes = [];

    /// <summary>How many distinct principals have been seen.</summary>
    public int Count => _text.Count;

    /// <summary>
    /// How many built-in SIDs arrived without a domain to scope them by.
    /// </summary>
    /// <remarks>
    /// <b>Counted rather than refused, and never zero-by-assumption.</b> A built-in SID with no
    /// domain cannot be told apart from the same SID in another domain, so those are interned
    /// together exactly as they were before <c>0087</c> - and this says how many times that
    /// happened. A derivation reporting no such objects and one that never checked are different
    /// facts, which is the whole reason this is a count and not a flag.
    /// </remarks>
    public int UnscopedBuiltins { get; private set; }

    /// <summary>
    /// The id for a principal, assigning one if this is the first time it has been seen.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A SID is unique within its scope, not within a forest.</b> A SID in the built-in domain
    /// names a different group in every domain that has one - <c>S-1-5-32-544</c> is that domain's
    /// <c>BUILTIN\Administrators</c>, holding that domain's members - so it is interned under
    /// <paramref name="domainFqdn"/> as well as its text. Everything else is interned by text
    /// alone, because Microsoft guarantees a domain SID carries the issuing domain inside it and
    /// scoping one would split a single principal into several. See
    /// <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c>.
    /// </para>
    /// <para>
    /// <b>Comparison is ordinal, and the SID must already be canonical.</b> The dictionary cannot
    /// be the place where two spellings of one SID are reconciled, because it is also what the
    /// unique index over the text column is checking - if it folded case here, two rows that
    /// differ only in case would collapse to one id and the index would never see the problem.
    /// Canonicalising a SID is the caller's job and belongs where the SID is decoded.
    /// </para>
    /// </remarks>
    /// <param name="sid">The SID in its canonical text form.</param>
    /// <param name="domainFqdn">
    /// The domain the SID was captured from, or null where the caller genuinely has none. Ignored
    /// for any SID outside the built-in domain, and required for one inside it - a built-in SID
    /// with no domain is counted in <see cref="UnscopedBuiltins"/> rather than refused.
    /// <para>
    /// <b>Required rather than defaulted</b>, per gate 1. A scope a caller could forget is a scope
    /// callers will forget, and the consequence is not a missing feature but two domains' groups
    /// merged into one - the defect <c>0087</c> was written about.
    /// </para>
    /// </param>
    /// <returns>The id standing in for that principal in this store.</returns>
    public int Intern(string sid, string? domainFqdn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);

        var scope = ScopeFor(sid, domainFqdn);

        if (scope is null && Sid.IsBuiltinDomain(sid))
            UnscopedBuiltins++;

        var key = KeyFor(sid, scope);

        if (_ids.TryGetValue(key, out var existing))
            return existing;

        var id = _text.Count;
        _ids.Add(key, id);
        _text.Add(sid);
        _scopes.Add(scope);
        return id;
    }

    /// <summary>
    /// The id for a principal if it has been seen, without assigning one.
    /// </summary>
    /// <remarks>
    /// For the caller resolving something that may name a principal this capture never saw - an
    /// ACE trustee from a domain outside the run's coverage, most often. Interning it would put a
    /// principal in the dictionary that no evidence supports; an unresolved trustee is a fact about
    /// the capture and is recorded as one.
    /// </remarks>
    /// <param name="sid">The SID in its canonical text form.</param>
    /// <param name="domainFqdn">The domain, for a SID in the built-in domain.</param>
    /// <param name="id">The id, when the principal is known.</param>
    /// <returns>Whether the principal was known.</returns>
    public bool TryGetId(string sid, string? domainFqdn, out int id)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);
        return _ids.TryGetValue(KeyFor(sid, ScopeFor(sid, domainFqdn)), out id);
    }

    /// <summary>
    /// The SID an id stands for.
    /// </summary>
    /// <remarks>
    /// <b>The scope is part of the key and never part of the answer.</b> Callers asking what a
    /// principal's SID is - <c>ProtectedGroupCatalogue</c> among them - want the SID the directory
    /// holds, not a composite this class invented. Two ids may return the same text, and that is
    /// the point: they are the same SID naming different principals.
    /// </remarks>
    /// <param name="id">An id this interner assigned.</param>
    /// <returns>The SID in its canonical text form.</returns>
    public string TextOf(int id)
    {
        ThrowIfUnknown(id);
        return _text[id];
    }

    /// <summary>
    /// The domain an id is scoped to, or null where the principal is forest-wide.
    /// </summary>
    /// <param name="id">An id this interner assigned.</param>
    /// <returns>The domain, for a built-in principal; null otherwise.</returns>
    public string? ScopeOf(int id)
    {
        ThrowIfUnknown(id);
        return _scopes[id];
    }

    /// <summary>
    /// Every SID, in id order, so the dictionary can be written out.
    /// </summary>
    /// <returns>The interned SIDs, where the index of each is its id.</returns>
    public IReadOnlyList<string> InIdOrder() => _text;

    /// <summary>
    /// Every scope, in id order, alongside <see cref="InIdOrder"/>.
    /// </summary>
    /// <returns>The scopes, where the index of each is its id.</returns>
    public IReadOnlyList<string?> ScopesInIdOrder() => _scopes;

    /// <summary>
    /// The scope a SID is keyed under: its domain when it is built-in, nothing otherwise.
    /// </summary>
    private static string? ScopeFor(string sid, string? domainFqdn) =>
        Sid.IsBuiltinDomain(sid) && !string.IsNullOrWhiteSpace(domainFqdn)
            ? domainFqdn
            : null;

    private static string KeyFor(string sid, string? scope) =>
        scope is null ? sid : scope + ScopeSeparator + sid;

    private void ThrowIfUnknown(int id)
    {
        if (id < 0 || id >= _text.Count)
        {
            throw new ArgumentOutOfRangeException(
                nameof(id),
                id,
                "No SID has been interned under that id. Ids are assigned in first-seen order "
                + "within one derivation and mean nothing outside it, so an id from elsewhere "
                + "cannot be resolved here.");
        }
    }
}

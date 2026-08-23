namespace SecureAD.Kernel.Security;

/// <summary>
/// Identifies the canonicalization logic that produced a <see cref="CanonicalAce"/>.
/// </summary>
/// <remarks>
/// <para>
/// In the previous implementation this lived on <c>SchemaConstants</c> alongside the bundle's
/// schema version. It is stated here instead because the Kernel is the lowest layer and cannot
/// reference the bundle, and because the number describes this component's own output rather than
/// the storage it happens to be written to.
/// </para>
/// <para>
/// Changing it invalidates every stored <c>ace_hash</c> and every golden value in the tests, so it
/// changes only as a deliberate decision.
/// </para>
/// <para>
/// <b>Version 2</b> added <c>ace_type</c> to the hash inputs and to the ordering tiebreak. Version
/// 1 hashed three of the four fields that define an ACE, so two ACEs differing only by type
/// collided and one was silently dropped, and their relative order depended on the order they
/// arrived in. See <c>docs/layers/kernel/security-descriptors.md</c>.
/// </para>
/// <para>
/// <b>Version 3</b> added the callback ACE's <c>ApplicationData</c> - the condition bytes. Version
/// 2 hashed every field that distinguishes an unconditional ACE and none that distinguishes a
/// conditional one, so <i>allow X when Department = IT</i> and <i>allow X when Department = HR</i>
/// collided, and <see cref="AceNormalizer"/> discarded one of them before it was written. A
/// conditional entry and an otherwise identical unconditional one collided the same way. Recorded
/// as F-S58-11, in the fix brief that carried it, since deleted.
/// </para>
/// </remarks>
public static class AceCanonicalization
{
    /// <summary>The version of the normalization pipeline stamped onto each canonical ACE.</summary>
    public const int Version = 3;

    /// <summary>
    /// The canonical ordering category of an entry: 0 explicit deny, 1 explicit allow,
    /// 2 inherited deny, 3 inherited allow.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Stated here because two callers need it and they must not disagree.</b>
    /// <see cref="AceNormalizer"/> sorts by it, and <see cref="SecurityDescriptorParser"/> judges
    /// whether a DACL arrived in canonical order by it. Written twice, the two would be a pair of
    /// lists of ACE types that had to stay in step, and the failure when they drifted would be
    /// silent - a descriptor called canonical by one and reordered by the other.
    /// </para>
    /// <para>
    /// The order is the documented one: all explicit entries before inherited ones, and within
    /// each, denies before allows. Order decides the outcome because AD evaluates a DACL by
    /// accumulating granted and denied masks and adds a deny only for rights that are <i>not
    /// already granted</i> - so an allow read first keeps a later deny from taking effect.
    /// <c>[MS-ADTS]</c> 5.1.3.3.2. It is <b>not</b> because evaluation stops at the first match:
    /// AD examines every ACE to the end of the DACL, and this comment said otherwise until
    /// <c>S-58</c> finding <c>#7</c>.
    /// </para>
    /// </remarks>
    public static int CategoryOf(AceType aceType, bool isInherited)
    {
        var isDeny = aceType is AceType.AccessDenied or AceType.AccessDeniedObject
            or AceType.AccessDeniedCallback or AceType.AccessDeniedCallbackObject;

        return (isInherited, isDeny) switch
        {
            (false, true) => 0,
            (false, false) => 1,
            (true, true) => 2,
            (true, false) => 3,
        };
    }

    /// <summary>
    /// Whether <paramref name="aces"/>, in the order the directory stored them, shows any locally
    /// provable violation of the four-category ordering rule.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required by <c>docs/decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md</c>.
    /// A DACL with an allow before a deny for the same trustee grants access that the canonical
    /// form denies, because AD accumulates granted and denied masks across the whole DACL and adds
    /// a deny only for rights <i>not already granted</i> - so the earlier allow wins
    /// (<c>[MS-ADTS]</c> 5.1.3.3.2). Tooling that assumes canonical order reports the deny while
    /// the directory honours the allow, which is why it is worth recording and why it must be
    /// recorded <i>before</i> <see cref="AceNormalizer"/> sorts.
    /// </para>
    /// <para>
    /// <b>This is narrower than asking whether the DACL is canonical, and the difference is
    /// <c>S-57</c> finding <c>#7</c>.</b> It answers one question: were the entries this build
    /// recognised in explicit-deny, explicit-allow, inherited-deny, inherited-allow order.
    /// <c>S-56</c> v4 R5 asks for three further claims that this does not make and must not be read
    /// as making. <b>AD canonicality proper</b> also puts regular ACEs before object ACEs and
    /// orders lexicographically within groups at applicable forest functional levels, neither of
    /// which is checked here. <b>Inherited-generation order</b> cannot be established at all from
    /// one DACL, because an inherited ACE carries no depth field - proving it needs ancestor
    /// descriptors, so a DACL violating only that is reported as in order, and a test pins it to
    /// keep the gap visible. <b>Whether the DC was expected to standardise</b> depends on forest
    /// functional level and <c>fDontStandardizeSDs</c>, neither of which any capture collects.
    /// </para>
    /// <para>
    /// <b>Entries whose type this product does not model are skipped, not guessed at.</b>
    /// <see cref="CategoryOf"/> maps any undefined type to <i>not a deny</i>, which is a reasonable
    /// default for a total sort order and a bad one for a judgement: it would have this method
    /// decide that a DACL was or was not in order partly on the strength of where it imagined an
    /// entry belonged. So the answer this returns means <i>the entries I recognised were in
    /// order</i>, and it is only honest because the entry this skipped is still visible - a type
    /// with no name is written to <c>ace.ace_type</c> as its number, which is what
    /// <c>BundleWriterTests</c> holds.
    /// </para>
    /// <para>
    /// An empty or single-entry list is in order, trivially and correctly: there is no pair to be
    /// out of order. A list of nothing but unmodelled entries is in order for the same reason, and
    /// the same caveat applies - it is a statement about what was understood.
    /// </para>
    /// </remarks>
    /// <param name="aces">The entries in the order they were parsed, which is the order stored.</param>
    public static bool IsCanonicalOrder(IReadOnlyList<ParsedAce> aces)
    {
        ArgumentNullException.ThrowIfNull(aces);

        var highestSoFar = 0;

        foreach (var ace in aces)
        {
            if (!Enum.IsDefined(ace.AceType))
            {
                continue;
            }

            var category = CategoryOf(ace.AceType, ace.IsInherited);

            if (category < highestSoFar)
            {
                return false;
            }

            highestSoFar = category;
        }

        return true;
    }
}

namespace SecureAD.Evidence.Run;

/// <summary>
/// Identifies the target of an audit: the forest a run assessed.
/// </summary>
/// <remarks>
/// <para>
/// A profile groups a forest's runs so its history stays visible. It says nothing about how much
/// of that forest a run saw - that is <see cref="CoverageId"/> - because folding coverage in here
/// would make an incomplete run vanish into a group of its own, hiding runs in order to avoid
/// comparing them.
/// </para>
/// <para>
/// <b>It is a pure function of the forest name, and that is the point.</b> Any caller holding the
/// forest name can recompute it rather than storing it, so a bundle whose metadata was never
/// written still lands in the right group. The predecessor recorded what happens when that is not
/// true: it once had a second factory taking a separate forest root distinguished name, nothing
/// checked the name was the forest name's transform, and two callers could therefore compute
/// different profiles for one forest. Such a run matched nothing, sat in a group of one, was never
/// offered as a compare partner, and said nothing about why.
/// </para>
/// <para>
/// A baseline belongs to a forest per
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c>, so this is also the key a
/// nominated baseline hangs from.
/// </para>
/// </remarks>
public sealed record ProfileId
{
    private ProfileId(string value, string forestFqdn)
    {
        Value = value;
        ForestFqdn = forestFqdn;
    }

    /// <summary>Sixteen lowercase hex characters identifying the forest.</summary>
    /// <remarks>
    /// Fixed at a width and an alphabet because it is used in folder names, log lines and
    /// comparisons, all of which are awkward to change later.
    /// </remarks>
    public string Value { get; }

    /// <summary>
    /// The forest name that was hashed, lowercased. Kept so a reader can see what produced the
    /// value rather than being shown a hash and asked to trust it.
    /// </summary>
    public string ForestFqdn { get; }

    /// <summary>
    /// Computes the profile of a forest.
    /// </summary>
    /// <remarks>
    /// Deliberately the only factory. A second one taking anything else would reintroduce the
    /// possibility of two values for one forest, which is the failure described on this type.
    /// </remarks>
    /// <param name="forestFqdn">
    /// The forest root fully qualified domain name, for example <c>contoso.com</c>. Compared
    /// without regard to case, because Active Directory does not distinguish forest names by case
    /// and a product that did would split one forest's history on nothing but typing.
    /// </param>
    /// <returns>The profile for <paramref name="forestFqdn"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="forestFqdn"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="forestFqdn"/> is blank.</exception>
    public static ProfileId ForForest(string forestFqdn)
    {
        ArgumentNullException.ThrowIfNull(forestFqdn);
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);

        var forest = forestFqdn.Trim().ToLowerInvariant();

        return new ProfileId(RunHash.Of($"forest|{forest}"), forest);
    }

    /// <summary>Returns <see cref="Value"/>.</summary>
    public override string ToString() => Value;
}

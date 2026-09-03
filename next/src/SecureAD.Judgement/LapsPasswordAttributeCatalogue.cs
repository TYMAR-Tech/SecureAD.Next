namespace SecureAD.Judgement;

/// <summary>
/// The attributes that carry a machine's local administrator password, in any LAPS product and in
/// either encryption posture.
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own type because gate 4's exemption is granted per type</b>, and this follows the
/// precedent <c>PrivilegedSidCatalogue</c> set in September and
/// <c>GpoClientSideExtensionCatalog</c> set in August. The table first lived on
/// <see cref="LapsAttributes"/>, which also answers <c>Judgeability</c> - whether a rule may treat
/// an absent value as a fact about a machine. Exempting that type would have exempted the judging,
/// which is exactly what gate 4 exists to prevent. Splitting the table out was the alternative to an
/// exemption covering the thing the gate was pointing at.
/// </para>
/// <para>
/// <b>Nothing here can fail.</b> The values are written out in this source, they read nothing and
/// open nothing, and an empty answer is not a state any query produces - which is what makes a bare
/// collection honest here and dishonest almost everywhere else.
/// </para>
/// <para>
/// <b>All three, because a delegation is granted across them as a set.</b> Microsoft describes
/// <c>Set-LapsADReadPasswordPermission</c> as specifying who can read "various password attributes",
/// so where an administrator used the cmdlet the same principal already holds an entry on each and
/// the extra matches de-duplicate. The list only changes the answer where somebody delegated one of
/// them by hand - which is exactly the case that would otherwise be invisible.
/// </para>
/// <para>
/// <b>Why the encrypted attribute is not optional.</b> The password is in one attribute or the
/// other and never both. Microsoft says <c>ADPasswordEncryptionEnabled</c> defaults to true and
/// separately that it "highly recommends" enabling it, so on a forest following that advice
/// <see cref="LapsAttributes.WindowsLapsPassword"/> is empty on every machine. A rule watching only
/// the clear-text attributes would report such an estate clean while a broad principal held read
/// access to the attribute actually carrying the secret.
/// </para>
/// <para>
/// <b>The DSRM and password-history variants are deliberately absent.</b> They concern domain
/// controllers rather than the member-machine population SEC-090 judges, and folding them in would
/// mix two questions. Recorded on the punch list rather than smuggled in here.
/// </para>
/// </remarks>
public static class LapsPasswordAttributeCatalogue
{
    /// <summary>
    /// Every attribute that holds a LAPS password, by <c>lDAPDisplayName</c>.
    /// </summary>
    public static IReadOnlyList<string> All { get; } =
    [
        LapsAttributes.WindowsLapsPassword,
        LapsAttributes.WindowsLapsEncryptedPassword,
        LapsAttributes.LegacyLapsPassword,
    ];
}

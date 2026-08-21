namespace SecureAD.Kernel.Security;

/// <summary>
/// What a well-known SID is, for the purpose of saying who holds a permission.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the distinction the product was missing.</b> Every trustee used to be resolved the
/// same way - search the captured objects for one whose <c>objectSid</c> matches - and that
/// question has an answer for SIDs that are not principals at all. Active Directory keeps real
/// objects under <c>CN=WellKnown Security Principals</c> for <c>CREATOR OWNER</c> and
/// <c>PRINCIPAL SELF</c>, so the search succeeded and the screen showed them beside real accounts,
/// with a domain, formatted identically to a group. An operator reading that is told something
/// untrue about who holds the permission.
/// </para>
/// <para>
/// <b>The roles are about what a reader may conclude</b>, not about how Windows implements them.
/// A permission held by a <see cref="Principal"/> is held by somebody. A permission naming a
/// <see cref="Placeholder"/> is held by nobody until the placeholder is substituted, and by
/// different somebodies on different objects.
/// </para>
/// </remarks>
public enum WellKnownSidRole
{
    /// <summary>
    /// A real principal. Something authenticates as it, or is a member of it, so a permission
    /// naming it is genuinely held.
    /// </summary>
    Principal,

    /// <summary>
    /// Not a principal. A template that the system replaces with a real SID when the entry is
    /// applied or inherited - <c>CREATOR OWNER</c> becomes the creator, <c>PRINCIPAL SELF</c>
    /// becomes the object the entry sits on. Reporting one as a holder over-reports on the
    /// container and under-reports on the object.
    /// </summary>
    Placeholder,

    /// <summary>
    /// Not a principal. <c>OWNER RIGHTS</c> (<c>S-1-3-4</c>) is present in a DACL to change what
    /// the object's owner implicitly holds. MS-DTYP 2.4.2.4: the system ignores the implicit
    /// <c>READ_CONTROL</c> and <c>WRITE_DAC</c> permissions for the object owner. It says nothing
    /// about <c>WRITE_OWNER</c>, and neither does this product.
    /// </summary>
    OwnerRightsQualifier,

    /// <summary>
    /// Not a principal in any useful sense here. Describes how a caller authenticated or where it
    /// came from - <c>NETWORK</c>, <c>BATCH</c>, <c>NTLM AUTHENTICATION</c>. A permission naming
    /// one grants access to anyone arriving that way, which is a real grant but not one that
    /// attributes to a person or a group.
    /// </summary>
    LogonContext,
}

/// <summary>
/// Which SID a domain-relative identifier is counted from.
/// </summary>
/// <remarks>
/// MS-DTYP 2.4.2.4 distinguishes these and the distinction is load-bearing. Reading every
/// relative identifier as though it hung off any domain would let the product match RID 519 under
/// a child domain and call the result <c>Enterprise Admins</c> - a group that exists only in the
/// forest root. The old product's catalogue used one pattern for all of them.
/// </remarks>
public enum DomainRelativeScope
{
    /// <summary>Counted from a specific machine's SID.</summary>
    Machine,

    /// <summary>Counted from any domain's SID.</summary>
    Domain,

    /// <summary>Counted from the forest root domain's SID only.</summary>
    RootDomain,
}

/// <summary>
/// One well-known SID, exactly as MS-DTYP 2.4.2.4 publishes it.
/// </summary>
/// <param name="Sid">The SID in written form.</param>
/// <param name="ConstantName">
/// Microsoft's constant, such as <c>PRINCIPAL_SELF</c>. Carried so that a reader can find the row
/// in the specification, and so the anchor test can name what it is pinning.
/// </param>
/// <param name="DisplayName">What an operator reads.</param>
/// <param name="Role">Whether a permission naming this is held by somebody.</param>
/// <param name="Meaning">One plain sentence, for a reader who does not know the SID.</param>
public sealed record WellKnownSid(
    string Sid,
    string ConstantName,
    string DisplayName,
    WellKnownSidRole Role,
    string Meaning)
{
    /// <summary>
    /// Whether this names somebody. False for placeholders and for <c>OWNER RIGHTS</c>, which is
    /// the question the permission display has to ask before it credits an entry to a trustee.
    /// </summary>
    public bool NamesAPrincipal => Role is WellKnownSidRole.Principal;
}

/// <summary>
/// One relative identifier that means the same thing under every domain it is counted from.
/// </summary>
/// <param name="Rid">The relative identifier.</param>
/// <param name="ConstantName">Microsoft's constant, such as <c>DOMAIN_ADMINS</c>.</param>
/// <param name="DisplayName">What an operator reads.</param>
/// <param name="Scope">Which SID it is counted from.</param>
/// <param name="Meaning">One plain sentence.</param>
public sealed record DomainRelativeSid(
    int Rid,
    string ConstantName,
    string DisplayName,
    DomainRelativeScope Scope,
    string Meaning);

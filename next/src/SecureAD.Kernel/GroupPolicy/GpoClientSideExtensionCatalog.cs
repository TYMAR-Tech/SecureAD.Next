namespace SecureAD.Kernel.GroupPolicy;

/// <summary>
/// The Group Policy client-side extensions (CSEs) whose on-disk settings this product parses,
/// and the GUIDs that identify them.
/// </summary>
/// <remarks>
/// <para>
/// A client-side extension is the component on a domain-joined machine that applies one kind of
/// policy. A GPO's <c>gPCMachineExtensionNames</c> attribute lists the extensions whose settings
/// it contains, which is what lets capture fetch files only for the GPOs that hold settings this
/// product assesses rather than for every GPO in the forest.
/// </para>
/// <para>
/// <b>Separate from <see cref="GpoClientSideExtensions"/> on purpose.</b> This is a table written
/// out in the source: it reads nothing, opens nothing and cannot fail. The parsing lives next
/// door, where it can fail and says so. Keeping them in one type would have meant exempting the
/// parser from gate 4 along with the table, because that gate exempts a type rather than a member
/// - and the parser is exactly the kind of thing gate 4 exists to hold.
/// </para>
/// <para>
/// The GUID values are documented in the ADMX_GroupPolicy policy CSP (CSE_Registry,
/// CSE_Security). This file is the declared home for client-side-extension GUIDs under
/// <c>SchemaGuidSingleSourceGateTests</c>; they are not Active Directory schema GUIDs and have no
/// LDAP name, so <c>SchemaGuidCatalog</c> cannot answer for them.
/// </para>
/// </remarks>
public static class GpoClientSideExtensionCatalog
{
    /// <summary>
    /// Registry CSE - produces and consumes <c>Registry.pol</c>.
    /// </summary>
    public static readonly Guid RegistryCse = new("35378EAC-683F-11D2-A89A-00C04FBBCFA2");

    /// <summary>
    /// Security CSE - produces and consumes <c>GptTmpl.inf</c> security templates.
    /// </summary>
    public static readonly Guid SecurityCse = new("827D319E-6EAC-11D2-A4EA-00C04F79F83A");

    /// <summary>
    /// The CSEs whose on-disk settings this product parses.
    /// </summary>
    /// <remarks>
    /// Exempt from the collection half of gate 4 on the terms the other exemptions carry: a
    /// compiled table that cannot fail. It is two entries written out above, so an empty answer
    /// from <see cref="Contains"/> means only that the GUID is not one of the two, never that a
    /// question failed.
    /// </remarks>
    public static readonly IReadOnlySet<Guid> AnalyzableCses = new HashSet<Guid>
    {
        RegistryCse,
        SecurityCse,
    };

    /// <summary>
    /// Whether the given client-side extension is one whose settings this product parses.
    /// </summary>
    /// <param name="cse">The client-side extension GUID.</param>
    public static bool Contains(Guid cse) => AnalyzableCses.Contains(cse);
}

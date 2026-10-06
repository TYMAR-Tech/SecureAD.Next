namespace SecureAD.Shell.ViewModels;

/// <summary>
/// Which view of the Assets screen is showing.
/// </summary>
/// <remarks>
/// <para>
/// The directory-scoped views share the tree selection and level. Delegations answers a
/// whole-run question instead; changing the tree must not silently narrow its answer.
/// </para>
/// <para>
/// <b>It replaced a pair of booleans when the third view arrived.</b> The pair worked while one was
/// the negation of the other; a third would have let the two flags describe a state that is not a
/// view - both false, or both true - and nothing on screen would have said which was showing.
/// </para>
/// </remarks>
internal enum AssetsPane
{
    /// <summary>What the run captured, as objects in the directory.</summary>
    Objects,

    /// <summary>What the rules concluded about them.</summary>
    Findings,

    /// <summary>
    /// Which machines are managing their local administrator password, and by what.
    /// </summary>
    /// <remarks>
    /// <b>It is not a view of the findings and cannot be built from them.</b> A findings store holds
    /// only what a rule reported, and <i>which machines have modern, which have legacy, which have
    /// none</i> includes the healthy ones. It reads sealed evidence instead.
    /// </remarks>
    Laps,

    /// <summary>Original permission entries naming a selected principal, across captured AD objects.</summary>
    Delegations,
}

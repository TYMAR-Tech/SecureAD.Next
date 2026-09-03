namespace SecureAD.Shell.ViewModels;

/// <summary>
/// Which view of the Assets screen is showing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Four views of one screen, not four screens.</b> All of them are scoped by the same tree
/// selection and the same level, so an operator who narrows to an organisational unit stays
/// narrowed to it when he moves between them. That is why the shell tells this screen which of its
/// views is showing rather than switching between view models the way the navigation rail does.
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

    /// <summary>
    /// What the product checked for, and what each check did to this run.
    /// </summary>
    /// <remarks>
    /// <b>It exists because a findings grid cannot say what was looked at.</b> A rule that judged
    /// four thousand accounts and reported nothing leaves no row anywhere else in the shell, and
    /// is indistinguishable there from a rule that could not run. Unlike <see cref="Laps"/> this
    /// reads the judgement rather than the evidence, and is unscoped: a rule is a question asked
    /// of the whole forest, so narrowing the tree does not narrow it.
    /// </remarks>
    Rules,
}

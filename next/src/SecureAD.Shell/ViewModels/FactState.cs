namespace SecureAD.Shell.ViewModels;

/// <summary>
/// Which of the four states one fact on a screen is in.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a statement about the fact, not about how it looks.</b> A view model may not hold a
/// <c>Brush</c>, a <c>Color</c>, a <c>Visibility</c> or a <c>Style</c> - a view model that decides
/// appearance has moved presentation into the one layer that has tests, and
/// <c>ShellMvvmGateTests</c> fails the build for it. Naming the state is different in kind: it
/// says what the run established, and the view decides what that looks like.
/// </para>
/// <para>
/// <b>Why it has to exist at all.</b> Before this, every fact reached the screen as a finished
/// sentence and nothing else. A sentence is enough to read and not enough to style: there is no
/// way to give three states three treatments when the view is handed one string. Adding this is
/// what makes <c>docs/decisions/0056-the-visual-language-encodes-three-states.md</c> decision 1
/// enforceable in XAML rather than aspirational.
/// </para>
/// <para>
/// <b>Four members, and the fourth is not a fifth state of the first three.</b> A fault is
/// something the run reported about itself, and its remedy is technical. An established-bad answer
/// is a fact about the customer's forest. A not-established fact is nobody's fault. Collapsing any
/// two of these is the defect
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exists to prevent.
/// </para>
/// </remarks>
internal enum FactState
{
    /// <summary>
    /// The question was never put, or could not be answered. Nothing is claimed either way.
    /// </summary>
    /// <remarks>
    /// First deliberately, so that a field left at its default claims nothing rather than claiming
    /// a clean answer. A default of <see cref="EstablishedGood"/> would mean every fact nobody
    /// thought about renders as reassuring.
    /// </remarks>
    NotEstablished = 0,

    /// <summary>The question was put and the answer was good.</summary>
    EstablishedGood,

    /// <summary>
    /// The question was put and the answer was not good. A fact about the forest, not a failure of
    /// the run.
    /// </summary>
    EstablishedBad,

    /// <summary>
    /// The run reported a fault. Something broke, and the remedy is technical.
    /// </summary>
    Fault,
}

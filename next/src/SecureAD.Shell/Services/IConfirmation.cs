namespace SecureAD.Shell.Services;

/// <summary>
/// How the operator is asked to confirm something that cannot be undone.
/// </summary>
/// <remarks>
/// <para>
/// A seam rather than a direct call to a message box, for the reason
/// <see cref="IRunCatalog"/> gives: a view model given this can be shown a confirmed deletion and a
/// declined one without a window opening. A test that had to dismiss a dialog would not be run.
/// </para>
/// <para>
/// <b>One question, and it names the thing.</b>
/// <c>docs/decisions/0078-a-run-can-be-deleted-after-one-confirmation.md</c> decides that a second
/// prompt, a typed name or an <i>I understand</i> box buys nothing: the operator about to delete
/// the wrong run is equally willing to confirm twice, and every extra step teaches him that this
/// product's prompts are noise to click through. That lesson is expensive, because the same
/// operator later meets a prompt that matters.
/// </para>
/// </remarks>
internal interface IConfirmation
{
    /// <summary>
    /// Puts a question to the operator and reports whether he agreed.
    /// </summary>
    /// <param name="title">What is about to happen, in a few words.</param>
    /// <param name="question">
    /// The question, naming the thing it will happen to. The operator is choosing between runs that
    /// differ by a timestamp, and seeing which one he picked stated back to him is what makes the
    /// choice safe.
    /// </param>
    /// <param name="confirmLabel">
    /// What the confirming button says. A verb naming the act rather than <i>OK</i>, so the button
    /// still reads correctly to somebody who did not read the sentence above it.
    /// </param>
    /// <returns>True when the operator confirmed.</returns>
    bool Confirm(string title, string question, string confirmLabel);
}

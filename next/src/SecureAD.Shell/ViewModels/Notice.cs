namespace SecureAD.Shell.ViewModels;

/// <summary>
/// Something the audit surface is telling the operator, stated on the surface itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>This replaced a <c>MessageBox</c>.</b> Two of them, and they were the last controls on the
/// audit path drawn by Windows rather than by this product -
/// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c>. A dialog
/// nothing can theme is the one thing a design system cannot reach.
/// </para>
/// <para>
/// <b>It no longer blocks.</b> A message box held the thread until it was dismissed; this does not.
/// Nothing depended on the waiting: what followed a dismissal was clearing the box an operator had
/// typed into, and that now happens at once while the refusal stays both on the row and here.
/// </para>
/// <para>
/// <b>Two strings, not a severity.</b> <c>docs/decisions/0056-the-visual-language-encodes-three-states.md</c>
/// keeps the state vocabulary for facts a run established, and neither of these is one: a refused
/// controller and a preflight that could not run are things that happened to the tool, not findings
/// about a forest.
/// </para>
/// </remarks>
/// <param name="Title">What happened, in a few words.</param>
/// <param name="Detail">Why, in the audit layer's own words rather than reworded.</param>
internal sealed record Notice(string Title, string Detail);

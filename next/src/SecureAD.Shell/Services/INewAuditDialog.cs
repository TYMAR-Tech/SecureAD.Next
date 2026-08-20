using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services;

/// <summary>
/// Starting an audit, and putting the one question that still needs a dialog in front of the
/// operator.
/// </summary>
/// <remarks>
/// <para>
/// A seam, for the same reason <see cref="IFolderPicker"/> is one: a view model that put its own
/// surface on screen could not be tested without someone present to dismiss it.
/// </para>
/// <para>
/// <b>Each call plans a new run.</b> The surface and everything behind it are built when the audit
/// starts and discarded when it is left, per
/// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c>: a half-planned run must be
/// thrown away rather than left to be found later in a state nobody remembers choosing.
/// </para>
/// <para>
/// <b>It no longer tells the operator things.</b> Refusals and failures are stated on the audit
/// surface itself, as a <see cref="Notice"/> beside the work they concern -
/// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c>. What is left
/// here is the one exchange that genuinely needs a dialog, because it asks rather than tells.
/// </para>
/// </remarks>
internal interface INewAuditDialog
{
    /// <summary>
    /// Puts a freshly planned audit on the shell's audit surface.
    /// </summary>
    void Show();

    /// <summary>
    /// Asks the operator to attest to a domain being left out, and returns what he stated - or
    /// <see langword="null"/> where he dismissed it without stating anything.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The only method here that returns something, and it has to.</b> The other two tell him
    /// something; this one asks him for something, and an exclusion is only allowed to happen
    /// because of what comes back. A void version would have to leave the answer somewhere for the
    /// caller to find, which is the same as not having asked.
    /// </para>
    /// <para>
    /// <b>Null is a real answer and must be handled.</b> Per
    /// <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c> the friction is the
    /// control, so a dismissed dialog may not quietly become an exclusion: a domain the operator
    /// unticked goes back in, and a domain with no candidates - which cannot go back in, because
    /// there is nothing to read it from - stays out, unattested, and stops the run at Review.
    /// </para>
    /// <para>
    /// <b>Nothing is pre-filled and nothing is suggested.</b> <c>0059</c> refuses to carry an
    /// attestation forward or offer the last one for confirmation, because a remembered reason
    /// presented for confirmation is a button an operator presses without reading by the third run.
    /// </para>
    /// </remarks>
    /// <param name="domain">The domain being left out, as it is named on screen.</param>
    /// <param name="kind">
    /// Which kind of exclusion this is, so the dialog can say why it is being asked. The two are
    /// never worded alike, per <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c>.
    /// </param>
    ExclusionStatement? AskForAttestation(string domain, DomainInclusion kind);

    /// <summary>
    /// Leaves the audit surface, discarding whatever was planned on it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is what closing the window used to be.</b> With the audit a surface inside the shell
    /// rather than a window over it -
    /// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c> - there is
    /// no close box to enforce the discipline
    /// <c>docs/decisions/0057-starting-an-audit-is-a-modal-act.md</c> asked for, so it is stated
    /// here instead: what was half-planned is dropped, not kept for a later visit.
    /// </para>
    /// <para>
    /// The caller decides when leaving is allowed. Nothing here refuses it.
    /// </para>
    /// </remarks>
    void Leave();
}

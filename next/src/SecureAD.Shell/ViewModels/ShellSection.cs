namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The parts of the product a window can be showing.
/// </summary>
/// <remarks>
/// <para>
/// <b>Only what exists is named here.</b> There is no member for reports or comparison, because a
/// navigation entry leading to an empty screen tells an operator that a thing was looked for and
/// nothing was found - which would be false.
/// <c>docs/decisions/0045-the-shell-is-built-before-the-judgement-half.md</c> records the same
/// rule: screens bound to findings are left out rather than stubbed.
/// </para>
/// <para>
/// A member is added here when the screen behind it can answer for itself.
/// </para>
/// </remarks>
internal enum ShellSection
{
    /// <summary>Where the run library is chosen.</summary>
    Home,

    /// <summary>
    /// What the runs say about the forest's posture.
    /// </summary>
    /// <remarks>
    /// <b>Nothing behind this is built, and it is a tab anyway.</b> That reverses the no-stub
    /// clause of <c>docs/decisions/0045</c>, on the owner's instruction of 2026-08-18, so that the
    /// shape of the navigation can be judged before the screens behind it exist. What stands in
    /// its place says plainly that it is not built; <b>it never renders an empty result</b>, which
    /// is the part of the original reasoning that still holds - an empty dashboard would tell an
    /// administrator his directory is clean.
    /// </remarks>
    Dashboard,

    /// <summary>What the selected run captured: the directory as its evidence can rebuild it.</summary>
    Assets,

    /// <summary>What this installation has been told - where the runs live, and what else.</summary>
    Settings,

    /// <summary>
    /// The audit being planned, or the capture running from it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is not the rail entry <c>0057</c> removed.</b> That entry was <i>New Audit</i> - a
    /// standing invitation to start something - and it is still gone: an audit is started from
    /// Home. This member names a surface that exists only while there is an audit on it, and
    /// disappears with it.
    /// </para>
    /// <para>
    /// It is reachable from the rail only once a capture has started, per
    /// <c>docs/decisions/0071-the-audit-is-modal-in-effect-not-in-its-own-window.md</c>. While the
    /// audit is still being planned the rail is inert altogether, so there is nothing to return
    /// from and nothing to leave.
    /// </para>
    /// </remarks>
    Audit,
}

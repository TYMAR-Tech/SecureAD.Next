using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// What a capture produced, in the shell's own words.
/// </summary>
/// <remarks>
/// <b>A run that ended without a bundle is not a run that failed to start.</b> Both are reported,
/// and they read differently: <see cref="ProducedABundle"/> false with a directory means the run
/// happened and recorded why it stopped there, which an operator can go and read.
/// </remarks>
/// <param name="ProducedABundle">Whether the run ended with sealed evidence.</param>
/// <param name="BundleDirectory">Where the run's directory is, produced or not.</param>
internal sealed record CaptureOutcome(bool ProducedABundle, string BundleDirectory);

/// <summary>
/// What one named controller answered, in the shell's own words.
/// </summary>
/// <remarks>
/// <b>Three outcomes, not two.</b> A controller that did not answer, one that answered and does not
/// hold the domain, and one that is usable are three different things, and
/// <c>docs/decisions/0056-the-visual-language-encodes-three-states.md</c> forbids collapsing them.
/// The refusal carries the audit layer's own words, because a window that reworded them would be a
/// second account of the same failure and the two would drift.
/// </remarks>
/// <param name="IsUsable">Whether this controller may be read for the domain it was named for.</param>
/// <param name="Refusal">Why it may not be, or <see langword="null"/> where it may.</param>
internal sealed record NamedControllerView(bool IsUsable, string? Refusal);

/// <summary>
/// Planning, checking and starting a capture, from a window.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a caller of the one capture entry point, not a second one.</b>
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c> settles that there is a single way into
/// capture and that a graphical surface drives it rather than reimplementing it. The implementation
/// of this interface constructs a <c>CaptureSession</c> and does nothing a session would not.
/// </para>
/// <para>
/// The audit layer's own types are deliberately not exposed here. A view model that could see a
/// <c>CaptureSession</c> could start one, and the point of the seam is that it cannot. What crosses
/// instead is <see cref="AuditPlanView"/>, which carries the same facts in a shape a window can
/// render without knowing what a naming context is.
/// </para>
/// </remarks>
internal interface ICaptureLauncher
{
    /// <summary>
    /// Works out what a run would read and from where, contacting no domain's controller.
    /// </summary>
    /// <remarks>
    /// One connection, to whichever controller answered for this machine's own domain, and the
    /// configuration partition read behind it. It says what the run intends, not what the forest
    /// will allow - which is why the answer columns of every row come back unasked rather than
    /// negative.
    /// </remarks>
    /// <param name="libraryRoot">
    /// The operator's run library. Nothing is created inside it here; it is required because the
    /// one capture entry point is constructed over a library and <c>0025</c> forbids inventing one.
    /// </param>
    /// <param name="forest">
    /// A forest or domain name to enter by, used only when this machine cannot find a forest of its
    /// own. Null or blank for the ordinary case.
    /// </param>
    /// <param name="overrides">
    /// Controllers the operator named, keyed by the domain's declared DNS name. A name the forest does not
    /// list for that domain fails this call rather than being replaced by the ranked choice.
    /// </param>
    /// <param name="cancellationToken">Stops the look; nothing has been written.</param>
    Task<Result<AuditPlanView>> PlanAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken);

    /// <summary>
    /// Asks every domain the four preflight questions, still reading no object.
    /// </summary>
    /// <remarks>
    /// The same check the run performs before it reads, rather than a second one. Two
    /// implementations of "can this run work" would eventually disagree, and the first sign of it
    /// would be a window that said yes and a run that did not.
    /// </remarks>
    /// <param name="libraryRoot">As <see cref="PlanAsync"/>.</param>
    /// <param name="forest">As <see cref="PlanAsync"/>.</param>
    /// <param name="overrides">As <see cref="PlanAsync"/>.</param>
    /// <param name="cancellationToken">Stops the check.</param>
    Task<Result<AuditCheck>> ValidateAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken);

    /// <summary>
    /// Asks one named controller whether it serves the domain it was named for.
    /// </summary>
    /// <remarks>
    /// One connection to one machine. It does not plan, rank or read the configuration partition,
    /// which is the whole difference between it and <see cref="PlanAsync"/> and is finding
    /// <c>F-S41-4</c> closed: an operator correcting a typo used to pay for a pass over the whole
    /// forest on every press.
    /// </remarks>
    /// <param name="libraryRoot">As <see cref="PlanAsync"/>.</param>
    /// <param name="host">The controller the operator named, by DNS host name.</param>
    /// <param name="namingContext">The domain it was named for.</param>
    /// <param name="cancellationToken">Stops the check; nothing has been written.</param>
    Task<NamedControllerView> CheckNamedControllerAsync(
        string libraryRoot,
        string host,
        string namingContext,
        CancellationToken cancellationToken);

    /// <summary>Runs a capture and waits for it to finish.</summary>
    /// <param name="forest">
    /// A forest or domain name to enter by, used only when this machine cannot find a forest of its
    /// own. Null or blank for the ordinary case, where the run finds the forest it is already in.
    /// </param>
    /// <param name="overrides">
    /// Controllers the operator named, keyed by the domain's declared DNS name. Per run and never stored,
    /// per <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>.
    /// </param>
    /// <param name="exclusions">
    /// What the operator stated for every domain leaving this run. Per run and never stored, per
    /// <c>docs/decisions/0059-an-exclusion-is-attested-once-per-run.md</c>, and carried into the
    /// bundle in full per
    /// <c>docs/decisions/0062-what-an-exclusion-attestation-asks-for.md</c>.
    /// </param>
    /// <param name="domainsAtOnce">
    /// How many domains to read at the same time. A limit on this machine rather than on any
    /// controller - each domain in flight writes a database of its own - per
    /// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> as amended. It is not passed
    /// to the planning calls above because none of them reads a domain, so a ceiling would govern
    /// nothing there and passing one would suggest otherwise.
    /// </param>
    /// <param name="includeEnatelSso">Includes the three otherwise-excluded Enatel SSO classes for this run.</param>
    /// <param name="scanGppPasswords">Runs the optional recursive SEC-083 XML scan for this audit.</param>
    /// <param name="cancellationToken">Stops the run; it still records why it stopped.</param>
    Task<Result<CaptureOutcome>> RunAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        IReadOnlyList<ExclusionAttestation> exclusions,
        int domainsAtOnce,
        bool includeEnatelSso,
        bool scanGppPasswords,
        CancellationToken cancellationToken);
}

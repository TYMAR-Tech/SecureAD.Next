using System.Text.Json;
using System.Text.Json.Serialization;
using SecureAD.Evidence;

namespace SecureAD.Audit.Connect;

/// <summary>
/// One domain's preflight answers, as they are written to disk.
/// </summary>
/// <remarks>
/// A shape of its own rather than the report serialized directly, because what a run wrote down
/// must not change every time an in-memory type gains a member. The names here are the file's
/// contract with whoever reads it.
/// </remarks>
/// <param name="NamingContext">The domain partition.</param>
/// <param name="DomainController">The controller that was asked.</param>
/// <param name="Answered">Whether any rung of the connection ladder answered.</param>
/// <param name="RungReached">
/// Which rung answered, or null when nothing did. Null here means nothing was observed about this
/// controller's security posture - never that it refused protection.
/// </param>
/// <param name="ServesThePartition">Whether the controller says it serves the partition.</param>
/// <param name="PasswordSettingsContainerReadable">
/// Whether the domain's Password Settings Container could be read.
/// </param>
/// <param name="Faults">What went wrong, in the words an operator should see.</param>
/// <param name="PdcEmulator">
/// What was established about this domain's PDC emulator. Three states, per
/// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>: a question that could
/// not be put has no answer, and "not yet established" never means "holds no role".
/// </param>
/// <param name="ReadFromPdcEmulator">
/// Whether this domain was read from its own PDC emulator. <c>0055</c> permits it where nothing
/// else was available and requires that it is said - this field is where it is said durably, rather
/// than only on a console nobody kept.
/// </param>
/// <param name="WasRepinnedOffPdcEmulator">
/// Whether selection moved this domain off its PDC emulator once preflight established which
/// controller that was.
/// </param>
/// <param name="SelectionWasInformed">
/// Whether the controller was chosen on every input the ranking wants. False where the run had no
/// site of its own, or where the PDC emulator could not be established - in which case the busiest
/// machine in the domain ranked level with the rest and may be the one that was read.
/// </param>
/// <param name="Alternatives">
/// The other controllers the forest names for this domain, in ranked order. The candidate list
/// <c>0048</c> asks for.
/// </param>
/// <param name="ControllerWasNamedByOperator">
/// Whether a human insisted on this controller or a rule selected it. The pin origin <c>0048</c>
/// asks for.
/// </param>
public sealed record PreflightDomainRecord(
    string NamingContext,
    string DomainController,
    bool Answered,
    ConnectionSecurityLevel? RungReached,
    PreflightAnswer ServesThePartition,
    PreflightAnswer PasswordSettingsContainerReadable,
    IReadOnlyList<string> Faults,
    PdcEmulatorKnowledge PdcEmulator,
    bool ReadFromPdcEmulator,
    bool WasRepinnedOffPdcEmulator,
    bool SelectionWasInformed,
    IReadOnlyList<string> Alternatives,
    bool ControllerWasNamedByOperator)
{
    /// <summary>
    /// Whether all four questions were put to this domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The same statement <see cref="DomainPreflight.IsComplete"/> makes, carried into the file so
    /// that a reader can tell a row that was answered from one that was cut short.
    /// </para>
    /// <para>
    /// <b>Named for what it measures rather than "complete".</b> It sits beside
    /// <see cref="SelectionWasInformed"/>, which is a different question - whether the controller
    /// was chosen knowing everything the ranking wanted - and the two are routinely true and false
    /// together. A field called <c>IsComplete</c> reading <c>true</c> beside it invites an auditor
    /// who was not present to conclude that nothing about the run was missing. In-memory types keep
    /// <c>IsComplete</c>, which is this codebase's convention for "everything that should have been
    /// seen was seen"; this file is a contract with a reader who knows none of that.
    /// </para>
    /// </remarks>
    public bool AllQuestionsWereAsked =>
        Answered
        && ServesThePartition != PreflightAnswer.NotAsked
        && PasswordSettingsContainerReadable != PreflightAnswer.NotAsked;
}

/// <summary>
/// The contents of <c>preflight.json</c>.
/// </summary>
/// <param name="Forest">The forest the run was about to read.</param>
/// <param name="WrittenAt">When preflight finished, before any capture traffic was sent.</param>
/// <param name="RunMayProceed">Whether the run may proceed with the recorded attestations.</param>
/// <param name="Domains">One entry per domain, in the order the plan lists them.</param>
/// <param name="DeclaredDomains">Every domain the forest declared, including domains with no controller to ask.</param>
/// <param name="ExcludedObjectClasses">The object classes deliberately excluded by this run's policy.</param>
public sealed record PreflightContents(
    string Forest,
    DateTimeOffset WrittenAt,
    bool RunMayProceed,
    IReadOnlyList<PreflightDomainRecord> Domains,
    IReadOnlyList<string> DeclaredDomains,
    IReadOnlyList<string> ExcludedObjectClasses)
{
    /// <summary>Declared domains with no candidate controller, keyed by naming context.</summary>
    public IReadOnlyDictionary<string, string> DomainsWithNoCandidates { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The validated attestations used to decide whether this run may proceed.</summary>
    public IReadOnlyList<AttestedExclusion> Exclusions { get; init; } = [];

    /// <summary>
    /// Whether every domain in this file was asked all four questions.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A file with no domains in it is the case this exists for: without the statement it would
    /// read exactly like a forest in which nothing went wrong.
    /// </para>
    /// <para>
    /// It says nothing about whether the controllers were well chosen. That is per domain, in
    /// <see cref="PreflightDomainRecord.SelectionWasInformed"/>.
    /// </para>
    /// </remarks>
    public bool AllDomainsWereAsked =>
        Domains.Count > 0
        && Domains.Count == DeclaredDomains.Count
        && DomainsWithNoCandidates.Count == 0
        && Domains.All(d => d.AllQuestionsWereAsked);
}

/// <summary>
/// Writes down what preflight proved, into the run's own directory, before a single object is read.
/// </summary>
/// <remarks>
/// <para>
/// This is <c>docs/decisions/0048-preflight-proves-a-controller-before-a-run-commits.md</c> and it
/// closes finding <c>F-S35-4</c>: the predecessor recorded which controller actually answered, and
/// the rebuild recorded nothing, so a bundle could not say which controller served each domain -
/// which <c>docs/decisions/0040-a-failed-domain-is-read-again-from-another-controller.md</c> says
/// it should.
/// </para>
/// <para>
/// <b>The two fields <c>0048</c> names are written.</b> That record says the file names, per domain,
/// the candidate list in the order it was ranked and whether the pin came from ranking or from an
/// operator override. Until `S-39` neither existed - every domain had exactly one controller,
/// reached through its DNS name - and writing an empty list or a defaulted origin would have put a
/// measured-looking value in a file an auditor reads. Both exist now and both are recorded.
/// </para>
/// <para>
/// <b>What a run did to a customer's forest outlives the console it was started from.</b> A capture
/// that read three domains from their PDC emulators and said so only on a terminal has told nobody:
/// the bundle is what an auditor holds six months later. That is why the <c>0055</c> facts are here
/// and not only in the run's output.
/// </para>
/// <para>
/// <b>It is not evidence.</b> Like <c>run-outcome.json</c> it sits outside the seal and has to: it
/// is written before there is an evidence file for a seal to cover. Anyone can change it, and
/// nothing that reads it may present it as proof of anything.
/// </para>
/// </remarks>
public static class PreflightFile
{
    /// <summary>
    /// How the file is formatted: indented, and enumerations by name.
    /// </summary>
    /// <remarks>
    /// Names rather than numbers because this is the file an operator reads when an unattended run
    /// failed overnight, and <c>2</c> does not tell anybody that a question was never asked.
    /// </remarks>
    private static readonly JsonSerializerOptions Format = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// Writes the report into a run's directory.
    /// </summary>
    /// <param name="bundleDirectory">The run's directory.</param>
    /// <param name="report">What preflight found.</param>
    /// <param name="writtenAt">When, from the run's own clock.</param>
    public static void Write(
        string bundleDirectory, PreflightReport report, DateTimeOffset writtenAt) =>
        Write(bundleDirectory, report, writtenAt,
            new Dictionary<string, AttestedExclusion>(StringComparer.OrdinalIgnoreCase));

    /// <summary>Writes preflight facts and the validated attestations used to permit this run.</summary>
    public static void Write(
        string bundleDirectory, PreflightReport report, DateTimeOffset writtenAt,
        IReadOnlyDictionary<string, AttestedExclusion> exclusions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(report);

        ArgumentNullException.ThrowIfNull(exclusions);
        if (report.Plan.ValidateExclusions(exclusions) is { } invalid)
            throw new ArgumentException(invalid.Description, nameof(exclusions));

        var contents = new PreflightContents(
            report.Plan.ForestFqdn,
            writtenAt,
            report.Refusal(exclusions.Keys.ToList()) is null,
            [.. report.Domains.Select(Record)],
            report.Plan.DeclaredDomains,
            report.Plan.ObjectScope.ExcludedClasses)
        {
            DomainsWithNoCandidates = report.DomainsWithNoCandidates,
            Exclusions = [.. exclusions.Values],
        };

        File.WriteAllText(
            BundleLayout.PreflightPath(bundleDirectory),
            JsonSerializer.Serialize(contents, Format));
    }

    private static PreflightDomainRecord Record(DomainPreflight domain) =>
        new(domain.NamingContext,
            domain.DomainController,
            domain.Answered,
            domain.RungReached,
            domain.ServesThePartition,
            domain.PasswordSettingsContainerReadable,
            [.. domain.Faults.Select(f => f.Description)],
            domain.PdcEmulator,
            domain.ReadFromPdcEmulator,
            domain.WasRepinnedOffPdcEmulator,
            domain.SelectionWasInformed,
            domain.Alternatives,
            domain.ControllerWasNamedByOperator);
}

using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// Stand-ins for the shell's seams, so a view model can be shown a library that is empty, damaged
/// or unreachable without one being arranged on disk.
/// </summary>
internal sealed class FakeSettingsStore : IShellSettingsStore
{
    public ShellSettings Stored { get; set; } = ShellSettings.Unconfigured;

    public AuditError? ReadFails { get; set; }

    public AuditError? WriteFails { get; set; }

    public Result<ShellSettings> Read() =>
        ReadFails is { } error
            ? Result<ShellSettings>.Failure(error)
            : Result<ShellSettings>.Success(Stored);

    public Result<bool> Write(ShellSettings settings)
    {
        if (WriteFails is { } error)
            return Result<bool>.Failure(error);

        Stored = settings;
        return Result<bool>.Success(true);
    }
}

internal sealed class FakeRunCatalog : IRunCatalog
{
    public List<RunListing> Runs { get; } = [];

    public AuditError? Fails { get; set; }

    public string? AskedFor { get; private set; }

    public Result<IReadOnlyList<RunListing>> List(string libraryRoot)
    {
        AskedFor = libraryRoot;

        return Fails is { } error
            ? Result<IReadOnlyList<RunListing>>.Failure(error)
            : Result<IReadOnlyList<RunListing>>.Success(Runs);
    }

    /// <summary>What was last saved, and against which run.</summary>
    public (string BundleDirectory, RunAnnotation Annotation)? Annotated { get; private set; }

    public AuditError? AnnotationFails { get; set; }

    public Result<RunAnnotation> Annotate(string bundleDirectory, RunAnnotation annotation)
    {
        if (AnnotationFails is { } error)
            return Result<RunAnnotation>.Failure(error);

        Annotated = (bundleDirectory, annotation);
        return Result<RunAnnotation>.Success(annotation);
    }

    /// <summary>Which run was deleted, or null if none was.</summary>
    public string? Deleted { get; private set; }

    public AuditError? DeletionFails { get; set; }

    public Result<string> Delete(string bundleDirectory)
    {
        if (DeletionFails is { } error)
            return Result<string>.Failure(error);

        Deleted = bundleDirectory;
        Runs.RemoveAll(run =>
            string.Equals(run.Path, bundleDirectory, StringComparison.OrdinalIgnoreCase));

        return Result<string>.Success(bundleDirectory);
    }
}

/// <summary>
/// Remembers which run it was asked to open, so a screen can be checked without a window.
/// </summary>
internal sealed class FakeRunOpener : IRunOpener
{
    /// <summary>The run last opened, or null if nothing was.</summary>
    public string? Opened { get; private set; }

    /// <summary>
    /// Runs at the moment a run is opened, so a test can see what had already happened by then.
    /// </summary>
    /// <remarks>
    /// <b>Order is the whole point of this hook.</b> Opening a run and leaving the audit both
    /// navigate, so which happens last decides where the operator ends up. Asserting afterwards
    /// that both occurred cannot tell them apart, and a test that did exactly that passed while
    /// the product sent him to the wrong screen.
    /// </remarks>
    public Action? WhenOpening { get; set; }

    public void Open(string bundleDirectory)
    {
        WhenOpening?.Invoke();
        Opened = bundleDirectory;
    }
}

/// <summary>
/// An operator who answers a confirmation the same way every time, and remembers being asked.
/// </summary>
internal sealed class FakeConfirmation : IConfirmation
{
    /// <summary>What the operator answers. Declining is the default, as the real dialog's is.</summary>
    public bool Answer { get; set; }

    /// <summary>What he was asked, or null if nothing asked him anything.</summary>
    public (string Title, string Question, string ConfirmLabel)? Asked { get; private set; }

    /// <summary>How many times he was asked, so a second prompt cannot creep in unnoticed.</summary>
    public int TimesAsked { get; private set; }

    public bool Confirm(string title, string question, string confirmLabel)
    {
        Asked = (title, question, confirmLabel);
        TimesAsked++;
        return Answer;
    }
}

internal sealed class FakeAssetSource : IAssetSource
{
    public DirectoryTree Tree { get; set; } = new([], []);

    public ObjectPage Page { get; set; } = new([], 0, true, null);

    public AuditError? Fails { get; set; }

    public AuditError? ListingFails { get; set; }

    public string? AskedFor { get; private set; }

    public string? ListedContainer { get; private set; }

    public ListingScope ListedScope { get; private set; }

    public int ListedPage { get; private set; }

    public ObjectPermissions? Permissions { get; set; }

    public AuditError? PermissionsFail { get; set; }

    public string? OpenedObject { get; private set; }

    public Result<DirectoryTree> ReadTree(string bundleDirectory)
    {
        AskedFor = bundleDirectory;

        return Fails is { } error
            ? Result<DirectoryTree>.Failure(error)
            : Result<DirectoryTree>.Success(Tree);
    }

    public Result<ObjectPage> ListObjects(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ListedContainer = containerDn;
        ListedScope = scope;
        ListedPage = pageNumber;

        return ListingFails is { } error
            ? Result<ObjectPage>.Failure(error)
            : Result<ObjectPage>.Success(Page);
    }

    public Result<ObjectPermissions?> ReadPermissions(
        string bundleDirectory, string distinguishedName)
    {
        OpenedObject = distinguishedName;

        return PermissionsFail is { } error
            ? Result<ObjectPermissions?>.Failure(error)
            : Result<ObjectPermissions?>.Success(Permissions);
    }

    public ObjectAttributes? Attributes { get; set; }

    public AuditError? AttributesFail { get; set; }

    public Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName) =>
        AttributesFail is { } error
            ? Result<ObjectAttributes?>.Failure(error)
            : Result<ObjectAttributes?>.Success(Attributes);

    /// <summary>
    /// The schema this run is pretending to have captured. The shipped table by default, so a test
    /// that does not care about names behaves as the product did before the captured layer existed.
    /// </summary>
    public SchemaGuidCatalog Schema { get; set; } = SchemaGuidCatalog.Embedded;

    public AuditError? SchemaFails { get; set; }

    /// <summary>How many times the catalogue was asked for, so a test can prove it is not per object.</summary>
    public int SchemaReads { get; private set; }

    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory)
    {
        SchemaReads++;

        return SchemaFails is { } error
            ? Result<SchemaGuidCatalog>.Failure(error)
            : Result<SchemaGuidCatalog>.Success(Schema);
    }

    /// <summary>The findings this run is pretending to have judged. None, unless a test says so.</summary>
    public FindingsPage FindingsPage { get; set; } = new([], null, RulesRan: 1);

    /// <summary>Why the findings could not be read, when a test wants that.</summary>
    public AuditError? FindingsFail { get; set; }

    /// <summary>What the findings were last asked for, so a test can prove the grid is scoped.</summary>
    public FindingsQuery? FindingsAsked { get; private set; }

    /// <summary>How many times findings were asked for.</summary>
    public int FindingsReads { get; private set; }

    public Result<FindingsPage> ReadFindings(string bundleDirectory, FindingsQuery query)
    {
        FindingsAsked = query;
        FindingsReads++;

        return FindingsFail is { } error
            ? Result<FindingsPage>.Failure(error)
            : Result<FindingsPage>.Success(FindingsPage);
    }
}

internal sealed class FakeFolderPicker : IFolderPicker
{
    public string? Answer { get; set; }

    public bool WasAsked { get; private set; }

    public string? Pick(string title, string? startingAt)
    {
        WasAsked = true;
        return Answer;
    }
}

/// <summary>
/// A stand-in for the audit surface, so Home can be asked to start an audit without one appearing.
/// </summary>
internal sealed class FakeNewAuditDialog : INewAuditDialog
{
    public int TimesOpened { get; private set; }

    /// <summary>How many times the operator left the audit surface.</summary>
    public int TimesLeft { get; private set; }

    public void Show() => TimesOpened++;

    public void Leave() => TimesLeft++;

    /// <summary>
    /// Every domain the operator was asked to attest to, in the order he was asked.
    /// </summary>
    /// <remarks>
    /// Ordered, because the order is part of what is being proved: several domains with no
    /// candidates are put to him one at a time, and a set would lose that.
    /// </remarks>
    public List<(string Domain, DomainInclusion Kind)> Attestations { get; } = [];

    /// <summary>
    /// What the operator states when he is asked, or null for an operator who dismisses it.
    /// </summary>
    /// <remarks>
    /// <b>Null is the interesting setting.</b> It is the dismissal that must not quietly become an
    /// exclusion - a domain he unticked goes back in, and a domain with no candidates stays out and
    /// stops the run at Review.
    /// </remarks>
    public ExclusionStatement? Statement { get; set; } = new(
        ExclusionReason.OutsideThisAuditsRemit, Note: null, AuthorisedBy: "R. Zamus");

    /// <summary>
    /// A statement to give for one named domain, overriding <see cref="Statement"/>.
    /// </summary>
    /// <remarks>
    /// So a test can have an operator attest to one domain and dismiss another, which is the case
    /// that proves the run is blocked by the one he walked away from rather than by the pair.
    /// </remarks>
    public Dictionary<string, ExclusionStatement?> StatementFor { get; } = [];

    public ExclusionStatement? AskForAttestation(string domain, DomainInclusion kind)
    {
        Attestations.Add((domain, kind));

        return StatementFor.TryGetValue(domain, out var scripted) ? scripted : Statement;
    }

    /// <summary>Every set of domains the operator was shown details for.</summary>
    public List<IReadOnlyList<DomainRowViewModel>> Details { get; } = [];

}

/// <summary>
/// A stand-in for the one entry point into capture, so a window can be shown a forest that is
/// single-controller, re-pinned, unreachable or refusing an override without one existing.
/// </summary>
internal sealed class FakeCaptureLauncher : ICaptureLauncher
{    public CaptureOutcome Outcome { get; set; } = new(ProducedABundle: true, @"D:\audits\run");

    public AuditError? Fails { get; set; }

    public AuditError? PlanFails { get; set; }

    public AuditError? CheckFails { get; set; }

    public bool Cancels { get; set; }

    /// <summary>
    /// An exception the capture throws rather than returning, for the defect case.
    /// </summary>
    /// <remarks>
    /// A <c>Result</c> is how the audit layer reports a failure it expected. This is the other kind
    /// - a defect - and the window has to survive one.
    /// </remarks>
    public Exception? Throws { get; set; }

    public AuditPlanView Plan { get; set; } = Forests.OneDomain();

    public AuditCheck Check { get; set; } = Forests.Answered();

    public string? AskedForRoot { get; private set; }

    public IReadOnlyDictionary<string, string> AskedWithOverrides { get; private set; } =
        new Dictionary<string, string>();

    public bool WasRun { get; private set; }

    /// <summary>How many times the whole forest was planned, for F-S41-4.</summary>
    public int TimesPlanned { get; private set; }

    public Task<Result<AuditPlanView>> PlanAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        AskedForRoot = libraryRoot;
        AskedWithOverrides = overrides;
        TimesPlanned++;

        return Task.FromResult(PlanFails is { } error
            ? Result<AuditPlanView>.Failure(error)
            : Result<AuditPlanView>.Success(Plan));
    }

    /// <summary>How many times every domain was checked, so an opening pass can be counted.</summary>
    public int TimesChecked { get; private set; }

    /// <summary>
    /// Something to do in the middle of a check, so a test can stop a pass while it is running.
    /// </summary>
    public Action? WhileChecking { get; set; }

    public Task<Result<AuditCheck>> ValidateAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        CancellationToken cancellationToken)
    {
        AskedForRoot = libraryRoot;
        AskedWithOverrides = overrides;
        TimesChecked++;

        WhileChecking?.Invoke();
        cancellationToken.ThrowIfCancellationRequested();

        return Task.FromResult(CheckFails is { } error
            ? Result<AuditCheck>.Failure(error)
            : Result<AuditCheck>.Success(Check));
    }

    /// <summary>How many times one named controller was checked, for F-S41-4.</summary>
    public int NamedControllersChecked { get; private set; }

    /// <summary>The host most recently checked, and the domain it was named for.</summary>
    public (string Host, string NamingContext)? LastNamedControllerCheck { get; private set; }

    /// <summary>What a named controller check answers. Usable unless a test says otherwise.</summary>
    public NamedControllerView NamedController { get; set; } = new(IsUsable: true, Refusal: null);

    public Task<NamedControllerView> CheckNamedControllerAsync(
        string libraryRoot,
        string host,
        string namingContext,
        CancellationToken cancellationToken)
    {
        AskedForRoot = libraryRoot;
        NamedControllersChecked++;
        LastNamedControllerCheck = (host, namingContext);

        return Task.FromResult(NamedController);
    }

    /// <summary>The attestations the run was started with, in the order they were gathered.</summary>
    public IReadOnlyList<ExclusionAttestation> AskedWithExclusions { get; private set; } = [];

    public Task<Result<CaptureOutcome>> RunAsync(
        string libraryRoot,
        string? forest,
        IReadOnlyDictionary<string, string> overrides,
        IReadOnlyList<ExclusionAttestation> exclusions,
        CancellationToken cancellationToken)
    {
        AskedForRoot = libraryRoot;
        AskedWithOverrides = overrides;
        AskedWithExclusions = exclusions;
        WasRun = true;

        if (Cancels)
            throw new OperationCanceledException();

        if (Throws is { } defect)
            throw defect;

        return Task.FromResult(Fails is { } error
            ? Result<CaptureOutcome>.Failure(error)
            : Result<CaptureOutcome>.Success(Outcome));
    }
}

/// <summary>
/// Forests to show a window, described in the shell's own vocabulary.
/// </summary>
/// <remarks>
/// The shapes here are the ones that matter: a domain the forest names one controller for, which
/// is the owner's own lab and the case where the PDC prompt must not appear, and a domain with
/// alternatives, which is the case where it must.
/// </remarks>
internal static class Forests
{
    public const string Root = "DC=ad,DC=lab";

    public const string Controller = "dc01.ad.lab";

    public const string Other = "dc02.ad.lab";

    /// <summary>A forest of one domain with one controller, and no site established.</summary>
    public static AuditPlanView OneDomain(params string[] alternatives) =>
        new(
            "ad.lab",
            ThisMachinesSite: null,
            SiteKnowledge.ForestDeclaresNoSubnets,
            [Domain(alternatives)],
            [],
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [Controller] = "Default-First-Site-Name",
                [Other] = "Default-First-Site-Name",
            });

    public static DomainPlanRow Domain(params string[] alternatives) =>
        new(
            Root,
            Controller,
            ControllerSite: "Default-First-Site-Name",
            Established.NotEstablished,
            alternatives,
            ChoiceWasFullyInformed: false,
            ControllerWasNamedByOperator: false);

    /// <summary>Preflight answering everything, from a controller that is not the PDC emulator.</summary>
    public static AuditCheck Answered() =>
        new(RunMayProceed: true, [Answers()]);

    public static DomainAnswers Answers(
        bool readFromPdcEmulator = false, params string[] alternatives) =>
        new(
            Root,
            Controller,
            Established.Yes,
            "SignAndSeal",
            Established.Yes,
            Established.Yes,
            readFromPdcEmulator ? Established.Yes : Established.No,
            readFromPdcEmulator,
            ChoiceWasFullyInformed: true,
            alternatives,
            ControllerWasNamedByOperator: false,
            []);
}

internal static class Failures
{
    public static AuditError Any(string description) => AuditError.Create(
        ErrorCategory.Shell,
        "TestFailure",
        ErrorSeverity.Failed,
        description,
        context: null);
}

/// <summary>
/// A stand-in for judging, so the window can be shown a judging that succeeded, failed, found
/// something or found nothing, without hours of work or a bundle on disk.
/// </summary>
internal sealed class FakeJudgingLauncher : IJudgingLauncher
{
    /// <summary>What a judging concludes. Completed, nothing found, unless a test says otherwise.</summary>
    public JudgingOutcome Outcome { get; set; } =
        new(JudgementRunState.Completed, ObjectsJudged: 0, new Dictionary<Severity, int>());

    /// <summary>Why the judging could not be done, when a test wants that.</summary>
    public AuditError? Fails { get; set; }

    /// <summary>Whether the judging observes cancellation, for the stop case.</summary>
    public bool Cancels { get; set; }

    /// <summary>The bundle it was asked to judge, or null where it was never asked.</summary>
    public string? AskedFor { get; private set; }

    /// <summary>Whether judging was run at all, so a test can prove it was not.</summary>
    public bool WasRun { get; private set; }

    /// <summary>Progress to report before answering, so a watching screen can be observed.</summary>
    public IReadOnlyList<long> Reports { get; set; } = [];

    public Task<Result<JudgingOutcome>> RunAsync(
        string bundleDirectory,
        IProgress<JudgingRun.JudgingProgress> progress,
        CancellationToken cancellationToken)
    {
        AskedFor = bundleDirectory;
        WasRun = true;

        foreach (var read in Reports)
            progress.Report(new JudgingRun.JudgingProgress(read));

        if (Cancels)
            throw new OperationCanceledException();

        return Task.FromResult(Fails is { } error
            ? Result<JudgingOutcome>.Failure(error)
            : Result<JudgingOutcome>.Success(Outcome));
    }
}

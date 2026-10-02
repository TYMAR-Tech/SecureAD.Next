using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Derivation;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
namespace SecureAD.Shell.ViewModels;

/// <summary>
/// The runs this library holds.
/// </summary>
/// <remarks>
/// <para>
/// <b>Three outcomes are kept apart, because collapsing them would mislead.</b> No library chosen
/// is a question the operator has not answered. A library that could not be read is a failure they
/// need to see. A library that was read and holds nothing is an empty library. Showing an empty
/// list for all three would say "you have no runs" in two cases where that is not known to be true.
/// </para>
/// <para>
/// <b>A listing says what became of a run, not what it saw.</b> What became of it is read from the
/// bundle directory without opening anything. How much of the forest it covered is inside the
/// bundle, and is read by opening it - which this product does, through
/// <c>BundleReader.ReadScope</c>. This remark previously said the product could not open a bundle
/// at all; that stopped being true when the Assets section landed, and it is corrected here rather
/// than left to mislead the next reader.
/// </para>
/// </remarks>
internal sealed partial class RunLibraryViewModel : ObservableObject
{
    private readonly IRunCatalog _catalog;
    private readonly RunLibraryLocation _location;
    private readonly IConfirmation _confirmation;
    private readonly IRunOpener _opener;
    private readonly IDerivationLauncher _deriving;
    private readonly IJudgingLauncher _judging;

    /// <summary>
    /// Stops whichever analysis is running.
    /// </summary>
    /// <remarks>
    /// <b>This screen's own, and not the audit window's.</b> Deriving and judging from the library
    /// happen outside the New Audit page entirely - that page's busy flags, progress clock and
    /// cancellation belong to a capture it is running, and there is no capture here. Reaching for
    /// them would tie two unrelated pieces of work to one Stop.
    /// </remarks>
    private CancellationTokenSource? _stopping;

    /// <summary>
    /// Which analysis this screen is currently watching.
    /// </summary>
    /// <remarks>
    /// A progress report from a run the operator has already stopped, or from one superseded by a
    /// later start, must not write over the status of the one he is watching now. The same guard
    /// <c>NewAuditViewModel</c> keeps over its own progress, and for the same reason.
    /// </remarks>
    private long _analysisEpoch;

    [ObservableProperty]
    private string? _problem;

    [ObservableProperty]
    private bool _hasLooked;

    [ObservableProperty]
    private RunSummaryViewModel? _selected;

    /// <summary>Whether an analysis started from this screen is still running.</summary>
    [ObservableProperty]
    private bool _isAnalysing;

    /// <summary>
    /// What the analysis has to say, or null where none has been started.
    /// </summary>
    /// <remarks>
    /// <b>Every sentence names its run.</b> The library is a list an operator goes on clicking
    /// through while a judging runs, so by the time one finishes the selection may be a different
    /// run entirely. A bare "Judged 40,000 objects" under the wrong heading is the failure this
    /// screen exists to avoid, and naming the run is what stops it being possible.
    /// </remarks>
    [ObservableProperty]
    private string? _analysisStatus;

    /// <summary>Creates the run library screen's state.</summary>
    /// <param name="location">Where this installation keeps its runs.</param>
    /// <param name="catalog">How the runs are listed.</param>
    /// <param name="confirmation">How the operator is asked before something cannot be undone.</param>
    /// <param name="opener">How a run is opened for reading.</param>
    /// <param name="deriving">
    /// How facts are derived from a run that holds none. The same seam the audit window uses, so a
    /// derivation is started one way rather than two that can drift apart.
    /// </param>
    /// <param name="judging">How a run holding derived facts is judged.</param>
    public RunLibraryViewModel(
        RunLibraryLocation location,
        IRunCatalog catalog,
        IConfirmation confirmation,
        IRunOpener opener,
        IDerivationLauncher deriving,
        IJudgingLauncher judging)
    {
        ArgumentNullException.ThrowIfNull(location);
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(confirmation);
        ArgumentNullException.ThrowIfNull(opener);
        ArgumentNullException.ThrowIfNull(deriving);
        ArgumentNullException.ThrowIfNull(judging);

        _location = location;
        _catalog = catalog;
        _confirmation = confirmation;
        _opener = opener;
        _deriving = deriving;
        _judging = judging;

        // Grouped once, here, rather than rebuilt on every refresh: the view watches the collection
        // and a second view built later would leave the screen bound to the first one, showing runs
        // that had already been replaced.
        RunsView = CollectionViewSource.GetDefaultView(Runs);
        RunsView.GroupDescriptions.Add(
            new PropertyGroupDescription(nameof(RunSummaryViewModel.GroupKey)));
    }

    /// <summary>
    /// The runs, gathered into groups of like scope.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Runs are grouped by which domains they covered, per
    /// <c>docs/decisions/0069-a-baseline-is-marked-deliberately.md</c>, because those are the runs
    /// that may be compared with one another and each group carries its own baseline.
    /// </para>
    /// <para>
    /// <b>Grouped on the key and headed with the sentence.</b> The key is the run's own evidence
    /// identity, which already accounts for the forest - two forests whose domains happen to be
    /// named alike are different groups, and grouping on the heading would have merged them.
    /// </para>
    /// </remarks>
    public ICollectionView RunsView { get; }

    /// <summary>The runs found, in the order the library listed them.</summary>
    public ObservableCollection<RunSummaryViewModel> Runs { get; } = [];

    /// <summary>Whether a run is selected, and so whether there is anything to detail.</summary>
    public bool HasSelection => Selected is not null;

    /// <summary>
    /// Whether the selected run may have facts derived from it now.
    /// </summary>
    /// <remarks>
    /// <b>Asked of the run, not restated here.</b> <see cref="RunSummaryViewModel.MayDerive"/>
    /// already answers it from the products axis, and a second answer living on this screen would
    /// be free to disagree with the row the operator is looking at.
    /// </remarks>
    public bool CanDerive => Selected?.MayDerive == true && !IsAnalysing;

    /// <summary>
    /// Whether the selected run may be judged now.
    /// </summary>
    /// <remarks>
    /// False for a run already judged, which is what keeps a second judging from being offered at
    /// all. See <see cref="JudgeAsync"/> for why the command refuses as well as the button hiding.
    /// </remarks>
    public bool CanJudge => Selected?.MayJudge == true && !IsAnalysing;

    public bool CanDiscardJudgement => Selected?.MayDiscardJudgement == true && !IsAnalysing;

    /// <summary>
    /// Whether the library was read and genuinely holds nothing. False while unread or failed, so
    /// that "no runs" is only ever said when it was established.
    /// </summary>
    public bool IsEmpty => HasLooked && Problem is null && Runs.Count == 0;

    /// <summary>Reads the library again, keeping the selected run selected if it is still there.</summary>
    /// <remarks>
    /// <b>The selection survives because this is called on every arrival at Home.</b> An operator
    /// who picks a run, goes to look at its assets and comes back finds it still picked - the
    /// details card and the analysis buttons are where he left them. Clearing it was correct when
    /// the only way back here was an explicit refresh; it became wrong once navigation re-read the
    /// library, which is nine occasions including returning from another screen.
    /// </remarks>
    [RelayCommand]
    public void Refresh()
    {
        // Held by path rather than by object. Every row is built fresh below, so the old instance
        // is gone whatever happens; the path is what says which run the operator had chosen.
        var chosen = Selected?.Path;

        Runs.Clear();
        HasLooked = false;

        // Cleared while the list is empty, then restored below if the run is still there. A
        // selection pointing into a list that no longer exists would leave a details card
        // describing a run this library may no longer hold.
        Selected = null;

        if (!_location.IsChosen)
        {
            Problem = "No run library has been chosen yet.";
            OnPropertyChanged(nameof(IsEmpty));
            return;
        }

        var listed = _catalog.List(_location.Path!);

        if (!listed.IsSuccess)
        {
            Problem = listed.Error.Description;
            OnPropertyChanged(nameof(IsEmpty));
            return;
        }

        Problem = null;

        foreach (var run in listed.Value)
            Runs.Add(new RunSummaryViewModel(run));

        HasLooked = true;
        OnPropertyChanged(nameof(IsEmpty));

        // A run that has been deleted, or that a newly chosen library does not hold, leaves nothing
        // selected rather than selecting something else on the operator's behalf.
        if (chosen is not null)
        {
            Selected = Runs.FirstOrDefault(
                run => string.Equals(run.Path, chosen, StringComparison.OrdinalIgnoreCase));
        }
    }

    partial void OnSelectedChanged(RunSummaryViewModel? value)
    {
        // The boxes follow the selection rather than being cleared, so an operator who selects a
        // run he has already named sees what he wrote and can correct it rather than retype it.
        TypedName = value?.IsNamed == true ? value.Name : null;
        TypedNotes = value?.Notes;

        OnPropertyChanged(nameof(HasSelection));
        AnalysisOffersChanged();
    }

    /// <summary>
    /// Whichever analysis actions this run and this moment allow, said again.
    /// </summary>
    /// <remarks>
    /// Both the property and the command are told. The property draws the button; the command
    /// decides whether pressing it does anything, and a command left unnotified stays pressable
    /// after the answer has changed underneath it.
    /// </remarks>
    private void AnalysisOffersChanged()
    {
        OnPropertyChanged(nameof(CanDerive));
        OnPropertyChanged(nameof(CanJudge));
        OnPropertyChanged(nameof(CanDiscardJudgement));
        DeriveFactsCommand.NotifyCanExecuteChanged();
        JudgeCommand.NotifyCanExecuteChanged();
        DiscardJudgementAndJudgeAgainCommand.NotifyCanExecuteChanged();
        StopAnalysisCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsAnalysingChanged(bool value) => AnalysisOffersChanged();

    /// <summary>The name the operator is typing for the selected run.</summary>
    [ObservableProperty]
    private string? _typedName;

    /// <summary>The notes the operator is typing for the selected run.</summary>
    [ObservableProperty]
    private string? _typedNotes;

    /// <summary>
    /// Saves what the operator typed against the selected run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The library is read again afterwards, because a name is what a run is listed under and the
    /// list would otherwise go on showing the old one. The selection is restored by path, since the
    /// refresh discards the object it pointed at.
    /// </para>
    /// <para>
    /// This writes beside the evidence and never into it - see
    /// <see cref="Evidence.Run.RunAnnotations"/>. A failure to save is reported as a problem and
    /// leaves the run untouched.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void SaveAnnotation()
    {
        if (Selected is not { } selected)
            return;

        var path = selected.Path;

        // The baseline mark is carried through rather than defaulted. Both live in one row, so
        // saving a name built from the typed boxes alone would clear the mark - an operator who
        // corrected a spelling would silently un-baseline his own run, and nothing on the screen
        // would have suggested that was what Save did.
        var saved = _catalog.Annotate(
            path, new RunAnnotation(TypedName, TypedNotes, selected.IsBaseline));

        if (!saved.IsSuccess)
        {
            Problem = saved.Error.Description;
            return;
        }

        // Refresh keeps the selection, so the renamed run stays selected and its new name appears
        // in the details card without the operator having to find it again.
        Refresh();
    }

    /// <summary>
    /// Reads the library again and selects the run at <paramref name="bundleDirectory"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>For a run that did not exist when the library was last read.</b> A capture just finished
    /// writes a bundle the listed runs know nothing about, so selecting it without reading the
    /// library again would look for a row that is not there.
    /// </para>
    /// <para>
    /// A path the refreshed library does not hold says so rather than leaving nothing selected with
    /// no reason given. That is the case where a run was written somewhere other than the library
    /// this screen is pointed at, and an operator sent to an empty Assets screen would have no way
    /// to tell that from a run that captured nothing.
    /// </para>
    /// </remarks>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    public void Adopt(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        Refresh();

        var found = Runs.FirstOrDefault(
            run => string.Equals(run.Path, bundleDirectory, StringComparison.OrdinalIgnoreCase));

        if (found is null)
        {
            Problem = "This run is not in the library at " + _location.Path
                + ". Its evidence is at " + bundleDirectory + ".";
            return;
        }

        Selected = found;
    }

    /// <summary>
    /// Opens the selected run so its evidence can be read.
    /// </summary>
    /// <remarks>
    /// <b>Only a run that finished can be opened.</b> A run that ended badly wrote no evidence, so
    /// there is nothing to open; saying so here is better than handing a reader a directory and
    /// letting it report a missing file, which describes the symptom rather than the cause.
    /// </remarks>
    [RelayCommand]
    public void OpenRun()
    {
        if (Selected is not { } selected)
            return;

        if (!selected.FinishedCleanly)
        {
            Problem = "This run has no sealed evidence to open. " + selected.Meaning;
            return;
        }

        Problem = null;
        _opener.Open(selected.Path);
    }

    /// <summary>
    /// Makes the selected run the baseline of its scope group.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One baseline per group, per
    /// <c>docs/decisions/0069-a-baseline-is-marked-deliberately.md</c>, so marking one clears the
    /// mark from every other run of the same scope. Runs of a <i>different</i> scope are left
    /// alone: each group answers <i>what does changed mean here</i> for itself.
    /// </para>
    /// <para>
    /// <b>Marking is never refused for coverage.</b> A baseline speaks only for its own scope, and
    /// every run it will be compared against left the same domains out, so there is nothing to
    /// withhold. A run whose scope could not be established is the one exception - it has no group
    /// to be the baseline of, and marking it would put the mark somewhere nothing can find it.
    /// </para>
    /// <para>
    /// The clearing pass writes to each run in the group. A failure part way leaves the library
    /// with no baseline in that group rather than two, which is the safer of the two wrong states:
    /// no baseline is visibly missing, whereas two would make <i>changed since baseline</i> depend
    /// on which one a later reader happened to find first.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void MarkAsBaseline()
    {
        if (Selected is not { } selected)
            return;

        if (!selected.ScopeIsKnown)
        {
            Problem = "This run's scope could not be established, so there is no group of like "
                + "runs for it to be the baseline of. Runs are compared only against runs that "
                + "covered the same domains.";
            return;
        }

        var group = selected.GroupKey;
        var chosen = selected.Path;

        // Cleared first, so that a failure leaves no baseline rather than two.
        foreach (var run in Runs.Where(run => run.GroupKey == group && run.Path != chosen))
        {
            if (!run.IsBaseline)
                continue;

            var cleared = _catalog.Annotate(
                run.Path, new RunAnnotation(run.RawName, run.Notes, IsBaseline: false));

            if (!cleared.IsSuccess)
            {
                Problem = cleared.Error.Description;
                Refresh();
                return;
            }
        }

        var marked = _catalog.Annotate(
            chosen, new RunAnnotation(selected.RawName, selected.Notes, IsBaseline: true));

        if (!marked.IsSuccess)
        {
            Problem = marked.Error.Description;
            Refresh();
            return;
        }

        // Refresh keeps the selection, so the run the operator just marked stays selected.
        Refresh();
    }

    /// <summary>
    /// Deletes the selected run, after asking once.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One confirmation, naming the run, per
    /// <c>docs/decisions/0078-a-run-can-be-deleted-after-one-confirmation.md</c>. The operator is
    /// choosing between runs that differ by a timestamp, so the prompt states which one he picked
    /// rather than asking whether he is sure.
    /// </para>
    /// <para>
    /// <b>A failure leaves the run listed.</b> Refreshing regardless would drop the row for a run
    /// still on disk, telling the operator he had recovered space he has not.
    /// </para>
    /// </remarks>
    [RelayCommand]
    public void DeleteRun()
    {
        if (Selected is not { } selected)
            return;

        var confirmed = _confirmation.Confirm(
            "Delete this run",
            $"{selected.Name} and all of its evidence will be deleted from "
            + $"{selected.Path}. This cannot be undone.",
            "delete it");

        if (!confirmed)
            return;

        var deleted = _catalog.Delete(selected.Path);

        if (!deleted.IsSuccess)
        {
            Problem = deleted.Error.Description;
            return;
        }

        Refresh();
    }

    /// <summary>
    /// Stops the analysis this screen started, leaving the evidence untouched.
    /// </summary>
    /// <remarks>
    /// Neither deriving nor judging writes its store until it has finished, so stopping loses the
    /// work and nothing else. The evidence was sealed before either was offered.
    /// </remarks>
    [RelayCommand(CanExecute = nameof(IsAnalysing))]
    public void StopAnalysis() => _stopping?.Cancel();

    /// <summary>
    /// Derives facts from the selected run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Offered only to a run holding none.</b> A capture taken with <i>Capture only</i> is
    /// complete evidence and an ordinary thing to have - it is what the command line's
    /// <c>--capture</c> has always produced - so this is how it is analysed later, without reading
    /// the forest a second time.
    /// </para>
    /// <para>
    /// <b>The refusal is stated as well as the button hidden.</b> A control an operator cannot
    /// press and cannot see a reason for is the screen refusing without explaining itself.
    /// </para>
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanDerive))]
    public Task DeriveFactsAsync()
    {
        if (Selected is not { } selected)
            return Task.CompletedTask;

        if (!selected.MayDerive)
        {
            Problem = selected.FinishedCleanly
                ? $"{selected.Name} already holds derived facts."
                : $"{selected.Name} has no sealed evidence to derive from. {selected.Meaning}";
            return Task.CompletedTask;
        }

        return AnalyseAsync(
            selected,
            $"Deriving facts from {selected.Name}. Nothing is read from the directory.",
            read => $"Deriving facts from {selected.Name} - {read:N0} objects read.",
            (path, report, token) => _deriving.RunAsync(
                path,
                new Progress<DerivationProgress>(value => report(value.ObjectsRead)),
                token),
            derived => Describe(selected.Name, derived),
            refused =>
                $"{selected.Name}: nothing could be derived. {refused} The evidence is sealed and "
                + "can be derived from again without capturing the forest a second time.",
            $"{selected.Name}: deriving was stopped. The evidence is untouched and can be derived "
            + "from again.",
            defect =>
                $"{selected.Name}: deriving stopped on an error the product did not expect: "
                + $"{defect} This is a defect rather than something you did. The evidence is "
                + "sealed and can be derived from again once it is fixed.");
    }

    /// <summary>
    /// Judges the selected run.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Never offered to a run holding no derived facts.</b> Rules that read more than one object
    /// rest on those facts, so a judging that ran before them would rest on nothing - the same
    /// order <c>NewAuditViewModel</c> keeps after a capture.
    /// </para>
    /// <para>
    /// <b>And never offered twice.</b> <see cref="RunSummaryViewModel.MayJudge"/> is false once a
    /// judgement is published, so a second judging is refused here rather than started and left to
    /// discover halfway through that it is overwriting a store something else may be reading.
    /// </para>
    /// </remarks>
    [RelayCommand(CanExecute = nameof(CanJudge))]
    public Task JudgeAsync()
    {
        if (Selected is not { } selected)
            return Task.CompletedTask;

        if (!selected.MayJudge)
        {
            Problem = !selected.FinishedCleanly
                ? $"{selected.Name} has no sealed evidence to judge. {selected.Meaning}"
                : selected.HasResults
                    ? $"{selected.Name} has already been judged. Open it to read what was found."
                    : $"{selected.Name} holds no derived facts yet. Derive facts from it first - "
                        + "rules that read more than one object rest on them.";
            return Task.CompletedTask;
        }

        return AnalyseAsync(
            selected,
            $"Judging {selected.Name}. Nothing is read from the directory.",
            read => $"Judging {selected.Name} - {read:N0} objects judged.",
            (path, report, token) => _judging.RunAsync(
                path,
                new Progress<JudgingRun.JudgingProgress>(value => report(value.ObjectsRead)),
                token),
            judged => Describe(selected.Name, judged),
            refused =>
                $"{selected.Name}: it could not be judged. {refused} The findings can be produced "
                + "again from this bundle without capturing the forest a second time.",
            $"{selected.Name}: judging was stopped. No judgement was written and the evidence is "
            + "untouched.",
            defect =>
                $"{selected.Name}: judging stopped on an error the product did not expect: "
                + $"{defect} This is a defect rather than something you did. The evidence is "
                + "sealed and can be judged again once it is fixed.");
    }

    [RelayCommand(CanExecute = nameof(CanDiscardJudgement))]
    public Task DiscardJudgementAndJudgeAgainAsync()
    {
        if (Selected is not { } selected) return Task.CompletedTask;
        if (!CanDiscardJudgement)
        {
            Problem = $"{selected.Name} must have sealed evidence, derived facts and a saved judgement, "
                + "with no analysis already running, before its judgement can be discarded.";
            return Task.CompletedTask;
        }
        const string action = "Discard judgement and judge again";
        if (!_confirmation.Confirm(action,
            $"{selected.Name} ({selected.Path})\n\n"
            + "This deletes this run's saved judgement before starting again. Captured evidence, "
            + "derived facts and the run log are kept. If judging is stopped or fails, "
            + "there will be no completed judgement to open.", action))
            return Task.CompletedTask;

        return AnalyseAsync(
            selected,
            $"Discarding the saved judgement and judging {selected.Name}. Nothing is read from the directory.",
            read => $"Judging {selected.Name} - {read:N0} objects judged.",
            async (path, report, token) =>
            {
                await _opener.CloseAsync();
                token.ThrowIfCancellationRequested();
                var discarded = await Task.Run(() => _catalog.DiscardJudgement(path), token);
                if (!discarded.IsSuccess) return Result<JudgingOutcome>.Failure(discarded.Error);
                return await _judging.RunAsync(path,
                    new Progress<JudgingRun.JudgingProgress>(value => report(value.ObjectsRead)), token);
            },
            judged => Describe(selected.Name, judged),
            refused => $"{selected.Name}: the discard-and-judge attempt did not finish successfully. "
                + $"{refused} Captured evidence and derived facts are kept.",
            $"{selected.Name}: judging was stopped. Captured evidence and derived facts are kept.",
            defect => $"{selected.Name}: the discard-and-judge attempt stopped on an unexpected error: "
                + $"{defect} Captured evidence and derived facts are kept.");
    }

    /// <summary>
    /// Runs one analysis against one run, and keeps what it says tied to the run it was about.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every sentence it writes names <paramref name="run"/>.</b> This screen is a list the
    /// operator goes on clicking through, so the selection when an hour-long judging returns is
    /// frequently not the run that was judged. An outcome written under whatever happens to be
    /// selected then would attribute one run's results to another - which is the one thing an audit
    /// tool must not do, because a security decision is made on the strength of it.
    /// </para>
    /// <para>
    /// <b>And his selection is left where he put it.</b> The library is read again so the analysed
    /// run's row stops saying <i>not assessed</i>, and whatever he had selected at that moment is
    /// restored. Forcing the selection back to the analysed run would yank the screen out from
    /// under him; leaving it null would lose it.
    /// </para>
    /// <para>
    /// <b>The outcome is written after the work is over.</b> A progress report that arrived late
    /// would otherwise overwrite the result with a count, so progress is admitted only while this
    /// epoch is the current one and the screen is still analysing - both false by the time the
    /// outcome is set.
    /// </para>
    /// </remarks>
    private async Task AnalyseAsync<TOutcome>(
        RunSummaryViewModel run,
        string started,
        Func<long, string> progressing,
        Func<string, Action<long>, CancellationToken, Task<Result<TOutcome>>> launch,
        Func<TOutcome, string> describe,
        Func<string, string> refused,
        string stopped,
        Func<string, string> defect)
    {
        var path = run.Path;
        var epoch = ++_analysisEpoch;

        _stopping?.Dispose();
        _stopping = new CancellationTokenSource();

        Problem = null;
        AnalysisStatus = started;
        IsAnalysing = true;

        string outcome;

        try
        {
            var result = await launch(
                    path,
                    read =>
                    {
                        if (epoch == _analysisEpoch && IsAnalysing)
                            AnalysisStatus = progressing(read);
                    },
                    _stopping.Token)
                .ConfigureAwait(true);

            outcome = result.IsSuccess
                ? describe(result.Value)
                : refused(result.Error.Description);
        }
        catch (OperationCanceledException)
        {
            outcome = stopped;
        }
        catch (Exception failure)
        {
            // A defect in an analysis costs the analysis and nothing else. Left to escape, it would
            // reach the dispatcher unhandled and take the window down with it - and the evidence,
            // which took hours and read a forest that has moved on, is sealed and safe either way.
            // Nothing is swallowed: the exception's own words are put in front of the operator.
            outcome = defect(failure.Message);
        }
        finally
        {
            IsAnalysing = false;
            _stopping.Dispose();
            _stopping = null;
        }

        var showing = Selected?.Path;

        Refresh();

        Selected = Runs.FirstOrDefault(
            listed => string.Equals(listed.Path, showing, StringComparison.OrdinalIgnoreCase));

        AnalysisStatus = outcome;
    }

    /// <summary>What a finished derivation produced, under the name of the run it read.</summary>
    /// <remarks>
    /// <b>A degraded derivation says so.</b> A closure that could not be completed has established
    /// less than a complete one, and wording that omits what it missed reads as a clean result.
    /// </remarks>
    private static string Describe(string name, DerivingOutcome derived) => derived.State switch
    {
        DerivationRunState.Completed =>
            $"{name}: derived {derived.Principals:N0} principals and "
            + $"{derived.NestingEdges:N0} nesting relationships.",
        DerivationRunState.CompletedDegraded =>
            $"{name}: derived {derived.Principals:N0} principals and "
            + $"{derived.NestingEdges:N0} nesting relationships, and at least one part could not "
            + "be completed. Rules resting on it are not working from the whole picture.",
        _ =>
            $"{name}: nothing was derived. The evidence is sealed and can be derived from again.",
    };

    /// <summary>What a finished judging produced, under the name of the run it read.</summary>
    /// <remarks>
    /// <b>It sends the operator to the findings rather than counting them here.</b> A card beside a
    /// list is not where a severity breakdown belongs, and a bare object count with no mention of
    /// what was found would be read as nothing found.
    /// </remarks>
    private static string Describe(string name, JudgingOutcome judged) => judged.State switch
    {
        JudgementRunState.Completed =>
            $"{name}: judged {judged.ObjectsJudged:N0} objects. Every rule reached a verdict. "
            + "Open the run to read what they found.",
        JudgementRunState.CompletedDegraded =>
            $"{name}: judged {judged.ObjectsJudged:N0} objects, and at least one rule could not "
            + "reach a verdict. What the rules that did finish found is not the whole picture. "
            + "Open the run to read it.",
        _ =>
            $"{name}: the judging did not finish. The evidence is sealed and can be judged again.",
    };
}

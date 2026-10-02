using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One domain's line on the dashboard: what it held, or why it held no number.
/// </summary>
/// <remarks>
/// <para>
/// <b>A row that was not counted exposes no count, not a zero.</b> The numbers are strings built
/// only where <see cref="DomainInventory.WasCounted"/> is true, so there is nothing for a view to
/// bind that would render as <c>0</c> against a domain nobody read. That is the whole point of the
/// screen: <i>we could not read this</i> and <i>this was empty</i> are different facts, and the
/// second is the one that tells an administrator to stop looking.
/// </para>
/// <para>
/// <b>The words come from the coverage, not from a lookup here.</b>
/// <see cref="DomainCoverage.Reason"/> is what the run recorded at the time, in terms an operator
/// can act on, and rewording it here would put a second account of one event in the product.
/// </para>
/// </remarks>
internal sealed class DomainInventoryRowViewModel
{
    private readonly ObjectCounts? _counts;

    /// <summary>Builds a row from what the evidence said about one domain.</summary>
    /// <param name="inventory">The domain, counted or not.</param>
    public DomainInventoryRowViewModel(DomainInventory inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);

        Inventory = inventory;
        _counts = inventory.TryGetCounts(out var counts) ? counts : null;
    }

    /// <summary>What the evidence said about this domain.</summary>
    public DomainInventory Inventory { get; }

    /// <summary>The domain, as an administrator names it.</summary>
    public string DomainFqdn => Inventory.DomainFqdn;

    /// <summary>Whether this row has numbers to show at all.</summary>
    public bool CountsAreShown => _counts is not null;

    /// <summary>Whether this row instead has to explain itself.</summary>
    /// <remarks>
    /// Its own answer rather than the negation of <see cref="CountsAreShown"/>, because a view
    /// cannot negate a binding without a converter and the shell keeps only one.
    /// </remarks>
    public bool ExplanationIsShown => _counts is null;

    /// <summary>How many accounts whose most specific class is <c>user</c>.</summary>
    public string? Users => Formatted(_counts?.Users);

    /// <summary>How many accounts whose most specific class is <c>computer</c>.</summary>
    public string? Computers => Formatted(_counts?.Computers);

    /// <summary>How many groups.</summary>
    public string? Groups => Formatted(_counts?.Groups);

    /// <summary>How many organisational units.</summary>
    public string? OrganisationalUnits => Formatted(_counts?.OrganisationalUnits);

    /// <summary>
    /// What happened to this domain, in words, for a row that has no numbers.
    /// </summary>
    /// <remarks>
    /// <b>The outcome is said before the reason.</b> A domain left out by choice and a domain the
    /// forest could name no controller for both produce an empty row, and an operator reading only
    /// the reason would have to work out which he is looking at.
    /// </remarks>
    public string Explanation => Inventory.Coverage.Outcome switch
    {
        DomainReadOutcome.Read => string.Empty,
        DomainReadOutcome.PartiallyRead =>
            "Only part of this domain was read, so nothing here can be counted. "
            + Inventory.Coverage.Reason,
        DomainReadOutcome.NotRead =>
            "This domain could not be read. " + Inventory.Coverage.Reason,
        DomainReadOutcome.ExcludedByChoice =>
            "You left this domain out of the run. " + Inventory.Coverage.Reason,
        DomainReadOutcome.ExcludedForWantOfCandidates =>
            "The forest named no writable domain controller for this domain, so nothing was "
            + "attempted. " + Inventory.Coverage.Reason,
        _ => "This domain's outcome was not recognised, so nothing here can be counted.",
    };

    /// <summary>
    /// Whether this domain was read over a connection that could have withheld attributes.
    /// </summary>
    public bool MayBeMissingConfidentialValues => Inventory.MayBeMissingConfidentialValues;

    /// <summary>
    /// Thousands separated, because these are read by eye and 4102 is harder than 4,102.
    /// </summary>
    private static string? Formatted(int? count) =>
        count?.ToString("N0", CultureInfo.CurrentCulture);
}

/// <summary>
/// What one run says about the size of the forest it read, and how much of it it read.
/// </summary>
/// <remarks>
/// <para>
/// <b>Coverage first, counts underneath.</b> The owner's decision of 2026-09-05. An operator
/// opening a run is answering <i>what am I looking at</i>, and a total he cannot yet trust is not
/// an answer to it. <see cref="CoverageHeadline"/> is therefore the first thing the screen states,
/// and every number below is qualified by it.
/// </para>
/// <para>
/// <b>This screen reports no findings and counts no severities.</b> Not an omission: the findings
/// pane already counts them, and a second count here is two numbers about one judgement that will
/// eventually disagree. <c>ROADMAP.md</c> § Stage 2 - <i>no rules, no graph</i>.
/// </para>
/// <para>
/// <b>Four silences are kept apart, as <see cref="AssetsViewModel"/> keeps them.</b> No run chosen
/// is a question the operator has not answered. A bundle that would not open is a failure stated in
/// the evidence layer's own words. A run whose coverage cannot be established yields no counts at
/// all. A domain read and found empty is a claim, and is the only one of the four that may draw a
/// zero.
/// </para>
/// </remarks>
internal sealed partial class DashboardViewModel : ObservableObject
{
    private static readonly ResourceManager ScopeWording = new(
        "SecureAD.Shell.Resources.CaptureObjectScope", typeof(DashboardViewModel).Assembly);

    private static string ScopeText(string key, params object[] values) => string.Format(
        CultureInfo.CurrentCulture,
        ScopeWording.GetString(key, CultureInfo.CurrentUICulture) ?? throw new InvalidOperationException(key), values);

    private readonly IAssetSource _assets;
    private CancellationTokenSource? _pending;
    private long _revision;
    private string? _membershipReadError;

    [ObservableProperty]
    private string? _bundlePath;

    [ObservableProperty]
    private bool _isLoading;

    /// <summary>The current Dashboard read, including application of its result.</summary>
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    /// <summary>Why there is nothing to show, or null when there is.</summary>
    /// <remarks>
    /// Held rather than left to an empty collection. A dashboard drawn empty says <i>your forest
    /// holds nothing</i>, which is the one thing this screen must never say by accident.
    /// </remarks>
    [ObservableProperty]
    private Notice? _refusal;

    private ForestInventory? _inventory;

    /// <summary>
    /// Groups that claimed a member the run could not identify, or null where deriving has not run.
    /// </summary>
    /// <remarks>
    /// Null is load-bearing and is not a missing value: it says nobody has worked the membership
    /// out, which <see cref="MembershipNotice"/> states rather than rounding down to none.
    /// </remarks>
    private int? _groupsWithUnidentifiedMembers;

    /// <summary>Builds the dashboard over a source of run evidence.</summary>
    /// <param name="assets">Where the counts come from.</param>
    public DashboardViewModel(IAssetSource assets)
    {
        ArgumentNullException.ThrowIfNull(assets);
        _assets = assets;
    }

    /// <summary>Whether there is a refusal worth a card of its own.</summary>
    /// <remarks>
    /// Stated as a boolean because the theme carries one visibility converter and it takes a
    /// boolean. A view testing the notice for null would be a view holding a rule about when a
    /// refusal exists.
    /// </remarks>
    public bool HasRefusal => Refusal is not null;

    /// <summary>Each declared domain, in name order, counted or explained.</summary>
    public ObservableCollection<DomainInventoryRowViewModel> Domains { get; } = [];

    /// <summary>Whether a run is being shown at all.</summary>
    public bool HasRun => _inventory is not null;

    /// <summary>
    /// Whether the operator has chosen no run.
    /// </summary>
    /// <remarks>
    /// Stated positively for the reason <see cref="DomainInventoryRowViewModel.ExplanationIsShown"/>
    /// gives, and separately from <see cref="Refusal"/> because <i>you have not chosen a run</i>
    /// and <i>this run would not open</i> send an operator to do different things.
    /// </remarks>
    public bool HasNoRun => BundlePath is null && _inventory is null && Refusal is null;

    /// <summary>The forest the run captured.</summary>
    public string? ForestFqdn => _inventory?.ForestFqdn;

    /// <summary>Names the exclusions saved by the opened run rather than the current capture default.</summary>
    public string ObjectClassScopeStatement => _inventory is { } inventory
        ? ScopeText("RecordedExclusions", string.Join(", ", inventory.ExcludedObjectClasses))
        : string.Empty;

    /// <summary>
    /// How much of the forest this run read, said before any number below it.
    /// </summary>
    /// <remarks>
    /// <b>It states the denominator every time, including when nothing was missed.</b> A headline
    /// that appeared only when something went wrong would train an operator to read its absence as
    /// reassurance, and its absence is also what a broken binding looks like.
    /// </remarks>
    public string CoverageHeadline
    {
        get
        {
            if (_inventory is not { } inventory)
                return string.Empty;

            var declared = inventory.DomainsDeclared;
            var counted = inventory.DomainsCounted;

            return inventory.AllDeclaredDomainsAreComplete
                ? ScopeText("AllDomains", Count(declared, "domain"))
                : ScopeText("SomeDomains", counted, Count(declared, "domain"));
        }
    }

    /// <summary>Whether every declared domain was read, so the totals are the whole forest.</summary>
    public bool EveryDomainCounted => _inventory?.AllDeclaredDomainsAreComplete ?? false;

    /// <summary>
    /// The warning that goes above everything, or null when there is none.
    /// </summary>
    /// <remarks>
    /// <b>A domain with no writable controller is raised, not listed.</b> The owner's decision of
    /// 2026-09-05: it is not an exclusion he chose and may be the first he hears of a trust,
    /// replication or decommissioning problem. <c>docs/decisions/0063</c> requires it never to read
    /// as an ordinary exclusion, and putting it in the same list as the domains he deliberately
    /// left out would do exactly that.
    /// </remarks>
    public Notice? Warning
    {
        get
        {
            if (_inventory is not { } inventory)
                return null;

            var stranded = inventory.DomainsWithNoController;
            if (stranded.Count == 0)
                return null;

            var named = string.Join(", ", stranded.Select(d => d.DomainFqdn));

            return new Notice(
                stranded.Count == 1
                    ? "A domain has no writable domain controller"
                    : "Domains have no writable domain controller",
                $"The forest declares {named}, but named no writable controller able to serve "
                + "it, so this run never attempted to read it. Nothing below counts it. This is "
                + "not something you excluded - it usually means a broken trust, a replication "
                + "problem, or a domain that was decommissioned without being removed from the "
                + "forest.");
        }
    }

    /// <summary>Whether there is a warning to raise.</summary>
    public bool HasWarning => Warning is not null;

    /// <summary>
    /// What the run can and cannot say about who is inside its groups, or null where there is
    /// nothing to say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Below the coverage headline, because it is a coverage fact.</b> The owner's decision of
    /// 2026-09-12. A group listing a member the run could not identify holds more than this bundle
    /// can show, and until <c>P-164</c> that was indistinguishable from a group holding nobody -
    /// so rules reported such objects clean. They now decline instead, and this is where an
    /// operator learns how much of the forest that covers.
    /// </para>
    /// <para>
    /// <b>A notice rather than a statistic, because it can be acted on.</b> The usual cause is a
    /// domain left out of the run or a member in another forest, and the remedy is to widen the
    /// scope and capture again.
    /// </para>
    /// <para>
    /// <b>Not derived is stated, not counted as none.</b> Deriving is a separate stage that may not
    /// have run, and reporting that as <i>no groups affected</i> would be this screen making the
    /// exact claim the rest of it exists to refuse.
    /// </para>
    /// </remarks>
    public Notice? MembershipNotice
    {
        get
        {
            if (_inventory is null)
                return null;

            if (_membershipReadError is not null)
                return new Notice("Saved membership results could not be read.", _membershipReadError);

            if (_groupsWithUnidentifiedMembers is not { } groups)
            {
                return new Notice(
                    "Group membership has not been worked out yet",
                    "Deriving has not run for this run, so whether every group's membership could "
                    + "be read is unknown. Nothing below counts it either way.");
            }

            if (groups == 0)
                return null;

            var lead = groups == 1
                ? "1 group lists at least one member this run could not identify"
                : $"{groups:N0} groups list at least one member this run could not identify";

            return new Notice(
                "Some groups' membership could not be fully read",
                lead
                + " \u2014 usually an account in a domain you left out of the run, or one in "
                + "another forest. Those groups are reported as incomplete, and rules that depend "
                + "on who is inside them will decline to judge rather than report them clean.");
        }
    }

    /// <summary>Whether there is anything to say about group membership.</summary>
    public bool HasMembershipNotice => MembershipNotice is not null;

    /// <summary>Accounts across every domain that was read.</summary>
    public string TotalUsers => Total(c => c.Users);

    /// <summary>Computer accounts across every domain that was read.</summary>
    public string TotalComputers => Total(c => c.Computers);

    /// <summary>Groups across every domain that was read.</summary>
    public string TotalGroups => Total(c => c.Groups);

    /// <summary>Organisational units across every domain that was read.</summary>
    public string TotalOrganisationalUnits => Total(c => c.OrganisationalUnits);

    /// <summary>
    /// What the totals cover, stated beside them and never left to be inferred.
    /// </summary>
    /// <remarks>
    /// A total is only the forest when every domain was read. Where it is not, this names the
    /// domains it does cover rather than counting them: <i>2 of 3</i> says how many and not which,
    /// and which is what decides whether the total covers the domain being worried about.
    /// </remarks>
    public string TotalsCover
    {
        get
        {
            if (_inventory is not { } inventory)
                return string.Empty;

            if (inventory.AllDeclaredDomainsAreComplete)
                return "Across the whole forest.";

            var counted = inventory.Domains
                .Where(d => d.WasCounted)
                .Select(d => d.DomainFqdn)
                .ToArray();

            return counted.Length == 0
                ? "No domain in this run was read in full, so there is nothing to total."
                : "Across " + string.Join(", ", counted) + " only.";
        }
    }

    /// <summary>Whether there is anything to total at all.</summary>
    public bool HasTotals => _inventory is { DomainsCounted: > 0 };

    /// <summary>
    /// What became of the Group Policy objects, as read of declared.
    /// </summary>
    /// <remarks>
    /// <b>Both numbers, exactly, because both are known.</b> The owner's ruling of 2026-09-05. The
    /// declaration comes from the directory, which is read all-or-nothing, while the files come
    /// from SYSVOL, which <c>docs/decisions/0044</c> allows to fail without failing the run - so
    /// this is the one figure in the product where an exact shortfall can be stated rather than
    /// warned about.
    /// </remarks>
    public string Policies
    {
        get
        {
            if (_inventory is not { } inventory)
                return string.Empty;

            if (inventory.PoliciesDeclared == 0)
                return "This forest declares no Group Policy objects.";

            return inventory.AllPoliciesRead
                ? $"{Count(inventory.PoliciesDeclared, "Group Policy object")}, all read in full."
                : $"{inventory.PoliciesRead:N0} of "
                  + $"{Count(inventory.PoliciesDeclared, "Group Policy object")} were read in "
                  + $"full. {inventory.PoliciesNotRead:N0} could not be read from SYSVOL, so what "
                  + "those policies contain is not in this run's evidence.";
        }
    }

    /// <summary>Whether some declared policy's files were not read.</summary>
    public bool SomePoliciesWereNotRead => _inventory is { AllPoliciesRead: false };

    /// <summary>
    /// The caveat about confidential attributes, or null where none applies.
    /// </summary>
    /// <remarks>
    /// <b>It does not qualify the counts, and says so.</b> An object still arrives over an
    /// unencrypted search; what a 2025 controller strips are attribute values, silently
    /// (<c>F-S24-1</c>). Wording this as <i>the counts may be wrong</i> would be its own falsehood,
    /// and wording it as nothing at all would let a screen present detail more certain than the
    /// evidence supports.
    /// </remarks>
    public Notice? ConfidentialCaveat
    {
        get
        {
            if (_inventory is not { AnyDomainMayBeMissingConfidentialValues: true } inventory)
                return null;

            var over = inventory.Domains
                .Where(d => d.WasCounted && d.MayBeMissingConfidentialValues)
                .Select(d => d.DomainFqdn);

            return new Notice(
                "Some attribute values may be missing",
                $"{string.Join(", ", over)} was read over a connection that was not encrypted. A "
                + "domain controller may withhold confidential attribute values from such a "
                + "search without reporting that it has done so. The object counts here are "
                + "unaffected - every object still arrived - but detail shown elsewhere for these "
                + "domains may be incomplete.");
        }
    }

    /// <summary>Whether the confidential-attribute caveat applies.</summary>
    public bool HasConfidentialCaveat => ConfidentialCaveat is not null;

    /// <summary>Shows the dashboard for one run.</summary>
    /// <param name="bundleDirectory">The run's bundle directory.</param>
    public void Show(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        CancelRead();
        _assets.SelectRun(bundleDirectory);
        BundlePath = bundleDirectory;
        _inventory = null;
        _groupsWithUnidentifiedMembers = null;
        _membershipReadError = null;
        Refusal = null;
        Domains.Clear();
        IsLoading = true;
        Restated();
        var pending = new CancellationTokenSource();
        _pending = pending;
        ReadCompletion = LoadAsync(bundleDirectory, pending, _revision);
    }

    private async Task LoadAsync(string bundleDirectory, CancellationTokenSource pending, long revision)
    {
        using var navigation = NavigationDiagnostics.Begin(bundleDirectory, "open Dashboard");
        try
        {
            var read = await _assets.ReadAsync(bundleDirectory, (reader, token) =>
            {
                token.ThrowIfCancellationRequested();
                var inventory = reader.ReadInventory(bundleDirectory);
                token.ThrowIfCancellationRequested();
                var membership = reader.ReadGroupsWithUnidentifiedMembers(bundleDirectory);
                token.ThrowIfCancellationRequested();
                return (Inventory: inventory, Membership: membership);
            }, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested)
            {
                navigation.Complete("cancelled", null);
                return;
            }

            if (!read.Inventory.IsSuccess)
            {
                Refusal = new Notice("This run cannot be summarised", read.Inventory.Error.Description);
                navigation.Complete("refused", read.Inventory.Error.Code);
                return;
            }

            _inventory = read.Inventory.Value;
            if (read.Membership.IsSuccess)
                _groupsWithUnidentifiedMembers = read.Membership.Value;
            else
                _membershipReadError = read.Membership.Error.Description;
            foreach (var domain in _inventory.Domains)
                Domains.Add(new DomainInventoryRowViewModel(domain));
            navigation.Complete(read.Membership.IsSuccess ? "success" : "refused",
                read.Membership.IsSuccess ? null : read.Membership.Error.Code);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested)
        {
            navigation.Complete("cancelled", null);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested)
            {
                Refusal = new Notice("This run cannot be summarised", error.Message);
                navigation.Complete("refused", error.GetType().Name);
            }
        }
        finally
        {
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                IsLoading = false;
                Restated();
            }
            pending.Dispose();
        }
    }

    /// <summary>Shows nothing, because no run is chosen.</summary>
    public void Clear()
    {
        CancelRead();
        BundlePath = null;
        _inventory = null;
        _groupsWithUnidentifiedMembers = null;
        _membershipReadError = null;
        Refusal = null;
        Domains.Clear();
        Restated();
    }

    private void CancelRead()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        IsLoading = false;
    }

    /// <summary>
    /// Tells the view that every computed statement on this screen may have changed.
    /// </summary>
    /// <remarks>
    /// Listed by name rather than raised for all properties, because a view model that announces
    /// everything is one where a missing binding never shows up in a test.
    /// </remarks>
    private void Restated()
    {
        OnPropertyChanged(nameof(HasRun));
        OnPropertyChanged(nameof(HasNoRun));
        OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(ForestFqdn));
        OnPropertyChanged(nameof(CoverageHeadline));
        OnPropertyChanged(nameof(ObjectClassScopeStatement));
        OnPropertyChanged(nameof(EveryDomainCounted));
        OnPropertyChanged(nameof(Warning));
        OnPropertyChanged(nameof(HasWarning));
        OnPropertyChanged(nameof(MembershipNotice));
        OnPropertyChanged(nameof(HasMembershipNotice));
        OnPropertyChanged(nameof(TotalUsers));
        OnPropertyChanged(nameof(TotalComputers));
        OnPropertyChanged(nameof(TotalGroups));
        OnPropertyChanged(nameof(TotalOrganisationalUnits));
        OnPropertyChanged(nameof(TotalsCover));
        OnPropertyChanged(nameof(HasTotals));
        OnPropertyChanged(nameof(Policies));
        OnPropertyChanged(nameof(SomePoliciesWereNotRead));
        OnPropertyChanged(nameof(ConfidentialCaveat));
        OnPropertyChanged(nameof(HasConfidentialCaveat));
    }

    /// <summary>
    /// A total over the domains that were counted, or an em dash where none were.
    /// </summary>
    /// <remarks>
    /// The dash rather than <c>0</c>, for the reason the whole screen exists: a run that read no
    /// domain in full has not established that the forest holds nothing.
    /// </remarks>
    private string Total(Func<ObjectCounts, int> of) =>
        _inventory is { DomainsCounted: > 0 } inventory
            ? of(inventory.CountedTotal).ToString("N0", CultureInfo.CurrentCulture)
            : "\u2014";

    /// <summary>Pluralises a counted noun, so no screen reads <i>1 domains</i>.</summary>
    private static string Count(int howMany, string noun) =>
        howMany == 1
            ? $"1 {noun}"
            : $"{howMany:N0} {noun}s";
}

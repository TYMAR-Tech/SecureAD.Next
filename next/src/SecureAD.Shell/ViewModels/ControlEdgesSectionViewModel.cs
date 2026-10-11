using System.Globalization;
using System.IO;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Shell.ViewModels;

internal enum ControlEdgeDetailView
{
    Evidence,
    Requester,
    Membership,
}

/// <summary>Two paged views over the same persisted edge product, never an authorization calculation in the screen.</summary>
internal sealed partial class ControlEdgesSectionViewModel : ObjectSectionViewModel
{
    private Func<bool, bool, long, CancellationToken, Task<Result<ControlEdgePage>>>? _read;
    private Func<bool, CancellationToken, Task<Result<SelfMembershipAssessmentSet>>>? _readAssessments;
    private CancellationTokenSource? _pending;
    private long _revision;
    private bool _active;
    /// <summary>The current control-page read and its dependent saved products.</summary>
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    private bool _selectedIsUser;
    private bool _configuring;
    private long _after;
    private Guid? _generation;
    public string CountHeader => ControlEdgeRowViewModel.Text("CountHeader");
    [ObservableProperty] private bool _byHolder;
    [ObservableProperty] private bool _includeExpected;
    [ObservableProperty] private bool _hasPrincipal;
    [ObservableProperty] private bool _hasMore;
    [ObservableProperty] private string _coverage = "Control edges have not been read.";
    [ObservableProperty] private string _counts = "Expected edges hidden: unknown (product not read).";
    [ObservableProperty] private IReadOnlyList<ControlEdgeRowViewModel> _rows = [];
    [ObservableProperty] private ControlEdgeRowViewModel? _selectedEdge;
    [ObservableProperty] private string _edgeSearchText = "";
    [ObservableProperty] private ControlEdgeDetailView _detailView;
    [ObservableProperty] private bool _hasCoverageWarning;
    [ObservableProperty] private string _analysisSummary = "Not read";
    [ObservableProperty] private string _captureSummary = "Capture unknown";
    [ObservableProperty] private string _unexpectedSummary = "Unexpected unknown";
    [ObservableProperty] private string _unknownSummary = "Unknown unresolved";
    [ObservableProperty] private string _expectedSummary = "Expected unknown";
    private string _requesterCoverage = "Requester assessments have not been read.";
    private IReadOnlyList<SelfMembershipAssessmentRowViewModel> _requesterAssessments = [];
    private SelfMembershipAssessmentRowViewModel? _selectedRequesterAssessment;

    public string RequesterCoverage { get => _requesterCoverage; private set => SetProperty(ref _requesterCoverage, value); }
    public SelfMembershipAssessmentRowViewModel? SelectedRequesterAssessment
    {
        get => _selectedRequesterAssessment;
        set => SetProperty(ref _selectedRequesterAssessment, value);
    }
    public IReadOnlyList<SelfMembershipAssessmentRowViewModel> RequesterAssessments
    {
        get => _requesterAssessments;
        private set => SetProperty(ref _requesterAssessments, value);
    }

    public string SupportedScope => ControlEdgePage.SupportedScope;
    public string ObjectName { get; }
    public string OnObjectQuestion => $"Who can control {ObjectName}?";
    public string HeldByObjectQuestion => $"What can {ObjectName} control?";
    public bool ShowsEdgesOnObject
    {
        get => !ByHolder;
        set { if (value) ByHolder = false; }
    }
    public bool ShowsEdgesHeldByObject
    {
        get => ByHolder;
        set { if (value) ByHolder = true; }
    }
    public bool ShowsHolderColumn => !ByHolder;
    public bool ShowsTargetColumn => ByHolder;
    public bool ShowsEvidenceDetails
    {
        get => DetailView == ControlEdgeDetailView.Evidence;
        set { if (value) DetailView = ControlEdgeDetailView.Evidence; }
    }
    public bool ShowsRequesterDetails
    {
        get => DetailView == ControlEdgeDetailView.Requester;
        set { if (value) DetailView = ControlEdgeDetailView.Requester; }
    }
    public bool ShowsMembershipDetails
    {
        get => DetailView == ControlEdgeDetailView.Membership;
        set { if (value) DetailView = ControlEdgeDetailView.Membership; }
    }
    public IReadOnlyList<ControlEdgeRowViewModel> VisibleRows => string.IsNullOrWhiteSpace(EdgeSearchText)
        ? Rows
        : Rows.Where(row => Contains(row.Holder) || Contains(row.Target) || Contains(row.Capability)
            || Contains(row.Evaluation) || Contains(row.Expectedness)).ToArray();
    public bool HasVisibleRows => VisibleRows.Count != 0;
    public bool HasNoVisibleRows => !HasVisibleRows;
    public bool HasSelectedEdge => SelectedEdge is not null;
    public bool HasNoSelectedEdge => SelectedEdge is null;
    public ControlEdgesSectionViewModel(ObjectSectionDefinition definition, string objectName = "this object") : base(definition)
    {
        ObjectName = string.IsNullOrWhiteSpace(objectName) ? "this object" : objectName;
    }

    public void Configure(bool hasPrincipal, bool selectedIsUser,
        Func<bool, bool, long, Result<ControlEdgePage>> read,
        Func<bool, Result<SelfMembershipAssessmentSet>> readAssessments)
        => ConfigureAsync(hasPrincipal, selectedIsUser,
            (holder, expected, after, _) => Task.FromResult(read(holder, expected, after)),
            (requester, _) => Task.FromResult(readAssessments(requester)));

    /// <summary>Binds protected cancellable callbacks for the selected object section.</summary>
    public void ConfigureAsync(bool hasPrincipal, bool selectedIsUser,
        Func<bool, bool, long, CancellationToken, Task<Result<ControlEdgePage>>> read,
        Func<bool, CancellationToken, Task<Result<SelfMembershipAssessmentSet>>> readAssessments)
    {
        _active = true;
        _configuring = true;
        try
        {
            HasPrincipal = hasPrincipal;
            _selectedIsUser = selectedIsUser;
            _read = read;
            _readAssessments = readAssessments;
            ByHolder = selectedIsUser;
        }
        finally { _configuring = false; }
        FirstPage();
    }
    partial void OnByHolderChanged(bool value)
    {
        EdgeSearchText = "";
        AnnounceDirection();
        if (!_configuring) FirstPage();
    }
    partial void OnIncludeExpectedChanged(bool value)
    {
        if (!_configuring) FirstPage();
    }

    [RelayCommand]
    private void FirstPage()
    {
        _after = 0;
        _generation = null;
        Load();
    }
    [RelayCommand]
    private void NextPage()
    {
        if (HasMore) Load();
    }
    private void Load()
    {
        if (_active) ReadCompletion = LoadAsync();
    }

    /// <summary>Prevents retained commands from reading a section that is no longer visible.</summary>
    public void Suspend()
    {
        _active = false;
        CancelRead();
    }

    /// <summary>Invalidates all pending and displayed answers when the section is left.</summary>
    public void CancelRead()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        CancelMemberReads();
        ClearContent();
    }

    private void ClearContent()
    {
        Rows = [];
        SelectedEdge = null;
        ThroughMembership = [];
        HasMoreThroughMembership = false;
        HasMore = false;
        SelectedRequesterAssessment = null;
        RequesterAssessments = [];
        RequesterCoverage = "Requester assessments have not been read.";
        Coverage = "Control edges have not been read.";
        Counts = "Expected edges hidden: unknown (product not read).";
        HasCoverageWarning = false;
        AnalysisSummary = "Not read";
        CaptureSummary = "Capture unknown";
        UnexpectedSummary = "Unexpected unknown";
        UnknownSummary = "Unknown unresolved";
        ExpectedSummary = "Expected unknown";
        ThroughMembershipCoverage = MemberAttributionPanelViewModel.Text("SelectPermission");
    }

    private async Task LoadAsync()
    {
        CancelRead();
        if (_read is null) return;
        var revision = _revision;
        var pending = new CancellationTokenSource();
        _pending = pending;
        Coverage = NavigationText.Get("SavedLoading");
        Counts = RequesterCoverage = ThroughMembershipCoverage = "";
        try
        {
            var result = await _read(ByHolder, IncludeExpected, _after, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested) return;
            if (result.IsSuccess && !AcceptGeneration(result.Value)) return;
            Result<SelfMembershipAssessmentSet>? assessments = null;
            if (result.IsSuccess && _readAssessments is not null && ByHolder == _selectedIsUser)
                assessments = await _readAssessments(ByHolder, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested) return;
            ApplyPage(result, assessments);
            await MembershipReadCompletion;
            await MemberReadCompletion;
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested)
            {
                ClearContent();
                Coverage = NavigationText.Get("Refused") + " " + error.Message;
                Counts = RequesterCoverage = ThroughMembershipCoverage = "";
            }
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            pending.Dispose();
        }
    }

    private void ApplyPage(Result<ControlEdgePage> result, Result<SelfMembershipAssessmentSet>? assessments)
    {
        if (!result.IsSuccess)
        {
            Coverage = result.Error.Description;
            Counts = "Expected edges hidden: unknown (product unreadable).";
            RequesterCoverage = "Requester assessments were not read because control edges could not be read.";
            HasCoverageWarning = true;
            AnalysisSummary = "Unreadable";
            CaptureSummary = "Capture unknown";
            UnexpectedSummary = "Unexpected unknown";
            UnknownSummary = "Unknown unresolved";
            ExpectedSummary = "Expected unknown";
            return;
        }
        var page = result.Value;
        if (!ApplyRequesterAssessments(page.GenerationId, assessments)) return;
        _generation = page.GenerationId;
        Coverage = !page.ProductWasDerived ? "Control edges were not derived for this selection; re-judge the bundle."
            : $"Capture coverage: {(page.CaptureIsComplete ? "all declared domains read" : "incomplete")}. "
                + $"Objects with unanswered supported rights: {page.UnansweredObjects}. "
                + (ByHolder ? "Unanswered-object count covers the whole capture because unread ACLs may name this principal. " : "")
                + "This is a named-trustee view, not an expansion of rights inherited through group membership. "
                + "Counts include unknown candidates; expectedness is not proof that a capability is established.";

        // WITHOUT THIS SENTENCE THE COUNTS READ AS FOREST-WIDE TOTALS. Under decision 0116 a judgement
        // written by the gated pipeline counts the objects discovery reached, not everything captured,
        // and the two are indistinguishable on screen. Shown only where the stored generation actually
        // is scoped, because saying it of a forest-wide product would understate real coverage.
        if (page.ProductWasDerived && page.IsScopedToDiscovery)
            Coverage += Environment.NewLine + ControlEdgeRowViewModel.Text("DiscoveryScope");
        if (page.OwnershipCoverage is { } ownershipCoverage) Coverage += Environment.NewLine + ownershipCoverage.Description;
        HasCoverageWarning = !page.ProductWasDerived || !page.CaptureIsComplete || page.UnansweredObjects != 0
            || page.IsScopedToDiscovery || page.OwnershipCoverage is { } ownership
            && (!ownership.InputsAvailable || ownership.Execution != OwnershipAssessmentExecution.Completed
                || !ownership.ScopeCoverage.IsComplete);
        Counts = page.ProductWasDerived
            ? $"{page.UnexpectedCount} unexpected; {page.UnknownCount} expectedness unknown; {page.ExpectedCount} expected "
                + (IncludeExpected ? "(shown)." : "(hidden).")
            : "Expected edges hidden: unknown (product not derived).";
        if (page.ProductWasDerived) Counts += " " + ControlEdgeRowViewModel.Text("FullControlCounts");
        AnalysisSummary = page.ProductWasDerived ? "Saved analysis" : "Not derived";
        CaptureSummary = page.CaptureIsComplete ? "Capture complete" : "Capture incomplete";
        UnexpectedSummary = $"{page.UnexpectedCount} unexpected";
        UnknownSummary = $"{page.UnknownCount} unknown";
        ExpectedSummary = $"{page.ExpectedCount} expected " + (IncludeExpected ? "shown" : "hidden");
        Rows = page.Edges.Select(edge => new ControlEdgeRowViewModel(edge, page.FullControlSupports.ContainsKey(edge.Id)))
            .Concat(page.FullControlAssessments.Select(value => new ControlEdgeRowViewModel(value)))
            .OrderBy(row => row.DisplayOrder).ToArray();
        SelectedEdge = Rows.FirstOrDefault();
        HasMore = page.HasMore;
        _after = page.LastId;
        FirstMembershipPermissionPage();
    }

    private bool AcceptGeneration(ControlEdgePage page)
    {
        if (page.ProductWasDerived && page.GenerationId is null)
        {
            WithholdGeneration("The judgement generation is missing. Return to the first page to read the products again.");
            return false;
        }
        if (_generation is not null && _generation != page.GenerationId
            || page.OwnershipCoverage is { } ownership && ownership.GenerationId != page.GenerationId)
        {
            WithholdGeneration("The judgement changed while paging. Return to the first page to read the new generation.");
            return false;
        }
        return true;
    }

    private bool ApplyRequesterAssessments(Guid? generation, Result<SelfMembershipAssessmentSet>? read)
    {
        if (read is not { } result)
        {
            RequesterCoverage = ByHolder
                ? "Requester assessments are shown when this selected object is the requester."
                : "Requester assessments are shown when this selected object is the target group.";
            return true;
        }
        if (!result.IsSuccess)
        {
            RequesterCoverage = result.Error.Description;
            return true;
        }
        if (result.Value.ProductWasDerived)
        {
            if (generation is null || result.Value.GenerationId is null)
            {
                WithholdGeneration("The judgement generation is missing. Return to the first page to read the products again.");
                return false;
            }
            if (generation != result.Value.GenerationId)
            {
                WithholdGeneration("The judgement changed between reading control edges and requester assessments. Return to the first page to read the same generation.");
                return false;
            }
        }
        RequesterCoverage = !result.Value.ProductWasDerived
            ? "Concrete requester analysis was not derived; re-judge with an explicit requester request."
            : result.Value.Assessments.Count == 0
                ? "No concrete requester request was scheduled for this selection. This is not a refusal result."
                : $"{result.Value.Assessments.Count} stored concrete requester assessment(s). These do not add to holder-edge counts.";
        RequesterAssessments = result.Value.Assessments.Select(value => new SelfMembershipAssessmentRowViewModel(value)).ToArray();
        SelectedRequesterAssessment = RequesterAssessments.FirstOrDefault();
        return true;
    }

    private void WithholdGeneration(string message)
    {
        Coverage = message;
        RequesterCoverage = message;
        Counts = "Counts withheld: judgement generations could not be matched.";
        HasCoverageWarning = true;
        AnalysisSummary = "Results withheld";
        CaptureSummary = "Generation mismatch";
        UnexpectedSummary = "Unexpected withheld";
        UnknownSummary = "Unknown withheld";
        ExpectedSummary = "Expected withheld";
    }

    partial void OnRowsChanged(IReadOnlyList<ControlEdgeRowViewModel> value) => AnnounceRows();
    partial void OnEdgeSearchTextChanged(string value) => AnnounceRows();
    partial void OnDetailViewChanged(ControlEdgeDetailView value)
    {
        OnPropertyChanged(nameof(ShowsEvidenceDetails));
        OnPropertyChanged(nameof(ShowsRequesterDetails));
        OnPropertyChanged(nameof(ShowsMembershipDetails));
    }

    private bool Contains(string value) => value.Contains(EdgeSearchText.Trim(), StringComparison.OrdinalIgnoreCase);

    private void AnnounceDirection()
    {
        OnPropertyChanged(nameof(ShowsEdgesOnObject));
        OnPropertyChanged(nameof(ShowsEdgesHeldByObject));
        OnPropertyChanged(nameof(ShowsHolderColumn));
        OnPropertyChanged(nameof(ShowsTargetColumn));
    }

    private void AnnounceRows()
    {
        OnPropertyChanged(nameof(VisibleRows));
        OnPropertyChanged(nameof(HasVisibleRows));
        OnPropertyChanged(nameof(HasNoVisibleRows));
    }
}

internal sealed class SelfMembershipAssessmentRowViewModel(SelfMembershipAssessment value)
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.RequesterPresentation",
        typeof(SelfMembershipAssessmentRowViewModel).Assembly);

    public string EvidenceHeader => Text("EvidenceHeader");
    public string Requester => value.Request.RequesterDn;
    public string Target => value.Request.TargetDn;
    public string Operation => Text(value.Request.Operation switch
    {
        SelfMembershipOperation.Add => "OperationAdd",
        SelfMembershipOperation.Remove => "OperationRemove",
        _ => "OperationUnknown",
    });
    public string Authorization => State("Authorization", value.Authorization);
    public string OwnAccount => State("OwnAccount", value.OwnAccount);
    public string Readiness => State("Readiness", value.Readiness);
    public string Limits => value.Issues.Count == 0 ? Text("NoIssues")
        : string.Join(" ", value.Issues.Select(issue => Explanation("Issue", issue)));
    public string Evidence => string.Join("\n\n",
        Text("Answer", Operation, Authorization, OwnAccount, Readiness),
        Text("Identities", Requester, Recorded(value.RequesterGuid), Recorded(value.RequesterSid),
            Target, Recorded(value.TargetGuid), Recorded(value.TargetSid), value.Request.MemberDn ?? Requester,
            Recorded(value.MemberGuid), Recorded(value.MemberSid)),
        Text("Provenance", value.GenerationId, Recorded(value.DerivationGenerationId), value.EvidenceSeal,
            Recorded(value.RequesterCapturedUtc), Recorded(value.UserAccountControl),
            Text(value.MemberPresent switch { true => "MemberPresent", false => "MemberAbsent", null => "MemberUnknown" }),
            value.DescriptorOutcome),
        Text("Limitations", Limits),
        Text("Context"),
        Text("HolderEdges", value.HolderEdgeIds.Count == 0 ? Text("NoneRecorded") : string.Join(", ", value.HolderEdgeIds)),
        value.Evidence.Count == 0 ? Text("NoEntries") : string.Join("\n\n", value.Evidence.Select(PermissionEvidence)));

    private static string PermissionEvidence(SelfMembershipAceEvidence evidence)
    {
        var entry = evidence.Entry;
        var trustee = evidence.Trustee;
        return Text("PermissionEntry", entry.Ordinal, entry.AceType, entry.Trustee.Sid, entry.AccessMask,
            Text(entry.IsInherited ? "Yes" : "No"), entry.InheritanceFlags, entry.PropagationFlags,
            Text(entry.HasObjectType ? "Yes" : "No"), Recorded(entry.ObjectTypeGuid),
            Text(entry.HasInheritedObjectType ? "Yes" : "No"), Recorded(entry.InheritedObjectTypeGuid),
            entry.ApplicationData.Length == 0 ? Text("NoneRecorded") : Convert.ToHexString(entry.ApplicationData),
            State("Scope", evidence.Scope), Explanation("Trustee", trustee.State), Explanation("Reason", trustee.Reason),
            Recorded(trustee.HolderDn), Recorded(trustee.HolderGuid), Recorded(trustee.HolderDomain),
            Recorded(trustee.GroupType), Recorded(trustee.CapturedUtc), Recorded(trustee.DirectMemberDn));
    }

    private static string State(string prefix, ControlEvaluationState state) => Text(prefix + (state switch
    {
        ControlEvaluationState.Established => "Established",
        ControlEvaluationState.NotEstablished => "NotEstablished",
        _ => "Unknown",
    }));

    private static string Explanation<T>(string prefix, T value) where T : struct, Enum =>
        Resources.GetString(prefix + value, CultureInfo.CurrentUICulture) ?? Text(prefix + "Unknown", value);

    private static string Recorded(object? value) => value switch
    {
        null => Text("NotRecorded"),
        DateTimeOffset time => time.ToString("O", CultureInfo.InvariantCulture),
        IFormattable formatted => formatted.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? Text("NotRecorded"),
    };

    private static string Text(string key, params object?[] arguments)
    {
        var format = Resources.GetString(key, CultureInfo.CurrentUICulture)
            ?? throw new MissingManifestResourceException(key);
        return arguments.Length == 0 ? format : string.Format(CultureInfo.CurrentCulture, format, arguments);
    }
}

/// <summary>A stored statement and its proof; compound support is labelled and never added to the counted total.</summary>
internal sealed class ControlEdgeRowViewModel
{
    private static readonly ResourceManager Presentation = new("SecureAD.Shell.Resources.ControlEdgePresentation", typeof(ControlEdgeRowViewModel).Assembly);
    private readonly ControlEdge? _edge;
    private readonly FullControlAssessment? _summary;
    private readonly bool _included;
    private ControlEdge edge => _edge ?? throw new InvalidOperationException();

    /// <summary>Shows a primitive without changing its stored counting or authorization proof.</summary>
    public ControlEdgeRowViewModel(ControlEdge value, bool included = false) { _edge = value; _included = included; }
    /// <summary>Shows a stored full-control assessment without recomputing rights in the screen.</summary>
    public ControlEdgeRowViewModel(FullControlAssessment value) { _summary = value; }
    public long DisplayOrder => _summary is { } value ? value.Id * 2 - 1 : edge.Id * 2;
    public string HolderSid => _summary?.Source.Holder.Sid ?? edge.HolderSid;
    public string? HolderScope => _summary is { } value ? value.Source.HolderScope : edge.HolderScope;
    public string CountStatus => _summary is { } value ? Text(value.IsCounted ? "CountedOnce" : "NotCounted")
        : Text(_included ? "FullControlIncluded" : edge.IsCounted ? "CountedOnce" : "NotCounted");
    public string Holder => _summary is { } value ? value.Source.Holder.Name ?? value.Source.Holder.Sid : (edge.HolderName ?? edge.HolderSid)
        + (edge.EdgeClass == ControlEdgeClass.ReplicationControl && edge.HolderDomainControllerAsset == ControlEvaluationState.Established
            ? " — " + Text("DomainControllerAsset") : "");
    public string Group => _summary is not null ? "" : edge.EdgeClass == ControlEdgeClass.ReplicationControl
        ? string.Format(CultureInfo.CurrentCulture, Text("ReplicationGroup"), Holder, edge.HolderSid, DisplayedHolderScope, edge.Target)
        : "";

    /// <summary>
    /// The holder's scope as the row should show it, marked where the stored value is a stamp
    /// rather than an answer.
    /// </summary>
    /// <remarks>
    /// <b>A domain beside a per-domain SID reads as a conclusion.</b> Capture stamps every
    /// configuration and schema object with the forest root, because those objects belong to no
    /// domain and something has to be recorded. Printing that plainly next to
    /// <c>S-1-5-32-544</c> tells an operator the product resolved which domain's Administrators
    /// this entry means, when <see cref="ScopeCannotBeSettled"/> says nothing can. The value is
    /// kept, because hiding it would lose evidence, and marked, because showing it bare states
    /// something untrue.
    /// </remarks>
    private string DisplayedHolderScope => ScopeCannotBeSettled(edge)
        ? string.Format(CultureInfo.CurrentCulture, Text("HolderScopeNotVerified"), edge.HolderScope ?? "SID-scoped")
        : edge.HolderScope ?? "SID-scoped";
    /// <summary>
    /// Whether this row's holder scope is a question Active Directory itself leaves open, rather
    /// than something the capture failed to answer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A BUILTIN group exists once per domain and every one of them carries the same SID.</b>
    /// Microsoft's group-scope table gives a domain local group's reach as <i>within the same
    /// domain</i>, and the access-check description says the token built at the resource adds the
    /// SIDs of domain local groups <i>in the target domain</i>. So an entry naming
    /// <c>S-1-5-32-544</c> grants to the Administrators of whichever domain owns the resource.
    /// </para>
    /// <para>
    /// <b>A forest-wide partition owns no domain, which is what makes this unanswerable.</b> The
    /// configuration and schema naming contexts are replicated to every controller in every domain,
    /// so the target domain the rule turns on is a property of the controller serving the request
    /// and not of the object. No capture setting reaches it. Recorded under <c>0120</c>.
    /// </para>
    /// <para>
    /// <b>The uncertainty flag alone is not the condition, and that matters.</b> Fourteen edges in
    /// the laboratory run carry <c>ResourceContextUnverified</c> and only four are this case; the
    /// rest are <c>UnknownCapabilityScope</c>, a different open question. Attaching this
    /// explanation to all of them would answer ten rows with a reason that does not describe them,
    /// which is worse than leaving them unexplained.
    /// </para>
    /// </remarks>
    private static bool ScopeCannotBeSettled(ControlEdge edge) =>
        (edge.Uncertainty & ControlUncertainty.ResourceContextUnverified) != 0
        && Sid.IsBuiltinDomain(edge.HolderSid);

    public string Target => _summary?.Source.Target ?? edge.Target;
    public string Capability => _summary is not null ? Text("FullControlLabel") : CapabilityText(edge.Capability);
    internal static string CapabilityText(ControlCapability capability) => capability switch
    {
        ControlCapability.CanWriteDacl => "Can change permissions (WRITE_DAC)",
        ControlCapability.CanSetOwner => "Holds WRITE_OWNER — takeover not proven",
        ControlCapability.CanBecomeOwnerAndRewriteDacl => Text("OwnerTransitionLabel"),
        ControlCapability.IsOwnerAndCanRewriteDacl => Text("ExistingOwnerLabel"),
        ControlCapability.CanModifyGroupMembership => "General group-membership changes — no own-account restriction",
        ControlCapability.CanAddSelfToGroup => "Self-Membership candidate — own account only; requester not verified",
        ControlCapability.CanResetPassword => Text("PasswordResetLabel"),
        ControlCapability.CanWriteKeyCredentialLink => Text("KeyCredentialLinkLabel"),
        ControlCapability.CanReplicateSecretDomainData => Text("ReplicationSecretLabel"),
        ControlCapability.CanReplicateFilteredAttributes => Text("ReplicationFilteredLabel"),
        _ => "Unsupported capability",
    };
    public string Evaluation => (_summary?.EvaluationState ?? edge.EvaluationState).ToString();
    public string Expectedness => (_summary?.Expectedness ?? edge.Expectedness).ToString();
    public string Evidence => _summary is { } value ? SummaryEvidence(value) : $"Holder: {edge.HolderSid}; scope: {edge.HolderScope ?? "SID-scoped"}\n"
        + $"Object: {edge.TargetGuid?.ToString() ?? "stable identity not captured"}\n"
        + (edge.Capability == ControlCapability.CanWriteKeyCredentialLink ? Text("KeyCredentialLinkAttribute") + "\n" : "")
        + (edge.EdgeClass == ControlEdgeClass.ReplicationControl
            ? string.Format(CultureInfo.CurrentCulture, Text("ReplicationScope"), edge.Target, edge.ReplicationNamingContextKind) + "\n"
                + Text("ReplicationCategory") + "\n"
                + (ScopeCannotBeSettled(edge) ? Text("DomainLocalScopeOnForestPartition") + "\n" : "")
                + (edge.HolderDomainControllerAsset == ControlEvaluationState.Established ? Text("DomainControllerAsset") + "\n"
                    : edge.HolderDomainControllerAsset == ControlEvaluationState.Unknown ? Text("DomainControllerUnknown") + "\n" : "")
            : edge.Capability is ControlCapability.IsOwnerAndCanRewriteDacl or ControlCapability.CanBecomeOwnerAndRewriteDacl ? Text("OwnershipCategory") + "\n"
            : edge.EdgeClass == ControlEdgeClass.CredentialExposure ? Text("CredentialExposureCategory") + "\n"
            : $"Category: {edge.EdgeClass}; this does not classify the target group as privileged.\n")
        + $"Evaluation: {edge.EvaluationState}; feasibility: {edge.Feasibility}; research: {edge.ResearchStatus}; counted: {edge.IsCounted && !_included}\n"
        + CountStatus + "\n"
        + $"Expectedness: {edge.ExpectednessReason}; principal catalogue {edge.PrincipalCatalogueVersion}\n"
        + $"Generation: {edge.GenerationId}; derivation: {edge.DerivationGenerationId?.ToString() ?? "not used"}\n"
        + $"Uncertainty: {edge.Uncertainty}\n"
        + $"Descriptor outcome: {edge.DescriptorOutcome}\n"
        + string.Join("\n", edge.Evidence.Select(ace => $"ACE {ace.Ordinal}: {ace.AceType}; {ace.Trustee.Sid}; mask 0x{ace.AccessMask:X8}; "
            + $"inherited={ace.IsInherited}; inheritance=0x{ace.InheritanceFlags:X2}; propagation=0x{ace.PropagationFlags:X2}; "
            + $"object type={ace.ObjectTypeGuid ?? "all"}; inherited class={ace.InheritedObjectTypeGuid ?? "all"}; "
            + $"application data={Convert.ToHexString(ace.ApplicationData)}"))
        + "\n" + string.Join("\n", edge.Preconditions.Select(condition => $"{condition.Name}: {condition.State} — {condition.EvidenceSource}"))
        + "\n" + edge.MembershipRoutes.CompletenessDescription
        + "\n" + string.Join("\n", edge.MembershipRoutes.Memberships.SelectMany(group => group.Routes)
            .Select(route => $"{route.Authorization}: " + string.Join(" -> ", route.Steps.Select(step =>
                $"{step.Principal.DistinguishedName ?? step.Principal.Sid} [{step.Principal.Sid}; {step.Principal.Scope ?? "SID-scoped"}]"
                + (step.IsPrimaryGroup ? " (primary membership)" : "")))))
        + "\nSupporting membership chains are representative, not proof that every route can be removed."
        + (edge.Capability switch
        {
            ControlCapability.CanResetPassword => "\n" + Text("PasswordResetCaveat"),
            ControlCapability.CanWriteKeyCredentialLink => "\n" + Text("KeyCredentialLinkCaveat"),
            ControlCapability.CanReplicateSecretDomainData or ControlCapability.CanReplicateFilteredAttributes => "\n" + Text("ReplicationCaveat"),
            ControlCapability.IsOwnerAndCanRewriteDacl or ControlCapability.CanBecomeOwnerAndRewriteDacl => "\n" + Text("OwnershipCaveat"),
            _ => "",
        });

    private static string SummaryEvidence(FullControlAssessment value) => Text(value.EvaluationState switch
        {
            ControlEvaluationState.Established => "FullControlEstablished",
            ControlEvaluationState.NotEstablished => "FullControlNotEstablished",
            _ => "FullControlUnknown",
        }) + "\n" + Text("FullControlEvidenceHeading") + "\n"
        + string.Format(CultureInfo.CurrentCulture, Text("FullControlProofHeader"), value.GenerationId,
            value.DerivationGenerationId?.ToString() ?? Text("NotUsed"), value.PrincipalCatalogueVersion,
            value.ExpectednessReason, value.Uncertainty)
        + "\n" + string.Join("\n", value.Rights.Select(right => string.Format(CultureInfo.CurrentCulture,
            Text("FullControlRightProof"), right.Mask, right.ObjectType ?? Text("WholeObject"), right.State,
            string.Join(", ", right.GrantOrdinals), string.Join(", ", right.BlockingOrdinals))))
        + "\n" + Text("FullControlAlternativeProof")
        + (value.HasIndependentGrantRoutes ? "\n" + Text("FullControlIndependentRoutes") : "")
        + "\n" + System.Text.Json.JsonSerializer.Serialize(value.Source, new System.Text.Json.JsonSerializerOptions { WriteIndented = true })
        + "\n" + Text("FullControlCaveat");

    internal static string Text(string key) => Presentation.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
}

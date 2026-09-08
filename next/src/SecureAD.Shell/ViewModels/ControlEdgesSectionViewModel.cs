using System.Globalization;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

/// <summary>Two paged views over the same persisted edge product, never an authorization calculation in the screen.</summary>
internal sealed partial class ControlEdgesSectionViewModel : ObjectSectionViewModel
{
    private Func<bool, bool, long, Result<ControlEdgePage>>? _read;
    private Func<bool, Result<SelfMembershipAssessmentSet>>? _readAssessments;
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
    public ControlEdgesSectionViewModel(ObjectSectionDefinition definition) : base(definition) { }

    public void Configure(bool hasPrincipal, bool selectedIsUser,
        Func<bool, bool, long, Result<ControlEdgePage>> read,
        Func<bool, Result<SelfMembershipAssessmentSet>> readAssessments)
    {
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
        if (_read is null) return;
        var result = _read(ByHolder, IncludeExpected, _after);
        if (!result.IsSuccess)
        {
            Coverage = result.Error.Description;
            Counts = "Expected edges hidden: unknown (product unreadable).";
            RequesterCoverage = "Requester assessments were not read because control edges could not be read.";
            return;
        }
        var page = result.Value;
        if (page.ProductWasDerived && page.GenerationId is null)
        {
            WithholdGeneration("The judgement generation is missing. Return to the first page to read the products again.");
            return;
        }
        if (_generation is not null && _generation != page.GenerationId)
        {
            WithholdGeneration("The judgement changed while paging. Return to the first page to read the new generation.");
            return;
        }
        if (!LoadRequesterAssessments(page.GenerationId)) return;
        _generation = page.GenerationId;
        Coverage = !page.ProductWasDerived ? "Control edges were not derived for this selection; re-judge the bundle."
            : $"Capture coverage: {(page.CaptureIsComplete ? "all declared domains read" : "incomplete")}. "
                + $"Objects with unanswered supported rights: {page.UnansweredObjects}. "
                + (ByHolder ? "Unanswered-object count covers the whole capture because unread ACLs may name this principal. " : "")
                + "This is a named-trustee view, not an expansion of rights inherited through group membership. "
                + "Counts include unknown candidates; expectedness is not proof that a capability is established.";
        Counts = page.ProductWasDerived
            ? $"{page.UnexpectedCount} unexpected; {page.UnknownCount} expectedness unknown; {page.ExpectedCount} expected "
                + (IncludeExpected ? "(shown)." : "(hidden).")
            : "Expected edges hidden: unknown (product not derived).";
        if (page.ProductWasDerived) Counts += " " + ControlEdgeRowViewModel.Text("FullControlCounts");
        Rows = page.Edges.Select(edge => new ControlEdgeRowViewModel(edge, page.FullControlSupports.ContainsKey(edge.Id)))
            .Concat(page.FullControlAssessments.Select(value => new ControlEdgeRowViewModel(value)))
            .OrderBy(row => row.DisplayOrder).ToArray();
        SelectedEdge = Rows.FirstOrDefault();
        HasMore = page.HasMore;
        _after = page.LastId;
        FirstMembershipPermissionPage();
    }

    private bool LoadRequesterAssessments(Guid? generation)
    {
        if (_readAssessments is null || ByHolder != _selectedIsUser)
        {
            RequesterCoverage = ByHolder
                ? "Requester assessments are shown when this selected object is the requester."
                : "Requester assessments are shown when this selected object is the target group.";
            return true;
        }
        var result = _readAssessments(ByHolder);
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
        ? string.Format(CultureInfo.CurrentCulture, Text("ReplicationGroup"), Holder, edge.HolderSid, edge.HolderScope ?? "SID-scoped", edge.Target)
        : "";
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

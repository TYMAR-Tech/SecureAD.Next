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

    public string RequesterCoverage { get => _requesterCoverage; private set => SetProperty(ref _requesterCoverage, value); }
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
        HasMore = false;
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
        Rows = page.Edges.Select(edge => new ControlEdgeRowViewModel(edge)).ToArray();
        SelectedEdge = Rows.FirstOrDefault();
        HasMore = page.HasMore;
        _after = page.LastId;
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
    public string Requester => value.Request.RequesterDn;
    public string Target => value.Request.TargetDn;
    public string Operation => value.Request.Operation.ToString();
    public string Authorization => value.Authorization.ToString();
    public string OwnAccount => value.OwnAccount.ToString();
    public string Readiness => value.Readiness.ToString();
    public string Limits => string.Join(", ", value.Issues) + ". " + SelfMembershipAssessment.Context;
}

/// <summary>A stored statement and its proof; compound support is labelled and never added to the counted total.</summary>
internal sealed class ControlEdgeRowViewModel(ControlEdge edge)
{
    public string Holder => edge.HolderName ?? edge.HolderSid;
    public string Target => edge.Target;
    public string Capability => edge.Capability switch
    {
        ControlCapability.CanWriteDacl => "Can change permissions (WRITE_DAC)",
        ControlCapability.CanSetOwner => "Holds WRITE_OWNER — takeover not proven",
        ControlCapability.CanBecomeOwnerAndRewriteDacl => "Owner-to-DACL takeover — supporting compound, not counted",
        ControlCapability.CanModifyGroupMembership => "General group-membership changes — no own-account restriction",
        ControlCapability.CanAddSelfToGroup => "Self-Membership candidate — own account only; requester not verified",
        _ => "Unsupported capability",
    };
    public string Evaluation => edge.EvaluationState.ToString();
    public string Expectedness => edge.Expectedness.ToString();
    public string Evidence => $"Holder: {edge.HolderSid}; scope: {edge.HolderScope ?? "SID-scoped"}\n"
        + $"Object: {edge.TargetGuid?.ToString() ?? "stable identity not captured"}\n"
        + $"Category: {edge.EdgeClass}; this does not classify the target group as privileged.\n"
        + $"Evaluation: {edge.EvaluationState}; feasibility: {edge.Feasibility}; research: {edge.ResearchStatus}; counted: {edge.IsCounted}\n"
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
        + "\nSupporting membership chains are representative, not proof that every route can be removed.";
}

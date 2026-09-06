using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

/// <summary>Two paged views over the same persisted edge product, never an authorization calculation in the screen.</summary>
internal sealed partial class ControlEdgesSectionViewModel : ObjectSectionViewModel
{
    private Func<bool, bool, long, Result<ControlEdgePage>>? _read;
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

    public string SupportedScope => ControlEdgePage.SupportedScope;
    public ControlEdgesSectionViewModel(ObjectSectionDefinition definition) : base(definition) { }

    public void Configure(bool hasPrincipal, Func<bool, bool, long, Result<ControlEdgePage>> read)
    {
        HasPrincipal = hasPrincipal;
        _read = read;
        FirstPage();
    }
    partial void OnByHolderChanged(bool value) => FirstPage();
    partial void OnIncludeExpectedChanged(bool value) => FirstPage();

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
        if (_read is null) return;
        var result = _read(ByHolder, IncludeExpected, _after);
        if (!result.IsSuccess)
        {
            Coverage = result.Error.Description;
            Counts = "Expected edges hidden: unknown (product unreadable).";
            return;
        }
        var page = result.Value;
        if (_generation is not null && _generation != page.GenerationId)
        {
            Coverage = "The judgement changed while paging. Return to the first page to read the new generation.";
            Counts = "Counts withheld: generation changed.";
            return;
        }
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

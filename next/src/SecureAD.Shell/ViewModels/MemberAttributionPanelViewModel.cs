using System.Globalization;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Derivation;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class MemberAttributionPanelViewModel : ObservableObject
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.MemberAttributionPresentation", typeof(MemberAttributionPanelViewModel).Assembly);
    private MemberAttributionDetail? _detail;
    private int _offset;
    private Func<bool>? _isCurrent;
    [ObservableProperty] private string _status = Text("SelectPermission");
    [ObservableProperty] private string _evidence = "";
    [ObservableProperty] private IReadOnlyList<MemberAttributionRowViewModel> _rows = [];
    [ObservableProperty] private MemberAttributionRowViewModel? _selectedRow;
    [ObservableProperty] private bool _hasMore;
    [ObservableProperty] private string _showing = "";
    public string Heading => Text("Heading");
    public string Counting => Text("Counting");
    public string Caveat => Text("Caveat");
    public string RoutesHeading => Text("RoutesHeading");
    public string RoutesCaveat => Text("RoutesCaveat");
    public string FirstPageLabel => Text("FirstPage");
    public string NextPageLabel => Text("NextPage");
    public string MemberHeader => Text("Member");
    public string IdentityHeader => Text("IdentityStatus");
    public string RouteHeader => Text("MembershipRoute");
    public string ApplicabilityHeader => Text("ResourceApplicability");
    public string AccountHeader => Text("AccountStatus");

    /// <summary>Withholds prior support while the selected permission's saved support is read.</summary>
    public void ShowLoading()
    {
        Clear();
        Status = NavigationText.Get("SavedLoading");
    }

    /// <summary>States the read failure rather than displaying an empty membership result.</summary>
    public void ShowRefusal(string reason)
    {
        Clear();
        Status = NavigationText.Get("Refused") + " " + reason;
    }

    public void Clear()
    {
        _detail = null;
        _isCurrent = null;
        Rows = [];
        SelectedRow = null;
        HasMore = false;
        Evidence = Showing = "";
        Status = Text("SelectPermission");
    }

    public void Show(Result<MemberAttributionDetail> result, Guid? generation, Func<bool> isCurrent)
    {
        ArgumentNullException.ThrowIfNull(isCurrent);
        Clear();
        _isCurrent = isCurrent;
        if (!result.IsSuccess) { Status = Text("InvalidEvidence") + " " + result.Error.Description; return; }
        if (generation is null || result.Value.GenerationId != generation) { Status = Text("InvalidEvidence"); return; }
        _detail = result.Value;
        if (!_detail.WasRun) { Status = Text("NotRun"); return; }
        if (_detail.Expansion is not { } value) { Status = Text("NoGroup"); return; }
        Status = value.IsComplete ? value.ResolvedMemberCount == 0 ? Text("Empty") : Text("Complete", value.ResolvedMemberCount)
            : Text("Partial", value.ResolvedMemberCount, value.UnresolvedMemberCount, value.UnconfirmedMemberCount);
        if (value.Stop is not (MemberAttributionStop.None or MemberAttributionStop.NotRun))
            Status += " " + Text("BudgetStop", Text(value.Stop.ToString()));
        if (value.Stop != MemberAttributionStop.None && value.Members.Count == 0 && value.ProcessingPosition is null)
            Status = Text("NotStarted") + " " + Status;
        if (value.Limitations.Count > 0) Status += " " + Text("Missing", string.Join("; ", value.Limitations));
        if (_detail.ResourceMembers.Any(member => member.State == MemberAttributionState.Unknown))
            Status += " " + Text("UnknownApplicability", string.Join("; ", _detail.ResourceMembers.Where(member => member.State == MemberAttributionState.Unknown).Select(member => member.Reason).Distinct()));
        Evidence = Text("Evidence", value.Budget, value.Stop, value.VisitedNodes, value.TraversedLinks, value.StoredRecords,
            value.Elapsed, value.ProcessingPosition, value.GenerationId, value.DerivationGenerationId);
        FirstPage();
    }

    [RelayCommand] private void FirstPage() { _offset = 0; LoadPage(); }
    [RelayCommand] private void NextPage() { if (HasMore) { _offset += 100; LoadPage(); } }
    private void LoadPage()
    {
        if (_isCurrent?.Invoke() == false)
        {
            ShowRefusal(SavedPathText.Get("GenerationChanged"));
            return;
        }
        if (_detail?.Expansion is not { } expansion) return;
        var applicability = _detail.ResourceMembers.ToDictionary(item => item.Member, StringComparer.OrdinalIgnoreCase);
        var routes = expansion.Routes.GroupBy(route => route.Member, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        Rows = expansion.Members.Skip(_offset).Take(100).Select(member => new MemberAttributionRowViewModel(member,
            applicability[member.Identity], expansion, routes.GetValueOrDefault(member.Identity) ?? [])).ToArray();
        HasMore = _offset + Rows.Count < expansion.Members.Count;
        Showing = Text("Showing", Rows.Count);
        SelectedRow = Rows.FirstOrDefault();
    }

    internal static string Text(string key, params object?[] values)
    {
        var format = Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key);
        return values.Length == 0 ? format : string.Format(CultureInfo.CurrentCulture, format, values);
    }
}

internal sealed class MemberAttributionRowViewModel(MemberAttributionMember member, MemberResourceApplicability resource,
    MemberAttribution expansion, IReadOnlyList<MemberAttributionRoute> routes)
{
    public string Member => member.Source?.Find("sAMAccountName")?.OnlyValue?.Text ?? member.Identity;
    public string IdentityStatus => MemberAttributionPanelViewModel.Text(member.IsResolved ? "Resolved" : "Unresolved");
    public string AccountStatus => MemberAttributionPanelViewModel.Text(member.IsDeleted ? "Deleted"
        : member.Source is { } source && RequesterTrusteeReading.Number(source, "userAccountControl") is { } flags && (flags & 2) != 0 ? "Disabled" : "AccountUnknown");
    public string Applicability => MemberAttributionPanelViewModel.Text(resource.State switch
    {
        MemberAttributionState.Established => "Applicable",
        MemberAttributionState.NotEstablished => "NotApplicable",
        _ => "UnknownApplicability",
    }, resource.Reason);
    public string Routes => string.Join("\n", routes.Select(route =>
    {
        var chain = new List<string>();
        for (MemberAttributionRoute? current = route; current is not null;
             current = current.ParentRouteId is { } parent ? expansion.Routes[parent] : null)
        {
            var link = expansion.Links[current.LinkIndex];
            chain.Add(current.Member + (link.Attribute == "primaryGroupID" ? " [" + MemberAttributionPanelViewModel.Text("Primary") + "]" : ""));
        }
        chain.Add(expansion.Holder?.DistinguishedName ?? expansion.HolderSid);
        chain.Reverse();
        return string.Join(" -> ", chain);
    }));
}

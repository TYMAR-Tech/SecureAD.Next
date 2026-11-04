using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Naming;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One object opened from the listing: a header, and the sections its class has.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a host, not a screen.</b> It holds an ordered list of sections and which one is being
/// read, and nothing else. The predecessor's equivalent is one 1,311-line window holding sixteen
/// sections and their logic together, which is why adding to it is expensive; here a section is a
/// type and a control, and the seventeenth costs what the first did.
/// </para>
/// <para>
/// <b>Which sections exist is decided by the object's class</b>, in
/// <see cref="ObjectSectionCatalog"/> and for the reasons recorded there. A section this build
/// cannot yet fill is present and says so, rather than being left out - an object missing a section
/// looks completely described when it is not.
/// </para>
/// <para>
/// <b>This is a reading tool and not a verdict.</b> The owner's framing, 2026-08-18: the findings
/// are the point of the product, and since the permissions were captured anyway it is a good
/// secondary use of the tool to help an administrator understand what is on an object.
/// </para>
/// </remarks>
internal sealed partial class ObjectViewModel : ObservableObject
{
    private readonly Func<ObjectSectionDefinition, CancellationToken, Task<ObjectSectionViewModel>> _read;
    private readonly IReadOnlyList<ObjectSectionDefinition> _definitions;
    private CancellationTokenSource? _pending;
    private long _revision;
    private bool _publishing;
    private bool _active = true;
    internal bool ShowShortestTier0Route { get; set; }

    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private Notice? _refusal;

    /// <summary>The selected section read, including its publication.</summary>
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;

    /// <summary>The selected section's content, never a previous section's result.</summary>
    public ObjectSectionViewModel? Content => IsLoading || HasRefusal || !_active ? null : Selected;

    /// <summary>Whether the selected section could not be read.</summary>
    public bool HasRefusal => Refusal is not null;

    /// <summary>The approved loading wording for the selected kind of information.</summary>
    public string LoadingText => NavigationText.Get(Selected?.Key is ObjectSectionCatalog.Findings
        or ObjectSectionCatalog.Permissions or ObjectSectionCatalog.ControlEdges ? "SavedLoading" : "CapturedLoading");

    /// <summary>The section being read.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SelectedKey))]
    private ObjectSectionViewModel? _selected;

    /// <summary>Stable navigation identity while a placeholder is replaced by its read result.</summary>
    public string? SelectedKey
    {
        get => Selected?.Key;
        set
        {
            // A selector briefly clears its value when its selected item is replaced. That is
            // not a request to cancel the read or forget the operator's section choice.
            if (value is not null && value != Selected?.Key) Show(value);
        }
    }

    /// <summary>Creates navigation from captured identity, without preparing any section's content.</summary>
    public ObjectViewModel(
        string distinguishedName,
        string objectType,
        string? objectClass,
        Func<ObjectSectionDefinition, CancellationToken, Task<ObjectSectionViewModel>> read)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        ArgumentException.ThrowIfNullOrWhiteSpace(objectType);
        ArgumentNullException.ThrowIfNull(read);
        DistinguishedName = distinguishedName;
        ObjectType = objectType;
        _read = read;
        _definitions = ObjectSectionCatalog.For(objectClass);
        foreach (var definition in _definitions) Sections.Add(new UnloadedObjectSectionViewModel(definition));
    }

    /// <summary>The object's name.</summary>
    public string Name => DnHelper.ExtractFirstRdn(DistinguishedName);
    public string Heading => $"{Name} ({ObjectTypeLabel})";

    /// <summary>Its full name, for an operator who needs to be certain which object this is.</summary>
    public string DistinguishedName { get; }

    /// <summary>What kind of object it is.</summary>
    public string ObjectType { get; }
    private string ObjectTypeLabel => ObjectType switch
    {
        "domainDNS" => "Domain",
        "organizationalUnit" => "Organizational unit",
        "groupPolicyContainer" => "Group policy",
        "msDS-PasswordSettings" => "Password settings",
        "msWMI-Som" => "WMI filter",
        _ => string.IsNullOrEmpty(ObjectType)
            ? "Object"
            : char.ToUpperInvariant(ObjectType[0]) + ObjectType[1..],
    };
    public Guid? ObjectGuid { get; init; }

    /// <summary>The sections this object's class has, in reading order.</summary>
    public ObservableCollection<ObjectSectionViewModel> Sections { get; } = [];

    /// <summary>
    /// The section with this key, or null when the object's class does not have one.
    /// </summary>
    /// <param name="key">The section's stable name, from <see cref="ObjectSectionCatalog"/>.</param>
    public ObjectSectionViewModel? Section(string key) =>
        Sections.FirstOrDefault(s => s.Key == key);

    /// <summary>
    /// Selects the section with this key, if the object's class has one.
    /// </summary>
    /// <remarks>
    /// <b>A section the class does not have leaves the selection alone.</b> An operator who reached
    /// this object by asking about something lands on the first section instead, which is a whole
    /// object rather than an empty screen. Nothing in the catalogue is optional today, so this is a
    /// guard against a future class list rather than a case that arises.
    /// </remarks>
    /// <param name="key">The section's stable name, from <see cref="ObjectSectionCatalog"/>.</param>
    public void Show(string key)
    {
        if ((Section(key) ?? Sections.FirstOrDefault()) is { } section)
            Selected = section;
    }

    /// <summary>
    /// Builds the view model for one section, or a placeholder saying it is not built.
    /// </summary>
    /// <remarks>
    /// Overview embeds the account wording beside identity because it says something beyond its
    /// values. The sections built from attributes alone share one type, because they are one
    /// behaviour and separate copies would drift.
    /// </remarks>
    internal static ObjectSectionViewModel BuildAttributes(
        ObjectSectionDefinition definition, ObjectAttributes attributes, string? objectClass) =>
        definition.Key switch
        {
            ObjectSectionCatalog.PolicyLinks =>
                new PolicyLinksSectionViewModel(definition, attributes),
            ObjectSectionCatalog.Membership
                or ObjectSectionCatalog.Delegation
                or ObjectSectionCatalog.Group
                or ObjectSectionCatalog.Laps
                or ObjectSectionCatalog.PasswordReaders
                or ObjectSectionCatalog.Policy =>
                new AttributeSectionViewModel(definition, attributes),
            ObjectSectionCatalog.OtherValues =>
                new OtherValuesSectionViewModel(definition, attributes, objectClass),
            _ => new NotBuiltSectionViewModel(definition),
        };

    /// <summary>
    /// Keeps the section list's own selection in step, so a list can bind to it and a section can
    /// be chosen from anywhere.
    /// </summary>
    partial void OnSelectedChanged(
        ObjectSectionViewModel? oldValue, ObjectSectionViewModel? newValue)
    {
        if (_publishing) return;
        StopContent();
        if (oldValue is not null)
        {
            if (oldValue is SavedTier0PathSectionViewModel path) path.CancelRead();
            if (oldValue is ControlEdgesSectionViewModel controls) controls.Suspend();
            if (oldValue is GroupMembershipSectionViewModel members) members.Suspend();
            if (oldValue is FindingsSectionViewModel findings) findings.Suspend();
            oldValue.IsSelected = false;
            var index = Sections.IndexOf(oldValue);
            if (index >= 0) Sections[index] = new UnloadedObjectSectionViewModel(_definitions[index]);
        }

        if (newValue is not null)
        {
            newValue.IsSelected = true;
            if (_active) ReadCompletion = LoadAsync(newValue.Key);
        }
    }

    /// <summary>Suspends the selected section without changing the operator's section choice.</summary>
    public void Suspend()
    {
        _active = false;
        StopContent();
        OnPropertyChanged(nameof(Content));
    }

    /// <summary>Reads the selected section afresh after the protected object lifetime is checked.</summary>
    public void Resume()
    {
        _active = true;
        if (Selected is { } selected) ReadCompletion = LoadAsync(selected.Key);
    }

    private void StopContent()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        if (Selected is SavedTier0PathSectionViewModel path) path.CancelRead();
        if (Selected is ControlEdgesSectionViewModel controls) controls.Suspend();
        if (Selected is GroupMembershipSectionViewModel members) members.Suspend();
        if (Selected is FindingsSectionViewModel findings) findings.Suspend();
        IsLoading = false;
    }

    private async Task LoadAsync(string key)
    {
        StopContent();
        var revision = _revision;
        var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = true;
        Refusal = null;
        AnnounceContent();
        try
        {
            var definition = _definitions.First(item => item.Key == key);
            var content = await _read(definition, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested || !_active) return;
            _publishing = true;
            var index = Sections.IndexOf(Selected!);
            Sections[index] = content;
            Selected = content;
            content.IsSelected = true;
            _publishing = false;
            IsLoading = false;
            AnnounceContent();
            if (content is SavedTier0PathSectionViewModel path)
            {
                path.Read();
                await path.ReadCompletion;
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested && _active)
                Refusal = new Notice(NavigationText.Get("Refused"), error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                IsLoading = false;
                AnnounceContent();
            }
            pending.Dispose();
        }
    }

    private void AnnounceContent()
    {
        OnPropertyChanged(nameof(Content));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(LoadingText));
    }
}

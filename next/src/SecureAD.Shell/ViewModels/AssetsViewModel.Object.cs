using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    private long _objectRevision;
    private CancellationTokenSource? _objectPending;
    [ObservableProperty] private bool _isOpeningObject;
    [ObservableProperty] private Notice? _objectRefusal;
    public Task ObjectReadCompletion { get; private set; } = Task.CompletedTask;
    public bool HasObjectRefusal => ObjectRefusal is not null;
    public bool HasObjectPresentation => IsOpeningObject || Opened is not null || HasObjectRefusal;
    public bool ShowsObjectContent => Opened is not null && !IsOpeningObject && !HasObjectRefusal;
    public string ObjectTitle => Opened is { } value ? value.Name + " - Object details | SecureAD" : "Object details | SecureAD";
    public event EventHandler? LocateObjectRequested;

    partial void OnIsOpeningObjectChanged(bool value) => AnnounceObjectPresentation();
    partial void OnObjectRefusalChanged(Notice? value) => AnnounceObjectPresentation();
    partial void OnOpenedChanged(ObjectViewModel? value) => AnnounceObjectPresentation();

    private void AnnounceObjectPresentation()
    {
        OnPropertyChanged(nameof(HasObjectRefusal));
        OnPropertyChanged(nameof(HasObjectPresentation));
        OnPropertyChanged(nameof(ShowsObjectContent));
        OnPropertyChanged(nameof(ObjectTitle));
        OnPropertyChanged(nameof(HasOpenObject));
    }

    private void CancelObjectRead()
    {
        _objectRevision++;
        var pending = _objectPending;
        _objectPending = null;
        pending?.Cancel();
        Opened?.Suspend();
        IsOpeningObject = false;
    }

    private void ClearObjectPresentation()
    {
        CancelObjectRead();
        Opened = null;
        ObjectRefusal = null;
        _groupObjectBack.Clear();
    }

    private async Task OpenAsync(string bundle, string distinguishedName, string section)
    {
        var revision = _objectRevision;
        var pending = new CancellationTokenSource();
        _objectPending = pending;
        using var navigation = NavigationDiagnostics.Begin(bundle, "open captured object");
        try
        {
            var result = await _assets.ReadAsync(bundle, (reader, token) =>
            {
                token.ThrowIfCancellationRequested();
                var attributes = reader.ReadObjectAttributes(bundle, distinguishedName);
                return (Attributes: attributes, Current: reader.CaptureReadValidity());
            }, pending.Token);
            if (pending.IsCancellationRequested || revision != _objectRevision || BundlePath != bundle) return;
            if (!result.Attributes.IsSuccess) throw new InvalidOperationException(result.Attributes.Error.Description);
            if (!result.Current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            if (result.Attributes.Value is not { } attributes)
            {
                ObjectRefusal = new Notice(NavigationText.Get("Refused"), NavigationText.Get("ObjectMissing"));
                if (section == ObjectSectionCatalog.SavedTier0Path)
                {
                    Tier0ObjectLimitation = "The selected saved analysis identity has no captured object to open. Its unresolved or unassessed result remains in the overview; no object details or route are inferred.";
                }
                navigation.Complete("refused", "object missing");
                return;
            }
            var objectClass = ClassOf(attributes);
            var opened = new ObjectViewModel(distinguishedName, objectClass ?? "not recorded", objectClass,
                (definition, token) => ReadSectionAsync(bundle, attributes, objectClass, definition, result.Current, token))
            {
                ObjectGuid = attributes.ObjectGuid,
            };
            Opened = opened;
            IsOpeningObject = false;
            opened.Show(section);
            navigation.Complete("success", null);
            await opened.ReadCompletion;
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { navigation.Complete("cancelled", null); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _objectRevision && !pending.IsCancellationRequested)
                ObjectRefusal = new Notice(NavigationText.Get("Refused"), error.Message);
            navigation.Complete("refused", error.GetType().Name);
        }
        finally
        {
            if (ReferenceEquals(_objectPending, pending))
            {
                _objectPending = null;
                IsOpeningObject = false;
            }
            pending.Dispose();
        }
    }

    [RelayCommand]
    private void LocateObject()
    {
        if (Opened is not { } opened || BundlePath is null) return;
        LocateObjectRequested?.Invoke(this, EventArgs.Empty);
        Pane = AssetsPane.Objects;
        var parent = SecureAD.Kernel.Naming.DnHelper.GetParentDn(opened.DistinguishedName);
        var node = Roots.SelectMany(root => root.ThisAndBelow()).FirstOrDefault(value =>
            string.Equals(value.DistinguishedName, parent, StringComparison.OrdinalIgnoreCase));
        if (node is not null)
        {
            node.IsSelected = true;
            Selected = node;
        }
        else
        {
            ObjectSearchText = opened.Name;
            SearchObjects();
        }
    }

    private async Task<ObjectSectionViewModel> ReadSectionAsync(string bundle, ObjectAttributes attributes,
        string? objectClass, ObjectSectionDefinition definition, Func<bool> current, CancellationToken token)
    {
        var dn = attributes.DistinguishedName;
        if (definition.Key == ObjectSectionCatalog.Help)
            return new ObjectHelpSectionViewModel(definition);
        if (definition.Key == ObjectSectionCatalog.Membership && string.Equals(objectClass, "group", StringComparison.OrdinalIgnoreCase))
        {
            var members = new GroupMembershipSectionViewModel(definition, attributes,
                (names, cancellation) => ReadBoundAsync(bundle, current,
                    reader => reader.ResolveMembershipReferences(bundle, names), cancellation, "read captured group members"),
                OpenGroupMember, current);
            using var cancellation = token.Register(members.Suspend);
            await members.ReadCompletion;
            token.ThrowIfCancellationRequested();
            return members;
        }
        if (definition.Key == ObjectSectionCatalog.SavedTier0Path)
        {
            var path = new SavedTier0PathSectionViewModel(definition);
            path.ShowShortest = Opened?.ShowShortestTier0Route ?? false;
            path.PropertyChanged += (_, change) =>
            {
                if (change.PropertyName == nameof(SavedTier0PathSectionViewModel.ShowShortest) && Opened is { } currentObject
                    && currentObject.DistinguishedName == dn) currentObject.ShowShortestTier0Route = path.ShowShortest;
            };
            path.ConfigureAsync(dn, (group, after, cancellation) => ReadBoundAsync(bundle, current,
                reader => reader.ReadSavedTier0Path(bundle, dn, group, after), cancellation, "read saved Tier 0 path"));
            return path;
        }
        if (definition.Key == ObjectSectionCatalog.ControlEdges)
        {
            var sidValue = attributes.Find("objectSid")?.OnlyValue;
            var sid = sidValue?.Bytes is { } bytes ? Sid.ToText(bytes) : sidValue?.Text;
            var scope = sid is not null && Sid.IsBuiltinDomain(sid) ? attributes.DomainFqdn : null;
            var controls = new ControlEdgesSectionViewModel(definition, DnHelper.ExtractFirstRdn(dn));
            controls.ConfigureMemberAttributionAsync(
                (row, cancellation) => ReadBoundAsync(bundle, current,
                    reader => reader.ReadMemberAttribution(bundle, row.HolderSid, row.HolderScope, row.Target), cancellation,
                    "read saved member attribution"),
                sid is null ? null : (expected, after, cancellation) => ReadBoundAsync(bundle, current,
                    reader => reader.ReadPermissionsThroughMembership(bundle, sid, scope, expected, after), cancellation,
                    "read saved membership permissions"), current);
            controls.ConfigureAsync(sid is not null, string.Equals(objectClass, "user", StringComparison.OrdinalIgnoreCase),
                (byHolder, expected, after, cancellation) => ReadBoundAsync(bundle, current,
                    reader => reader.ReadControlEdges(bundle, byHolder ? null : dn, byHolder ? sid : null, scope, expected, after), cancellation,
                    "read saved control edges"),
                (byRequester, cancellation) => ReadBoundAsync(bundle, current,
                    reader => reader.ReadSelfMembershipAssessments(bundle, byRequester ? null : dn, byRequester ? dn : null), cancellation,
                    "read saved membership assessments"));
            using var cancellation = token.Register(controls.CancelRead);
            await controls.ReadCompletion;
            token.ThrowIfCancellationRequested();
            return controls;
        }
        var content = await ReadBoundAsync(bundle, current, reader =>
        {
            if (definition.Key == ObjectSectionCatalog.Findings)
            {
                var findings = reader.ReadFindingsList(bundle, FindingsQuery.About(dn));
                return findings.IsSuccess
                    ? Result<ObjectSectionViewModel>.Success(new FindingsSectionViewModel(definition, findings.Value, null))
                    : Result<ObjectSectionViewModel>.Failure(findings.Error);
            }
            if (definition.Key is ObjectSectionCatalog.Overview or ObjectSectionCatalog.Permissions or ObjectSectionCatalog.Evidence)
            {
                var permissions = reader.ReadPermissions(bundle, dn);
                if (!permissions.IsSuccess) return Result<ObjectSectionViewModel>.Failure(permissions.Error);
                if (permissions.Value is not { } value) throw new InvalidOperationException(NavigationText.Get("ObjectMissing"));
                if (definition.Key == ObjectSectionCatalog.Overview)
                    return Result<ObjectSectionViewModel>.Success(new OverviewSectionViewModel(definition, value, attributes, objectClass ?? "not recorded"));
                if (definition.Key == ObjectSectionCatalog.Evidence)
                    return Result<ObjectSectionViewModel>.Success(new EvidenceSectionViewModel(definition, value));
                var classification = reader.ReadPermissionClassification(bundle, dn);
                PermissionVocabulary? vocabulary = null;
                if (!classification.IsSuccess)
                {
                    var schema = reader.ReadSchemaGuids(bundle);
                    vocabulary = schema.IsSuccess ? new PermissionVocabulary(schema.Value) : PermissionVocabulary.Shipped;
                }
                return Result<ObjectSectionViewModel>.Success(new PermissionsSectionViewModel(definition, value, vocabulary,
                    classification.IsSuccess ? classification.Value.Classification : null,
                    classification.IsSuccess ? null : classification.Error.Description));
            }
            return Result<ObjectSectionViewModel>.Success(ObjectViewModel.BuildAttributes(definition, attributes, objectClass));
        }, token, "read object " + definition.Key);
        return content.IsSuccess ? content.Value : throw new InvalidOperationException(content.Error.Description);
    }

    private async Task<Result<T>> ReadBoundAsync<T>(string bundle, Func<bool> current,
        Func<IAssetReader, Result<T>> read, CancellationToken token, string action)
    {
        using var navigation = NavigationDiagnostics.Begin(bundle, action);
        try
        {
            token.ThrowIfCancellationRequested();
            if (!current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var result = await _assets.ReadAsync(bundle, (reader, cancellation) =>
            {
                cancellation.ThrowIfCancellationRequested();
                if (!current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
                return read(reader);
            }, token);
            token.ThrowIfCancellationRequested();
            if (!current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            navigation.Complete(result.IsSuccess ? "success" : "refused",
                result.IsSuccess ? null : result.Error.Code);
            return result;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            navigation.Complete("cancelled", null);
            throw;
        }
        catch (InvalidOperationException error)
        {
            navigation.Complete("refused", error.Message);
            throw;
        }
    }
}

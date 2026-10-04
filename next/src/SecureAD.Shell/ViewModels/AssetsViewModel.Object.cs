using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    private async Task OpenAsync(string bundle, string distinguishedName, string section)
    {
        var revision = _revision + 1;
        ObjectViewModel? opened = null;
        await ReadViewAsync(bundle, reader => reader.ReadObjectAttributes(bundle, distinguishedName), (attributes, current) =>
        {
            if (attributes is null)
            {
                RefuseView(NavigationText.Get("ObjectMissing"));
                return;
            }
            var objectClass = ClassOf(attributes);
            opened = new ObjectViewModel(distinguishedName, objectClass ?? "not recorded", objectClass,
                (definition, token) => ReadSectionAsync(bundle, attributes, objectClass, definition, current, token));
            _objectCurrent = current;
            Opened = opened;
        }, saved: false);
        if (revision != _revision || opened is null || !ReferenceEquals(Opened, opened)) return;
        opened.Show(section);
        Announce();
        await opened.ReadCompletion;
    }

    private async Task<ObjectSectionViewModel> ReadSectionAsync(string bundle, ObjectAttributes attributes,
        string? objectClass, ObjectSectionDefinition definition, Func<bool> current, CancellationToken token)
    {
        var dn = attributes.DistinguishedName;
        if (definition.Key == ObjectSectionCatalog.SavedTier0Path)
        {
            var path = new SavedTier0PathSectionViewModel(definition);
            path.ConfigureAsync(dn, (group, after, cancellation) => ReadBoundAsync(bundle, current,
                reader => reader.ReadSavedTier0Path(bundle, dn, group, after), cancellation, "read saved Tier 0 path"));
            return path;
        }
        if (definition.Key == ObjectSectionCatalog.ControlEdges)
        {
            var sidValue = attributes.Find("objectSid")?.OnlyValue;
            var sid = sidValue?.Bytes is { } bytes ? Sid.ToText(bytes) : sidValue?.Text;
            var scope = sid is not null && Sid.IsBuiltinDomain(sid) ? attributes.DomainFqdn : null;
            var controls = new ControlEdgesSectionViewModel(definition);
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
                var findings = reader.ReadFindings(bundle, FindingsQuery.About(dn));
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
            return Result<ObjectSectionViewModel>.Success(ObjectViewModel.BuildAttributes(definition, attributes));
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

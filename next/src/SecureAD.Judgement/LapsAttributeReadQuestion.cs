using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>One captured attribute question, with scope qualified once before evaluating its holders.</summary>
internal sealed class LapsAttributeReadQuestion
{
    private readonly ObjectAttributes _target;
    private readonly ObjectPermissions _permissions;
    private readonly SchemaGuidCatalog _catalogue;
    private readonly IReadOnlyDictionary<int, (ControlEvaluationState State, string Source)> _scopes;
    private readonly string? _class;
    private readonly string? _classGuid;
    private readonly AttributeVisibilityFact? _flags;

    internal LapsAttributeReadQuestion(ObjectAttributes target, ObjectPermissions permissions,
        JudgingContext context, SchemaGuidEntry attribute)
    {
        (_target, _permissions, Attribute) = (target, permissions, attribute);
        _catalogue = context.SchemaGuids ?? throw new InvalidOperationException("The captured schema was not supplied.");
        _class = AttributeReading.LastText(target, "objectClass");
        var classDefinition = _class is null ? null : _catalogue.FindUnambiguousByLdapName(_class);
        _classGuid = classDefinition is { Kind: SchemaGuidKind.ObjectClass, Source: SchemaGuidSource.Captured }
            ? classDefinition.Guid : null;
        _flags = context.AttributeVisibility?.Find(attribute.LdapName);
        Confidentiality = Requirement(_flags?.SearchFlags, _flags?.SystemFlags);
        var scopes = new Dictionary<int, (ControlEvaluationState, string)>();
        var entries = new List<LapsReadEntryEvidence>();
        foreach (var entry in permissions.Entries)
        {
            if (!FullControlEvaluator.Applies(entry) || (entry.AccessMask & 0x110) == 0) continue;
            var scope = ControlEdgeDeriver.AttributeScope(entry, attribute.LdapName, _class, _catalogue);
            var definitions = entry.ObjectTypeGuid is { } guid ? _catalogue.FindByGuid(guid) : [];
            if (entry.HasObjectType && definitions.Any(value => value.Kind == SchemaGuidKind.ObjectClass)
                && _classGuid is null)
                scope = (ControlEvaluationState.Unknown, "The target class identity was not captured.");
            if (!scopes.TryAdd(entry.Ordinal, scope))
                throw new InvalidDataException("A captured permission occurrence has a duplicate ordinal.");
            entries.Add(new(entry, State(scope.State), scope.Source, definitions,
                entry.ObjectTypeGuid is { } propertySet ? _catalogue.MembersOfPropertySet(propertySet) : null));
        }
        _scopes = scopes;
        Entries = entries;
    }

    internal SchemaGuidEntry Attribute { get; }
    internal LapsConfidentiality Confidentiality { get; }
    internal bool SchemaIsComplete => Confidentiality != LapsConfidentiality.Unresolved;
    internal IReadOnlyList<LapsReadEntryEvidence> Entries { get; }

    internal static LapsConfidentiality Requirement(int? searchFlags, int? systemFlags) =>
        systemFlags is { } system && (system & SchemaAttributeFlags.BaseSchemaObject) != 0
            || searchFlags is { } flags && (flags & SchemaAttributeFlags.Confidential) == 0
            ? LapsConfidentiality.NotConfidential
            : searchFlags.HasValue && systemFlags.HasValue
                ? LapsConfidentiality.Confidential : LapsConfidentiality.Unresolved;

    internal bool HasPossibleGrant(string holder)
    {
        var observed = Entries.Where(value => Same(EffectiveHolder(value.Entry), holder)
            && value.Entry.AceType.StartsWith("AccessAllowed", StringComparison.Ordinal)
            && value.Scope != LapsReadState.NotEstablished)
            .Aggregate(0, (mask, value) => mask | value.Entry.AccessMask);
        return (observed & 0x10) != 0
            && (Confidentiality != LapsConfidentiality.Confidential || (observed & 0x100) != 0);
    }

    internal (LapsReadState State, LapsReadRightProof ReadProperty, LapsReadRightProof ControlAccess)
        Assess(PermissionTrustee holder, string broadSid, bool membershipQualified, bool holderResolved)
    {
        var scope = Sid.IsBuiltinDomain(holder.Sid) ? _target.DomainFqdn : null;
        var source = new FullControlSource(_target.DistinguishedName, _target.ObjectGuid,
            OwnerRightsReading.TargetSid(_target), _target.DomainFqdn,
            _target.Find("objectClass")?.Values.Select(value => value.Text).OfType<string>().ToArray() ?? [],
            holder, scope, !Sid.IsBuiltinDomain(holder.Sid) || !string.IsNullOrWhiteSpace(scope),
            false, _permissions.Availability, _permissions.DaclState, _permissions.DaclCompleteness,
            _permissions.DaclWasCanonical, _permissions.Entries);
        bool? MatchDeny(PermissionEntry entry)
        {
            var sid = EffectiveHolder(entry);
            if (membershipQualified && Same(sid, broadSid)) return true;
            if (Same(sid, "S-1-1-0") && Same(broadSid, "S-1-5-11")) return true;
            return null;
        }
        ControlEvaluationState Scope(PermissionEntry entry) => _scopes.TryGetValue(entry.Ordinal, out var value)
            ? value.State : ControlEvaluationState.NotEstablished;
        var read = Proof(FullControlEvaluator.AssessAttributeRight(source, 0x10, Scope, MatchDeny, holderResolved));
        var control = Proof(FullControlEvaluator.AssessAttributeRight(source, 0x100, Scope, MatchDeny, holderResolved));
        var state = Confidentiality switch
        {
            LapsConfidentiality.NotConfidential => read.State,
            LapsConfidentiality.Confidential when read.State == LapsReadState.NotEstablished
                || control.State == LapsReadState.NotEstablished => LapsReadState.NotEstablished,
            _ when read.State == LapsReadState.NotEstablished => LapsReadState.NotEstablished,
            _ when read.State == LapsReadState.Established && control.State == LapsReadState.Established
                => LapsReadState.Established,
            _ => LapsReadState.Unresolved,
        };
        return (state, read, control);
    }

    internal LapsReadExposure Exposure(PermissionTrustee holder, IReadOnlyList<PathStep> path,
        bool membershipComplete, LapsReadState state, LapsReadRightProof read, LapsReadRightProof control)
    {
        var supports = read.GrantOrdinals.Concat(control.GrantOrdinals).ToHashSet();
        var possible = Entries.Where(value => Same(EffectiveHolder(value.Entry), holder.Sid)
            && value.Entry.AceType.StartsWith("AccessAllowed", StringComparison.Ordinal)
            && value.Scope != LapsReadState.NotEstablished).ToArray();
        var illustrative = possible.Where(value => supports.Contains(value.Entry.Ordinal)).ToArray();
        if (illustrative.Length == 0) illustrative = possible;
        var rights = (read.State == LapsReadState.Established, control.State == LapsReadState.Established) switch
        {
            (true, true) => LapsReadRights.Both,
            (true, false) => LapsReadRights.ReadPropertyOnly,
            (false, true) => LapsReadRights.ControlAccessOnly,
            _ => LapsReadRights.Neither,
        };
        var reach = illustrative.Any(value => value.Scope == LapsReadState.Unresolved) ? LapsGrantReach.Unresolved
            : illustrative.All(value => !value.Entry.HasObjectType) ? LapsGrantReach.EveryAttribute
            : illustrative.All(value => Same(value.Entry.ObjectTypeGuid, Attribute.Guid)) ? LapsGrantReach.ThisAttributeOnly
            : illustrative.All(value => value.Definitions.Any(definition => definition.Kind == SchemaGuidKind.ObjectClass))
                ? LapsGrantReach.ObjectClass
            : illustrative.All(value => value.PropertySetMembers is not null) ? LapsGrantReach.PropertySet
            : LapsGrantReach.Mixed;
        var sourceEntries = Entries.Where(value => value.Scope != LapsReadState.NotEstablished
            && (Same(EffectiveHolder(value.Entry), holder.Sid) || FullControlEvaluator.IsDeny(value.Entry))).ToArray();
        return new(_target.DistinguishedName, _target.ObjectGuid
                ?? throw new InvalidOperationException("The read question has no target identity."),
            _target.DomainFqdn, holder.Sid, holder.Name, Sid.IsBuiltinDomain(holder.Sid) ? _target.DomainFqdn : null,
            Attribute.LdapName, Attribute.Guid, _class, _classGuid, _flags?.SearchFlags, _flags?.SystemFlags,
            Confidentiality, state, rights, reach, illustrative.Any(value => value.Entry.IsInherited),
            illustrative.Where(value => value.Entry.HasInheritedObjectType).Select(value => value.Entry.InheritedObjectTypeGuid)
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToArray(),
            path, membershipComplete, read, control, sourceEntries.Select(value => value.Entry.Ordinal).ToArray(), sourceEntries);
    }

    private string? EffectiveHolder(PermissionEntry entry) => entry.Trustee.Sid == "S-1-5-10"
        ? OwnerRightsReading.TargetSid(_target) : entry.Trustee.Sid;
    private static LapsReadRightProof Proof(FullControlRight value) =>
        new(value.Mask, State(value.State), value.GrantOrdinals, value.BlockingOrdinals,
            value.Uncertainty == ControlUncertainty.None ? [] : value.Uncertainty.ToString().Split(", "));
    private static LapsReadState State(ControlEvaluationState value) => value switch
    {
        ControlEvaluationState.Established => LapsReadState.Established,
        ControlEvaluationState.NotEstablished => LapsReadState.NotEstablished,
        _ => LapsReadState.Unresolved,
    };
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

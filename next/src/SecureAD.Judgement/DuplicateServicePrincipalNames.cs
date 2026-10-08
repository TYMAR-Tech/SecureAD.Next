using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>One forest-wide assessment, completed after the existing captured-object pass.</summary>
public sealed class DuplicateServicePrincipalNames : IRule
{
    public RuleDefinition Definition { get; } = new("SEC-026", "Duplicate service principal names", Severity.High, 1,
        ["*"], ["objectGUID", "objectClass", "sAMAccountName", "servicePrincipalName"], []);

    internal const string Explanation = "The same complete service principal name is recorded on more than one captured object. "
        + "This can prevent Kerberos from identifying the service account. It does not prove ticket issuance, credential exposure or takeover.";
    internal const string Guidance = "Identify the actual service and account that should own each registration before changing AD. "
        + "Use setspn -F -Q <SPN> and setspn -F -X to investigate in the affected forest when authorized; these commands are not run by this rule. "
        + "Remove only a confirmed erroneous registration under change control, then verify service authentication and capture again. "
        + "Do not remove krbtgt or kadmin registrations based on this finding alone.";

    // MS-ADTS 2.2.21 permits :port OR :instancename; never strip either or apply HOST aliases.
    // https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/cd328386-4d97-4666-be33-056545c1cad2
    internal static bool Supports(string value)
    {
        var parts = value.Split('/');
        if (parts.Length is < 2 or > 3 || parts.Any(string.IsNullOrWhiteSpace)
            || parts[0].Any(char.IsWhiteSpace) || parts[1].Any(char.IsWhiteSpace)
            || value.Any(char.IsControl) || value.Contains('*') || value.Contains('?')) return false;
        var colon = parts[1].IndexOf(':');
        return colon < 0 || colon > 0 && colon < parts[1].Length - 1;
    }
}

internal sealed class DuplicateSpnAssessment(DuplicateServicePrincipalNames rule, string forest, string seal, bool captureComplete)
{
    private sealed record Owner(DuplicateSpnOwner Identity, EvidenceCompleteness Completeness);
    private readonly Dictionary<Guid, Owner> _owners = [];
    private readonly Dictionary<string, Guid> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<Guid, List<DuplicateSpnOccurrence>>> _values = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<Guid> _ambiguous = [];
    private readonly HashSet<string> _limitations = new(StringComparer.Ordinal);
    private int _notApplicable;
    private int _missingIdentity;
    private bool _finished;

    internal void Add(ObjectAttributes subject, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_finished) throw new InvalidOperationException("The duplicate-SPN assessment has already completed.");
        var attribute = subject.Find("servicePrincipalName");
        var classes = subject.Find("objectClass");
        var account = classes?.Values.Any(value => value.Text is { } text &&
            (text.Equals("user", StringComparison.OrdinalIgnoreCase) || text.Equals("computer", StringComparison.OrdinalIgnoreCase)
                || text.Equals("msDS-ManagedServiceAccount", StringComparison.OrdinalIgnoreCase)
                || text.Equals("msDS-GroupManagedServiceAccount", StringComparison.OrdinalIgnoreCase))) == true;
        if (!account && attribute?.HasValue != true && classes?.HasValue == true) { _notApplicable++; return; }
        if (attribute is null) _limitations.Add("servicePrincipalName was not captured for every candidate.");
        if (subject.Completeness != EvidenceCompleteness.Complete)
            _limitations.Add("Some candidate objects were read with limited attribute visibility.");
        var objectClass = classes?.Values.LastOrDefault()?.Text;
        if (subject.ObjectGuid is not { } guid || guid == Guid.Empty || string.IsNullOrWhiteSpace(subject.DomainFqdn)
            || string.IsNullOrWhiteSpace(objectClass) || string.IsNullOrWhiteSpace(subject.DistinguishedName))
        {
            _missingIdentity++;
            _limitations.Add("Some SPN owner identities could not be established.");
            return;
        }
        var identity = new DuplicateSpnOwner(guid, subject.DistinguishedName, subject.DomainFqdn,
            objectClass, subject.Find("sAMAccountName")?.OnlyValue?.Text);
        if (_names.TryGetValue(identity.DistinguishedName, out var named) && named != guid)
        {
            _ambiguous.Add(named);
            _ambiguous.Add(guid);
            _limitations.Add("A captured distinguished name has conflicting objectGUIDs; those identities were not used to prove duplicates.");
        }
        else _names.TryAdd(identity.DistinguishedName, guid);
        if (_owners.TryGetValue(guid, out var previous))
        {
            if (!string.Equals(previous.Identity.DistinguishedName, identity.DistinguishedName, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(previous.Identity.DomainFqdn, identity.DomainFqdn, StringComparison.OrdinalIgnoreCase))
            {
                _ambiguous.Add(guid);
                _limitations.Add("Conflicting captured identities share an objectGUID; those identities were not used to prove duplicates.");
            }
        }
        else _owners.Add(guid, new(identity, subject.Completeness));
        foreach (var value in attribute?.Values ?? [])
        {
            token.ThrowIfCancellationRequested();
            if (value.Text is not { } text || !DuplicateServicePrincipalNames.Supports(text) || value.Ordinal < 0)
            {
                _limitations.Add("Some servicePrincipalName values were unreadable or outside the supported full-value syntax.");
                continue;
            }
            if (!_values.TryGetValue(text, out var owners)) _values[text] = owners = [];
            if (!owners.TryGetValue(guid, out var occurrences)) owners[guid] = occurrences = [];
            var occurrence = new DuplicateSpnOccurrence(guid, value.Ordinal, text);
            if (!occurrences.Contains(occurrence)) occurrences.Add(occurrence);
        }
    }

    internal RuleExecution Complete(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (_finished) throw new InvalidOperationException("The duplicate-SPN assessment has already completed.");
        _finished = true;
        if (!captureComplete) _limitations.Add("The capture did not record every declared unit as read; forest-wide uniqueness is not established.");
        var matches = new Dictionary<Guid, List<DuplicateSpnMatch>>();
        foreach (var (name, recorded) in _values.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();
            var ids = recorded.Keys.Where(id => !_ambiguous.Contains(id)).OrderBy(id => id.ToString("D"), StringComparer.Ordinal).ToArray();
            if (ids.Length < 2) continue;
            var match = new DuplicateSpnMatch(name.ToUpperInvariant(), ids.Select(id => _owners[id].Identity).ToArray(),
                ids.SelectMany(id => recorded[id].OrderBy(value => value.Ordinal).ThenBy(value => value.Value, StringComparer.Ordinal)).ToArray());
            foreach (var id in ids)
            {
                if (!matches.TryGetValue(id, out var list)) matches[id] = list = [];
                list.Add(match);
            }
        }
        var findings = new List<Finding>();
        foreach (var (id, duplicates) in matches.OrderBy(pair => pair.Key.ToString("D"), StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            var owner = _owners[id];
            var limitations = _limitations.Order(StringComparer.Ordinal).ToList();
            if (duplicates.Any(value => value.MatchKey.StartsWith("KADMIN/", StringComparison.Ordinal)
                || value.MatchKey.StartsWith("KRBTGT/", StringComparison.Ordinal)))
                limitations.Add("Kerberos system-service names require protocol-specific review; do not remove their registrations automatically.");
            var evidence = new DuplicateSpnEvidence(seal, forest, id, duplicates, limitations);
            var detail = DuplicateServicePrincipalNames.Explanation + "\n\n"
                + string.Join("\n\n", duplicates.Select(value => "Complete SPN (case-insensitive match): " + value.MatchKey
                    + "\nRecorded owners:\n" + string.Join("\n", value.Owners.Select(other =>
                        other.DistinguishedName + " [" + other.DomainFqdn + "; " + other.ObjectGuid.ToString("D") + "]"))
                    + "\nOriginal values:\n" + string.Join("\n", value.Occurrences.Select(occurrence =>
                        occurrence.OwnerGuid.ToString("D") + " / servicePrincipalName[" + occurrence.Ordinal + "]: " + occurrence.Value))))
                + "\n\nWindows case-insensitive full-value comparison only; SPN alias equivalence and other forests were not assessed. "
                + "Recorded values do not guarantee that every attribute was visible."
                + (limitations.Count == 0 ? "" : "\n\nLimitations:\n" + string.Join("\n", limitations));
            findings.Add(new(rule.Definition.Id, rule.Definition.Version, rule.Definition.Severity,
                new(FindingSubjectKind.DirectoryObject, id.ToString("D")), id, owner.Identity.DistinguishedName,
                owner.Identity.DomainFqdn, owner.Identity.ObjectClass, detail, owner.Completeness, evidence)
                { PrincipalName = owner.Identity.AccountName ?? owner.Identity.DistinguishedName });
        }
        var candidates = _owners.Count + _missingIdentity;
        if (_limitations.Count == 0)
            return RuleExecution.Judged(rule.Definition, candidates, _notApplicable, findings);
        if (candidates == 0) return RuleExecution.DidNotRun(rule.Definition);
        return RuleExecution.Indeterminate(rule.Definition, 0, _notApplicable, candidates,
            _limitations.Order(StringComparer.Ordinal).Select(reason => new MissingInput("SPN inventory: " + reason, candidates)).ToArray(), findings);
    }
}

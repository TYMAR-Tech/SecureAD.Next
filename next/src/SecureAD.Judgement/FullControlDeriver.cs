using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

internal static class FullControlDeriver
{
    internal static IReadOnlyList<FullControlAssessment> Derive(ObjectAttributes subject, ObjectPermissions original,
        ObjectPermissions normalized, JudgingContext context, Guid generation, Guid? derivationGeneration,
        Func<string, string?> domainSid, string? targetSid, IReadOnlyList<ControlEdge> edges)
    {
        var classes = subject.Find("objectClass")?.Values.Select(value => value.Text).OfType<string>().ToArray() ?? [];
        var candidates = normalized.Entries.Where(FullControlEvaluator.Applies)
            .Where(entry => !FullControlEvaluator.IsDeny(entry))
            .GroupBy(entry => entry.Trustee.Sid, StringComparer.OrdinalIgnoreCase)
            .Where(group => (group.Aggregate(0, (mask, entry) => mask | entry.AccessMask) & FullControlEvaluator.RequiredMask) == FullControlEvaluator.RequiredMask
                || group.Any(entry => (entry.AccessMask & 0x10000000) != 0))
            .Select(group => group.First().Trustee).ToArray();
        if (original.Availability == DescriptorAvailability.Read && original.DaclState == DaclState.Null)
            candidates = [new("S-1-1-0", "Everyone", null, null, null, WellKnownSidRole.Principal, null)];
        var results = new List<FullControlAssessment>();
        foreach (var holder in candidates.OrderBy(value => value.Sid, StringComparer.Ordinal))
        {
            var holderScope = Sid.IsBuiltinDomain(holder.Sid) ? subject.DomainFqdn : null;
            var routes = context.ProtectedPrincipals?.Lookup(holder.Sid, holderScope)?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
            var authorityDomains = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            string? AuthorityDomain(string domain)
            {
                if (!authorityDomains.TryGetValue(domain, out var sid)) authorityDomains[domain] = sid = domainSid(domain);
                return sid;
            }
            var root = context.NamingContexts?.TryGetValue(subject.DistinguishedName, out var kind) == true
                && classes.Any(value => value == (kind switch
                {
                    NamingContextKind.Domain => "domainDNS",
                    NamingContextKind.Configuration => "configuration",
                    NamingContextKind.Schema => "dMD",
                    _ => "",
                }));
            var source = new FullControlSource(subject.DistinguishedName, subject.ObjectGuid, targetSid, subject.DomainFqdn,
                classes, holder, holderScope, !Sid.IsBuiltinDomain(holder.Sid)
                    || ControlEdgeDeriver.IsDomainTarget(subject, context.ForestFqdn) && subject.DomainFqdn is { } domain
                        && !string.IsNullOrWhiteSpace(AuthorityDomain(domain)),
                root, original.Availability, original.DaclState, original.DaclCompleteness, original.DaclWasCanonical, original.Entries)
            {
                ForestFqdn = context.ForestFqdn,
                AuthorityDomainSids = authorityDomains,
                MembershipRoutes = routes,
            };
            var rights = FullControlEvaluator.AssessFullControl(source, generation, derivationGeneration,
                ControlExpectedness.Unknown, ControlExpectednessReason.UnknownCapabilityScope, edges);
            var expected = ControlEdgeDeriver.Expected(holder, subject, context.ForestFqdn, routes,
                original.DaclCompleteness == DaclCompleteness.Complete,
                rights.IsCounted && original.DaclState != DaclState.Null, AuthorityDomain, fullControl: true);
            results.Add(FullControlEvaluator.AssessFullControl(source, generation, derivationGeneration, expected.State, expected.Reason, edges));
        }
        return results;
    }
}

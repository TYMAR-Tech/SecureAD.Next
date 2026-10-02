using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class Tier0DiscoveryResolutionTests
{
    [Fact]
    public void EveryMissingTrusteeOccurrenceKeepsItsOwnLimitation()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        const string missing = "S-1-5-21-99-98-97-1234";
        evidence.Describe(target, entries:
        [
            Tier0DiscoveryEvidence.AllowSid(2, missing, Tier0DiscoveryEvidence.WriteDacl),
            Tier0DiscoveryEvidence.AllowSid(7, missing, Tier0DiscoveryEvidence.WriteDacl),
        ]);

        var scheduler = Run(evidence);

        Assert.Equal(new int?[] { 2, 7 }, scheduler.Coverage().Limitations
            .Where(item => item.Reason == Tier0DiscoveryReason.UnresolvedTrustee)
            .Select(item => item.PermissionOrdinal));
    }

    [Fact]
    public void AnExactMatchWorksEvenWhenHolderIsObservedAfterItsTarget()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("A Target", "512");
        var holder = evidence.Principal("Z Holder", "1401", "user");
        evidence.Describe(target, entries: [evidence.Allow(3, holder, Tier0DiscoveryEvidence.WriteDacl)]);
        evidence.Describe(holder);

        Assert.Equal(holder.DistinguishedName, Assert.Single(Run(evidence).Candidates(diagnostic: null)).Controller.DistinguishedName);
    }

    [Fact]
    public void AmbiguousExactSidDoesNotFallBackToOneOfItsNames()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        var first = evidence.Principal("First", "1401", "user");
        var second = evidence.Principal("Second", "1401", "user");
        evidence.Describe(target, entries: [evidence.Allow(3, first, Tier0DiscoveryEvidence.WriteDacl)]);
        evidence.Describe(first);
        evidence.Describe(second);

        Assert.Empty(Run(evidence).Candidates(diagnostic: null));
    }

    [Fact]
    public void MissingSidKeepsTheCapturedNameFallback()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        var holder = evidence.Principal("Holder", "1401", "user");
        var entry = evidence.Allow(3, holder, Tier0DiscoveryEvidence.WriteDacl);
        entry = entry with { Trustee = entry.Trustee with { Sid = "S-1-5-21-9-9-9-1401" } };
        evidence.Describe(target, entries: [entry]);
        evidence.Describe(holder);

        Assert.Equal(holder.DistinguishedName, Assert.Single(Run(evidence).Candidates(diagnostic: null)).Controller.DistinguishedName);
    }

    [Fact]
    public void IdenticalMissingSidsWithDifferentFallbackNamesStaySeparate()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        var first = evidence.Principal("First", "1401", "user");
        var second = evidence.Principal("Second", "1402", "user");
        var a = evidence.Allow(2, first, Tier0DiscoveryEvidence.WriteDacl);
        var b = evidence.Allow(7, second, Tier0DiscoveryEvidence.WriteDacl);
        const string missing = "S-1-5-21-9-9-9-1401";
        evidence.Describe(target, entries:
        [
            a with { Trustee = a.Trustee with { Sid = missing } },
            b with { Trustee = b.Trustee with { Sid = missing } },
        ]);
        evidence.Describe(first);
        evidence.Describe(second);

        Assert.Equal(new[] { first.DistinguishedName, second.DistinguishedName },
            Run(evidence).Candidates(diagnostic: null).Select(item => item.Controller.DistinguishedName));
    }

    [Fact]
    public void ScopedNonBuiltinTargetIsInvalidAndCannotRescueAMissingSid()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        var holder = evidence.Principal("Holder", "1401", "user");
        var holderSid = holder.Find("objectSid")!.OnlyValue!.Text!;
        evidence.Describe(target, entries: [Tier0DiscoveryEvidence.AllowSid(2, holderSid, Tier0DiscoveryEvidence.WriteDacl)]);
        evidence.Describe(holder);
        var scheduler = new Tier0DiscoveryScheduler(evidence.Binding, true, evidence.Find,
            subject => evidence.Target(subject) with
            {
                SidScope = subject.DistinguishedName == holder.DistinguishedName ? "wrong.scope" : null,
            }, CancellationToken.None);
        foreach (var subject in evidence.Stream()) scheduler.Observe(subject, evidence.Permissions(subject.DistinguishedName));

        Assert.Empty(scheduler.Candidates(diagnostic: null));
    }

    [Fact]
    public void CancellationStillStopsCandidateResolution()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        evidence.Describe(target, entries: [Tier0DiscoveryEvidence.AllowSid(2, "S-1-5-21-9-9-9-1401", Tier0DiscoveryEvidence.WriteDacl)]);
        using var stop = new CancellationTokenSource();
        var scheduler = new Tier0DiscoveryScheduler(evidence.Binding, true, evidence.Find, evidence.Target, stop.Token);
        foreach (var subject in evidence.Stream()) scheduler.Observe(subject, evidence.Permissions(subject.DistinguishedName));
        stop.Cancel();

        Assert.Throws<OperationCanceledException>(() => scheduler.Candidates(diagnostic: null));
    }

    [Fact]
    public void BuiltinSidUsesItsOwnDomainRatherThanAnotherDomainsMatch()
    {
        var evidence = new Tier0DiscoveryEvidence();
        var target = evidence.Principal("Target", "512");
        var first = evidence.Principal("FirstBuiltin", "1401");
        first = first with { Attributes = [Tier0DiscoveryEvidence.Attribute("objectSid", "S-1-5-32-544"),
            Tier0DiscoveryEvidence.Attribute("objectClass", "group")] };
        var second = first with { DistinguishedName = "CN=OtherBuiltin,DC=other,DC=com", ObjectGuid = Guid.NewGuid(), DomainFqdn = "other.com" };
        var entry = Tier0DiscoveryEvidence.AllowSid(2, "S-1-5-32-544", Tier0DiscoveryEvidence.WriteDacl);
        entry = entry with { Trustee = entry.Trustee with { DomainFqdn = "contoso.com" } };
        var scheduler = new Tier0DiscoveryScheduler(evidence.Binding, true, _ => null,
            subject => Tier0Target.From(subject, subject.DomainFqdn == "other.com" ? "DC=other,DC=com" : evidence.Domain.DistinguishedName), CancellationToken.None);
        scheduler.Observe(first, null);
        scheduler.Observe(second, null);
        scheduler.Observe(target, evidence.Describe(target, entries: [entry]));

        Assert.Equal(first.DistinguishedName, Assert.Single(scheduler.Candidates(diagnostic: null)).Controller.DistinguishedName);
    }

    private static Tier0DiscoveryScheduler Run(Tier0DiscoveryEvidence evidence)
    {
        var scheduler = new Tier0DiscoveryScheduler(evidence.Binding, true, evidence.Find, evidence.Target, CancellationToken.None);
        foreach (var subject in evidence.Stream()) scheduler.Observe(subject, evidence.Permissions(subject.DistinguishedName));
        return scheduler;
    }
}

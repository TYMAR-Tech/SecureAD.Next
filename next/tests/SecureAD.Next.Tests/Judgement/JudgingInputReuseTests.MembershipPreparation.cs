using System.Runtime.CompilerServices;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class JudgingInputReuseTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AdmissionAndPathValidationReuseOneOwnedMembershipIndex(bool rules)
    {
        var directory = Ready();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId;
        using var counts = new CapturedMembershipPreparationTests.Counts(generation);
        Run(directory, rules ? RuleCatalogue.All : []);
        Assert.Equal((1L, 1L), (counts.For("membership.source_snapshots"), counts.For("membership.captured_index_builds")));
    }

    [Fact]
    public void OwnedRequesterIdentitiesDoNotChangeWhenTheCallerChangesItsDictionary()
    {
        using var sources = Sources(Ready());
        var contexts = sources.ReadNamingContexts().Value;
        var identities = sources.ReadMembershipInput().Objects.Select(subject => OwnershipAuditRun.Target(subject, contexts))
            .ToDictionary(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var target = identities[TargetDn];
        var context = sources.RequesterMemberships(sources.Binding(), identities, CancellationToken.None);
        identities.Clear();
        Assert.NotEmpty(context.CapturedRequesters(target.DistinguishedName));
    }

    [Fact]
    public void OwnedRequesterAttributesCannotBeChangedThroughReturnedBinaryValues()
    {
        using var sources = Sources(Ready());
        var contexts = sources.ReadNamingContexts().Value;
        var identities = sources.ReadMembershipInput().Objects.Select(subject => OwnershipAuditRun.Target(subject, contexts))
            .ToDictionary(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var context = sources.RequesterMemberships(sources.Binding(), identities, CancellationToken.None);
        var trustee = new PermissionTrustee(UserSid, "User", UserDn, "contoso.com", null, null, null);
        var subject = context.Holder(trustee, identities[TargetDn])!;
        var expected = subject.Find("objectSid")!.OnlyValue!.Bytes!.ToArray();
        subject.Find("objectSid")!.OnlyValue!.Bytes![0] ^= 0xff;
        Assert.Equal(expected, context.Holder(trustee, identities[TargetDn])!.Find("objectSid")!.OnlyValue!.Bytes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AClosedOrCancelledOwnerCannotReturnItsCachedRequesterContext(bool cancel)
    {
        using var stopping = new CancellationTokenSource();
        using var sources = Sources(Ready(), stopping.Token);
        var contexts = sources.ReadNamingContexts().Value;
        var identities = sources.ReadMembershipInput().Objects.Select(subject => OwnershipAuditRun.Target(subject, contexts))
            .ToDictionary(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var context = sources.RequesterMemberships(sources.Binding(), identities, stopping.Token);
        Assert.NotEmpty(context.CapturedRequesters(TargetDn));
        if (cancel)
        {
            stopping.Cancel();
            Assert.Throws<OperationCanceledException>(() => context.CapturedRequesters(TargetDn).ToArray());
        }
        else
        {
            sources.Dispose();
            Assert.Throws<ObjectDisposedException>(() => context.CapturedRequesters(TargetDn).ToArray());
        }
    }

    [Fact]
    public void DisposingTheOwnerCannotSilentlyFinishAPartlyEnumeratedRequesterSet()
    {
        var directory = Bundle(users: 2);
        Derive(directory);
        using var sources = Sources(directory);
        var contexts = sources.ReadNamingContexts().Value;
        var identities = sources.ReadMembershipInput().Objects.Select(subject => OwnershipAuditRun.Target(subject, contexts))
            .ToDictionary(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var context = sources.RequesterMemberships(sources.Binding(), identities, CancellationToken.None);
        using var iterator = context.CapturedRequesters(TargetDn).GetEnumerator();
        Assert.True(iterator.MoveNext());
        sources.Dispose();
        Assert.Throws<ObjectDisposedException>(() => iterator.MoveNext());
    }

    [Fact]
    public void DisposingTheOwnerReleasesCachedMembershipAttributeBodies()
    {
        using var sources = Sources(Ready());
        var contexts = sources.ReadNamingContexts().Value;
        var identities = sources.ReadMembershipInput().Objects.Select(subject => OwnershipAuditRun.Target(subject, contexts))
            .ToDictionary(identity => identity.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var context = sources.RequesterMemberships(sources.Binding(), identities, CancellationToken.None);
        var body = HoldMembershipSubject(context, identities[TargetDn]);
        GC.Collect();
        Assert.True(body.IsAlive);
        sources.Dispose();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(body.IsAlive);
        GC.KeepAlive(context);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference HoldMembershipSubject(RequesterMembershipContext context, Tier0Target resource)
    {
        var trustee = new PermissionTrustee(UserSid, "User", UserDn, "contoso.com", null, null, null);
        return new(context.Holder(trustee, resource)!);
    }
}

using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PermissionWitnessFingerprintTests
{
    [Theory]
    [InlineData("identical", true)]
    [InlineData("ordinal", false)]
    [InlineData("mask", false)]
    [InlineData("type", false)]
    [InlineData("sid", false)]
    [InlineData("resource", false)]
    [InlineData("name", false)]
    [InlineData("object-type", false)]
    [InlineData("inherited-type", false)]
    [InlineData("inheritance", false)]
    [InlineData("propagation", false)]
    [InlineData("object-flag", false)]
    [InlineData("application-data", false)]
    public void CachedWitnessFingerprintsRetainCompleteOriginalEntryEquality(string change, bool expected)
    {
        var original = Ace(7, Holder, 0x40000) with { ApplicationData = [1, 2, 3] };
        var grant = change switch
        {
            "identical" => original with { ApplicationData = [1, 2, 3] },
            "ordinal" => original with { Ordinal = 8 },
            "mask" => original with { AccessMask = 0x80000 },
            "type" => original with { AceType = "AccessDenied" },
            "sid" => original with { Trustee = original.Trustee with { Sid = "S-1-5-21-4-5-6-1200" } },
            "resource" => original with { Trustee = original.Trustee with { DomainFqdn = "other.example" } },
            "name" => original with { Trustee = original.Trustee with { DistinguishedName = "CN=Other,DC=contoso,DC=com" } },
            "object-type" => original with { ObjectTypeGuid = Guid.NewGuid().ToString("D") },
            "inherited-type" => original with { InheritedObjectTypeGuid = Guid.NewGuid().ToString("D") },
            "inheritance" => original with { IsInherited = true },
            "propagation" => original with { PropagationFlags = 1 },
            "object-flag" => original with { HasObjectType = true },
            "application-data" => original with { ApplicationData = [1, 2, 4] },
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        var edge = Edge([original]);
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => value.Evidence, CancellationToken.None);
        Assert.Equal(expected, TargetPermissionReference.EntryMatches(edge, grant));

        Assert.Equal(expected, matcher.Matches(edge, grant));
        Assert.Equal(expected, matcher.Matches(edge, grant));
    }

    [Fact]
    public void RepeatedPermissionMatchesReadAndEnumerateOriginalEntriesOnce()
    {
        var entries = new RequesterReuseTests.CountingList<PermissionEntry>(
            [Ace(3, Holder, 0x40000), Ace(7, Holder, 0x40000), Ace(11, Holder, 0x40000)]);
        var edge = Edge(entries);
        var reads = 0;
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => { reads++; return value.Evidence; }, CancellationToken.None);
        var grant = Ace(11, Holder, 0x40000);

        for (var index = 0; index < 100; index++) Assert.True(matcher.Matches(edge, grant));

        Assert.Equal(1, reads);
        Assert.Equal(3, entries.Visits);
    }

    [Fact]
    public void RepeatedPreparedMatchesDoNotAllocateFreshFingerprints()
    {
        var grant = Ace(7, Holder, 0x40000) with { ApplicationData = new byte[4096] };
        var edge = Edge([grant with { ApplicationData = new byte[4096] }]);
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => value.Evidence, CancellationToken.None);
        Assert.True(matcher.Matches(edge, grant));
        var before = GC.GetAllocatedBytesForCurrentThread();
        var matches = true;
        for (var index = 0; index < 2000; index++) matches &= matcher.Matches(edge, grant);
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.True(matches);
        Assert.True(allocated < 65_536, $"Repeating a prepared permission match allocated {allocated:N0} bytes.");
    }

    [Theory]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("derivation")]
    [InlineData("originals")]
    public void AReusedNumericEdgeIdCannotBorrowAnotherOriginalProof(string changed)
    {
        var grant = Ace(7, Holder, 0x40000);
        var first = Edge([grant]) with { Id = 17 };
        var second = changed switch
        {
            "target" => first with { Target = "CN=Other,DC=contoso,DC=com" },
            "generation" => first with { GenerationId = Guid.NewGuid() },
            "derivation" => first with { DerivationGenerationId = Guid.NewGuid() },
            _ => first with { Evidence = [grant with { Ordinal = 9 }] },
        };
        var reads = 0;
        var matcher = new RequesterDaclProofs.OriginalPermissions(edge =>
        {
            reads++;
            return ReferenceEquals(edge, first) ? [grant] : [grant with { Ordinal = 9 }];
        }, CancellationToken.None);

        Assert.True(matcher.Matches(first, grant));
        Assert.False(matcher.Matches(second, grant));
        Assert.Equal(2, reads);
    }

    [Fact]
    public void AFailedOriginalReadingIsNotCachedAsACompleteSet()
    {
        var failure = new IOException("Synthetic original-proof read failure");
        var entries = new RequesterReuseTests.CountingList<PermissionEntry>([Ace(3, Holder, 0x40000), Ace(7, Holder, 0x40000)])
        {
            OnVisit = visit => { if (visit == 2) throw failure; },
        };
        var edge = Edge(entries);
        var reads = 0;
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => { reads++; return value.Evidence; }, CancellationToken.None);
        var grant = Ace(7, Holder, 0x40000);

        Assert.Same(failure, Assert.Throws<IOException>(() => matcher.Matches(edge, grant)));
        Assert.True(matcher.Matches(edge, grant));
        Assert.Equal(2, reads);
        Assert.Equal(4, entries.Visits);
    }

    [Fact]
    public void PreparedPermissionMatchesStillHonorCancellation()
    {
        var grant = Ace(7, Holder, 0x40000);
        var edge = Edge([grant]);
        using var stopping = new CancellationTokenSource();
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => value.Evidence, stopping.Token);
        Assert.True(matcher.Matches(edge, grant));
        stopping.Cancel();

        Assert.Throws<OperationCanceledException>(() => matcher.Matches(edge, grant));
    }

    [Fact]
    public void OriginalFingerprintPreparationCanCancelBetweenEntries()
    {
        using var stopping = new CancellationTokenSource();
        var entries = new RequesterReuseTests.CountingList<PermissionEntry>([Ace(3, Holder, 0x40000), Ace(7, Holder, 0x40000)])
        {
            OnVisit = visit => { if (visit == 1) stopping.Cancel(); },
        };
        var edge = Edge(entries);
        var matcher = new RequesterDaclProofs.OriginalPermissions(value => value.Evidence, stopping.Token);

        Assert.Throws<OperationCanceledException>(() => matcher.Matches(edge, Ace(7, Holder, 0x40000)));
        Assert.Equal(1, entries.Visits);
    }

    private static ControlEdge Edge(IReadOnlyList<PermissionEntry> entries) =>
        Derive(Permissions(Ace(0, Holder, 0x40000))).Edges.Single(edge => edge.Capability == ControlCapability.CanWriteDacl)
            with { Evidence = entries };
}

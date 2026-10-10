using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class CapturedMembershipPreparationTests
{
    [Fact]
    public void OneOwnedSourceAndIndexServeClassificationAndLaterIdentityLookups()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        var member = evidence.Principal("Member", "S-1-5-21-1-2-3-1200", "user");
        using var counts = new Counts(evidence.Generation);
        var prepared = evidence.Input(root, member).Prepare(CancellationToken.None);
        Assert.Same(prepared, prepared.Prepare(CancellationToken.None));
        for (var pass = 0; pass < 3; pass++)
        {
            var batch = Tier0Classifier.QualifyMany(evidence.Binding, [evidence.Target(root), evidence.Target(member)],
                prepared, routes: null);
            Assert.Equal(Tier0State.Established, batch.Classifications[0].State);
            Assert.Equal(root.DistinguishedName, prepared.FindUnique(root.DistinguishedName, CancellationToken.None)?.DistinguishedName);
        }
        Assert.Equal((1L, 1L), (counts.For("membership.source_snapshots"), counts.For("membership.captured_index_builds")));
    }

    [Theory]
    [InlineData("objects")]
    [InlineData("attributes")]
    [InlineData("bytes")]
    [InlineData("returned-bytes")]
    public void PreparedMembershipOwnsCollectionsAndBinaryValues(string changed)
    {
        var evidence = new Tier0TestEvidence();
        var bytes = SecureAD.Kernel.Security.Sid.ToBytes("S-1-5-21-1-2-3-512")!;
        var values = new List<AttributeValue> { new(0, null, bytes) };
        var attributes = new List<ObjectAttribute>
        {
            new("objectSid", AttributeCardinality.SingleValued, values),
            Tier0TestEvidence.Attribute("objectClass", "top", "group"),
        };
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512") with { Attributes = attributes };
        var target = evidence.Target(root);
        var objects = new List<ObjectAttributes> { evidence.Domain, root };
        var input = new CapturedMembershipInput(evidence.Generation, true, objects);
        var expected = JsonSerializer.Serialize(input);
        var prepared = input.Prepare(CancellationToken.None);
        switch (changed)
        {
            case "objects": objects.Clear(); break;
            case "attributes": attributes.Clear(); break;
            case "bytes": bytes[0] ^= 0xff; values.Clear(); break;
            default: prepared.Objects[1].Find("objectSid")!.OnlyValue!.Bytes![0] ^= 0xff; break;
        }
        Assert.Equal(expected, JsonSerializer.Serialize(prepared));
        Assert.Equal(Tier0State.Established, Tier0Classifier.Qualify(evidence.Binding, target, prepared, routes: null).State);
    }

    [Fact]
    public void MetadataCopiesShareTheIndexButReplacingObjectsCannotReuseIt()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        using var counts = new Counts(evidence.Generation);
        var prepared = evidence.Input(root).Prepare(CancellationToken.None);
        prepared.FindUnique(root.DistinguishedName, CancellationToken.None);
        var incomplete = prepared with { IsComplete = false };
        var answer = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(root), incomplete, routes: null);
        Assert.True(answer.Coverage.Limitations.HasFlag(Tier0Limitations.InputIncomplete));
        Assert.Equal(1L, counts.For("membership.captured_index_builds"));
        var changed = (prepared with { Objects = [evidence.Domain, root with { DistinguishedName = "CN=Other,DC=contoso,DC=com" }] })
            .Prepare(CancellationToken.None);
        Assert.Null(changed.FindUnique(root.DistinguishedName, CancellationToken.None));
        Assert.Equal((2L, 2L), (counts.For("membership.source_snapshots"), counts.For("membership.captured_index_builds")));
    }

    [Theory]
    [InlineData("dn")]
    [InlineData("sid")]
    [InlineData("guid")]
    public void PreparedIndexesKeepAmbiguousCapturedIdentitiesUnresolved(string changed)
    {
        var evidence = new Tier0TestEvidence();
        var first = evidence.Principal("First", "S-1-5-21-1-2-3-512");
        var second = evidence.Principal("Second", "S-1-5-21-1-2-3-1200");
        second = changed switch
        {
            "dn" => second with { DistinguishedName = first.DistinguishedName.ToLowerInvariant() },
            "sid" => second with { Attributes = first.Attributes },
            _ => second with { ObjectGuid = first.ObjectGuid },
        };
        var prepared = evidence.Input(first, second).Prepare(CancellationToken.None);
        Assert.Equal(3, prepared.Objects.Count);
        if (changed == "dn") Assert.Null(prepared.FindUnique(first.DistinguishedName, CancellationToken.None));
        var answer = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(first), prepared, routes: null);
        if (changed != "guid") Assert.Equal(Tier0State.Unknown, answer.State);
        else
        {
            // Core SID classification does not claim GUID uniqueness; CA-asset qualification is tested separately.
            Assert.Equal(Tier0State.Established, answer.State);
        }
    }

    [Fact]
    public void APreparedSourceMismatchStillRefusesClassificationWithoutIndexing()
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        using var counts = new Counts(evidence.Generation);
        var prepared = evidence.Input(root).Prepare(CancellationToken.None);
        var different = evidence.Binding with { DerivationGenerationId = Guid.NewGuid() };
        var answer = Tier0Classifier.Qualify(different, evidence.Target(root), prepared, routes: null);
        Assert.Equal(Tier0State.Unknown, answer.State);
        Assert.True(answer.Coverage.Limitations.HasFlag(Tier0Limitations.SourceMismatch));
        Assert.Equal(0L, counts.For("membership.captured_index_builds"));
    }

    [Fact]
    public void CancelledPreparationCannotPublishAPartialOwnedSource()
    {
        var evidence = new Tier0TestEvidence();
        using var cancellation = new CancellationTokenSource();
        using var counts = new Counts(evidence.Generation);
        var objects = new CancellingObjects(evidence.Input(evidence.Principal("Root", "S-1-5-21-1-2-3-512")).Objects,
            cancellation.Cancel);
        Assert.Throws<OperationCanceledException>(() =>
            new CapturedMembershipInput(evidence.Generation, true, objects).Prepare(cancellation.Token));
        Assert.Equal(0L, counts.For("membership.source_snapshots"));
    }

    [Theory]
    [InlineData("prepare")]
    [InlineData("lookup")]
    [InlineData("classify")]
    public void CancellationWinsBeforeReturningPreparedData(string operation)
    {
        var evidence = new Tier0TestEvidence();
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-512");
        var prepared = evidence.Input(root).Prepare(CancellationToken.None);
        prepared.FindUnique(root.DistinguishedName, CancellationToken.None);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() =>
        {
            if (operation == "prepare") prepared.Prepare(cancellation.Token);
            else if (operation == "lookup") prepared.FindUnique(root.DistinguishedName, cancellation.Token);
            else Tier0Classifier.Qualify(evidence.Binding, evidence.Target(root), prepared, routes: null, cancellation.Token);
        });
    }

    [Fact]
    public void PreparedSourceDoesNotRetainTheCallersCollections()
    {
        var (prepared, original) = PrepareDetached();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(original.IsAlive);
        Assert.NotEmpty(prepared.Objects);
        GC.KeepAlive(prepared);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (CapturedMembershipInput Prepared, WeakReference Original) PrepareDetached()
    {
        var evidence = new Tier0TestEvidence();
        var original = evidence.Input(evidence.Principal("Root", "S-1-5-21-1-2-3-512")).Objects.ToList();
        return (new CapturedMembershipInput(evidence.Generation, true, original).Prepare(CancellationToken.None), new(original));
    }

    private sealed class CancellingObjects(IReadOnlyList<ObjectAttributes> objects, Action cancel) : IReadOnlyList<ObjectAttributes>
    {
        public int Count => objects.Count;
        public ObjectAttributes this[int index] => objects[index];
        public IEnumerator<ObjectAttributes> GetEnumerator()
        {
            for (var index = 0; index < Count; index++)
            {
                if (index == 1) cancel();
                yield return objects[index];
            }
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    internal sealed class Counts : IDisposable
    {
        private readonly ConcurrentDictionary<string, long> _values = new(StringComparer.Ordinal);
        private readonly MeterListener _listener = new();

        internal Counts(Guid generation)
        {
            var identity = generation.ToString("D");
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name is CapturedMembershipInput.MeterName or "SecureAD.Judgement.MembershipPreparation")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Key == "derivation" && tag.Value is string current && current == identity)
                        _values.AddOrUpdate(instrument.Name, value, (_, previous) => previous + value);
            });
            _listener.Start();
        }

        internal long For(string name) => _values.GetValueOrDefault(name);
        public void Dispose() => _listener.Dispose();
    }
}

using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PathResultPackageTests
{
    [Fact]
    public void OneOwnedFixedTargetIndexServesEveryResultConsumerAndMetadataCopy()
    {
        var target = Target();
        var inputs = Inputs([target, target]);
        using var counts = new Counts(inputs.JudgementGenerationId);
        for (var use = 0; use < 128; use++) Assert.True(inputs.IsFixedTarget(target, CancellationToken.None));
        var copy = inputs with { Coverage = inputs.Coverage with { InputsComplete = false } };
        Assert.True(copy.IsFixedTarget(target, CancellationToken.None));
        Assert.Equal(2, inputs.FixedTargets.Count);
        Assert.Equal(1L, counts.Indexes);
    }

    [Fact]
    public void ReplacingFixedTargetsDoesNotRetainThePreviousLookup()
    {
        var target = Target();
        var inputs = Inputs([target]);
        using var counts = new Counts(inputs.JudgementGenerationId);
        Assert.True(inputs.IsFixedTarget(target, CancellationToken.None));
        var other = target with { ObjectGuid = Guid.NewGuid() };
        var changed = inputs with { FixedTargets = [other] };
        Assert.False(changed.IsFixedTarget(target, CancellationToken.None));
        Assert.True(changed.IsFixedTarget(other, CancellationToken.None));
        Assert.Equal(2L, counts.Indexes);
    }

    [Fact]
    public void FixedTargetPreparationOwnsTheOriginalOrderAndDuplicates()
    {
        var target = Target();
        var other = target with { DistinguishedName = "CN=Other,DC=contoso,DC=com" };
        var original = new List<Tier0Target> { target, other, target };
        var inputs = Inputs(original);
        var expected = JsonSerializer.Serialize(inputs.FixedTargets);
        original.Clear();
        Assert.Equal(expected, JsonSerializer.Serialize(inputs.FixedTargets));
        Assert.True(inputs.IsFixedTarget(target, CancellationToken.None));
        Assert.Throws<NotSupportedException>(() => ((IList<Tier0Target>)inputs.FixedTargets)[0] = other);
    }

    [Theory]
    [InlineData("guid")]
    [InlineData("dn-case")]
    [InlineData("sid")]
    [InlineData("scope")]
    public void FixedTargetLookupUsesExactIdentityRatherThanASimilarName(string changed)
    {
        var target = Target();
        var other = changed switch
        {
            "guid" => target with { ObjectGuid = Guid.NewGuid() },
            "dn-case" => target with { DistinguishedName = target.DistinguishedName.ToLowerInvariant() },
            "sid" => target with { Sid = "S-1-5-21-1-2-3-1200" },
            _ => target with { SidScope = "child.contoso.com" },
        };
        Assert.False(Inputs([target]).IsFixedTarget(other, CancellationToken.None));
    }

    [Fact]
    public void CancellationWinsBeforeReturningTheCachedTargetLookup()
    {
        var target = Target();
        var inputs = Inputs([target]);
        Assert.True(inputs.IsFixedTarget(target, CancellationToken.None));
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.Throws<OperationCanceledException>(() => inputs.IsFixedTarget(target, stopping.Token));
    }

    [Fact]
    public void PreparedTargetInputsDoNotRetainTheCallersCollection()
    {
        var (inputs, caller) = Detached();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(caller.IsAlive);
        Assert.Single(inputs.FixedTargets);
        GC.KeepAlive(inputs);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (PathInputs Inputs, WeakReference Caller) Detached()
    {
        var caller = new List<Tier0Target> { Target() };
        return (Inputs(caller), new(caller));
    }

    internal static Tier0Target Target() => new(Guid.NewGuid(), "CN=Target,DC=contoso,DC=com",
        "DC=contoso,DC=com", "contoso.com", "S-1-5-21-1-2-3-512", null);

    internal static PathInputs Inputs(IReadOnlyList<Tier0Target> targets) => new(Guid.NewGuid(), PathInputAvailability.Recorded,
        null, new(false, false, true, Tier0Limitations.InputIncomplete), targets, [], [], [], [], null);

    internal sealed class Counts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _values = new(StringComparer.Ordinal);

        internal Counts(Guid generation)
        {
            var key = generation.ToString("D");
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecureAD.Judgement.PathPackage") listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Key == "generation" && tag.Value is string current && current == key)
                        _values.AddOrUpdate(instrument.Name, value, (_, previous) => previous + value);
            });
            _listener.Start();
        }

        internal long Indexes => _values.GetValueOrDefault("path.fixed_target_indexes");
        public void Dispose() => _listener.Dispose();
    }
}

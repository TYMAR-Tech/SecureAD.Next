using System.Diagnostics.Metrics;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PathSourceFingerprintTests
{
    [Theory]
    [InlineData("requester")]
    [InlineData("missing-requester")]
    [InlineData("target")]
    [InlineData("missing-target")]
    [InlineData("permissions")]
    [InlineData("entry-order")]
    [InlineData("entry-ordinal")]
    [InlineData("entry-bytes")]
    [InlineData("holders")]
    [InlineData("holder-order")]
    [InlineData("roots")]
    [InlineData("root-order")]
    [InlineData("schema")]
    [InlineData("catalogue")]
    [InlineData("contexts")]
    [InlineData("forest")]
    public void ComponentSourceFingerprintStillBindsEveryOriginalSourceField(string changed)
    {
        var (description, inputs) = Binding();
        var source = Material();
        var original = Fingerprint(source, description, inputs);
        var modified = changed switch
        {
            "requester" => source with { Requester = source.Requester! with { ObjectGuid = Guid.NewGuid() } },
            "missing-requester" => source with { Requester = null },
            "target" => source with { Target = source.Target! with { DistinguishedName = "CN=Different,DC=contoso,DC=com" } },
            "missing-target" => source with { Target = null },
            "permissions" => source with { Permissions = source.Permissions! with { IsDaclProtected = true } },
            "entry-order" => source with { Permissions = source.Permissions! with { Entries = source.Permissions.Entries.Reverse().ToArray() } },
            "entry-ordinal" => source with { Permissions = source.Permissions! with
                { Entries = [source.Permissions.Entries[0] with { Ordinal = 99 }, source.Permissions.Entries[1]] } },
            "entry-bytes" => source with { Permissions = source.Permissions! with
                { Entries = [source.Permissions.Entries[0] with { ApplicationData = [1, 2, 3] }, source.Permissions.Entries[1]] } },
            "holders" => source with { Holders = [source.Holders[0] with { ObjectGuid = Guid.NewGuid() }, source.Holders[1]] },
            "holder-order" => source with { Holders = source.Holders.Reverse().ToArray() },
            "roots" => source with { Roots = [source.Roots[0] with { ObjectGuid = Guid.NewGuid() }, source.Roots[1]] },
            "root-order" => source with { Roots = source.Roots.Reverse().ToArray() },
            "schema" => source with { Schema = [source.Schema[0] with { ObjectGuid = Guid.NewGuid() }] },
            "catalogue" => source with { Catalogue = [new(Guid.NewGuid().ToString("D"), "different", SchemaGuidKind.Attribute, SchemaGuidSource.Captured)] },
            "contexts" => source with { Contexts = [new("DC=other,DC=example", NamingContextKind.Domain)] },
            "forest" => source with { Forest = "other.example" },
            _ => throw new ArgumentOutOfRangeException(nameof(changed)),
        };

        var fingerprint = Fingerprint(modified, description, inputs);

        Assert.NotEqual(original, fingerprint);
        Assert.Equal(SourceFingerprintReference.FromLegacy(PathSourceFamily.OwnAccountMembership, description, inputs, modified), fingerprint);
    }

    [Theory]
    [InlineData("judgement")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    [InlineData("derivation-seal")]
    [InlineData("availability")]
    public void ComponentSourceFingerprintsAreBoundToTheProducingGenerations(string changed)
    {
        var (description, inputs) = Binding();
        var material = Material();
        var original = Fingerprint(material, description, inputs);
        var next = changed switch
        {
            "judgement" => description with { GenerationId = Guid.NewGuid() },
            "evidence" => description with { EvidenceSeal = new string('c', 64) },
            "derivation" => description with { DerivationGenerationId = Guid.NewGuid() },
            _ => description,
        };
        var binding = inputs.Input! with { EvidenceSeal = next.EvidenceSeal, DerivationGenerationId = next.DerivationGenerationId!.Value };
        if (changed == "derivation-seal") binding = binding with { DerivationSeal = new string('d', 64) };
        var nextInputs = inputs with
        {
            JudgementGenerationId = next.GenerationId,
            Input = changed == "availability" ? null : binding,
            Availability = changed == "availability" ? PathInputAvailability.RequiredInputsUnavailable : inputs.Availability,
        };

        Assert.NotEqual(original, Fingerprint(material, next, nextInputs));
    }

    [Theory]
    [InlineData("judgement")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    public void ComponentPreparationRefusesMismatchedInputBindings(string changed)
    {
        var (description, inputs) = Binding();
        inputs = changed switch
        {
            "judgement" => inputs with { JudgementGenerationId = Guid.NewGuid() },
            "evidence" => inputs with { Input = inputs.Input! with { EvidenceSeal = new string('d', 64) } },
            _ => inputs with { Input = inputs.Input! with { DerivationGenerationId = Guid.NewGuid() } },
        };

        Assert.Throws<InvalidDataException>(() => Fingerprint(Material(), description, inputs));
    }

    [Theory]
    [InlineData(false, 100)]
    [InlineData(true, 100)]
    [InlineData(false, 50694)]
    [InlineData(true, 50694)]
    public void PreparedSourceComponentsAreNotRehashedForEachQuestion(bool requesterFamily, int questions)
    {
        var family = requesterFamily ? PathSourceFamily.RequesterDacl : PathSourceFamily.OwnAccountMembership;
        var (description, inputs) = Binding();
        var material = Material();
        var shared = new RequesterReuseTests.CountingList<string>(
            [.. Enumerable.Range(1, 9).Select(index => $"domain-{index}"), "schema"]);
        var holders = new RequesterReuseTests.CountingList<ObjectAttributes?>(material.Holders);
        var entries = new RequesterReuseTests.CountingList<PermissionEntry>(material.Permissions!.Entries);
        var values = new RequesterReuseTests.CountingList<AttributeValue>([new(0, "captured", null)]);
        var requester = material.Requester! with { Attributes = [new("description", AttributeCardinality.SingleValued, values)] };
        using var counts = new Counts(description.GenerationId);
        var builder = new PathSourceFingerprints(family, description, inputs, new { Shared = shared }, CancellationToken.None);
        var target = builder.PrepareTarget(material.Target, material.Permissions with { Entries = entries }, holders);
        var assessment = Assessment(description);
        string? first = null;

        for (var index = 0; index < questions; index++)
        {
            var actual = family == PathSourceFamily.OwnAccountMembership ? target.OwnAccount(requester) : target.RequesterDacl(requester, null, assessment);
            if (first is null) first = actual;
            Assert.Equal(first, actual);
        }

        Assert.Equal(10, shared.Visits);
        Assert.Equal(material.Holders.Count, holders.Visits);
        // The saved source includes both Entries and the computed OwnerRightsEntryIsPresent value.
        Assert.Equal(material.Permissions.Entries.Count * 2, entries.Visits);
        Assert.Equal(2, values.Visits); // Values and the saved OnlyValue projection.
        Assert.Equal((1L, 1L, 1L, (long)questions),
            (counts.Read(family, "shared"), counts.Read(family, "target"), counts.Read(family, "requester"), counts.Read(family, "question")));
    }

    [Fact]
    public void AChangedRequesterInstanceDoesNotBorrowThePreviousFingerprint()
    {
        var (description, inputs) = Binding();
        var material = Material();
        var target = new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs,
            material.Shared, CancellationToken.None).PrepareTarget(material.Target, material.Permissions, material.Holders);
        var original = target.OwnAccount(material.Requester);
        var changed = material.Requester! with { ObjectGuid = Guid.NewGuid() };

        Assert.NotEqual(original, target.OwnAccount(changed));
        Assert.Equal(original, target.OwnAccount(material.Requester));
    }

    [Theory]
    [InlineData("shared")]
    [InlineData("target")]
    [InlineData("question")]
    public void ComponentFingerprintingPreservesCancellation(string stage)
    {
        var (description, inputs) = Binding();
        using var stopping = new CancellationTokenSource();
        if (stage == "shared")
        {
            stopping.Cancel();
            Assert.Throws<OperationCanceledException>(() =>
                new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, new { }, stopping.Token));
            return;
        }
        var builder = new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, new { }, stopping.Token);
        if (stage == "target")
        {
            stopping.Cancel();
            Assert.Throws<OperationCanceledException>(() => builder.PrepareTarget(null, null, []));
            return;
        }
        var target = builder.PrepareTarget(null, null, []);
        stopping.Cancel();
        Assert.Throws<OperationCanceledException>(() => target.OwnAccount(null));
    }

    [Fact]
    public void ASerializationFailureDoesNotBecomeACompletedFingerprint()
    {
        var (description, inputs) = Binding();
        var failure = new IOException("Synthetic source failure");
        using var counts = new Counts(description.GenerationId);

        Assert.Same(failure, Assert.Throws<IOException>(() =>
            new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, new BrokenSource(failure), CancellationToken.None)));
        Assert.Equal(0, counts.Read(PathSourceFamily.OwnAccountMembership, "shared"));
    }

    [Fact]
    public void SourceFamiliesCannotSubstituteForEachOther()
    {
        var (description, inputs) = Binding();
        var own = new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, new { }, CancellationToken.None)
            .PrepareTarget(null, null, []);
        var requester = new PathSourceFingerprints(PathSourceFamily.RequesterDacl, description, inputs, new { }, CancellationToken.None)
            .PrepareTarget(null, null, []);

        Assert.Throws<InvalidDataException>(() => own.RequesterDacl(null, null, Assessment(description)));
        Assert.Throws<InvalidDataException>(() => requester.OwnAccount(null));
    }

    [Theory]
    [InlineData("judgement")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    public void ARequesterAnswerCannotBorrowAnotherSourceGeneration(string change)
    {
        var (description, inputs) = Binding();
        var target = new PathSourceFingerprints(PathSourceFamily.RequesterDacl, description, inputs, new { }, CancellationToken.None)
            .PrepareTarget(null, null, []);
        var assessment = Assessment(description);
        assessment = change switch
        {
            "judgement" => assessment with { GenerationId = Guid.NewGuid() },
            "evidence" => assessment with { EvidenceSeal = new string('f', 64) },
            _ => assessment with { DerivationGenerationId = Guid.NewGuid() },
        };

        Assert.Throws<InvalidDataException>(() => target.RequesterDacl(null, null, assessment));
    }

    private sealed class BrokenSource(IOException failure)
    {
        public string Evidence => throw failure;
    }

    private static RequesterDaclAssessment Assessment(JudgementDescription description) =>
        new(new("CN=User,DC=contoso,DC=com", "OU=Test,DC=contoso,DC=com"), description.GenerationId,
            description.DerivationGenerationId, description.EvidenceSeal, null, null, ControlEvaluationState.Unknown, [], [], [], []);

    private static (JudgementDescription Description, PathInputs Inputs) Binding()
    {
        var description = new JudgementDescription(new string('a', 64), Guid.NewGuid(), Guid.NewGuid(), JudgementRunState.Running,
            DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, default);
        var binding = new Tier0InputBinding(description.EvidenceSeal, description.DerivationGenerationId!.Value, new string('b', 64),
            PrincipalClassificationRegistry.Version, 2, 2, "DC=contoso,DC=com", "CN=Configuration,DC=contoso,DC=com");
        return (description, new(description.GenerationId, PathInputAvailability.Recorded, binding,
            new(false, false, false, Tier0Limitations.InputIncomplete), [], [], [], [], [], null));
    }

    private sealed record SourceMaterial(ObjectAttributes? Requester, ObjectAttributes? Target, ObjectPermissions? Permissions,
        IReadOnlyList<ObjectAttributes> Holders, IReadOnlyList<ObjectAttributes> Roots, IReadOnlyList<ObjectAttributes> Schema,
        IReadOnlyList<SchemaGuidEntry> Catalogue, IReadOnlyList<KeyValuePair<string, NamingContextKind>> Contexts, string Forest)
    {
        internal object Shared => new { Roots, Schema, Catalogue, Contexts, Forest };
    }

    private static SourceMaterial Material() => new(Subject with { DistinguishedName = "CN=User,DC=contoso,DC=com" },
        Subject, Permissions(Ace(3, Holder, 0x40000), Ace(7, Holder, 0x80000)),
        [Subject, Subject with { DistinguishedName = "CN=Other,DC=contoso,DC=com" }],
        [Subject with { DistinguishedName = "DC=contoso,DC=com" }, Subject with { DistinguishedName = "DC=child,DC=contoso,DC=com" }],
        [Subject with { DistinguishedName = "CN=Member,CN=Schema,CN=Configuration,DC=contoso,DC=com" }],
        [new("bf9679c0-0de6-11d0-a285-00aa003049e2", "member", SchemaGuidKind.Attribute, SchemaGuidSource.Captured)],
        [new("DC=contoso,DC=com", NamingContextKind.Domain)], "contoso.com");

    private static string Fingerprint(SourceMaterial source, JudgementDescription description, PathInputs inputs) =>
        new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, source.Shared, CancellationToken.None)
            .PrepareTarget(source.Target, source.Permissions, source.Holders).OwnAccount(source.Requester);

    internal sealed class Counts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly Dictionary<(PathSourceFamily Family, string Component), long> _counts = [];

        internal Counts(Guid generation)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "SecureAD.Judgement.PathSources" && instrument.Name == "path_source.fingerprints")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                Guid? source = null;
                PathSourceFamily? family = null;
                string? component = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "generation" && tag.Value is Guid id) source = id;
                    if (tag.Key == "family" && tag.Value is PathSourceFamily kind) family = kind;
                    if (tag.Key == "component" && tag.Value is string part) component = part;
                }
                if (source != generation || family is null || component is null) return;
                lock (_counts) _counts[(family.Value, component)] = _counts.GetValueOrDefault((family.Value, component)) + value;
            });
            _listener.Start();
        }

        internal long Read(PathSourceFamily family, string component)
        {
            lock (_counts) return _counts.GetValueOrDefault((family, component));
        }

        public void Dispose() => _listener.Dispose();
    }
}

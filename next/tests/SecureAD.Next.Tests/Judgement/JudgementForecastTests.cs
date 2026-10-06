using System.Buffers.Binary;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Measure;
using Xunit;
using SdBytes = global::SecureAD.Next.Tests.Kernel.Security.SdBytes;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// The read-only forecast of how large a judgement will be, checked against the thing it forecasts.
/// </summary>
/// <remarks>
/// <para>
/// <b>What these guard is the count, not the arithmetic.</b> The projected byte totals are a model
/// and are checked where a real judgement exists to check them against; what cannot be allowed to
/// go wrong silently is <i>what is being counted</i>. <c>descriptor_entry</c> and
/// <c>captured_object.ace_count</c> are one cheap column away and hold the canonical projection,
/// which is sorted and deduplicated. Judging writes one row per entry read back out of the stored
/// bytes. A forecast built on the cheap column would agree with itself, report a plausible figure,
/// and be wrong by however much deduplication removed - which is the shape of defect that passes
/// while measuring nothing.
/// </para>
/// <para>
/// Bundles are written beneath the system temporary directory and left there, per the repository's
/// testing rules; the path is in the failure message when one fails.
/// </para>
/// </remarks>
public sealed class JudgementForecastTests
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-forecast-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 25, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 25, 11, 30, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string AliceDn = "CN=Alice," + DomainDn;
    private const string BobDn = "CN=Bob," + DomainDn;
    private const string AdminsSid = "S-1-5-32-544";

    // -------------------------------------------------------------------------------------------
    // What is counted
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A DACL carrying the same grant twice produces two judgement rows, and the forecast has to
    /// say two.
    /// </summary>
    /// <remarks>
    /// The one defect this whole class exists for. The deduplicated projection would say one, and
    /// a forecast reading it would be quietly short by exactly the entries the directory repeats.
    /// </remarks>
    [Fact]
    public void TheSameEntryTwiceInOneDaclIsTwoOccurrences()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry()));

        Assert.Equal(2, JudgementForecast.Of(_directory).Occurrences);
    }

    /// <summary>
    /// The fixture really does put the two counts in disagreement, so the test above cannot pass by
    /// measuring the same thing twice.
    /// </summary>
    /// <remarks>
    /// Without this, a fixture whose stored and projected entry counts happened to be equal would
    /// let a forecast reading the wrong column pass. This is the negative control for that.
    /// </remarks>
    [Fact]
    public void TheDeduplicatedProjectionOfThatDaclHoldsOnlyOneEntry()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry()));

        Assert.Equal(1, ProjectedEntries());
    }

    /// <summary>
    /// A descriptor two objects share is one stored descriptor and two objects' worth of rows.
    /// </summary>
    [Fact]
    public void ADescriptorSharedByTwoObjectsIsCountedForEachOfThem()
    {
        WriteSharedDescriptor();

        Assert.Equal(6, JudgementForecast.Of(_directory).Occurrences);
    }

    /// <summary>
    /// Parsing each distinct descriptor once must not be visible as a descriptor being counted once.
    /// </summary>
    [Fact]
    public void TwoObjectsSharingADescriptorStoreOnlyOneOfIt()
    {
        WriteSharedDescriptor();

        Assert.Equal(1, JudgementForecast.Of(_directory).DescriptorsUsedByObjects);
    }

    // -------------------------------------------------------------------------------------------
    // What the name costs
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The name is paid for once per occurrence row, not once per object.
    /// </summary>
    /// <remarks>
    /// Three entries on each of two objects means each name is written three times over, and this
    /// is the number the whole decision about an integer identifier rests on. Summed per object
    /// rather than taken from an average, so a forest where the most-reused descriptors carry the
    /// longest lists is measured rather than assumed away.
    /// </remarks>
    [Fact]
    public void TheNameIsPaidForOncePerOccurrenceRatherThanOncePerObject()
    {
        WriteSharedDescriptor();

        Assert.Equal(
            3 * (AliceDn.Length + BobDn.Length),
            JudgementForecast.Of(_directory).DistinguishedNameBytesAcrossOccurrences);
    }

    /// <summary>
    /// A name outside ASCII costs more bytes than it has characters, and the bytes are what is paid.
    /// </summary>
    /// <remarks>
    /// SQLite's <c>length</c> counts characters on text and bytes on a blob, and the store holds
    /// UTF-8. Counting characters would understate every forest with a name outside ASCII in it,
    /// which a directory of people's names certainly has.
    /// </remarks>
    [Fact]
    public void ANameOutsideAsciiCostsMoreBytesThanItHasCharacters()
    {
        const string Accented = "CN=Zo\u00eb," + DomainDn;
        WriteBundle(writer => WriteObject(writer, Accented, Twice(), OneCanonicalEntry()));

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(Accented.Length + 1, forecast.MeanNameBytesPerObject);
    }

    // -------------------------------------------------------------------------------------------
    // What is not counted
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// An object whose permissions could not be read carries no occurrences, and is still an object.
    /// </summary>
    /// <remarks>
    /// 280,871 of the production capture's 940,067 objects are in this state. Counting them as
    /// zero-entry objects is right; leaving them out of the object count would understate the other
    /// table, and treating them as though they had entries would invent permissions outright.
    /// </remarks>
    [Fact]
    public void AnObjectWithNoReadableDescriptorAddsNoOccurrences()
    {
        WriteBundle(writer =>
        {
            WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry());
            writer.WriteObject(ObjectAt(BobDn));
        });

        Assert.Equal(2, JudgementForecast.Of(_directory).Occurrences);
    }

    /// <summary>It is still captured, and the object table will still hold a row for it.</summary>
    [Fact]
    public void AnObjectWithNoReadableDescriptorIsStillACapturedObject()
    {
        WriteBundle(writer =>
        {
            WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry());
            writer.WriteObject(ObjectAt(BobDn));
        });

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(2, forecast.ObjectsCaptured);
        Assert.Equal(1, forecast.ObjectsWithReadablePermissions);
    }

    /// <summary>
    /// A bundle nothing could be read from is refused by name rather than forecast as zero.
    /// </summary>
    [Fact]
    public void ABundleWithNoReadablePermissionsIsRefusedRatherThanForecastAsNothing()
    {
        WriteBundle(writer => writer.WriteObject(ObjectAt(AliceDn)));

        var error = Assert.Throws<InvalidDataException>(() => JudgementForecast.Of(_directory));
        Assert.Contains("no permission occurrences", error.Message, StringComparison.Ordinal);
    }

    /// <summary>A directory that is not a bundle is named as such, not met with a stack trace.</summary>
    [Fact]
    public void ADirectoryThatIsNotABundleIsRefusedByName()
    {
        Directory.CreateDirectory(_directory);

        var error = Assert.Throws<InvalidDataException>(() => JudgementForecast.Of(_directory));
        Assert.Contains("no sealed evidence file", error.Message, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // What could not be read
    // -------------------------------------------------------------------------------------------
    //
    // P-284. The bundle keeping bytes for an object and those bytes yielding a DACL are two
    // different facts, and the forecast was answering the first while labelling it the second. A
    // stored but unparseable descriptor arrived as one object with readable permissions and zero
    // occurrences - could not compute reported as found nothing, which is the one thing an audit
    // tool may not do. Each count below is held separately, because an operator deciding whether a
    // run will fit needs to know whether a small total is a small forest or a forest nobody read.

    /// <summary>
    /// An object whose stored descriptor cannot be parsed is not an object with readable
    /// permissions.
    /// </summary>
    /// <remarks>
    /// The defect itself. Bob's bytes are there and yield nothing, and before this he was counted
    /// beside Alice as though the product had read him and found he carried no permissions.
    /// </remarks>
    [Fact]
    public void AnObjectWhoseStoredDescriptorCannotBeParsedHasNoReadablePermissions()
    {
        WriteAliceReadableAndBobUnreadable();

        Assert.Equal(1, JudgementForecast.Of(_directory).ObjectsWithReadablePermissions);
    }

    /// <summary>
    /// He still has a descriptor stored, which is the fact the old count was actually measuring.
    /// </summary>
    /// <remarks>
    /// The negative control for the test above. Without it, a forecast that simply dropped
    /// unparseable objects from every count would pass - and that is the opposite error, losing the
    /// evidence that the product could not read something.
    /// </remarks>
    [Fact]
    public void AnObjectWhoseStoredDescriptorCannotBeParsedStillHasOneStored()
    {
        WriteAliceReadableAndBobUnreadable();

        Assert.Equal(2, JudgementForecast.Of(_directory).ObjectsWithADescriptorStored);
    }

    /// <summary>He is counted as unreadable, so the gap is a number rather than a subtraction.</summary>
    [Fact]
    public void AnObjectWhoseStoredDescriptorCannotBeParsedIsCountedAsUnreadable()
    {
        WriteAliceReadableAndBobUnreadable();

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(1, forecast.ObjectsWithAnUnreadableDescriptor);
        Assert.Equal(1, forecast.DescriptorsUnreadable);
    }

    /// <summary>And he contributes no occurrences, because judging will write none for him.</summary>
    [Fact]
    public void AnUnreadableDescriptorAddsNoOccurrences()
    {
        WriteAliceReadableAndBobUnreadable();

        Assert.Equal(2, JudgementForecast.Of(_directory).Occurrences);
    }

    /// <summary>
    /// One unreadable descriptor carried by two objects is one descriptor and two objects.
    /// </summary>
    /// <remarks>
    /// The two levels are reported apart because they are different problems at the same object
    /// count: one malformed descriptor inherited by fifty thousand objects is one thing to look at,
    /// and fifty thousand distinct malformed descriptors is a broken directory.
    /// </remarks>
    [Fact]
    public void AnUnreadableDescriptorSharedByTwoObjectsIsOneDescriptorAndTwoObjects()
    {
        var unreadable = UnparseableDacl();

        WriteBundle(writer =>
        {
            WriteObject(writer, AliceDn, unreadable, NothingCouldBeParsed());
            WriteObject(writer, BobDn, unreadable, NothingCouldBeParsed());
        });

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(2, forecast.ObjectsWithAnUnreadableDescriptor);
        Assert.Equal(1, forecast.DescriptorsUnreadable);
    }

    /// <summary>
    /// A DACL that yielded only some of the entries it declared says so, rather than passing its
    /// survivors off as the whole list.
    /// </summary>
    [Fact]
    public void ADaclThatYieldedOnlySomeOfItsEntriesIsCountedAsPartlyParsed()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, PartlyParsedDacl(), SomeWentMissing()));

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(1, forecast.ObjectsWithAPartiallyParsedDescriptor);
        Assert.Equal(1, forecast.DescriptorsPartiallyParsed);
    }

    /// <summary>
    /// It contributes the entries that parsed, never the number its header declared.
    /// </summary>
    /// <remarks>
    /// The fixture declares five and yields two. Judging writes one row per entry it could read, so
    /// two is the correct forecast and five would be three rows that never exist - a shortfall
    /// hidden inside the very number it corrupted. This is why the count above is held beside the
    /// occurrence total instead of being folded into it.
    /// </remarks>
    [Fact]
    public void APartlyParsedDaclContributesItsSurvivorsAndNotWhatItDeclared()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, PartlyParsedDacl(), SomeWentMissing()));

        Assert.Equal(2, JudgementForecast.Of(_directory).Occurrences);
    }

    /// <summary>
    /// Partly parsed is still readable. Some of the DACL was read, and what it said is true.
    /// </summary>
    /// <remarks>
    /// Kept apart from the unreadable case deliberately: <see cref="DaclState.Unreadable"/> is set
    /// only when a DACL declared entries and yielded none, and a DACL that yielded some stays
    /// <see cref="DaclState.Present"/>. Counting this object as unreadable would discard permissions
    /// the product did read and must report.
    /// </remarks>
    [Fact]
    public void APartlyParsedDaclIsStillCountedAsReadablePermissions()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, PartlyParsedDacl(), SomeWentMissing()));

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(1, forecast.ObjectsWithReadablePermissions);
        Assert.Equal(0, forecast.ObjectsWithAnUnreadableDescriptor);
    }

    /// <summary>
    /// A bundle whose every descriptor is unreadable is forecast at zero, not refused.
    /// </summary>
    /// <remarks>
    /// Refusing it would be the same substitution one layer up - silence where the answer is that
    /// the product could not read anything. The refusal is kept for a bundle with no descriptor
    /// stored at all, which is a different fact and has its own test above.
    /// </remarks>
    [Fact]
    public void ABundleWhoseDescriptorsAllFailToParseIsForecastRatherThanRefused()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, UnparseableDacl(), NothingCouldBeParsed()));

        var forecast = JudgementForecast.Of(_directory);

        Assert.Equal(0, forecast.Occurrences);
        Assert.Equal(0, forecast.ObjectsWithReadablePermissions);
        Assert.Equal(1, forecast.ObjectsWithAnUnreadableDescriptor);
    }

    // -------------------------------------------------------------------------------------------
    // Nothing is written
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Forecasting a bundle leaves it byte for byte as it was, which is what makes it safe to run
    /// against a customer's only copy.
    /// </summary>
    [Fact]
    public void ForecastingWritesNothingToTheBundle()
    {
        WriteBundle(writer => WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry()));
        var before = BundleSealing.HashFile(BundleLayout.EvidencePath(_directory));

        JudgementForecast.Of(_directory);

        Assert.Equal(before, BundleSealing.HashFile(BundleLayout.EvidencePath(_directory)));
    }

    // -------------------------------------------------------------------------------------------
    // What each shape would cost
    // -------------------------------------------------------------------------------------------

    /// <summary>The name is paid for in the row, the primary key and the unique index.</summary>
    [Fact]
    public void TheNameIsPaidForInThreePlaces()
    {
        var withName = JudgementForecast.RowModel.AsItStands(rows: 100, keyBytesAcrossRows: 10_000, 0, 0);
        var withNothing = JudgementForecast.RowModel.AsItStands(rows: 100, keyBytesAcrossRows: 0, 0, 0);

        Assert.Equal(3 * 10_000, withName - withNothing);
    }

    /// <summary>
    /// An entry carrying an object type pays for the GUID on every occurrence of it.
    /// </summary>
    /// <remarks>
    /// The calibration bundle has none at all, so this part of the model cannot be checked against
    /// a real judgement and has to be held here instead. It matters: a GUID is stored as text, so
    /// each one is 36 bytes on every row that carries it.
    /// </remarks>
    [Fact]
    public void AnEntryCarryingAnObjectTypePaysForTheGuidOnEveryOccurrence()
    {
        var without = JudgementForecast.RowModel.AsItStands(rows: 1_000, keyBytesAcrossRows: 0, 0, 0);
        var with = JudgementForecast.RowModel.AsItStands(rows: 1_000, keyBytesAcrossRows: 0, objectTypes: 1_000, 0);

        Assert.Equal(1_000 * JudgementForecast.RowModel.GuidAsText, with - without);
    }

    /// <summary>
    /// Moving the classification off the occurrence row takes the fingerprint and both GUIDs with it.
    /// </summary>
    /// <remarks>
    /// This is the whole of the difference between keying per descriptor and normalising as well:
    /// five values that are functions of the entry stop being copied onto each occurrence of it.
    /// </remarks>
    [Fact]
    public void NormalisingTakesTheFingerprintOffEveryOccurrenceRow()
    {
        const long Rows = 1_000_000;

        var perDescriptor = JudgementForecast.RowModel.WithIntegerKey(Rows, objectTypes: Rows, inheritedTypes: 0);
        var normalised = JudgementForecast.RowModel.Normalised(Rows, distinctEntries: 1_000);

        Assert.True(normalised < perDescriptor);
        Assert.True(perDescriptor - normalised > Rows * JudgementForecast.RowModel.Fingerprint);
    }

    // -------------------------------------------------------------------------------------------
    // What the tool was asked to do
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Nothing unrecognised starts the Self-Membership sweep, whatever it looks like.
    /// </summary>
    /// <remarks>
    /// Found in the field on 2026-09-24, and it cost the owner a production session. Every other
    /// mode is asked for by name and the sweep was what ran when none of them matched, so a missing
    /// flag or a single mistyped letter started a synthetic benchmark that builds forests for
    /// twenty minutes and looks the whole time like work being done. No capture was harmed - the
    /// sweep writes only beneath the temporary directory - but no measurement was taken either.
    /// </remarks>
    [Theory]
    [InlineData]
    [InlineData("--judgement-forcast", @"C:\run")]
    [InlineData("--judgement-forecast", @"C:\run")]
    [InlineData("--descriptor-redundancy", @"C:\run")]
    [InlineData(@"C:\run")]
    [InlineData("0")]
    [InlineData("-1")]
    public void NothingUnrecognisedStartsTheSelfMembershipSweep(params string[] args)
    {
        Assert.False(Program.AsksForTheSweep(args));
    }

    /// <summary>The sweep is still reachable, by the leading repeat count that has always meant it.</summary>
    [Theory]
    [InlineData("3")]
    [InlineData("1", "20000", "2000", "5")]
    [InlineData("3", "--production", "0.05")]
    public void ALeadingRepeatCountStillAsksForTheSweep(params string[] args)
    {
        Assert.True(Program.AsksForTheSweep(args));
    }

    // -------------------------------------------------------------------------------------------
    // Which build produced the figures
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A single-file build hashes its own executable, because there the executable is the code.
    /// </summary>
    /// <remarks>
    /// This is the case that crashed. <c>Assembly.Location</c> is empty under a single-file
    /// publish, and hashing it threw on startup - in the one build shape the owner would carry
    /// into production, where it would have cost him the trip rather than a minute here.
    /// </remarks>
    [Fact]
    public void ASingleFileBuildIsNamedByItsExecutable()
    {
        var executable = WriteFile("carried.exe");

        var (hash, covers) = JudgementForecast.Provenance(assemblyLocation: "", executable);

        Assert.Equal(BundleSealing.HashFile(executable), hash);
        Assert.Contains("single-file", covers, StringComparison.Ordinal);
    }

    /// <summary>
    /// An ordinary build is named by its assembly, because its executable is only a launcher.
    /// </summary>
    /// <remarks>
    /// The Debug and Release launchers of this very tool measured byte-identical, so a hash of one
    /// distinguishes nothing. Hashing the executable here would be a provenance field that reports
    /// the same value for two different builds.
    /// </remarks>
    [Fact]
    public void AnOrdinaryBuildIsNamedByItsAssemblyRatherThanItsLauncher()
    {
        var assembly = WriteFile("SecureAD.Measure.dll");
        var launcher = WriteFile("SecureAD.Measure.exe");

        var (hash, _) = JudgementForecast.Provenance(assembly, launcher);

        Assert.Equal(BundleSealing.HashFile(assembly), hash);
        Assert.NotEqual(BundleSealing.HashFile(launcher), hash);
    }

    /// <summary>Neither available is said, not thrown.</summary>
    [Fact]
    public void ABuildThatCanNameNeitherSaysSoRatherThanFailing()
    {
        var (hash, covers) = JudgementForecast.Provenance(assemblyLocation: null, processPath: null);

        Assert.Equal("unknown", hash);
        Assert.Contains("Neither", covers, StringComparison.Ordinal);
    }

    /// <summary>A file whose contents are its own name, so two of them never hash alike.</summary>
    private string WriteFile(string name)
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, name);
        return path;
    }

    // -------------------------------------------------------------------------------------------
    // Fixtures
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// Alice and Bob under one descriptor of three distinct entries: six occurrences, one
    /// descriptor.
    /// </summary>
    private void WriteSharedDescriptor()
    {
        byte[] raw = SdBytes.SelfRelativeSd(
            ownerSid: null,
            daclAces: [Allow(0x10), Allow(0x20), Allow(0x40)]);

        var normalization = Canonical(Entry(0x10), Entry(0x20), Entry(0x40));

        WriteBundle(writer =>
        {
            WriteObject(writer, AliceDn, raw, normalization);
            WriteObject(writer, BobDn, raw, normalization);
        });
    }

    /// <summary>
    /// A descriptor whose stored bytes carry one grant twice.
    /// </summary>
    /// <remarks>
    /// This is not a contrived shape. A DACL carrying the same grant at two positions is what the
    /// directory holds when it holds one, and <c>ObjectPermissions</c> shows both because deciding
    /// it meant once is editing evidence.
    /// </remarks>
    private static byte[] Twice() =>
        SdBytes.SelfRelativeSd(ownerSid: null, daclAces: [Allow(0x10), Allow(0x10)]);

    /// <summary>
    /// Alice, whose two entries parse, beside Bob, whose descriptor is stored and yields nothing.
    /// </summary>
    private void WriteAliceReadableAndBobUnreadable() =>
        WriteBundle(writer =>
        {
            WriteObject(writer, AliceDn, Twice(), OneCanonicalEntry());
            WriteObject(writer, BobDn, UnparseableDacl(), NothingCouldBeParsed());
        });

    /// <summary>
    /// A DACL whose header declares two entries and is followed by bytes that are not an entry.
    /// </summary>
    /// <remarks>
    /// The four bytes are an ACE header claiming a four-byte ACE, which cannot hold an access mask
    /// and a trustee, so nothing parses. The parser answers <see cref="DaclState.Unreadable"/>
    /// rather than <see cref="DaclState.Empty"/>, which is the distinction
    /// <c>docs/decisions/0037-an-unreadable-dacl-says-so.md</c> exists for: what this object grants
    /// is unknown, and it is not the most locked-down object it is possible to be.
    /// </remarks>
    private static byte[] UnparseableDacl()
    {
        var sd = SdBytes.SelfRelativeSd(ownerSid: null, daclAces: []);
        var daclOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(16));

        byte[] notAnAce = [0x00, 0x00, 0x04, 0x00];
        var built = new byte[daclOffset + 8 + notAnAce.Length];
        sd.AsSpan(0, daclOffset + 8).CopyTo(built);
        notAnAce.CopyTo(built.AsSpan(daclOffset + 8));

        var dacl = built.AsSpan(daclOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(dacl[2..], (ushort)(8 + notAnAce.Length));
        BinaryPrimitives.WriteUInt16LittleEndian(dacl[4..], 2);

        return built;
    }

    /// <summary>
    /// A DACL that declares five entries and yields the two it actually carries.
    /// </summary>
    /// <remarks>
    /// The shortfall is what makes this worth a fixture: the survivors are real permissions and
    /// must be forecast, and the three that did not arrive must not be.
    /// </remarks>
    private static byte[] PartlyParsedDacl()
    {
        var sd = SdBytes.SelfRelativeSd(ownerSid: null, daclAces: [Allow(0x10), Allow(0x20)]);
        var daclOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(sd.AsSpan(16));
        BinaryPrimitives.WriteUInt16LittleEndian(sd.AsSpan(daclOffset + 4), 5);

        return sd;
    }

    /// <summary>What the capturing run recorded for <see cref="UnparseableDacl"/>.</summary>
    private static AceNormalizationResult NothingCouldBeParsed() => new(
        Guid.Empty,
        OwnerSid: null,
        GroupSid: null,
        DaclState.Unreadable,
        IsDaclProtected: false,
        [],
        Errors: ["The DACL declared 2 entries and none of them parsed."],
        DaclCompleteness.Unknown,
        DaclWasCanonical: false);

    /// <summary>What the capturing run recorded for <see cref="PartlyParsedDacl"/>.</summary>
    private static AceNormalizationResult SomeWentMissing() => new(
        Guid.Empty,
        OwnerSid: null,
        GroupSid: null,
        DaclState.Present,
        IsDaclProtected: false,
        [Entry(0x10), Entry(0x20)],
        Errors: [],
        DaclCompleteness.Incomplete,
        DaclWasCanonical: true);

    /// <summary>
    /// What <see cref="AceNormalizer"/> yields for <see cref="Twice"/>: the pair collapsed to one.
    /// </summary>
    private static AceNormalizationResult OneCanonicalEntry() => Canonical(Entry(0x10));

    private static byte[] Allow(int mask) => SdBytes.AllowAce(SdBytes.Administrators, mask);

    private static AceNormalizationResult Canonical(params CanonicalAce[] aces) => new(
        Guid.Empty,
        OwnerSid: null,
        GroupSid: null,
        DaclState.Present,
        IsDaclProtected: false,
        aces,
        Errors: [],
        DaclCompleteness.Complete,
        DaclWasCanonical: true);

    private static CanonicalAce Entry(int mask) => new(
        AceType.AccessAllowed,
        AdminsSid,
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        ApplicationData: default,
        AceHash: $"AccessAllowed-{AdminsSid}-{mask:X8}",
        CanonicalizationVersion: AceCanonicalization.Version);

    private static void WriteObject(
        BundleWriter writer, string dn, byte[] raw, AceNormalizationResult normalization) =>
        writer.WriteSecurityDescriptor(writer.WriteObject(ObjectAt(dn)), raw, normalization);

    private void WriteBundle(Action<BundleWriter> write)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(SomeCoverage());
        write(writer);
        writer.Complete(OneDomainRead(), Finished);
    }

    /// <summary>How many entries the canonical projection kept, read straight out of the bundle.</summary>
    private long ProjectedEntries()
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(_directory),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM descriptor_entry";
        return (long)command.ExecuteScalar()!;
    }

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        DomainDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static EvidenceObject ObjectAt(string dn) =>
        new(SomeCoverage(), dn, Guid.NewGuid(), [], Started);
}

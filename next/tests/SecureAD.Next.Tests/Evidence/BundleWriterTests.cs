using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The bundle's write half: what a finished run leaves on disk, what an unfinished one leaves,
/// and what the two writers put in the file.
/// </summary>
/// <remarks>
/// These run against a real SQLite file rather than an in-memory one, deliberately. Half of what
/// is being asserted is about files - which exist, what they are called, and whether the
/// write-ahead log was folded back in before the seal was taken - and none of that is observable
/// in memory.
/// </remarks>
public sealed class BundleWriterTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-bundle-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 8, 21, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 21, 11, 30, 0, TimeSpan.Zero);

    // ---------------------------------------------------------------------------------------
    // What a run leaves behind
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AFinishedRunLeavesEvidenceASealAndAnAnnotationsFile()
    {
        CompleteAnEmptyBundle();

        Assert.True(File.Exists(BundleLayout.EvidencePath(_directory)));
        Assert.True(File.Exists(BundleLayout.SealPath(_directory)));
        Assert.True(File.Exists(BundleLayout.AnnotationsPath(_directory)));
    }

    [Fact]
    public void AFinishedRunLeavesNoPartialFile()
    {
        CompleteAnEmptyBundle();

        Assert.False(File.Exists(BundleLayout.PartialPath(_directory)));
    }

    /// <summary>
    /// The mechanism, stated as a test. An interrupted run leaves a file, and it is not the file a
    /// reader asks for - so a half-written bundle cannot be opened and read as a whole one without
    /// anyone having to remember to check.
    /// </summary>
    [Fact]
    public void AnInterruptedRunLeavesNothingAReaderCanOpen()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));

            // and the run dies here
        }

        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory)));
        Assert.True(File.Exists(BundleLayout.PartialPath(_directory)));
    }

    /// <summary>
    /// Nothing deletes a failed run's file. Reclaiming disk on a failure path destroys the only
    /// record of how far the run got, on a judgement made by the code that has just failed.
    /// </summary>
    [Fact]
    public void AnInterruptedRunsPartialFileIsLeftWhereItIs()
    {
        using (var writer = BundleWriter.Create(_directory, Started))
            writer.WriteCoverage(SomeCoverage());

        Assert.True(new FileInfo(BundleLayout.PartialPath(_directory)).Length > 0);
    }

    [Fact]
    public void ABundleIsNeverWrittenOver()
    {
        CompleteAnEmptyBundle();

        var error = Assert.Throws<InvalidOperationException>(
            () => BundleWriter.Create(_directory, Started));

        Assert.Contains("never written over", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NothingCanBeAddedAfterTheBundleIsSealed()
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.Complete(OneDomainRead(), Finished);

        Assert.Throws<InvalidOperationException>(() => writer.WriteCoverage(SomeCoverage()));
    }

    // ---------------------------------------------------------------------------------------
    // The seal
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AFinishedBundleVerifiesIntact()
    {
        CompleteAnEmptyBundle();

        var verdict = BundleSealing.Verify(_directory);

        Assert.Equal(SealState.Intact, verdict.State);
        Assert.True(verdict.MayBeOpened);
    }

    /// <summary>
    /// This is the check that would fail if the seal were taken before the write-ahead log was
    /// folded back in: the hash would cover a database that is not all there, and the bytes on
    /// disk would move under it.
    /// </summary>
    [Fact]
    public void TheSealCoversTheEvidenceAfterTheWriteAheadLogIsFoldedIn()
    {
        WriteAPopulatedBundle();

        Assert.Equal(SealState.Intact, BundleSealing.Verify(_directory).State);
        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory) + "-wal"));
    }

    [Fact]
    public void EditingTheEvidenceIsAMismatch()
    {
        WriteAPopulatedBundle();

        using (var connection = OpenForWriting(BundleLayout.EvidencePath(_directory)))
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE captured_object SET distinguished_name = 'CN=Mallory'";
            command.ExecuteNonQuery();
        }

        SqliteConnection.ClearAllPools();

        var verdict = BundleSealing.Verify(_directory);

        Assert.Equal(SealState.Mismatch, verdict.State);
        Assert.False(verdict.MayBeOpened);
    }

    /// <summary>
    /// The correction. A seal file that cannot be read is not an absent seal - the one thing that
    /// certainly happened is that something happened to the seal, and rendering that as "nobody
    /// ever sealed this" is a failure presented as a benign absence.
    /// </summary>
    [Fact]
    public void AnUnreadableSealIsNotReportedAsAnAbsentOne()
    {
        CompleteAnEmptyBundle();
        File.WriteAllText(BundleLayout.SealPath(_directory), "{ this is not json");

        var verdict = BundleSealing.Verify(_directory);

        Assert.Equal(SealState.Unreadable, verdict.State);
        Assert.False(verdict.MayBeOpened);
    }

    [Fact]
    public void ASealNamingAnAlgorithmThisBuildCannotComputeIsUnreadable()
    {
        CompleteAnEmptyBundle();
        File.WriteAllText(
            BundleLayout.SealPath(_directory), """{"Algorithm":"MD5","Hash":"abc"}""");

        Assert.Equal(SealState.Unreadable, BundleSealing.Verify(_directory).State);
    }

    [Fact]
    public void ARemovedSealIsAbsent()
    {
        CompleteAnEmptyBundle();
        File.Delete(BundleLayout.SealPath(_directory));

        var verdict = BundleSealing.Verify(_directory);

        Assert.Equal(SealState.Absent, verdict.State);
        Assert.False(verdict.MayBeOpened);
    }

    /// <summary>
    /// Every verdict says something a person can act on, including the one that passed. A caller
    /// rendering the detail must never render a blank.
    /// </summary>
    [Theory]
    [InlineData(SealState.Intact)]
    [InlineData(SealState.Absent)]
    [InlineData(SealState.Unreadable)]
    [InlineData(SealState.Mismatch)]
    public void EveryVerdictCarriesDetail(SealState state)
    {
        CompleteAnEmptyBundle();

        switch (state)
        {
            case SealState.Absent:
                File.Delete(BundleLayout.SealPath(_directory));
                break;
            case SealState.Unreadable:
                File.WriteAllText(BundleLayout.SealPath(_directory), "not json");
                break;
            case SealState.Mismatch:
                File.AppendAllText(BundleLayout.EvidencePath(_directory), "x");
                break;
        }

        var verdict = BundleSealing.Verify(_directory);

        Assert.Equal(state, verdict.State);
        Assert.True(verdict.Detail.Length > 40, $"'{verdict.Detail}' explains nothing.");
    }

    // ---------------------------------------------------------------------------------------
    // B9 - the object writer
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnAttributeThatDidNotComeBackLeavesItsColumnNull()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(
                    TextAttribute("cn", "Alice"),
                    new EvidenceAttribute(
                        "sAMAccountName", StoredAttributeCompleteness.NotReturned, [])));
        });

        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT cn, samaccountname FROM captured_object";

        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        Assert.Equal("Alice", reader.GetString(0));
        Assert.True(reader.IsDBNull(1), "An attribute that did not come back left a value behind.");
    }

    /// <summary>
    /// The other half of the same fact, and the reason no column records which happened: an
    /// attribute the object simply has no value for is stored exactly as one that was withheld,
    /// because per <c>docs/decisions/0022</c> the two are one emptiness on the wire.
    /// </summary>
    [Fact]
    public void AnAttributeWithNoValuesIsStoredTheSameWayAsOneThatDidNotComeBack()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(new EvidenceAttribute(
                    "sAMAccountName", StoredAttributeCompleteness.Complete, [])));
        });

        // Read through the reader rather than a scalar helper: a helper that renders null as an
        // empty string would pass this test while proving the opposite of what it claims.
        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT samaccountname FROM captured_object";

        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());
        Assert.True(reader.IsDBNull(0));
    }

    [Fact]
    public void ByteValuesAreStoredAsBytesAndNeverThroughAString()
    {
        var sid = new byte[] { 0x01, 0x05, 0x00, 0x00, 0x00, 0xFF, 0xFE };

        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(
                    new EvidenceAttribute(
                        "objectSid",
                        StoredAttributeCompleteness.Complete,
                        [EvidenceValue.OfBytes(sid)])));
        });

        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT objectsid, typeof(objectsid) FROM captured_object";

        using var reader = command.ExecuteReader();
        Assert.True(reader.Read());

        Assert.Equal(sid, (byte[])reader.GetValue(0));

        // SQLite stores what it is given rather than what the column declares, so the storage
        // class is asserted directly. A mangled string would satisfy the assertion above by
        // round-tripping and would read back as 'text' here.
        Assert.Equal("blob", reader.GetString(1));
    }

    [Fact]
    public void ValuesOfAMultiValuedAttributeGoToItsOwnTableInOrder()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(
                    new EvidenceAttribute(
                        "member",
                        StoredAttributeCompleteness.Complete,
                        [
                            EvidenceValue.OfText("CN=Alice"),
                            EvidenceValue.OfText("CN=Bob"),
                        ])));
        });

        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value FROM member_value ORDER BY ordinal";

        var members = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
            members.Add(reader.GetString(0));

        Assert.Equal(["CN=Alice", "CN=Bob"], members);
    }

    [Fact]
    public void AnAttributeCannotClaimNotToHaveArrivedAndAlsoCarryValues()
    {
        var error = Assert.Throws<InvalidOperationException>(() => WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(
                    new EvidenceAttribute(
                        "member",
                        StoredAttributeCompleteness.NotReturned,
                        [EvidenceValue.OfText("CN=Alice")])));
        }));

        Assert.Contains("did not come back", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The schema is derived from the catalogue, so an attribute the catalogue does not name has
    /// no column and no table. Dropping it silently would lose evidence that was read.
    /// </summary>
    [Fact]
    public void TheWriterRefusesAnAttributeTheCatalogueDoesNotName()
    {
        var error = Assert.Throws<InvalidOperationException>(() => WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectWith(TextAttribute("notInTheCatalogue", "x")));
        }));

        Assert.Contains("does not name", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// SQLite will not refuse this on its own. A column's declared type is an affinity rather than
    /// a constraint, so text bound to a <c>BLOB</c> column is stored as text and read back as text
    /// with no error - which is precisely the mangled value the storage split exists to prevent.
    /// </summary>
    [Fact]
    public void TheWriterRefusesAValueWhoseKindDisagreesWithTheCatalogue()
    {
        var error = Assert.Throws<InvalidOperationException>(() => WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectWith(TextAttribute("objectSid", "S-1-5-21")));
        }));

        Assert.Contains("catalogue declares it binary", error.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A single-valued attribute has one column, so a second value has nowhere to go and choosing
    /// between them would discard evidence.
    /// </summary>
    [Fact]
    public void TheWriterRefusesASecondValueForASingleValuedAttribute()
    {
        var error = Assert.Throws<InvalidOperationException>(() => WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                ObjectWith(
                    new EvidenceAttribute(
                        "cn",
                        StoredAttributeCompleteness.Complete,
                        [EvidenceValue.OfText("Alice"), EvidenceValue.OfText("Bob")])));
        }));

        Assert.Contains("single-valued", error.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------------------------------
    // B10 - the ACE writer
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ADescriptorThatCouldNotBeParsedIsDistinguishableFromAnObjectThatGrantsNothing()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            var unreadable = writer.WriteObject(ObjectWith(TextAttribute("cn", "Broken")));
            WriteDescriptor(
                writer,
                unreadable,
                Descriptor(DaclState.Present, [], ["ACE 3 extends past the end of the DACL"]));

            var grantsNothing = writer.WriteObject(ObjectWith(TextAttribute("cn", "Empty")));
            WriteDescriptor(writer, grantsNothing, Descriptor(DaclState.Empty, [], []));
        });

        // Both have no entries at all...
        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM ace"));

        // ...and the bundle can still tell them apart, which is the whole reason the error table
        // exists. Without it, "nobody knows what this object grants" reads as "this object grants
        // nothing".
        Assert.Equal(1, ScalarLong(ErrorsForObject(1)));
        Assert.Equal(0, ScalarLong(ErrorsForObject(2)));
    }

    /// <summary>
    /// Errors are stored per descriptor now that descriptors are deduplicated, so the question
    /// "what went wrong with this object's permissions" is asked through the link table.
    /// </summary>
    private static string ErrorsForObject(long objectId) =>
        "SELECT COUNT(*) FROM security_descriptor_error e "
        + "JOIN object_security_descriptor o ON o.descriptor_id = e.descriptor_id "
        + $"WHERE o.object_id = {objectId}";

    /// <summary>
    /// A null DACL and an empty DACL mean opposite things and both produce no entries, so the
    /// state is stored rather than inferred.
    /// </summary>
    [Theory]
    [InlineData(DaclState.Null)]
    [InlineData(DaclState.Empty)]
    [InlineData(DaclState.Present)]
    [InlineData(DaclState.Unreadable)]
    public void TheDaclStateIsStoredRatherThanInferredFromAnEmptyEntryList(DaclState state)
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(writer, objectId, Descriptor(state, [], []));
        });

        Assert.Equal(state.ToString(), ScalarText("SELECT dacl_state FROM security_descriptor"));
    }

    /// <summary>
    /// A DACL that yielded fewer entries than it declared is genuinely <c>Present</c>, so the
    /// shortfall has nowhere to live but its own column. Without it, an object under-reporting its
    /// permissions is indistinguishable from one that has exactly those permissions - and a missing
    /// allow entry is a permission the product will never report. See docs/decisions/0037.
    /// </summary>
    [Theory]
    [InlineData(DaclCompleteness.Complete)]
    [InlineData(DaclCompleteness.Incomplete)]
    [InlineData(DaclCompleteness.Unknown)]
    public void TheDaclCompletenessIsStored(DaclCompleteness completeness)
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(AliceGuid, DaclState.Present, [Ace("S-1-5-32-544", 0x000F01FF)], [],
                    completeness: completeness));
        });

        Assert.Equal(
            completeness.ToString(),
            ScalarText("SELECT dacl_completeness FROM security_descriptor"));
    }

    /// <summary>
    /// Whether the directory stored the DACL in canonical order, which normalisation destroys by
    /// sorting. See docs/decisions/0038.
    /// </summary>
    [Theory]
    [InlineData(true, 1L)]
    [InlineData(false, 0L)]
    public void WhetherTheDaclArrivedInCanonicalOrderIsStored(bool wasCanonical, long expected)
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(AliceGuid, DaclState.Present, [Ace("S-1-5-32-544", 0x000F01FF)], [],
                    wasCanonical: wasCanonical));
        });

        Assert.Equal(
            expected,
            ScalarLong("SELECT dacl_was_canonical FROM security_descriptor"));
    }

    /// <summary>
    /// The forest-wide question docs/decisions/0038 exists to make cheap: which objects hold their
    /// permissions in an order Windows will evaluate differently from the way this product reports
    /// them.
    /// </summary>
    [Fact]
    public void NonCanonicalDescriptorsCanBeFoundWithoutReadingEveryEntry()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            var tidy = Descriptor(
                DaclState.Present, [Ace("S-1-5-32-544", 0x000F01FF)], [], wasCanonical: true);
            var reordered = Descriptor(
                DaclState.Present, [Ace("S-1-5-21-9", 0x00000004)], [], wasCanonical: false);

            WriteDescriptor(
                writer, writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice"))), tidy);
            WriteDescriptor(
                writer, writer.WriteObject(ObjectWith(TextAttribute("cn", "Bob"))), reordered);
        });

        Assert.Equal(
            1,
            ScalarLong(
                "SELECT COUNT(*) FROM security_descriptor WHERE dacl_was_canonical = 0"));
    }

    /// <summary>
    /// An ACE type this product does not name is written to <c>ace_type</c> as its raw number.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is bound because it is currently an accident.</b> The column holds
    /// <c>ace.AceType.ToString()</c>, and .NET renders an undefined enum value as its number - so
    /// <c>0x12</c> lands as <c>"18"</c> rather than throwing or writing an empty string. Nothing
    /// said that was intended, and it is the entire query surface for <i>which entries did this
    /// product not model</i>: `SELECT ... WHERE ace_type GLOB '[0-9]*'`.
    /// </para>
    /// <para>
    /// A later tidy-up to <c>(int)ace.AceType</c>, a switch expression over the named members, or a
    /// converter would change or lose that with no other test noticing. `S-21` recorded the parser
    /// admitting unrecognised types in silence as `F-S21-5`; the reason that is a note rather than a
    /// defect is precisely that the evidence keeps them, so the evidence keeping them needs to be a
    /// guarantee rather than a happy accident.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(0x04, "4")]
    [InlineData(0x12, "18")]
    [InlineData(0x7F, "127")]
    public void AnAceTypeThisProductDoesNotNameIsStoredAsItsNumber(int typeByte, string expected)
    {
        var unmodelled = (AceType)typeByte;
        Assert.False(Enum.IsDefined(unmodelled), "This test is meaningless if the type is named.");

        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(DaclState.Present, [AceOfType(unmodelled, "S-1-5-32-544", 0x000F01FF)], []));
        });

        Assert.Equal(expected, ScalarText("SELECT ace_type FROM ace"));
    }

    /// <summary>
    /// And the query that finds them. Without this the column could hold the number and no reader
    /// would know to look for it.
    /// </summary>
    [Fact]
    public void EntriesThisProductDoesNotModelCanBeFoundByQueryingAceType()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(DaclState.Present,
                [
                    Ace("S-1-5-32-544", 0x000F01FF),
                    AceOfType((AceType)0x12, "S-1-5-21-9", 0x00000004),
                ], []));
        });

        Assert.Equal(
            1,
            ScalarLong("SELECT COUNT(*) FROM ace WHERE ace_type GLOB '[0-9]*'"));
    }

    /// <summary>
    /// An audit entry inside a DACL is a malformed descriptor, and finding those is owed to
    /// inventory row <c>E1</c> as <c>F-S21-7</c>. It is findable because the type is stored by name.
    /// </summary>
    /// <remarks>
    /// Since <c>docs/decisions/0036-capture-never-requests-the-sacl.md</c> capture never reads a
    /// SACL, so an audit entry can only have come from a DACL, where <c>[MS-DTYP]</c> does not
    /// permit it. It grants nothing - §2.5.3.2 gives it no part in evaluating a DACL - so it is
    /// correctly not dangerous, and the anomaly is a fact about the customer's forest rather than a
    /// permission verdict. This test exists so the rule that reports it has something to query.
    /// </remarks>
    [Theory]
    [InlineData(AceType.SystemAudit)]
    [InlineData(AceType.SystemAuditObject)]
    public void AnAuditEntryInADaclIsStoredByNameSoTheAnomalyCanBeFound(AceType auditType)
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(DaclState.Present,
                [AceOfType(auditType, "S-1-5-32-544", 0x00020000)], []));
        });

        Assert.Equal(
            auditType.ToString(),
            ScalarText("SELECT ace_type FROM ace"));

        Assert.Equal(
            1,
            ScalarLong(
                "SELECT COUNT(*) FROM ace WHERE ace_type IN ('SystemAudit', 'SystemAuditObject')"));
    }

    [Fact]
    public void InheritedEntriesAreStored()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
            WriteDescriptor(
                writer,
                objectId,
                Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x20, inherited: true)], []));
        });

        Assert.Equal(1, ScalarLong("SELECT COUNT(*) FROM ace WHERE is_inherited = 1"));
    }

    /// <summary>
    /// What survives of the deleted payload codec: one row per trustee for the whole forest, not
    /// one per object's list.
    ///
    /// <para>
    /// The entry count moved when descriptors were deduplicated. Five objects sharing one
    /// descriptor used to store five identical entries; they now store one, and the five objects
    /// reach it through <c>object_security_descriptor</c>. Each still reports its own
    /// <c>ace_count</c>, because "how many entries does this object have" is a question about the
    /// object even when the answer is shared.
    /// </para>
    /// </summary>
    [Fact]
    public void ATrusteeAppearingOnManyObjectsIsStoredOnce()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            for (var i = 0; i < 5; i++)
            {
                var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", $"O{i}")));
                WriteDescriptor(
                    writer,
                    objectId,
                    Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x20)], []));
            }
        });

        Assert.Equal(1, ScalarLong("SELECT COUNT(*) FROM ace"));
        Assert.Equal(1, ScalarLong("SELECT COUNT(*) FROM trustee"));
        Assert.Equal(5, ScalarLong("SELECT COUNT(*) FROM object_security_descriptor"));
        Assert.Equal(5, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE ace_count = 1"));
    }

    [Fact]
    public void TwoObjectsWithTheSameEntriesShareASetHashAndOneWithADifferentEntryDoesNot()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            var same = Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x20)], []);
            var different = Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x40)], []);

            WriteDescriptor(
                writer,
                writer.WriteObject(ObjectWith(TextAttribute("cn", "A"))), same);
            WriteDescriptor(
                writer,
                writer.WriteObject(ObjectWith(TextAttribute("cn", "B"))), same);
            WriteDescriptor(
                writer,
                writer.WriteObject(ObjectWith(TextAttribute("cn", "C"))), different);
        });

        Assert.Equal(2, ScalarLong("SELECT COUNT(DISTINCT ace_set_hash) FROM security_descriptor"));
    }

    // ---------------------------------------------------------------------------------------
    // Coverage
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A unit that asked a controller not to generate referrals cannot read an empty referral list
    /// as "there is nothing below here", so the suppression travels into the bundle rather than
    /// being flattened on the way in.
    /// </summary>
    [Fact]
    public void SuppressedReferralsAreRecordedSoAnEmptyListIsNotReadAsNothingBelow()
    {
        WriteBundle(writer => writer.WriteCoverage(
            SomeCoverage() with { ContinuationReferences = [], ReferralsSuppressed = true }));

        Assert.Equal(1, ScalarLong("SELECT referrals_suppressed FROM partition_coverage"));
        Assert.Equal(
            0,
            ScalarLong(
                "SELECT continuation_references_are_complete FROM partition_coverage"));
        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM continuation_reference"));
    }

    [Fact]
    public void TheBundleRecordsItsOwnAccountOfTheRun()
    {
        CompleteAnEmptyBundle();

        Assert.Equal("contoso.com", ScalarText("SELECT forest_fqdn FROM bundle"));
        Assert.Equal(BundleSchema.Version, (int)ScalarLong("SELECT schema_version FROM bundle"));
    }

    // ---------------------------------------------------------------------------------------
    // Exclusions. 0062: the whole attestation reaches the bundle, or an exclusion that governed
    // a run is a fact about the audit that the audit does not carry.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Everything <c>0062</c> asks for survives the trip into evidence.
    /// </summary>
    /// <remarks>
    /// The reason, the free text, both names and the time. The first person to need these is an
    /// auditor reading the run months later, with the operator unavailable and the screen long
    /// gone, so every field is checked rather than the row merely being present.
    /// </remarks>
    [Fact]
    public void AnExcludedDomainKeepsTheWholeAttestation()
    {
        var attestedUtc = new DateTimeOffset(2026, 9, 9, 11, 0, 0, TimeSpan.Zero);

        WriteBundle(writer => writer.RecordExcludedDomain(new AttestedExclusion(
            "DC=orphan,DC=contoso,DC=com",
            "orphan.contoso.com",
            ExclusionKind.ForWantOfCandidates,
            "credentials-not-held",
            "Waiting on the forest team.",
            @"CONTOSO\jistrand",
            "R. Zamus",
            attestedUtc)));

        Assert.Equal(
            "DC=orphan,DC=contoso,DC=com",
            ScalarText("SELECT naming_context_dn FROM excluded_domain"));
        Assert.Equal(
            nameof(ExclusionKind.ForWantOfCandidates),
            ScalarText("SELECT kind FROM excluded_domain"));
        Assert.Equal("credentials-not-held", ScalarText("SELECT reason FROM excluded_domain"));
        Assert.Equal("Waiting on the forest team.", ScalarText("SELECT note FROM excluded_domain"));
        Assert.Equal(@"CONTOSO\jistrand", ScalarText("SELECT run_by FROM excluded_domain"));
        Assert.Equal("R. Zamus", ScalarText("SELECT authorised_by FROM excluded_domain"));
        Assert.Contains(
            "2026-09-09", ScalarText("SELECT attested_utc FROM excluded_domain"),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The two kinds of exclusion are stored apart, never merged.
    /// </summary>
    /// <remarks>
    /// <c>0063</c> requires a domain an operator took out and one the forest named no controller
    /// for to be told apart wherever they appear. A bundle is where it matters most: there is no
    /// screen and no operator to ask.
    /// </remarks>
    [Fact]
    public void TheTwoKindsOfExclusionAreStoredApart()
    {
        WriteBundle(writer =>
        {
            writer.RecordExcludedDomain(new AttestedExclusion(
                "DC=chosen,DC=contoso,DC=com", "chosen.contoso.com", ExclusionKind.ByChoice,
                "outside-remit", null, @"CONTOSO\jistrand", "R. Zamus", Started));

            writer.RecordExcludedDomain(new AttestedExclusion(
                "DC=orphan,DC=contoso,DC=com", "orphan.contoso.com",
                ExclusionKind.ForWantOfCandidates,
                "outside-remit", null, @"CONTOSO\jistrand", "R. Zamus", Started));
        });

        Assert.Equal(
            nameof(ExclusionKind.ByChoice),
            ScalarText(
                "SELECT kind FROM excluded_domain WHERE naming_context_dn = "
                + "'DC=chosen,DC=contoso,DC=com'"));
        Assert.Equal(
            nameof(ExclusionKind.ForWantOfCandidates),
            ScalarText(
                "SELECT kind FROM excluded_domain WHERE naming_context_dn = "
                + "'DC=orphan,DC=contoso,DC=com'"));
    }

    /// <summary>
    /// A run that excluded nothing leaves the table empty, which is what its absence means.
    /// </summary>
    /// <remarks>
    /// Every table says what its absence means, per the rule <c>S-16</c> binds. For this one: no
    /// rows means no domain was excluded - it does not mean the attestation was not recorded.
    /// </remarks>
    [Fact]
    public void ARunThatExcludedNothingLeavesNoExclusionRows()
    {
        CompleteAnEmptyBundle();

        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM excluded_domain"));
    }

    // ---------------------------------------------------------------------------------------
    // Identity
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A distinguished name changes when an object is renamed or moved, and the row identifier is
    /// local to one file. Without the GUID, two bundles compared would report a moved object as
    /// one deleted and one created.
    /// </summary>
    [Fact]
    public void AnObjectIsStoredWithTheIdentityThatSurvivesARenameOrMove()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
        });

        Assert.Equal(AliceGuid.ToString("D"), ScalarText("SELECT object_guid FROM captured_object"));
    }

    /// <summary>
    /// An identity that did not arrive is stored as absent rather than invented. An object that
    /// cannot take part in a comparison must be visibly unable to, not silently joined to nothing.
    /// </summary>
    [Fact]
    public void AnObjectWhoseIdentityDidNotArriveIsNotGivenOne()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(
                new EvidenceObject(
                    SomeCoverage(), "CN=Nameless,DC=contoso,DC=com", null, [], Started));
        });

        Assert.Equal(1, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE object_guid IS NULL"));
    }

    /// <summary>
    /// A descriptor attributed to a different object than the one it is written against would put
    /// one object's permissions on another. There is no way to tell which side is wrong, so the
    /// run ends.
    /// </summary>
    [Fact]
    public void ADescriptorBelongingToADifferentObjectIsRefused()
    {
        var error = Assert.Throws<InvalidOperationException>(() => WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));

            WriteDescriptor(
                writer,
                objectId,
                new AceNormalizationResult(
                    Guid.Parse("99999999-9999-9999-9999-999999999999"),
                    null, null, DaclState.Present, false, [], [],
                    DaclCompleteness.Complete, DaclWasCanonical: true));
        }));

        Assert.Contains(
            "attribute one object's permissions to another", error.Message, StringComparison.Ordinal);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    // ---------------------------------------------------------------------------------------

    private void CompleteAnEmptyBundle() => WriteBundle(_ => { });

    private void WriteAPopulatedBundle() => WriteBundle(writer =>
    {
        writer.WriteCoverage(SomeCoverage());
        var objectId = writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice")));
        WriteDescriptor(
                writer,
            objectId, Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x20)], []));
    });

    // ---------------------------------------------------------------------------------------
    // C1 - what the row instructed, asserted
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The measurement this schema exists for: 4.81 GB down to 1.24 GB per 100k objects, because a
    /// forest holds a few thousand distinct descriptors repeated across millions of objects.
    /// </summary>
    [Fact]
    public void TwoObjectsSharingADescriptorStoreOneDescriptorAndOneEntrySet()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            IReadOnlyList<CanonicalAce> entries = [Ace("S-1-5-32-544", 0x20), Ace("S-1-5-18", 0x10)];

            var a = writer.WriteObject(ObjectAt("CN=A,DC=contoso,DC=com", GuidNumbered(1)));
            WriteDescriptor(writer, a, Descriptor(GuidNumbered(1), DaclState.Present, entries, []));

            var b = writer.WriteObject(ObjectAt("CN=B,DC=contoso,DC=com", GuidNumbered(2)));
            WriteDescriptor(writer, b, Descriptor(GuidNumbered(2), DaclState.Present, entries, []));
        });

        Assert.Equal(1, ScalarLong("SELECT COUNT(*) FROM security_descriptor"));
        Assert.Equal(2, ScalarLong("SELECT COUNT(*) FROM ace"));
        Assert.Equal(2, ScalarLong("SELECT COUNT(*) FROM object_security_descriptor"));

        // Both objects reach the one descriptor, and both still report their own entry count.
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(DISTINCT descriptor_id) FROM object_security_descriptor"));
        Assert.Equal(2, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE ace_count = 2"));
    }

    /// <summary>
    /// Two descriptors that differ are two descriptors. The dedup test above passes trivially if
    /// everything collapses into one row, so this is the other direction of the same claim.
    /// </summary>
    [Fact]
    public void TwoObjectsWithDifferentDescriptorsStoreTwo()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            WriteDescriptor(
                writer,
                writer.WriteObject(ObjectAt("CN=A,DC=contoso,DC=com", GuidNumbered(1))),
                Descriptor(GuidNumbered(1), DaclState.Present, [Ace("S-1-5-32-544", 0x20)], []));
            WriteDescriptor(
                writer,
                writer.WriteObject(ObjectAt("CN=B,DC=contoso,DC=com", GuidNumbered(2))),
                Descriptor(GuidNumbered(2), DaclState.Present, [Ace("S-1-5-32-544", 0x40)], []));
        });

        Assert.Equal(2, ScalarLong("SELECT COUNT(*) FROM security_descriptor"));
        Assert.Equal(2, ScalarLong("SELECT COUNT(*) FROM ace"));
    }

    /// <summary>
    /// 19,927 objects in 100,000 on a production domain. An object whose descriptor could not be
    /// read has to be distinguishable from one that grants nothing, or a fifth of a domain reads as
    /// safe.
    /// </summary>
    [Fact]
    public void AnObjectWhoseDescriptorCouldNotBeReadIsDistinguishableFromOneThatGrantsNothing()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            var unreadable = writer.WriteObject(ObjectAt("CN=Unreadable,DC=contoso,DC=com", GuidNumbered(1)));
            writer.WriteUnreadableSecurityDescriptor(
                unreadable, "The controller returned no nTSecurityDescriptor for this object.");

            var grantsNothing = writer.WriteObject(ObjectAt("CN=Empty,DC=contoso,DC=com", GuidNumbered(2)));
            WriteDescriptor(writer, grantsNothing, Descriptor(GuidNumbered(2), DaclState.Empty, [], []));
        });

        // Neither has an entry, which is exactly why they used to be indistinguishable.
        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM ace"));

        // The one that could not be read says so, and has no entry count at all.
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(*) FROM unreadable_security_descriptor WHERE object_id = 1"));
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE object_id = 1 AND ace_count IS NULL"));

        // The one that grants nothing has a descriptor, no error, and a count of zero. Null and
        // zero are the whole distinction.
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(*) FROM object_security_descriptor WHERE object_id = 2"));
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE object_id = 2 AND ace_count = 0"));
        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM security_descriptor_error"));
    }

    /// <summary>
    /// The run total is a sum over the coverage rows rather than a number stored beside them, so it
    /// cannot drift from the evidence. A reader can also get from the total back to the controller.
    /// </summary>
    [Fact]
    public void UnreadableDescriptorsAreCountedAgainstThePartitionTheyWereReadFrom()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());

            for (var i = 1; i <= 3; i++)
            {
                var objectId = writer.WriteObject(
                    ObjectAt($"CN=Broken{i},DC=contoso,DC=com", GuidNumbered(i)));
                writer.WriteUnreadableSecurityDescriptor(objectId, "Access denied reading the descriptor.");
            }
        });

        Assert.Equal(
            3, ScalarLong("SELECT SUM(unreadable_descriptors) FROM partition_coverage"));
        Assert.Equal(
            "dc01.contoso.com",
            ScalarText("SELECT controller FROM partition_coverage WHERE unreadable_descriptors > 0"));
    }

    /// <summary>
    /// A defect in the parser should be repairable by re-analysing bundles already captured, rather
    /// than by asking a customer to re-read his forest.
    /// </summary>
    [Fact]
    public void TheDescriptorBytesAreStoredAsTheyArrived()
    {
        var descriptor = Descriptor(DaclState.Present, [Ace("S-1-5-32-544", 0x20)], []);

        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            WriteDescriptor(writer, writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice"))), descriptor);
        });

        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT raw_bytes, byte_length FROM security_descriptor";
        using var reader = command.ExecuteReader();

        Assert.True(reader.Read());
        var stored = (byte[])reader["raw_bytes"];
        Assert.Equal(DescriptorBytes(descriptor), stored);
        Assert.Equal((long)stored.Length, (long)reader["byte_length"]);
    }

    /// <summary>
    /// <c>F-S24-1</c> option C. A partition read over a rung that strips confidential attributes
    /// without saying so has to be visible as such, or its silence reads as a fact about the forest.
    /// </summary>
    [Fact]
    public void TheConnectionSecurityAPartitionWasReadOverIsRecorded()
    {
        WriteBundle(writer => writer.WriteCoverage(SomeCoverage() with
        {
            ConnectionSecurity = ConnectionSecurityLevel.Signed,
        }));

        Assert.Equal("Signed", ScalarText("SELECT connection_security FROM partition_coverage"));
    }

    /// <summary>
    /// The reversed name is what turns a subtree question into an indexed prefix scan. Asserted as
    /// the property a query depends on, rather than as a string, because the value is only ever a
    /// means to that end.
    /// </summary>
    [Fact]
    public void EveryObjectUnderAContainerSharesAPrefixOfTheReversedName()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectAt("OU=Sales,DC=contoso,DC=com", GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Bob,OU=Sales,DC=contoso,DC=com", GuidNumbered(2)));
            writer.WriteObject(ObjectAt("CN=Eve,OU=Marketing,DC=contoso,DC=com", GuidNumbered(3)));
        });

        var reversedScope = SecureAD.Kernel.Naming.DnHelper.ReverseDn("OU=Sales,DC=contoso,DC=com");

        Assert.Equal(
            2,
            ScalarLong(
                "SELECT COUNT(*) FROM captured_object WHERE dn_reversed LIKE '"
                + reversedScope + "%'"));
    }

    /// <summary>
    /// The containment edge, resolved once when writing finishes because the container may not have
    /// been read yet when the child was written.
    /// </summary>
    [Fact]
    public void AnObjectWhoseContainerWasCapturedCarriesItsParent()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectAt("OU=Sales,DC=contoso,DC=com", GuidNumbered(1)));
            writer.WriteObject(ObjectAt("CN=Bob,OU=Sales,DC=contoso,DC=com", GuidNumbered(2)));
        });

        Assert.Equal(
            GuidNumbered(1).ToString("D"),
            ScalarText(
                "SELECT parent_guid FROM captured_object "
                + "WHERE distinguished_name = 'CN=Bob,OU=Sales,DC=contoso,DC=com'"));
    }

    /// <summary>
    /// The other half of the same pass. An object whose container nothing ever captured is a hole
    /// in the containment chain that inherited permissions travel down, so it is recorded by
    /// reference rather than left as a null nobody has to explain.
    /// </summary>
    [Fact]
    public void AContainerThatWasNeverCapturedIsRecordedAsAnUnresolvedReference()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectAt("CN=Bob,OU=Orphaned,DC=contoso,DC=com", GuidNumbered(2)));
        });

        Assert.Equal(
            "OU=Orphaned,DC=contoso,DC=com",
            ScalarText(
                "SELECT reference FROM unresolved_reference WHERE kind = 'ParentContainer'"));
        Assert.Equal(
            1, ScalarLong("SELECT COUNT(*) FROM captured_object WHERE parent_guid IS NULL"));
    }

    /// <summary>
    /// <c>F-S30-1</c>. A comma inside a name is escaped and does not separate anything, so
    /// <c>CN=Smith\, John</c> is one person in one container. Splitting on the first comma instead
    /// invents a container nobody named, which detaches the object from the containment tree that
    /// inherited permissions travel down.
    /// </summary>
    [Fact]
    public void AnObjectWhoseNameContainsAnEscapedCommaCarriesItsParent()
    {
        WriteBundle(writer => WriteTreeWithAnEscapedComma(writer));

        Assert.Equal(
            GuidNumbered(2).ToString("D"),
            ScalarText(
                "SELECT parent_guid FROM captured_object "
                + @"WHERE distinguished_name = 'CN=Smith\, John,OU=Users,DC=contoso,DC=com'"));
    }

    /// <summary>
    /// The other consequence of the same defect. The invented container matched nothing, so the
    /// object was also reported to the customer as one whose container the run failed to capture -
    /// naming a container that never existed.
    /// </summary>
    [Fact]
    public void AnObjectWhoseNameContainsAnEscapedCommaIsNotReportedAsUncontained()
    {
        WriteBundle(writer => WriteTreeWithAnEscapedComma(writer));

        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM unresolved_reference"));
    }

    /// <summary>
    /// A whole little tree - the partition root, a container, and a person whose name carries an
    /// escaped comma - so that every parent in it was genuinely captured and any unresolved row is
    /// therefore a defect rather than a property of the fixture.
    /// </summary>
    private static void WriteTreeWithAnEscapedComma(BundleWriter writer)
    {
        writer.WriteCoverage(SomeCoverage());
        writer.WriteObject(ObjectAt("DC=contoso,DC=com", GuidNumbered(1)));
        writer.WriteObject(ObjectAt("OU=Users,DC=contoso,DC=com", GuidNumbered(2)));
        writer.WriteObject(
            ObjectAt(@"CN=Smith\, John,OU=Users,DC=contoso,DC=com", GuidNumbered(3)));
    }

    /// <summary>
    /// <c>F-S30-1</c>, the other half. The root of a naming context has no parent inside the
    /// bundle and is not a gap. Excluding it by the absence of a comma held only for a root of one
    /// label; <c>DC=contoso,DC=com</c> has one, so the root was reported as a container the run
    /// failed to capture - a domain that does not exist, named to the customer as missing.
    /// </summary>
    [Fact]
    public void ThePartitionRootIsNotReportedAsAContainerNobodyCaptured()
    {
        WriteBundle(writer =>
        {
            writer.WriteCoverage(SomeCoverage());
            writer.WriteObject(ObjectAt("DC=contoso,DC=com", GuidNumbered(1)));
        });

        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM unresolved_reference"));
    }

    /// <summary>
    /// <c>F-S31-5</c>. A partition the forest declares and the run declines to read is stated in the
    /// evidence. It reached the operator's console and nothing else, so a reader opening the bundle
    /// afterwards could not tell a forest whose DNS partitions were skipped from a forest that has
    /// none - and those are different facts about a customer's directory.
    /// </summary>
    [Fact]
    public void APartitionTheRunDeclinedToReadIsStatedInTheEvidence()
    {
        WriteBundle(writer =>
        {
            writer.RecordUnreadPartition("DC=DomainDnsZones,DC=contoso,DC=com");
            writer.RecordUnreadPartition("DC=ForestDnsZones,DC=contoso,DC=com");
            writer.WriteCoverage(SomeCoverage());
        });

        Assert.Equal(
            "DC=DomainDnsZones,DC=contoso,DC=com|DC=ForestDnsZones,DC=contoso,DC=com",
            ScalarText(
                "SELECT group_concat(naming_context_dn, '|') FROM "
                + "(SELECT naming_context_dn FROM unread_partition ORDER BY naming_context_dn)"));
    }

    /// <summary>
    /// The other state, and the reason this member is worth having at all: a forest with no
    /// application partitions produces no rows. A record that could only ever say one thing would be
    /// decoration, which is the test <c>S-30</c> applied to <c>D2</c> and skipped on <c>D3</c>.
    /// </summary>
    [Fact]
    public void AForestWithNoUnreadPartitionsRecordsNone()
    {
        WriteBundle(writer => writer.WriteCoverage(SomeCoverage()));

        Assert.Equal(0, ScalarLong("SELECT COUNT(*) FROM unread_partition"));
    }

    /// <summary>
    /// <c>page_size</c> is fixed when the first table is created and only a full VACUUM can change
    /// it afterwards, which a sealed bundle will never get. A line setting it in the wrong place
    /// reads as configuration and does nothing, so the value is asserted on a real file.
    /// </summary>
    [Fact]
    public void ThePageSizeIsSetBeforeTheFirstTableExists()
    {
        CompleteAnEmptyBundle();

        Assert.Equal(8192, ScalarLong("PRAGMA page_size"));
    }

    /// <summary>
    /// Coverage is what an absence is interpreted against, so an object filed under a partition
    /// that was never recorded would quietly change what its neighbours' absence means. There is
    /// nothing sensible to fall back to, so the run ends.
    /// </summary>
    [Fact]
    public void AnObjectWhosePartitionWasNeverRecordedIsRefused()
    {
        using var writer = BundleWriter.Create(_directory, Started);

        var refusal = Assert.Throws<InvalidOperationException>(
            () => writer.WriteObject(ObjectWith(TextAttribute("cn", "Alice"))));

        Assert.Contains("DC=contoso,DC=com", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("dc01.contoso.com", refusal.Message, StringComparison.Ordinal);
    }

    private void WriteBundle(Action<BundleWriter> write)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        write(writer);
        writer.Complete(OneDomainRead(), Finished);
    }

    /// <summary>
    /// The smallest coverage a sealed bundle can honestly carry: one domain read, and both
    /// partitions belonging to the forest read.
    /// </summary>
    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));

    private static PartitionCoverage SomeCoverage() => new(
        "DC=contoso,DC=com",
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        ["ldap://child"],
        false);

    private static readonly Guid AliceGuid = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static EvidenceObject ObjectWith(params EvidenceAttribute[] attributes) =>
        new(SomeCoverage(), "CN=Alice,DC=contoso,DC=com", AliceGuid, attributes, Started);

    /// <summary>An object at a chosen place in the tree, with its own identity.</summary>
    private static EvidenceObject ObjectAt(string dn, Guid guid) =>
        new(SomeCoverage(), dn, guid, [TextAttribute("cn", "x")], Started);

    private static Guid GuidNumbered(int n) =>
        Guid.Parse($"00000000-0000-0000-0000-{n:D12}");

    /// <summary>
    /// Writes a descriptor with stand-in raw bytes derived from what it parsed to.
    /// </summary>
    /// <remarks>
    /// The writer deduplicates on the SHA-256 of the bytes the controller sent, and these tests do
    /// not have a controller. Deriving the bytes from the parsed content keeps the property the
    /// real thing has and the tests care about: two descriptors that are the same produce the same
    /// bytes, and two that differ produce different ones.
    /// </remarks>
    private static void WriteDescriptor(
        BundleWriter writer, long objectId, AceNormalizationResult descriptor) =>
        writer.WriteSecurityDescriptor(objectId, DescriptorBytes(descriptor), descriptor);

    private static byte[] DescriptorBytes(AceNormalizationResult descriptor) =>
        System.Text.Encoding.UTF8.GetBytes(string.Join(
            "|",
            descriptor.OwnerSid,
            descriptor.GroupSid,
            descriptor.DaclState,
            descriptor.IsDaclProtected,
            string.Join(",", descriptor.Aces.Select(a => a.AceHash)),
            string.Join(",", descriptor.Errors)));

    private static EvidenceAttribute TextAttribute(string name, string value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(value)]);

    private static AceNormalizationResult Descriptor(
        DaclState state,
        IReadOnlyList<CanonicalAce> aces,
        IReadOnlyList<string> errors,
        DaclCompleteness completeness = DaclCompleteness.Complete,
        bool wasCanonical = true) =>
        Descriptor(AliceGuid, state, aces, errors, completeness, wasCanonical);

    /// <summary>
    /// The same descriptor as read for a named object.
    /// </summary>
    /// <remarks>
    /// The object's own GUID is on the parse result, because the writer refuses a descriptor whose
    /// view of which object it belongs to disagrees with the object it is written against. It is
    /// deliberately not part of <see cref="DescriptorBytes"/>: two objects can carry byte-identical
    /// descriptors while each parse names its own object, and that is precisely the case
    /// deduplication exists for.
    /// </remarks>
    private static AceNormalizationResult Descriptor(
        Guid objectGuid,
        DaclState state,
        IReadOnlyList<CanonicalAce> aces,
        IReadOnlyList<string> errors,
        DaclCompleteness completeness = DaclCompleteness.Complete,
        bool wasCanonical = true) =>
        new(objectGuid, "S-1-5-21-1", "S-1-5-21-2", state, false, aces, errors,
            completeness, wasCanonical);

    private static CanonicalAce Ace(string trustee, int mask, bool inherited = false) => new(
        AliceGuid,
        AceType.AccessAllowed, trustee, mask, null, null, inherited, 0, 0,
        $"hash-{trustee}-{mask}-{inherited}", AceCanonicalization.Version);

    /// <summary>
    /// The same, with the ACE type chosen by the caller, so a type this product does not name can
    /// be put through the writer.
    /// </summary>
    private static CanonicalAce AceOfType(AceType aceType, string trustee, int mask) => new(
        AliceGuid,
        aceType, trustee, mask, null, null, false, 0, 0,
        $"hash-{aceType}-{trustee}-{mask}", AceCanonicalization.Version);

    private SqliteConnection OpenForReading() =>
        OpenForWriting(BundleLayout.EvidencePath(_directory));

    private static SqliteConnection OpenForWriting(string path)
    {
        var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
                ForeignKeys = true,
            }.ToString());

        connection.Open();
        return connection;
    }

    private string ScalarText(string sql) => Scalar(sql)?.ToString() ?? "(null)";

    private long ScalarLong(string sql) => Convert.ToInt64(Scalar(sql));

    private object? Scalar(string sql)
    {
        using var connection = OpenForReading();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
}

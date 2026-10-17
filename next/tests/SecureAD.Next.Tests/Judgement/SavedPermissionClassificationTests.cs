using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.ControlEdgeDeriverTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SavedPermissionClassificationTests
{
    private const string Seal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// <summary>Reads a classification the way a run does, with the descriptor the evidence names.</summary>
    /// <param name="reader">The judgement.</param>
    /// <param name="permissions">The evidence-side permissions, which name both object and descriptor.</param>
    /// <remarks>
    /// The reader cannot look the descriptor up for itself (<c>P-280</c>): it holds the judgement
    /// connection alone, and letting the judgement answer which descriptor an object carries is
    /// exactly the misattribution this design refuses. In the product
    /// <c>OpenedRunResults</c> asks the evidence and carries the answer across; here the fixture is
    /// the evidence, so it is asked the same way.
    /// </remarks>
    private static SavedPermissionClassification Read(JudgementReader reader, ObjectPermissions permissions) =>
        reader.ReadPermissionClassification(permissions.DistinguishedName, permissions.DescriptorId);

    [Fact]
    public void P248ClassificationSharedEntryLookupDoesNotScanTheForest()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        using var command = connection.CreateCommand();
        // The lookup P-279 put in the write path. It runs once per entry per object - 17 million times
        // on the measured bundle - so a scan here would cost more than the duplicate rows it replaced.
        command.CommandText = "EXPLAIN QUERY PLAN SELECT id FROM permission_entry WHERE entry_hash=$hash";
        command.Parameters.AddWithValue("$hash", new string('0', 64));

        using var read = command.ExecuteReader();
        read.Read();
        Assert.Contains("SEARCH permission_entry USING COVERING INDEX sqlite_autoindex_permission_entry_1", read.GetString(3), StringComparison.Ordinal);
    }

    [Fact]
    public void P248ClassificationKeepsMixedRightVerdicts()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x60000)));
        var directory = Store(result);
        using var reader = JudgementReader.Open(directory).Value;

        var saved = Read(reader, result.Permissions);

        Assert.Equal(new[] { PermissionVerdict.Dangerous, PermissionVerdict.NotDangerous },
            saved.Classification.Entries.Single().Rights.Select(value => value.Assessment.Verdict));
    }

    [Theory]
    [InlineData(0x200, "AccessAllowed")]
    [InlineData(0x40000, "UnknownAce")]
    public void P248ClassificationNeverCallsAnUnsupportedRightSafe(int mask, string type)
    {
        var result = Produce(Permissions(Ace(0, Holder, mask, type)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var right = Read(reader, result.Permissions).Classification.Entries.Single().Rights.Single();

        Assert.Equal(PermissionVerdict.CannotClassify, right.Assessment.Verdict);
    }

    [Theory]
    [InlineData("AccessAllowedCallback", 0, "condition")]
    [InlineData("AccessAllowed", 8, "inherit-only")]
    [InlineData("AccessAllowedCallback", 8, "inherit-only")]
    public void P248ClassificationRetainsApplicability(string type, byte propagation, string qualifier)
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x40000, type, propagation)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var reason = Read(reader, result.Permissions).Classification.Entries.Single().Rights.Single().Assessment.Reason;

        Assert.Contains(qualifier, reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void P248ClassificationPreservesDetailedEvidence()
    {
        var ace = Ace(7, Holder, 0x60000, "AccessAllowedCallbackObject", 8) with
        {
            IsInherited = true, InheritanceFlags = 2, ApplicationData = [1, 2, 3],
            InheritedObjectTypeGuid = "bf967a9c-0de6-11d0-a285-00aa003049e2", HasInheritedObjectType = true,
        };
        var permissions = Permissions(ace) with { DaclWasCanonical = false, IsDaclProtected = true,
            DaclCompleteness = DaclCompleteness.Unknown, Errors = ["partial descriptor"] };
        var result = Produce(permissions);
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, permissions);

        Assert.Equal(JsonSerializer.Serialize(result), JsonSerializer.Serialize(saved.Classification));
    }

    [Theory]
    [InlineData(null, PermissionVerdict.CannotClassify)]
    [InlineData("userAccountControl", PermissionVerdict.Dangerous)]
    [InlineData("description", PermissionVerdict.NotDangerous)]
    public void P248ClassificationPreservesForestPropertySetContext(string? member, PermissionVerdict verdict)
    {
        const string guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        var membership = PropertySetMembers(guid, member);
        var schema = SchemaGuidCatalog.CapturedOver([new(guid, "ForestSet", SchemaGuidKind.PropertySet, SchemaGuidSource.Captured)],
            SchemaGuidCatalog.Embedded, membership);
        var result = Produce(Permissions(Ace(0, Holder, 0x20) with { ObjectTypeGuid = guid, HasObjectType = true }), schema);
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, result.Permissions).Classification;

        Assert.Equal((true, verdict, JsonSerializer.Serialize(membership.GetValueOrDefault(guid))),
            (saved.HasCapturedSchema, saved.Entries.Single().Rights.Single().Assessment.Verdict,
                JsonSerializer.Serialize(saved.Entries.Single().ObjectType!.PropertySetMembers)));
    }

    [Fact]
    public void P248ClassificationKeepsShorthandAndUnnamedBitsSeparate()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x10000200)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var rights = Read(reader, result.Permissions).Classification.Entries.Single().Rights;

        Assert.Equal(new[] { (0x10000000, PermissionVerdict.Dangerous), (0x200, PermissionVerdict.CannotClassify) },
            rights.Select(value => (value.Right.Bits, value.Assessment.Verdict)));
    }

    [Theory]
    [InlineData(DescriptorAvailability.Read, DaclState.Null)]
    [InlineData(DescriptorAvailability.Read, DaclState.Empty)]
    [InlineData(DescriptorAvailability.Unreadable, DaclState.Unreadable)]
    [InlineData(DescriptorAvailability.NotAttempted, DaclState.Unreadable)]
    public void P248ClassificationKeepsEmptyAndUnknownEvidenceDistinct(DescriptorAvailability availability, DaclState state)
    {
        var result = Produce(Permissions() with { Availability = availability, DaclState = state });
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, result.Permissions);

        Assert.Equal((availability, state, 0), (saved.Classification.Permissions.Availability,
            saved.Classification.Permissions.DaclState, saved.Classification.Entries.Count));
    }

    [Fact]
    public void P248ClassificationKeepsOriginalOrderAndDuplicateEntries()
    {
        var result = Produce(Permissions(Ace(2, Holder, 0x40000), Ace(7, Holder, 0x40000)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, result.Permissions);

        int[] expected = [2, 7];
        Assert.Equal(expected, saved.Classification.Entries.Select(value => value.Entry.Ordinal));
    }

    [Theory]
    [InlineData("UPDATE permission_classification_product SET state='Writing'")]
    [InlineData("UPDATE permission_classification_product SET generation='wrong'")]
    [InlineData("UPDATE permission_classification_product SET producer_version=99")]
    [InlineData("UPDATE permission_classification_product SET schema_version=99")]
    [InlineData("DELETE FROM permission_classification_object")]
    [InlineData("UPDATE permission_classification_descriptor SET entry_count=2")]
    [InlineData("UPDATE permission_classification_descriptor SET descriptor=json_set(descriptor,'$.Errors',NULL)")]
    [InlineData("UPDATE permission_classification_descriptor SET fingerprint=zeroblob(32)")]
    [InlineData("DELETE FROM permission_classification_entry")]
    [InlineData("UPDATE permission_classification_entry SET ordinal=9")]
    [InlineData("UPDATE permission_classification_entry SET entry_id=99999")]
    [InlineData("UPDATE permission_entry SET generation='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE permission_entry SET entry_hash='0000000000000000000000000000000000000000000000000000000000000000'")]
    [InlineData("UPDATE permission_entry SET sid='S-1-5-32-544'")]
    [InlineData("UPDATE permission_classification_value SET right_count=2")]
    [InlineData("UPDATE permission_classification_value SET fingerprint=zeroblob(32)")]
    // THE OBJECT'S OWN DESCRIPTOR POINTER, WHICH THE EVIDENCE CONTRADICTS (P-280 binding 1). The
    // review's central objection: a judgement claiming X uses another descriptor would validate
    // every fingerprint it holds, because whoever edited it recomputes them. Only the evidence can
    // refuse this, and the read is given the evidence's answer precisely so that it can.
    [InlineData("UPDATE permission_classification_object SET descriptor_id=descriptor_id+1")]
    [InlineData("UPDATE permission_classification_object SET descriptor_id=NULL")]
    [InlineData("UPDATE permission_classification_reading SET payload=json_set(payload,'$.Rights[0].Assessment.Verdict',999)")]
    [InlineData("UPDATE permission_classification_reading SET payload=json_set(payload,'$.Rights[0].Assessment.Reason','')")]
    [InlineData("UPDATE permission_classification_reading SET payload=json_set(payload,'$.Rights[0].Right.Bits',0)")]
    [InlineData("UPDATE permission_classification_reading SET payload=json_set(payload,'$.RightsAreComplete',json('false'))")]
    public void P248ClassificationRefusesIncompleteOrMisboundRecords(string sql)
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x40000)));
        var directory = Store(result);
        Mutate(directory, sql);
        Refingerprint(directory);
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    [Fact]
    public void P248ClassificationMissingProductIsNotEmpty()
    {
        var result = Produce(Permissions());
        var directory = Store(result);
        Mutate(directory, "DELETE FROM permission_classification_product");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Equal("This run has no saved permission classification.",
            Assert.Throws<InvalidOperationException>(() => Read(reader, result.Permissions)).Message);
    }

    // -------------------------------------------------------------------------------------------
    // An occurrence is bound to the reading that explains it (P-283)
    // -------------------------------------------------------------------------------------------
    //
    // Until this, reading_id was covered by nothing. Every fingerprint kept matching when it was
    // repointed at another valid reading, and the structural checks underneath all pass for the
    // swap that matters: the verdict is defined, the reason is non-empty, the wording is complete,
    // and the rights still sum to the entry's own mask - because a deny reading of the same rights
    // has the same bits. The whole-judgement seal catches an edit made after publication; it does
    // not catch a wrong association written before sealing, and P-280 would have turned one such
    // association into every occurrence of that entry.

    /// <summary>
    /// An allow entry cannot be made to read as the deny entry beside it.
    /// </summary>
    /// <remarks>
    /// The two entries carry the same right on the same object and differ only in ACE type, so
    /// their readings differ in what they say and agree on the mask. That is precisely the swap the
    /// mask check cannot see: before <c>P-283</c> the allow entry read back as
    /// <i>"A deny entry grants no access"</i> - dangerous reported as harmless.
    /// </remarks>
    [Fact]
    public void P283AnOccurrenceCannotBeRepointedAtAnotherValidReading()
    {
        var result = Produce(AllowBesideDeny());
        var directory = Store(result);
        // THE READING NOW HANGS OFF THE DISTINCT ENTRY, NOT THE OCCURRENCE (P-280), so the repoint
        // is made there and the binding that refuses it is the value fingerprint rather than the
        // occurrence's. The attack is unchanged and so is what it would achieve; normalisation
        // makes it worse, which is why the binding moved with the column.
        Mutate(directory,
            """
            UPDATE permission_classification_value
            SET reading_id=(SELECT v.reading_id FROM permission_classification_value v
                JOIN permission_classification_entry e ON e.entry_id=v.entry_id WHERE e.ordinal=1)
            WHERE entry_id=(SELECT entry_id FROM permission_classification_entry WHERE ordinal=0)
            """);
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    /// <summary>
    /// Unrepointed, the same object reads back and its two entries carry different readings.
    /// </summary>
    /// <remarks>
    /// <b>The negative control, and it carries two claims.</b> That binding the occurrence to its
    /// reading did not simply break reading back, and that the fixture really does hold two
    /// <i>distinct</i> readings - without which the repoint above would be a no-op that passed
    /// while measuring nothing.
    /// <para>
    /// It asserts on the assessment rather than on the summary, because both entries summarise as
    /// <c>Modify permissions</c>: they carry the same right, and only what that right is judged to
    /// mean differs. Written against the summary first, this test failed - which is the whole use
    /// of it.
    /// </para>
    /// </remarks>
    [Fact]
    public void P283TheTwoEntriesAreReadWithTheirOwnDistinctReadings()
    {
        var result = Produce(AllowBesideDeny());
        using var reader = JudgementReader.Open(Store(result)).Value;

        var entries = Read(reader, result.Permissions).Classification.Entries;

        Assert.Equal(2, entries.Count);
        Assert.NotEqual(
            entries[0].Rights.Single().Assessment.Reason,
            entries[1].Rights.Single().Assessment.Reason);
    }

    /// <summary>
    /// One allow and one deny of the same right on one object: same mask, different reading.
    /// </summary>
    private static ObjectPermissions AllowBesideDeny() => Permissions(
        Ace(0, Holder, 0x40000),
        Ace(1, Holder, 0x40000, "AccessDenied"));

    [Fact]
    public void P249SharedReadingRefusesATamperedPayload()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x40000)));
        var directory = Store(result);
        // DELIBERATELY NOT REFINGERPRINTED. Changing only the summary leaves every semantic check
        // satisfied, so the digest covering the shared row is the one thing standing between a
        // tampered reading and an administrator being shown words nothing produced. Format 42 made
        // that row shared, so this is also the difference between misreporting one entry and
        // misreporting every entry that references it.
        Mutate(directory, "UPDATE permission_classification_reading SET payload=json_set(payload,'$.Summary','tampered')");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    [Fact]
    public void P248ClassificationRefusesMissingSchemaSupport()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x20) with { ObjectTypeGuid = "unknown-guid", HasObjectType = true }));
        var directory = Store(result);
        Mutate(directory, "DELETE FROM permission_classification_schema");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    [Fact]
    public void P248ClassificationReadsOnlyTheRequestedObject()
    {
        var first = Produce(Permissions(Ace(0, Holder, 0x40000)));
        var second = Produce(Permissions("CN=Other,DC=contoso,DC=com", Ace(0, Holder, 0x40000)));
        var directory = Store(first, second);
        // THE TWO OBJECTS CARRY DIFFERENT DESCRIPTORS HOLDING IDENTICAL ENTRIES, so the shared entry
        // row and the reading row belong to both while the descriptor rows do not. Damaging the
        // other object's descriptor fingerprint is therefore damage the requested object must not
        // notice - which is what this case is about, and which P-280's per-descriptor keying makes
        // a sharper question than it was when every object had its own occurrence rows.
        Mutate(directory, $"UPDATE permission_classification_descriptor SET fingerprint=zeroblob(32) WHERE descriptor_id={second.Permissions.DescriptorId}");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Equal(first.Permissions.DistinguishedName,
            Read(reader, first.Permissions).Classification.Permissions.DistinguishedName);
    }

    [Fact]
    public void P248ClassificationRefusesFormat40()
    {
        var directory = Store(Produce(Permissions()));
        Mutate(directory, "UPDATE judgement SET schema_version=40");

        var opened = JudgementReader.Open(directory);

        Assert.Contains("schema version 40", opened.Error?.Description ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void P248ClassificationCannotPublishAnUnfinishedProduct()
    {
        var directory = TempDirectories.Create("unfinished-permission-classification");
        using var writer = JudgementWriter.Create(directory, Seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        writer.StartPermissionClassifications(false);

        Assert.Throws<InvalidDataException>(() => writer.Complete(DateTimeOffset.UnixEpoch));
    }

    // -------------------------------------------------------------------------------------------
    // The classification is stored once per descriptor (P-280)
    // -------------------------------------------------------------------------------------------
    //
    // On the production forest 940,067 objects carry 267,550 distinct descriptors, so storing the
    // interpretation per object wrote it 2.34 times over. Sharing it is the whole change - and the
    // risk the review named is that sharing a row between objects is exactly how one object comes
    // to be shown another object's permissions. Every case below is about that, not about size.

    /// <summary>
    /// Two objects carrying one descriptor each read back their own complete permissions.
    /// </summary>
    /// <remarks>
    /// <b>The row count falling is the goal; a permission disappearing is the failure.</b> So this
    /// asserts what each object grants, and asserts beside it that the store really did keep one
    /// copy — without that second half the test would pass just as well against a store that had
    /// saved nothing at all, which is the shape of check that measures nothing.
    /// </remarks>
    [Fact]
    public void P280TwoObjectsSharingADescriptorEachReadBackTheirOwnPermissions()
    {
        var shared = Permissions(Ace(0, Holder, 0x40000), Ace(1, Holder, 0x20000)) with { DescriptorId = 7 };
        var first = Produce(shared);
        var second = Produce(shared with { DistinguishedName = "CN=Other,DC=contoso,DC=com" });
        var directory = Store(first, second);
        using var reader = JudgementReader.Open(directory).Value;

        var read = new[] { first, second }.Select(value => Read(reader, value.Permissions).Classification).ToArray();

        // The masks are joined into text rather than compared as arrays, because a tuple compares
        // an int[] by reference and would fail on identical contents.
        Assert.Equal(
            (2L, 1L, 2L, "CN=Other,DC=contoso,DC=com", "262144,131072", "262144,131072"),
            (Rows(directory, "permission_classification_object"),
                Rows(directory, "permission_classification_descriptor"),
                Rows(directory, "permission_classification_entry"),
                read[1].Permissions.DistinguishedName,
                Masks(read[0]), Masks(read[1])));

        static string Masks(PermissionClassification value) =>
            string.Join(',', value.Entries.Select(entry => entry.Entry.AccessMask));
    }

    /// <summary>
    /// An object cannot be read against a descriptor the evidence does not give it.
    /// </summary>
    /// <remarks>
    /// <b>Binding 1, and the review's central objection.</b> Nothing is tampered with here: the
    /// judgement is entirely self-consistent and every fingerprint in it verifies. What is refused
    /// is being asked to read an object against a descriptor the evidence did not name for it —
    /// because if the judgement were allowed to answer that question, an edited store would
    /// attribute one object's permissions to another with every check still passing.
    /// </remarks>
    [Fact]
    public void P280AnObjectIsNotReadAgainstADescriptorTheEvidenceDidNotName()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x40000)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        Assert.Throws<InvalidDataException>(() => reader.ReadPermissionClassification(
            result.Permissions.DistinguishedName, result.Permissions.DescriptorId + 1));
    }

    /// <summary>
    /// An entry removed from a descriptor's list is refused, not read back as a shorter list.
    /// </summary>
    /// <remarks>
    /// <b>Binding 2, and why it is taken over the list rather than per row.</b> A fingerprint on
    /// each occurrence would still verify every row that remained, so a descriptor could be quietly
    /// stripped of the one entry that made it dangerous and read back as a valid shorter DACL. The
    /// entry count is checked too and would catch this alone — but the count is a number in the
    /// same store, and the list fingerprint is what makes editing both together useless.
    /// </remarks>
    [Fact]
    public void P280RemovingAnEntryFromADescriptorIsRefused()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x40000), Ace(1, Holder, 0x20000)));
        var directory = Store(result);
        Mutate(directory, """
            DELETE FROM permission_classification_entry WHERE ordinal=1;
            UPDATE permission_classification_descriptor SET entry_count=1;
            """);
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    /// <summary>
    /// Two entries swapped within a descriptor are refused, though every row survives.
    /// </summary>
    /// <remarks>
    /// Order is not presentation. Windows evaluates a DACL in stored order, adding a deny only for
    /// rights not already granted ([MS-ADTS] 5.1.3.3.2), so moving a deny after an allow changes
    /// what the object actually grants. Every row is intact here and the count is unchanged; only
    /// the list fingerprint can see it.
    /// </remarks>
    [Fact]
    public void P280ReorderingTwoEntriesWithinADescriptorIsRefused()
    {
        var result = Produce(AllowBesideDeny());
        var directory = Store(result);
        Mutate(directory, """
            UPDATE permission_classification_entry SET ordinal=CASE ordinal WHEN 0 THEN 99 ELSE 0 END;
            UPDATE permission_classification_entry SET ordinal=1 WHERE ordinal=99;
            """);
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => Read(reader, result.Permissions));
    }

    /// <summary>
    /// An object whose descriptor was never read keeps saying so, and is not read as permissive.
    /// </summary>
    /// <remarks>
    /// 280,871 of the production capture's 940,067 objects have no stored descriptor. <i>Nobody
    /// could read it</i> and <i>it grants nothing</i> both have no entries, and telling them apart
    /// is what this half of the schema exists for — so the distinction has to survive an object row
    /// that now holds almost nothing.
    /// </remarks>
    [Fact]
    public void P280AnObjectWithNoDescriptorKeepsItsUnreadableReason()
    {
        var result = Produce(Permissions() with
        {
            DescriptorId = null,
            Availability = DescriptorAvailability.Unreadable,
            UnreadableReason = "access denied",
            DaclState = DaclState.Unreadable,
            DaclCompleteness = DaclCompleteness.Unknown,
        });
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, result.Permissions).Classification.Permissions;

        Assert.Equal((DescriptorAvailability.Unreadable, "access denied", 0),
            (saved.Availability, saved.UnreadableReason, saved.Entries.Count));
    }

    /// <summary>
    /// A product whose occurrence count disagrees with its descriptor cannot be published.
    /// </summary>
    /// <remarks>
    /// <b>The gate that stops a half-written object reaching an operator</b>, and the one the
    /// <c>P-280</c> review singled out to be mutation-tested. It counted occurrences per object by
    /// name and now counts them through the descriptor that object carries — a join rather than a
    /// column comparison, which is exactly the kind of rewrite that can keep passing while checking
    /// nothing. An object whose permissions were partly stored must not be publishable, because a
    /// short DACL reads as a permissive object unless something says it is incomplete.
    /// </remarks>
    [Fact]
    public void P280AProductMissingOccurrencesCannotBePublished()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var statements = new PreparedStatements(connection);
        JudgementSchema.CreateTables(connection);
        ControlEdgeStorage.Start(connection, true);
        var generation = Guid.NewGuid();
        PermissionClassificationStorage.Start(connection, generation, false);
        var result = Produce(Permissions(Ace(0, Holder, 0x40000), Ace(1, Holder, 0x20000)));
        StorageWrites.ControlEdges(connection, new(result.Permissions.DistinguishedName, null, null, "Computed", ControlUncertainty.None, []), null);
        using (var transaction = connection.BeginTransaction())
        {
            PermissionClassificationStorage.Write(connection, transaction, generation, result,
                new PermissionWriteWork(), statements, new PermissionWriteSession(), CancellationToken.None);
            transaction.Commit();
        }
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "DELETE FROM permission_classification_entry WHERE ordinal=1";
            command.ExecuteNonQuery();
        }

        Assert.Throws<InvalidDataException>(() => PermissionClassificationStorage.Complete(connection, 1));
    }

    /// <summary>How many rows a table holds, read out of the finished store.</summary>
    private static long Rows(string directory, string table)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        TestSealing.AttachJudgementParts(connection, directory, generation.GenerationId);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM " + table;
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static Dictionary<string, IReadOnlyList<string>> PropertySetMembers(string guid, string? member) =>
        member is null ? [] : new(StringComparer.OrdinalIgnoreCase) { [guid] = [member] };

    private static void Mutate(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var command = connection.CreateCommand();
        // Fabricate corrupt saved data rather than testing SQLite's write-time FK enforcement.
        command.CommandText = "PRAGMA foreign_keys=OFF";
        command.ExecuteNonQuery();
        if (TestSealing.TryMutateSavedText(connection, sql, out var changed))
        {
            Assert.True(changed > 0);
            return;
        }
        command.CommandText = sql;
        command.ExecuteNonQuery();
    });

    /// <summary>
    /// Recomputes every shared reading's fingerprint after a deliberate change to its payload.
    /// </summary>
    /// <remarks>
    /// Format 42 stores each distinct reading once and covers it with a digest, so tampering is
    /// refused before anything reads what the reading says. These cases are about the semantic
    /// checks underneath - a verdict of 999, an emptied reason, zeroed bits, a flipped completeness
    /// flag - so the digest is repaired first and the reader is made to reach them.
    /// </remarks>
    private static void Refingerprint(string directory) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        var payloads = TestSealing.ReadSavedTexts(connection, "permission_classification_reading", "payload");

        foreach (var (id, payload) in payloads)
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE permission_classification_reading SET fingerprint=$fingerprint WHERE id=$id";
            update.Parameters.AddWithValue("$fingerprint", System.Security.Cryptography.SHA256.HashData(
                System.Text.Encoding.UTF8.GetBytes(payload)));
            update.Parameters.AddWithValue("$id", id);
            update.ExecuteNonQuery();
        }
    });

    [Theory]
    [InlineData(0x40000, true)]
    [InlineData(0x40200, false)]
    public void P248ClassificationRetainsWordingCompleteness(int mask, bool complete)
    {
        var result = Produce(Permissions(Ace(0, Holder, mask)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = Read(reader, result.Permissions);

        Assert.Equal(complete, saved.Classification.Entries.Single().RightsAreComplete);
    }

    private static PermissionClassification Produce(ObjectPermissions permissions, SchemaGuidCatalog? schema = null) =>
        new PermissionClassificationProducer(schema ?? SchemaGuidCatalog.Embedded).CreateObjectResult(permissions);

    private static string Store(params PermissionClassification[] values)
    {
        var directory = TempDirectories.Create("saved-permission-classification");
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, Seal)));
        using var writer = JudgementWriter.Create(directory, Seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        writer.StartControlEdges(true);
        writer.StartPermissionClassifications(values.FirstOrDefault()?.HasCapturedSchema ?? false);
        foreach (var result in values)
        {
            writer.WriteControlEdges(new(result.Permissions.DistinguishedName, null, null, "Computed", ControlUncertainty.None, []), null);
            writer.WritePermissionClassification(result, CancellationToken.None);
        }
        writer.CompletePermissionClassifications(values.Length);
        writer.CompleteControlEdges();
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }
}

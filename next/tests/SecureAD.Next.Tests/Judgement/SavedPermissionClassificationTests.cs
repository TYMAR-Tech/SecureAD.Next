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

        var saved = reader.ReadPermissionClassification(result.Permissions.DistinguishedName);

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

        var right = reader.ReadPermissionClassification(result.Permissions.DistinguishedName).Classification.Entries.Single().Rights.Single();

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

        var reason = reader.ReadPermissionClassification(result.Permissions.DistinguishedName).Classification.Entries.Single().Rights.Single().Assessment.Reason;

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

        var saved = reader.ReadPermissionClassification(permissions.DistinguishedName);

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

        var saved = reader.ReadPermissionClassification(result.Permissions.DistinguishedName).Classification;

        Assert.Equal((true, verdict, JsonSerializer.Serialize(membership.GetValueOrDefault(guid))),
            (saved.HasCapturedSchema, saved.Entries.Single().Rights.Single().Assessment.Verdict,
                JsonSerializer.Serialize(saved.Entries.Single().ObjectType!.PropertySetMembers)));
    }

    [Fact]
    public void P248ClassificationKeepsShorthandAndUnnamedBitsSeparate()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x10000200)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var rights = reader.ReadPermissionClassification(result.Permissions.DistinguishedName).Classification.Entries.Single().Rights;

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

        var saved = reader.ReadPermissionClassification(result.Permissions.DistinguishedName);

        Assert.Equal((availability, state, 0), (saved.Classification.Permissions.Availability,
            saved.Classification.Permissions.DaclState, saved.Classification.Entries.Count));
    }

    [Fact]
    public void P248ClassificationKeepsOriginalOrderAndDuplicateEntries()
    {
        var result = Produce(Permissions(Ace(2, Holder, 0x40000), Ace(7, Holder, 0x40000)));
        using var reader = JudgementReader.Open(Store(result)).Value;

        var saved = reader.ReadPermissionClassification(result.Permissions.DistinguishedName);

        int[] expected = [2, 7];
        Assert.Equal(expected, saved.Classification.Entries.Select(value => value.Entry.Ordinal));
    }

    [Theory]
    [InlineData("UPDATE permission_classification_product SET state='Writing'")]
    [InlineData("UPDATE permission_classification_product SET generation='wrong'")]
    [InlineData("UPDATE permission_classification_product SET producer_version=99")]
    [InlineData("UPDATE permission_classification_product SET schema_version=99")]
    [InlineData("DELETE FROM permission_classification_object")]
    [InlineData("UPDATE permission_classification_object SET entry_count=2")]
    [InlineData("UPDATE permission_classification_object SET descriptor=json_set(descriptor,'$.Errors',NULL)")]
    [InlineData("DELETE FROM permission_classification_entry")]
    [InlineData("UPDATE permission_classification_entry SET position=1")]
    [InlineData("UPDATE permission_classification_entry SET ordinal=9")]
    [InlineData("UPDATE permission_classification_entry SET entry_id=99999")]
    [InlineData("UPDATE permission_classification_entry SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE permission_entry SET generation='99999999-9999-9999-9999-999999999999'")]
    [InlineData("UPDATE permission_entry SET entry_hash='0000000000000000000000000000000000000000000000000000000000000000'")]
    [InlineData("UPDATE permission_entry SET sid='S-1-5-32-544'")]
    [InlineData("UPDATE permission_classification_entry SET right_count=2")]
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

        Assert.Throws<InvalidDataException>(() => reader.ReadPermissionClassification(result.Permissions.DistinguishedName));
    }

    [Fact]
    public void P248ClassificationMissingProductIsNotEmpty()
    {
        var result = Produce(Permissions());
        var directory = Store(result);
        Mutate(directory, "DELETE FROM permission_classification_product");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Equal("This run has no saved permission classification.",
            Assert.Throws<InvalidOperationException>(() => reader.ReadPermissionClassification(result.Permissions.DistinguishedName)).Message);
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
        Mutate(directory,
            """
            UPDATE permission_classification_entry
            SET reading_id=(SELECT reading_id FROM permission_classification_entry WHERE position=1)
            WHERE position=0
            """);
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(
            () => reader.ReadPermissionClassification(result.Permissions.DistinguishedName));
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

        var entries = reader.ReadPermissionClassification(result.Permissions.DistinguishedName)
            .Classification.Entries;

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

        Assert.Throws<InvalidDataException>(() => reader.ReadPermissionClassification(result.Permissions.DistinguishedName));
    }

    [Fact]
    public void P248ClassificationRefusesMissingSchemaSupport()
    {
        var result = Produce(Permissions(Ace(0, Holder, 0x20) with { ObjectTypeGuid = "unknown-guid", HasObjectType = true }));
        var directory = Store(result);
        Mutate(directory, "DELETE FROM permission_classification_schema");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Throws<InvalidDataException>(() => reader.ReadPermissionClassification(result.Permissions.DistinguishedName));
    }

    [Fact]
    public void P248ClassificationReadsOnlyTheRequestedObject()
    {
        var first = Produce(Permissions(Ace(0, Holder, 0x40000)));
        var second = Produce(Permissions(Ace(0, Holder, 0x40000)) with { DistinguishedName = "CN=Other,DC=contoso,DC=com" });
        var directory = Store(first, second);
        // FORMAT 42 SHARES READINGS, and these two objects carry identical entries, so the reading
        // row belongs to both. Damaging it would be damaging the requested object as well; what this
        // case is about is that the reader does not go looking at rows belonging only to the other.
        Mutate(directory, "UPDATE permission_classification_entry SET fingerprint=zeroblob(32) WHERE target='CN=Other,DC=contoso,DC=com'");
        using var reader = JudgementReader.Open(directory).Value;

        Assert.Equal(first.Permissions.DistinguishedName,
            reader.ReadPermissionClassification(first.Permissions.DistinguishedName).Classification.Permissions.DistinguishedName);
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

    private static Dictionary<string, IReadOnlyList<string>> PropertySetMembers(string guid, string? member) =>
        member is null ? [] : new(StringComparer.OrdinalIgnoreCase) { [guid] = [member] };

    private static void Mutate(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var command = connection.CreateCommand();
        // Fabricate corrupt saved data rather than testing SQLite's write-time FK enforcement.
        command.CommandText = "PRAGMA foreign_keys=OFF; " + sql;
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
        var payloads = new Dictionary<long, string>();
        using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT id,payload FROM permission_classification_reading";
            using var rows = read.ExecuteReader();
            while (rows.Read()) payloads[rows.GetInt64(0)] = rows.GetString(1);
        }

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

        var saved = reader.ReadPermissionClassification(result.Permissions.DistinguishedName);

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

using Microsoft.Data.Sqlite;
using System.Buffers.Binary;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Kernel.Schema;
using SecureAD.Next.Tests.Kernel.Security;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class DelegationLookupTests
{
    private const string Holder = "S-1-5-21-1-2-3-1100";
    private const string Other = "S-1-5-21-1-2-3-1200";
    private static readonly Guid ResetPassword = new("00299570-246d-11d0-a768-00aa006e0529");
    private static readonly Guid UserClass = new("bf967aba-0de6-11d0-a285-00aa003049e2");
    private static readonly Guid GroupClass = new("bf967a9c-0de6-11d0-a285-00aa003049e2");
    private static byte[] HolderSid => Sid.ToBytes(Holder)!;

    [Fact]
    public void MultiplePermissionHoldersShareOnlyTheProtectedReadersCoveragePreparation()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [SdBytes.AllowAce(HolderSid, 0x100), SdBytes.AllowAce(Sid.ToBytes(Other)!, 0x100)]);
        var reader = fixture.Open();
        var coverageReads = 0;
        strdelegate_trace trace = (_, sql) =>
        {
            if (sql.StartsWith("SELECT (SELECT count(*) FROM unreadable_security_descriptor)", StringComparison.Ordinal))
                coverageReads++;
        };
        raw.sqlite3_trace(reader.Connection.Handle!, trace, null!);
        var first = reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null);
        var second = reader.ReadDelegations(new(Unresolved() with { Sid = Other }, DelegationPermission.All, false), null);
        raw.sqlite3_trace(reader.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);

        Assert.Equal(Holder, Assert.Single(first.Entries).Entry.Trustee.Sid);
        Assert.Equal(Other, Assert.Single(second.Entries).Entry.Trustee.Sid);
        Assert.Equal(1, coverageReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SysvolOnlyDescriptorsCannotBecomeAdResultsOrAdCoverageGaps(bool mismatchedIndex)
    {
        using var control = new Fixture();
        control.Target("People", [SdBytes.AllowAce(HolderSid, 0x100)]);
        var query = new DelegationQuery(Unresolved(), DelegationPermission.All, false);
        var controlPage = control.Open().ReadDelegations(query, null);
        using var fixture = new Fixture();
        fixture.Target("People", [SdBytes.AllowAce(HolderSid, 0x100)]);
        fixture.SysvolOnly(mismatchedIndex);
        var reader = fixture.Open();
        DelegationPage? page = null;

        var error = Record.Exception(() =>
            page = reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null));

        Assert.Null(error);
        Assert.Single(page!.Entries);
        Assert.Equal((0L, 0L), (page.Coverage.IncompleteDescriptors, page.Coverage.DescriptorErrors));
        Assert.Equal(controlPage.Coverage.IsComplete, page.Coverage.IsComplete);
        Assert.Equal(controlPage.Coverage.DeclaredScopeWasRead, page.Coverage.DeclaredScopeWasRead);
    }

    [Fact]
    public void UnknownCapturedDaclCompletenessIsNotUpgradedBySuccessfulParsing()
    {
        using var fixture = new Fixture();
        fixture.Target("Unknown", [SdBytes.AllowAce(HolderSid, 0x100)], recordedCompleteness: DaclCompleteness.Unknown);
        var reader = fixture.Open();

        var page = reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null);

        Assert.Equal(DaclCompleteness.Unknown, Assert.Single(page.Entries).DaclCompleteness);
        Assert.Equal(1, page.Coverage.IncompleteDescriptors);
    }

    [Fact]
    public void CallbackDataAndUnsupportedOriginalMasksSurviveLookup()
    {
        using var fixture = new Fixture();
        byte[] payload = [0x61, 0x72, 0x74, 0x78, 0x01, 0x00, 0xFE, 0x7F];
        var callback = SdBytes.SimpleAce(0x09, 0, 0x100, HolderSid).Concat(payload).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(callback.AsSpan(2), (ushort)callback.Length);
        fixture.Target("People", [callback, SdBytes.SimpleAce(0x7F, 0, 0x200, HolderSid)]);
        var reader = fixture.Open();

        var page = reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null);

        Assert.Equal(2, page.Entries.Count);
        Assert.Equal(payload, page.Entries[0].Entry.ApplicationData);
        Assert.Equal("AccessAllowedCallback", page.Entries[0].Entry.AceType);
        Assert.Equal(0x200, page.Entries[1].Entry.AccessMask);
        Assert.Equal("127", page.Entries[1].Entry.AceType);
    }

    [Fact]
    public void AZeroGuidStillPresentInTheOriginalEntryIsNotAnUnscopedGrant()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [
            SdBytes.AllowObjectAce(HolderSid, 0x101, Guid.Empty, null),
            SdBytes.AllowAce(HolderSid, 0x101),
        ]);
        var reader = fixture.Open();

        Assert.Equal([1], reader.ReadDelegations(new(Unresolved(), DelegationPermission.ResetPassword, false), null)
            .Entries.Select(entry => entry.Entry.Ordinal));
        Assert.Equal([1], reader.ReadDelegations(new(Unresolved(), DelegationPermission.CreateUser, false), null)
            .Entries.Select(entry => entry.Entry.Ordinal));
        Assert.Equal([0, 1], reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null)
            .Entries.Select(entry => entry.Entry.Ordinal));
    }

    [Theory]
    [InlineData(DelegationPermission.ResetPassword, "User-Force-Change-Password")]
    [InlineData(DelegationPermission.CreateUser, "user")]
    public void AnAmbiguousOrWrongKindSchemaDoesNotInventTheRequestedRight(DelegationPermission permission, string name)
    {
        using var fixture = new Fixture();
        var reader = fixture.Open();
        var schema = SchemaGuidCatalog.CapturedOver(
            [new(Guid.NewGuid().ToString("D"), name, SchemaGuidKind.Attribute, SchemaGuidSource.Captured)],
            SchemaGuidCatalog.Embedded, new Dictionary<string, IReadOnlyList<string>>());

        Assert.Throws<InvalidDataException>(() => DelegationLookup.Read(reader.Connection, fixture.Fingerprint,
            reader.Description, schema, new(Unresolved(), permission, false), null, CancellationToken.None));
    }

    [Fact]
    public void UnprotectedLibraryReadersCannotAnswerDelegationQuestions()
    {
        using var fixture = new Fixture();
        fixture.Open();
        using var reader = BundleReader.OpenUnverified(fixture.DirectoryPath).Value;

        Assert.Throws<InvalidOperationException>(() => reader.FindDelegationPrincipals(Holder, null));
        Assert.Throws<InvalidOperationException>(() => reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null));
    }

    [Fact]
    public void AnIndexThatCannotBeReproducedFromTheOriginalDescriptorIsExplicitlyRefused()
    {
        using var fixture = new Fixture();
        fixture.MismatchedTarget();
        var reader = fixture.Open();

        Assert.Throws<InvalidDataException>(() => reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null));
    }

    [Theory]
    [InlineData("scope")]
    [InlineData("classes")]
    [InlineData("unreadable")]
    [InlineData("unattempted")]
    [InlineData("incomplete")]
    [InlineData("errors")]
    public void CoverageCompletenessAccountsForEveryIndependentGap(string gap)
    {
        var complete = new DelegationCoverage(true, [], 0, 0, 0, 0);
        Assert.True(complete.IsComplete);
        var incomplete = gap switch
        {
            "scope" => complete with { DeclaredScopeWasRead = false },
            "classes" => complete with { ExcludedObjectClasses = ["dnsNode"] },
            "unreadable" => complete with { UnreadableDescriptors = 1 },
            "unattempted" => complete with { UnattemptedDescriptors = 1 },
            "incomplete" => complete with { IncompleteDescriptors = 1 },
            _ => complete with { DescriptorErrors = 1 },
        };
        Assert.False(incomplete.IsComplete);
    }

    [Fact]
    public void DirectLookupPreservesOriginalDuplicatesOrderAndGenericMask()
    {
        using var fixture = new Fixture();
        fixture.Principal("Helpdesk", Holder);
        fixture.Target("People", [
            SdBytes.AllowAce(HolderSid, 0x10000000),
            SdBytes.DenyAce(HolderSid, 0x100),
            SdBytes.AllowAce(HolderSid, 0x10000000),
            SdBytes.AllowAce(Sid.ToBytes(Other)!, 0x100),
        ]);
        var reader = fixture.Open();
        var principal = Assert.Single(reader.FindDelegationPrincipals("Helpdesk", null).Principals);

        var page = reader.ReadDelegations(new(principal, DelegationPermission.All, false), null);

        Assert.Equal([0, 1, 2], page.Entries.Select(row => row.Entry.Ordinal));
        Assert.Equal([0x10000000, 0x100, 0x10000000], page.Entries.Select(row => row.Entry.AccessMask));
        Assert.Equal(["AccessAllowed", "AccessDenied", "AccessAllowed"], page.Entries.Select(row => row.Entry.AceType));
        Assert.All(page.Entries, row => Assert.Equal(Holder, row.Entry.Trustee.Sid));
    }

    [Theory]
    [InlineData(DelegationPermission.ResetPassword, 0, 3, 4, 7)]
    [InlineData(DelegationPermission.CreateUser, 1, 3, 4, 8)]
    [InlineData(DelegationPermission.WriteUserProperties, 2, 3, 4, 5)]
    public void FiltersIncludeSpecificAndBroadRightsWithoutSubstitutingOtherRights(
        DelegationPermission permission, int first, int second, int third, int fourth)
    {
        using var fixture = new Fixture();
        fixture.Target("Alice", [
            SdBytes.AllowObjectAce(HolderSid, 0x100, ResetPassword, null),
            SdBytes.AllowObjectAce(HolderSid, 1, UserClass, null),
            SdBytes.AllowObjectAce(HolderSid, 0x20, Guid.NewGuid(), null),
            SdBytes.AllowAce(HolderSid, 0xF01FF),
            SdBytes.AllowAce(HolderSid, 0x10000000),
            SdBytes.AllowAce(HolderSid, 0x40000000),
            SdBytes.AllowObjectAce(HolderSid, 0x100, Guid.NewGuid(), null),
            SdBytes.DenyAce(HolderSid, 0x100),
            SdBytes.AllowAce(HolderSid, 1),
        ], ["top", "person", "user"]);
        var reader = fixture.Open();

        var page = reader.ReadDelegations(new(Unresolved(), permission, false), null);

        Assert.Equal([first, second, third, fourth], page.Entries.Select(row => row.Entry.Ordinal));
    }

    [Fact]
    public void InheritedEntriesAreAnExplicitChoiceAndKeepTheirOriginalWitness()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [
            SdBytes.AllowObjectAce(HolderSid, 0x100, ResetPassword, UserClass, 0x1A),
            SdBytes.AllowAce(HolderSid, 0x100),
        ]);
        var reader = fixture.Open();
        var query = new DelegationQuery(Unresolved(), DelegationPermission.ResetPassword, false);
        Assert.Equal([1], reader.ReadDelegations(query, null).Entries.Select(row => row.Entry.Ordinal));

        var inherited = reader.ReadDelegations(query with { IncludeInherited = true }, null).Entries[0].Entry;

        Assert.True(inherited.IsInherited);
        Assert.True(inherited.HasObjectType);
        Assert.True(inherited.HasInheritedObjectType);
        Assert.Equal(UserClass.ToString("D"), inherited.InheritedObjectTypeGuid);
        Assert.Equal((byte)8, inherited.PropagationFlags);
        Assert.Equal((byte)2, inherited.InheritanceFlags);
    }

    [Fact]
    public void PagingCrossesSharedObjectsAndDescriptorsWithoutLosingAnOriginalOccurrence()
    {
        using var fixture = new Fixture();
        var duplicate = SdBytes.AllowAce(HolderSid, 0x100);
        for (var n = 0; n < 80; n++) fixture.Target($"Target{n:D3}", [duplicate, duplicate, duplicate]);
        fixture.Target("Final", [SdBytes.DenyAce(HolderSid, 0x100)]);
        var reader = fixture.Open();
        var query = new DelegationQuery(Unresolved(), DelegationPermission.All, false);
        var entries = new List<DelegationEntry>();
        DelegationPageMark? mark = null;
        var reads = 0;
        strdelegate_trace trace = (_, sql) =>
        {
            if (sql.StartsWith("SELECT raw_bytes,", StringComparison.Ordinal)) reads++;
        };
        raw.sqlite3_trace(reader.Connection.Handle!, trace, null!);
        do
        {
            var page = reader.ReadDelegations(query, mark);
            Assert.InRange(page.Entries.Count, 1, DelegationLookup.PageSize);
            entries.AddRange(page.Entries);
            mark = page.Next;
        } while (mark is not null);
        raw.sqlite3_trace(reader.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);

        Assert.Equal(241, entries.Count);
        Assert.Equal(241, entries.Select(row => (row.DistinguishedName, row.Entry.Ordinal)).Distinct().Count());
        Assert.All(entries.GroupBy(row => row.DistinguishedName).Where(group => group.Count() == 3),
            group => Assert.Equal([0, 1, 2], group.Select(row => row.Entry.Ordinal)));
        Assert.Equal(4, reads);
    }

    [Theory]
    [InlineData("fingerprint")]
    [InlineData("principal")]
    [InlineData("permission")]
    [InlineData("inheritance")]
    public void ContinuationsRefuseDifferentEvidenceOrQuestions(string change)
    {
        using var fixture = new Fixture();
        var reader = fixture.Open();
        var query = new DelegationQuery(Unresolved(), DelegationPermission.All, false);
        var mark = new DelegationPageMark(fixture.Fingerprint, query, 1, 1, 0);
        if (change == "fingerprint") mark = mark with { EvidenceFingerprint = new string('0', 64) };
        if (change == "principal") query = query with { Principal = query.Principal with { Sid = Other } };
        if (change == "permission") query = query with { Permission = DelegationPermission.ResetPassword };
        if (change == "inheritance") query = query with { IncludeInherited = true };

        Assert.Throws<ArgumentException>(() => reader.ReadDelegations(query, mark));
    }

    [Fact]
    public void BuiltinGroupsAreDisambiguatedByTheirResourceDomain()
    {
        using var fixture = new Fixture();
        const string builtin = "S-1-5-32-544";
        fixture.Principal("Administrators", builtin, "contoso.com");
        fixture.Principal("Administrators", builtin, "child.contoso.com");
        fixture.Target("Root", [SdBytes.AllowAce(Sid.ToBytes(builtin)!, 0x100)], domain: "contoso.com");
        fixture.Target("Child", [SdBytes.AllowAce(Sid.ToBytes(builtin)!, 0x100)], domain: "child.contoso.com");
        var reader = fixture.Open();
        var principals = reader.FindDelegationPrincipals("Administrators", null).Principals;
        Assert.Equal(2, principals.Count);

        foreach (var principal in principals)
        {
            var page = reader.ReadDelegations(new(principal, DelegationPermission.All, false), null);
            Assert.Equal(principal.DomainFqdn, Assert.Single(page.Entries).DomainFqdn);
        }
    }

    [Fact]
    public void NameSearchIsLiteralPagedAndReturnsDomainQualifiedIdentities()
    {
        using var fixture = new Fixture();
        fixture.Principal("Help%desk", Holder);
        fixture.Principal("HelpXdesk", Other);
        for (var n = 0; n < DelegationLookup.PageSize + 2; n++) fixture.Principal($"Staff{n:D3}", $"S-1-5-21-1-2-3-{2000 + n}");
        var reader = fixture.Open();
        Assert.Equal("Help%desk", Assert.Single(reader.FindDelegationPrincipals("help%desk", null).Principals).Name);
        var first = reader.FindDelegationPrincipals("Staff", null);
        var second = reader.FindDelegationPrincipals("Staff", first.Next);

        Assert.Equal(DelegationLookup.PageSize, first.Principals.Count);
        Assert.Equal(2, second.Principals.Count);
        Assert.Null(second.Next);
        Assert.All(first.Principals, principal => Assert.Equal("contoso.com", principal.DomainFqdn));
        Assert.Empty(first.Principals.Intersect(second.Principals));
        Assert.Throws<ArgumentException>(() => reader.FindDelegationPrincipals("changed", first.Next));
        Assert.Throws<ArgumentException>(() => reader.FindDelegationPrincipals("Staff", first.Next! with { EvidenceFingerprint = "different" }));
    }

    [Fact]
    public void ExactUnresolvedSidCanFindEntriesWithoutInventingACapturedPrincipal()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [SdBytes.AllowAce(HolderSid, 0x100)]);
        var reader = fixture.Open();
        var principal = Assert.Single(reader.FindDelegationPrincipals(Holder, null).Principals);
        Assert.Null(principal.ObjectId);
        Assert.Null(principal.DomainFqdn);
        Assert.Null(principal.DistinguishedName);
        Assert.Single(reader.ReadDelegations(new(principal, DelegationPermission.All, false), null).Entries);
        Assert.Throws<ArgumentException>(() => reader.FindDelegationPrincipals("S-1-invalid", null));
    }

    [Theory]
    [InlineData("sid")]
    [InlineData("domain")]
    [InlineData("target")]
    public void ASelectedIdentityCannotBeBorrowedFromAnotherObject(string change)
    {
        using var fixture = new Fixture();
        fixture.Principal("Helpdesk", Holder);
        var reader = fixture.Open();
        var principal = Assert.Single(reader.FindDelegationPrincipals(Holder, null).Principals);
        principal = change switch
        {
            "sid" => principal with { Sid = Other },
            "domain" => principal with { DomainFqdn = "wrong.example" },
            _ => principal with { DistinguishedName = "CN=Other,DC=contoso,DC=com" },
        };
        Assert.Throws<InvalidDataException>(() => reader.ReadDelegations(new(principal, DelegationPermission.All, false), null));
    }

    [Fact]
    public void MissingIncompleteAndUnreadablePermissionsRemainSeparateFromPaging()
    {
        using var fixture = new Fixture();
        fixture.Principal("NoDescriptor", Holder);
        fixture.Unreadable("Denied");
        fixture.Target("Partial", [SdBytes.AllowAce(HolderSid, 0x100)], incomplete: true);
        var reader = fixture.Open(partial: true);

        var page = reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null);

        Assert.Null(page.Next);
        Assert.False(page.Coverage.DeclaredScopeWasRead);
        Assert.Equal((1L, 1L, 1L), (page.Coverage.UnreadableDescriptors, page.Coverage.UnattemptedDescriptors,
            page.Coverage.IncompleteDescriptors));
        Assert.Equal(DaclCompleteness.Incomplete, Assert.Single(page.Entries).DaclCompleteness);
    }

    [Fact]
    public void PropertySearchIncludesDescendantUsersAndPreservesUnresolvedClassScope()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [
            SdBytes.AllowObjectAce(HolderSid, 0x20, null, UserClass, 0x0A),
            SdBytes.AllowObjectAce(HolderSid, 0x20, null, Guid.NewGuid(), 0x0A),
            SdBytes.AllowAce(HolderSid, 0x20),
        ]);
        var reader = fixture.Open();

        var page = reader.ReadDelegations(new(Unresolved(), DelegationPermission.WriteUserProperties, false), null);

        Assert.Equal([0, 1], page.Entries.Select(row => row.Entry.Ordinal));
        Assert.Null(page.Entries[0].ScopeQualification);
        Assert.Contains("not established", page.Entries[1].ScopeQualification);
    }

    [Fact]
    public void CreatingAnotherChildClassIsNotCreatingUsers()
    {
        using var fixture = new Fixture();
        fixture.Target("Groups", [SdBytes.AllowObjectAce(HolderSid, 1, GroupClass, null)]);
        var reader = fixture.Open();

        Assert.Empty(reader.ReadDelegations(new(Unresolved(), DelegationPermission.CreateUser, false), null).Entries);
        Assert.Single(reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null).Entries);
    }

    [Fact]
    public void ACancelledLookupDoesNotReadSchemaOrCandidates()
    {
        using var fixture = new Fixture();
        var reader = fixture.Open();
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        var reads = 0;
        strdelegate_trace trace = (_, _) => reads++;
        raw.sqlite3_trace(reader.Connection.Handle!, trace, null!);

        Assert.Throws<OperationCanceledException>(() =>
            reader.ReadDelegations(new(Unresolved(), DelegationPermission.All, false), null, stopping.Token));

        raw.sqlite3_trace(reader.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);
        Assert.Equal(0, reads);
    }

    [Fact]
    public void CandidateLookupStartsWithTrusteeIndexesRatherThanEveryPermissionPosition()
    {
        using var fixture = new Fixture();
        fixture.Target("People", [SdBytes.AllowAce(HolderSid, 0x100)]);
        var reader = fixture.Open();
        using var command = reader.Connection.CreateCommand();
        command.CommandText = "EXPLAIN QUERY PLAN " + DelegationLookup.CandidateSql;
        command.Parameters.AddWithValue("$sid", Holder);
        command.Parameters.AddWithValue("$after", 0);
        command.Parameters.AddWithValue("$mask", 0x100);
        command.Parameters.AddWithValue("$inherited", 0);
        using var plan = command.ExecuteReader();
        var lines = new List<string>();
        while (plan.Read()) lines.Add(plan.GetString(3));

        Assert.Contains(lines, line => line.Contains("SEARCH t USING", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("SEARCH a USING INDEX ix_access_entry_trustee", StringComparison.Ordinal));
        Assert.Contains(lines, line => line.Contains("SEARCH d USING INDEX ix_descriptor_entry_entry", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, line => line.StartsWith("SCAN ", StringComparison.Ordinal));
    }

    private static DelegationPrincipal Unresolved() => new(null, Holder, Holder, null, null);

    internal sealed class Fixture : IDisposable
    {
        private static readonly DateTimeOffset Started = new(2026, 10, 5, 0, 0, 0, TimeSpan.Zero);
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "dlg-" + Guid.NewGuid().ToString("N"));
        private readonly BundleWriter _writer;
        private readonly HashSet<string> _domains = [];
        private ProtectedStoreFile? _store;
        private BundleReader? _reader;
        internal string DirectoryPath => _directory;
        internal string Fingerprint => _store!.Fingerprint;
        internal Fixture()
        {
            _writer = BundleWriter.Create(_directory, Started);
            Coverage("contoso.com");
        }
        private PartitionCoverage Coverage(string domain)
        {
            var coverage = new PartitionCoverage(Dn(domain), NamingContextKind.Domain, "dc." + domain,
                ConnectionSecurityLevel.SignedAndSealed, 12, 4200, 3, [], false);
            if (_domains.Add(domain)) _writer.WriteCoverage(coverage);
            return coverage;
        }
        internal void Principal(string name, string sid, string domain = "contoso.com", string? accountName = null) =>
            Object(name, ["top", "group"], domain, sid, accountName);
        private long Object(string name, string[] classes, string domain, string? sid = null, string? accountName = null)
        {
            var attributes = new List<EvidenceAttribute>
            {
                new("objectClass", StoredAttributeCompleteness.Complete, classes.Select(EvidenceValue.OfText).ToArray()),
                new("sAMAccountName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(accountName ?? name)]),
            };
            if (sid is not null) attributes.Add(new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]));
            return _writer.WriteObject(new(Coverage(domain), $"CN={name},{Dn(domain)}", Guid.NewGuid(), attributes, Started));
        }
        internal void Target(string name, byte[][] aces, string[]? classes = null, string domain = "contoso.com",
            bool incomplete = false, DaclCompleteness? recordedCompleteness = null)
        {
            var id = Object(name, classes ?? ["top", "organizationalUnit"], domain);
            var bytes = SdBytes.SelfRelativeSd(ownerSid: null, groupSid: null, daclAces: aces);
            var normalized = AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(bytes));
            if (incomplete) normalized = normalized with { DaclCompleteness = DaclCompleteness.Incomplete };
            if (recordedCompleteness is { } completeness) normalized = normalized with { DaclCompleteness = completeness };
            _writer.WriteSecurityDescriptor(id, bytes, normalized);
        }
        internal void Unreadable(string name) =>
            _writer.WriteUnreadableSecurityDescriptor(Object(name, ["top", "user"], "contoso.com"), "synthetic access denied");
        internal void MismatchedTarget()
        {
            var id = Object("Mismatched", ["top", "organizationalUnit"], "contoso.com");
            var original = SdBytes.SelfRelativeSd(null, null, [SdBytes.AllowAce(Sid.ToBytes(Other)!, 0x100)]);
            var indexed = SdBytes.SelfRelativeSd(null, null, [SdBytes.AllowAce(HolderSid, 0x100)]);
            _writer.WriteSecurityDescriptor(id, original, AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(indexed)));
        }
        internal void SysvolOnly(bool mismatchedIndex)
        {
            var raw = SdBytes.SelfRelativeSd(null, null, [
                SdBytes.AllowAce(mismatchedIndex ? Sid.ToBytes(Other)! : HolderSid, 0x40000)]);
            var indexed = SdBytes.SelfRelativeSd(null, null, [SdBytes.AllowAce(HolderSid, 0x40000)]);
            var normalized = AceNormalizer.Normalize(Guid.Empty, SecurityDescriptorParser.Parse(indexed))
                with { DaclCompleteness = DaclCompleteness.Incomplete, Errors = ["synthetic SYSVOL descriptor error"] };
            _writer.WriteSysvolSecurityDescriptor(Guid.NewGuid(), "Machine", raw, normalized);
        }
        internal BundleReader Open(bool partial = false)
        {
            _writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", _domains),
                _domains.Select(domain => partial ? DomainCoverage.PartiallyRead(domain, "synthetic capture gap") : DomainCoverage.Read(domain)).ToArray(),
                [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
                SysvolCoverage.Of([])), Started.AddMinutes(1));
            _writer.Dispose();
            _store = ProtectedStoreFile.OpenEvidence(_directory).Value;
            _reader = BundleReader.Open(_store).Value;
            return _reader;
        }
        private static string Dn(string domain) => "DC=" + domain.Replace(".", ",DC=", StringComparison.Ordinal);
        public void Dispose()
        {
            _reader?.Dispose();
            _store?.Dispose();
            _writer.Dispose();
            if (Directory.Exists(_directory)) Directory.Delete(_directory, recursive: true);
        }
    }
}

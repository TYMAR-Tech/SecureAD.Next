using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class DuplicateSpnReadTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(50)]
    [InlineData(51)]
    [InlineData(127)]
    public void RegisteredObjectPagesRetainEveryDistinctSavedOwner(int count)
    {
        var (evidence, selected) = Fixture(count);
        var owners = new List<Guid>();
        DuplicateSpnMark? position = null;
        do
        {
            var page = Project(evidence, selected, position);
            Assert.True(page.Context.Matches(selected));
            Assert.Equal(Severity.High, selected.Severity);
            Assert.Equal(count, page.TotalRows);
            Assert.Empty(page.Registrations);
            Assert.Equal(Math.Min(50, count - owners.Count), page.Owners.Count);
            owners.AddRange(page.Owners.Select(owner => owner.ObjectGuid));
            position = page.Next;
        } while (position is not null);
        Assert.Equal(evidence.Duplicates[0].Owners.Select(owner => owner.ObjectGuid), owners);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void ExplicitRegistrationPagesKeepOriginalSpellingOrderAndOccurrences(int copies)
    {
        var (evidence, selected) = Fixture(51, copies: copies);
        var first = Project(evidence, selected);
        DuplicateSpnMark? position = first.Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations };
        var values = new List<(Guid, int, string)>();
        do
        {
            var page = Project(evidence, selected, position);
            Assert.Empty(page.Owners);
            Assert.True(page.Context.SameAs(first.Context));
            values.AddRange(page.Registrations.Select(value => (value.Owner.ObjectGuid, value.Ordinal, value.Value)));
            position = page.Next;
        } while (position is not null);
        Assert.Equal(evidence.Duplicates[0].Occurrences.Select(value => (value.OwnerGuid, value.Ordinal, value.Value)), values);
    }

    [Fact]
    public void EachSavedConflictRemainsReachableWithoutChangingTheFindingGrain()
    {
        var (evidence, selected) = Fixture(2, matches: 3);
        var page = Project(evidence, selected);
        var keys = new List<string>();
        do
        {
            Assert.Equal(selected.Reference, page.Context.Reference);
            Assert.Equal(selected.Subject, page.Context.Subject);
            keys.Add(page.MatchKey);
            if (page.NextSpn is not { } next) break;
            page = Project(evidence, selected, next);
        } while (true);
        Assert.Equal(evidence.Duplicates.Select(match => match.MatchKey), keys);
    }

    [Theory]
    [InlineData("MSSQLSvc/host:1433")]
    [InlineData("Custom/host:instance")]
    [InlineData("LDAP/host/domain.example")]
    public void CompleteSavedNamesKeepPortsInstancesAndSuffixes(string value)
    {
        var (evidence, selected) = Fixture(2);
        var match = evidence.Duplicates[0];
        evidence = evidence with { Duplicates = [match with { MatchKey = value,
            Occurrences = match.Occurrences.Select(item => item with { Value = value }).ToArray() }] };
        Assert.Equal(value, Project(evidence, selected).MatchKey);
    }

    [Theory]
    [InlineData("missing inventory")]
    [InlineData("Kerberos system-service names require protocol-specific review; do not remove their registrations automatically.")]
    public void SavedLimitationsRemainVerbatimAndDoNotRemoveKnownDuplicates(string limitation)
    {
        var (evidence, selected) = Fixture(2);
        evidence = evidence with { Limitations = [limitation] };
        var page = Project(evidence, selected);
        Assert.Equal(new[] { limitation }, page.Context.Limitations);
        Assert.Equal(2, page.Owners.Count);
        Assert.Contains("not assurance of complete forest-wide uniqueness", SavedDuplicateSpn.LimitationsNote, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("seal")]
    [InlineData("subject")]
    [InlineData("owner")]
    [InlineData("verdict")]
    [InlineData("empty")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public void InvalidOrMisboundSavedDetailsAreRefused(string defect)
    {
        var (evidence, selected) = Fixture(2);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        switch (defect)
        {
            case "seal": json["EvidenceSeal"] = new string('b', 64); break;
            case "subject": json["SubjectGuid"] = Guid.NewGuid().ToString("D"); break;
            case "owner": json["Duplicates"]![0]!["Owners"]![0]!["DistinguishedName"] = "CN=Wrong,DC=contoso,DC=com"; break;
            case "verdict": json["Verdict"] = "RecordedDuplicatesWithLimitations"; break;
            case "empty": json["Duplicates"] = new JsonArray(); break;
        }
        var text = json.ToJsonString();
        if (defect == "truncated") text = text[..^1];
        if (defect == "trailing") text += "{}";
        Assert.Throws<InvalidDataException>(() => Project(evidence, selected, text: text));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("subject")]
    [InlineData("spn")]
    [InlineData("past-end")]
    [InlineData("kind")]
    public void PositionsCannotCrossQuestionsOrInventPages(string defect)
    {
        var (evidence, selected) = Fixture(51);
        var first = Project(evidence, selected);
        var mark = first.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "subject" => mark with { SubjectGuid = Guid.NewGuid() },
            "spn" => mark with { SpnIndex = 99 },
            "kind" => mark with { Kind = (DuplicateSpnPageKind)99 },
            _ => mark with { Offset = 1000 },
        };
        Assert.Throws<InvalidDataException>(() => Project(evidence, selected, mark));
    }

    [Fact]
    public void OrdinaryObjectPagesSkipOriginalOccurrencePayloads()
    {
        var (evidence, selected) = Fixture(2);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Duplicates"]![0]!["Occurrences"] = JsonNode.Parse("[{\"Unrequested\":\"" + new string('x', 160_000)
            + "\"},{\"Unrequested\":\"" + new string('y', 160_000) + "\"}]");
        Assert.Equal(2, Project(evidence, selected, text: json.ToJsonString()).Owners.Count);
    }

    [Fact]
    public void OriginalRegistrationsResolveOwnersEvenWhenJsonPropertiesAreReordered()
    {
        var (evidence, selected) = Fixture(2, copies: 2);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        var match = json["Duplicates"]![0]!.AsObject();
        var owners = match["Owners"]!.DeepClone();
        match.Remove("Owners");
        match.Add("Owners", owners);
        var position = Project(evidence, selected).Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations };
        Assert.Equal(4, Project(evidence, selected, position, json.ToJsonString()).Registrations.Count);
    }

    [Fact]
    public void UnrequestedOwnerNamesAreSkippedRatherThanReconstructed()
    {
        var (evidence, selected) = Fixture(51);
        var json = JsonSerializer.SerializeToNode(evidence, ProofSerialization.Options)!;
        json["Duplicates"]![0]!["Owners"]![50]!["AccountName"] = new JsonObject { ["Unrequested"] = new string('x', 160_000) };
        Assert.Equal(50, Project(evidence, selected, text: json.ToJsonString()).Owners.Count);
    }

    [Fact]
    public void AffectedIdentityOutsideTheLoadedOwnerPageStillBindsToTheSelectedFinding()
    {
        var (evidence, _) = Fixture(127);
        evidence = evidence with { SubjectGuid = evidence.Duplicates[0].Owners[^1].ObjectGuid };
        var selected = FindingListItem.FromFinding(Finding(evidence)) with { Reference = new(Guid.NewGuid(), 17) };
        var page = Project(evidence, selected);
        Assert.Equal(50, page.Owners.Count);
        Assert.DoesNotContain(page.Owners, owner => owner.ObjectGuid == evidence.SubjectGuid);
        Assert.True(page.Context.Matches(selected));
        Assert.Equal(evidence.SubjectGuid, page.Context.AffectedObject.ObjectGuid);
    }

    internal static (DuplicateSpnEvidence Evidence, FindingListItem Selected) Fixture(int owners, int matches = 1, int copies = 1)
    {
        var identities = Enumerable.Range(1, owners).Select(index => new DuplicateSpnOwner(
            Guid.Parse($"00000000-0000-0000-0000-{index:D12}"),
            $"CN=Same name,OU={index},DC=contoso,DC=com", index % 2 == 0 ? "child.contoso.com" : "contoso.com",
            "user", "Same name")).ToArray();
        var conflicts = Enumerable.Range(0, matches).Select(index =>
        {
            var key = $"HTTP/HOST{index}:1433/SERVICE";
            var occurrences = identities.SelectMany(owner => Enumerable.Range(0, copies).Select(copy =>
                new DuplicateSpnOccurrence(owner.ObjectGuid, copy, copy % 2 == 0 ? key : key.ToLowerInvariant()))).ToArray();
            return new DuplicateSpnMatch(key, identities, occurrences);
        }).ToArray();
        var evidence = new DuplicateSpnEvidence(new string('a', 64), "contoso.com", identities[0].ObjectGuid, conflicts, []);
        var selected = FindingListItem.FromFinding(Finding(evidence)) with { Reference = new(Guid.NewGuid(), 17) };
        return (evidence, selected);
    }

    internal static Finding Finding(DuplicateSpnEvidence evidence)
    {
        var owner = evidence.Duplicates[0].Owners.Single(owner => owner.ObjectGuid == evidence.SubjectGuid);
        return new("SEC-026", 1, Severity.High, new(FindingSubjectKind.DirectoryObject, owner.ObjectGuid.ToString("D")),
            owner.ObjectGuid, owner.DistinguishedName, owner.DomainFqdn, owner.ObjectClass, "Original raw proof prose.",
            EvidenceCompleteness.Complete, evidence) { PrincipalName = owner.AccountName ?? owner.DistinguishedName };
    }

    internal static SavedDuplicateSpn Project(DuplicateSpnEvidence evidence, FindingListItem selected,
        DuplicateSpnMark? position = null, string? text = null)
    {
        using var proof = new MemoryStream(Encoding.UTF8.GetBytes(text ?? JsonSerializer.Serialize(evidence, ProofSerialization.Options)));
        var description = new JudgementDescription(evidence.EvidenceSeal, selected.Reference!.Value.GenerationId, Guid.NewGuid(),
            JudgementRunState.Completed, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        return DuplicateSpnProjection.Read(proof, selected, description, position, CancellationToken.None);
    }
}

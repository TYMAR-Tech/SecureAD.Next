using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsReadSavedSupportTests
{
    [Theory]
    [InlineData(0, 0, 0x10, 4096)]
    [InlineData(128, 16, 0x10, 4096)]
    [InlineData(128, 0, 0x110, 4096)]
    [InlineData(128, 0, 0x110, 4098)]
    [InlineData(128, 0, 0x110, null)]
    public void Scout09RealCapturedSchemaAndDisabledStateReachSavedReadProof(int flags, int system, int mask, int? control)
    {
        var run = Scout09LapsRun.Create(searchFlags: flags, systemFlags: system, mask: mask, control: (uint?)control);
        using var reader = JudgementReader.Open(run.Directory).Value;
        var saved = reader.Read();
        var finding = Assert.Single(saved.Findings);
        Assert.Equal(("SEC-090", 2, Severity.High, run.TargetGuid),
            (finding.RuleId, finding.RuleVersion, finding.Severity, finding.ObjectGuid));
        var header = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.False(header.SupportsWereLoaded);
        Assert.Equal((true, true, true, true, 1),
            (header.Assessment.DescriptorIsComplete, header.Assessment.SchemaIsComplete,
                header.Assessment.MembershipIsComplete, header.Assessment.ReadChecksAreComplete,
                header.Assessment.EstablishedExposureCount));
        Assert.True(header.IsComplete);
        Assert.Equal(1, header.Assessment.ExposureCount);
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        var page = reader.ReadLapsReadSupports(row.Reference!.Value, after: null);
        Assert.True(page.IsSuccess, page.Error?.Description);
        var proof = Assert.Single(page.Value.Exposures);
        Assert.Equal((flags, system, run.TargetGuid, Scout09LapsRun.Target),
            (proof.SearchFlags, proof.SystemFlags, proof.TargetGuid, proof.Target));
        Assert.Equal(LapsReadState.Established, proof.State);
        Assert.Single(proof.Entries!);
        Assert.Equal(mask, Assert.Single(proof.Entries!).Entry.AccessMask);
        Assert.Null(page.Value.Next);
    }

    [Theory]
    [InlineData("property-set")]
    [InlineData("class")]
    public void Scout09RealCapturedHierarchyReachesBothSavedRights(string scope)
    {
        var run = Scout09LapsRun.Create(scope: scope, attribute: "msLAPS-EncryptedPassword");
        using var reader = JudgementReader.Open(run.Directory).Value;
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        var page = reader.ReadLapsReadSupports(row.Reference!.Value, after: null).Value;
        var proof = Assert.Single(page.Exposures, value => value.Attribute == "msLAPS-EncryptedPassword");
        Assert.Equal(LapsReadState.Established, proof.State);
        Assert.Equal(LapsReadState.Established, proof.ReadProperty.State);
        Assert.Equal(LapsReadState.Established, proof.ControlAccess.State);
        Assert.Equal(2, proof.Entries!.Count);
        if (scope == "property-set")
            Assert.Contains(proof.Entries, value => value.PropertySetMembers?.Contains("msLAPS-EncryptedPassword") == true);
        else
            Assert.Equal(Scout09LapsRun.ComputerGuid, proof.TargetClassGuid);
    }

    [Fact]
    public void Scout09EstablishedDirectReadRetainsAnIndependentMembershipSourceGap()
    {
        var run = Scout09LapsRun.Create(captureBroadPrincipal: false);
        using var reader = JudgementReader.Open(run.Directory).Value;
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        Assert.Equal(1, evidence.Assessment.EstablishedExposureCount);
        Assert.True(evidence.Assessment.DescriptorIsComplete);
        Assert.False(evidence.Assessment.MembershipIsComplete);
        Assert.False(evidence.IsComplete);
    }

    [Fact]
    public void Scout09ShortNativeDescriptorRetainsTheReviewWithoutACompleteHeader()
    {
        var run = Scout09LapsRun.Create(shortDescriptor: true);
        using var reader = JudgementReader.Open(run.Directory).Value;
        var finding = Assert.Single(reader.Read().Findings);
        var evidence = Assert.IsType<LapsPasswordReaderEvidence>(finding.Evidence);
        Assert.False(evidence.IsComplete);
        Assert.False(evidence.Assessment.DescriptorIsComplete);
        Assert.Equal(0, evidence.Assessment.EstablishedExposureCount);
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        Assert.False(row.EvidenceIsComplete);
        var support = Assert.Single(reader.ReadLapsReadSupports(row.Reference!.Value, after: null).Value.Exposures);
        Assert.Equal(LapsReadState.Unresolved, support.State);
    }

    [Fact]
    public void Scout09IndependentSupportsArePagedAtFiftyWithoutChangingTheFindingGrain()
    {
        var run = Scout09LapsRun.Create(holders: 103);
        using var reader = JudgementReader.Open(run.Directory).Value;
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        var first = reader.ReadLapsReadSupports(row.Reference!.Value, after: null).Value;
        var second = reader.ReadLapsReadSupports(row.Reference.Value, Assert.IsType<LapsReadSupportMark>(first.Next)).Value;
        var third = reader.ReadLapsReadSupports(row.Reference.Value, Assert.IsType<LapsReadSupportMark>(second.Next)).Value;
        Assert.Equal((50, 50, 3), (first.Exposures.Count, second.Exposures.Count, third.Exposures.Count));
        Assert.Equal((103, 103, 103), (first.Assessment.ExposureCount, second.Assessment.ExposureCount, third.Assessment.ExposureCount));
        Assert.Equal(103, first.Exposures.Concat(second.Exposures).Concat(third.Exposures).Select(value => value.TrusteeSid).Distinct().Count());
        Assert.All(first.Exposures.Concat(second.Exposures).Concat(third.Exposures), value =>
        {
            Assert.Equal("S-1-5-11", value.MembershipPath[^1].Sid);
            Assert.Single(value.Entries!);
        });
        Assert.Null(third.Next);
        Assert.Single(reader.Read().Findings);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("ordinal")]
    public void Scout09ContinuationCannotCrossItsSavedQuestion(string defect)
    {
        var run = Scout09LapsRun.Create(holders: 51);
        using var reader = JudgementReader.Open(run.Directory).Value;
        var reference = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings).Reference!.Value;
        var after = Assert.IsType<LapsReadSupportMark>(reader.ReadLapsReadSupports(reference, after: null).Value.Next);
        after = defect switch
        {
            "generation" => after with { Reference = reference with { GenerationId = Guid.NewGuid() } },
            "finding" => after with { Reference = reference with { FindingId = reference.FindingId + 1 } },
            _ => after with { AfterOrdinal = 51 },
        };
        var result = reader.ReadLapsReadSupports(reference, after);
        Assert.False(result.IsSuccess);
        Assert.Equal("Evidence.FindingSelectionChanged", result.Error.Code);
    }

    [Theory]
    [InlineData("payload")]
    [InlineData("entry")]
    public void Scout09SelectedSummaryAndFirstPageDoNotDecodeLaterSupports(string defect)
    {
        var run = Scout09LapsRun.Create(holders: 51);
        Scout09LapsRun.Mutate(run.Directory, defect == "payload"
            ? "UPDATE finding_laps_password_reader_support SET payload='not json' WHERE ordinal=50"
            : """
                UPDATE finding_laps_password_reader_entry SET payload='not json'
                WHERE ordinal=(SELECT json_extract(payload,'$.EntryOrdinals[0]')
                    FROM finding_laps_password_reader_support WHERE ordinal=50)
                """);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(run.Directory,
            FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        var selected = source.ReadSelectedFinding(run.Directory, row.Reference!.Value, false);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        var first = source.ReadLapsReadSupports(run.Directory, row.Reference.Value, null);
        Assert.True(first.IsSuccess);
        Assert.Equal(50, first.Value.Exposures.Count);
        var later = source.ReadLapsReadSupports(run.Directory, row.Reference.Value, first.Value.Next);
        Assert.False(later.IsSuccess);
        Assert.Equal("Shell.SavedResultsInvalidEvidence", later.Error.Code);
    }

    [Theory]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("missing-row")]
    [InlineData("wrong-count")]
    public void Scout09InvalidSavedSupportIsAnExplicitFailure(string defect)
    {
        var run = Scout09LapsRun.Create();
        Scout09LapsRun.Mutate(run.Directory, defect switch
        {
            "target" => "UPDATE finding_laps_password_reader_support SET payload=json_set(payload,'$.Target','CN=Different,DC=ad,DC=lab')",
            "generation" => $"UPDATE finding_laps_password_reader_support SET generation_id='{Guid.NewGuid():D}'",
            "missing-row" => "DELETE FROM finding_laps_password_reader_support",
            _ => "UPDATE finding_laps_password_reader SET exposure_count=exposure_count+1",
        });
        using var reader = JudgementReader.Open(run.Directory).Value;
        var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings);
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsReadSupports(row.Reference!.Value, after: null));
    }

    [Fact]
    public void Scout09OrdinarySelectedFindingUsesPreparedSummaryWithoutHydratingSupports()
    {
        var run = Scout09LapsRun.Create(holders: 51);
        Scout09LapsRun.Mutate(run.Directory, "UPDATE finding_laps_password_reader_support SET payload='not json'");
        using var source = new BundleAssetSource();
        var list = source.ReadFindingsList(run.Directory, FindingsQuery.About(Scout09LapsRun.Target));
        Assert.True(list.IsSuccess, list.Error?.Description);
        var reference = Assert.Single(list.Value.Findings).Reference!.Value;
        var selected = source.ReadSelectedFinding(run.Directory, reference, false);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Contains("51 established holder/attribute exposure(s)", selected.Value.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Scout09ApplicationServingUsesTheSameBoundedSavedQuestion(bool wrongGeneration)
    {
        var run = Scout09LapsRun.Create(holders: 51);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(run.Directory,
            FindingsQuery.About(Scout09LapsRun.Target)).Value.Findings).Reference!.Value;
        var first = source.ReadLapsReadSupports(run.Directory, reference, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        Assert.Equal(50, first.Value.Exposures.Count);
        var next = Assert.IsType<LapsReadSupportMark>(first.Value.Next);
        if (wrongGeneration) next = next with { Reference = reference with { GenerationId = Guid.NewGuid() } };
        var second = source.ReadLapsReadSupports(run.Directory, reference, next);
        if (wrongGeneration)
        {
            Assert.False(second.IsSuccess);
            Assert.Equal("Evidence.FindingSelectionChanged", second.Error.Code);
        }
        else
        {
            Assert.True(second.IsSuccess, second.Error?.Description);
            Assert.Single(second.Value.Exposures);
            Assert.Equal(51, second.Value.Assessment.ExposureCount);
            Assert.Null(second.Value.Next);
        }
    }
}

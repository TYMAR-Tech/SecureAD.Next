using SecureAD.Evidence;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

public sealed class CapturedObjectSearchTests
{
    [Fact]
    public void AccountNameCanMatchWhenItDoesNotAppearInTheDistinguishedName()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Friendly display name", "S-1-5-21-1-2-3-1100", accountName: "operator.27");
        var reader = fixture.Open();

        var match = Assert.Single(reader.SearchObjects("operator.27", null).Objects);

        Assert.Equal("Friendly display name", match.Name);
        Assert.DoesNotContain("operator.27", match.DistinguishedName);
    }

    [Fact]
    public void UnprotectedLibraryReaderCannotSearchCapturedObjects()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Open();
        using var reader = BundleReader.OpenUnverified(fixture.DirectoryPath).Value;

        Assert.Throws<InvalidOperationException>(() => reader.SearchObjects("Alice", null));
    }

    [Fact]
    public void SearchCoversAllDomainsAndKeepsNameTypeAndLocation()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Helpdesk", "S-1-5-21-1-2-3-1100", "contoso.com");
        fixture.Principal("Helpdesk", "S-1-5-21-4-5-6-1100", "child.contoso.com");
        fixture.Target("HelpdeskArchive", [], ["top", "container"]);
        var reader = fixture.Open();

        var page = reader.SearchObjects("helpdesk", null);

        Assert.Equal(3, page.Objects.Count);
        Assert.Equal(2, page.Objects.Select(row => row.DomainFqdn).Distinct().Count());
        Assert.Equal("container", page.Objects.Single(row => row.Name == "HelpdeskArchive").ObjectClass);
        Assert.All(page.Objects, row => Assert.NotNull(row.ParentDistinguishedName));
        Assert.Null(page.Next);
    }

    [Fact]
    public void SearchTreatsWildcardCharactersAsLiteralText()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Help%_desk", "S-1-5-21-1-2-3-1100");
        fixture.Principal("HelpXXdesk", "S-1-5-21-1-2-3-1101");
        var reader = fixture.Open();

        Assert.Equal("Help%_desk", Assert.Single(reader.SearchObjects("%_", null).Objects).Name);
        Assert.Empty(reader.SearchObjects("' OR 1=1 --", null).Objects);
        Assert.Throws<ArgumentException>(() => reader.SearchObjects("   ", null));
    }

    [Fact]
    public void PagesStayBoundToTheOriginalCaptureAndSubmittedSearch()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        for (var index = 0; index < 205; index++)
            fixture.Principal($"Person{index:D3}", $"S-1-5-21-1-2-3-{1100 + index}");
        var reader = fixture.Open();
        var first = reader.SearchObjects("Person", null);
        var second = reader.SearchObjects("Person", first.Next);
        var third = reader.SearchObjects("Person", second.Next);

        Assert.Equal(100, first.Objects.Count);
        Assert.Equal(100, second.Objects.Count);
        Assert.Equal(5, third.Objects.Count);
        Assert.Null(third.Next);
        Assert.Equal(205, first.Objects.Concat(second.Objects).Concat(third.Objects).Select(row => row.DistinguishedName).Distinct().Count());
        Assert.Throws<ArgumentException>(() => reader.SearchObjects("Different", first.Next));
        Assert.Throws<ArgumentException>(() => reader.SearchObjects("Person", first.Next! with { EvidenceFingerprint = "different" }));
        Assert.Throws<ArgumentException>(() => reader.SearchObjects("Person", first.Next! with { ObjectId = 0 }));
    }

    [Fact]
    public void EmptyMatchesDoNotConcealIncompleteCapture()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Alice", "S-1-5-21-1-2-3-1100");
        var reader = fixture.Open(partial: true);

        var page = reader.SearchObjects("NotCaptured", null);

        Assert.Empty(page.Objects);
        Assert.False(page.Coverage.IsComplete);
        Assert.Contains("may be missing", page.Coverage.Shortfall);
    }

    [Fact]
    public void SearchAndPreCancellationDoNotLoadPermissionsOrAnalysis()
    {
        using var fixture = new DelegationLookupTests.Fixture();
        fixture.Principal("Alice", "S-1-5-21-1-2-3-1100");
        var reader = fixture.Open();
        var statements = new List<string>();
        strdelegate_trace trace = (_, sql) => statements.Add(sql);
        raw.sqlite3_trace(reader.Connection.Handle!, trace, null!);

        var page = reader.SearchObjects("Alice", null);
        var reads = statements.Count;
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.SearchObjects("Alice", null, cancelled.Token));

        raw.sqlite3_trace(reader.Connection.Handle!, (strdelegate_trace)null!, null!);
        GC.KeepAlive(trace);
        Assert.Single(page.Objects);
        Assert.Equal(1, reads);
        Assert.Equal(reads, statements.Count);
        Assert.DoesNotContain(statements, sql => sql.Contains("security_descriptor", StringComparison.Ordinal)
            || sql.Contains("judgement", StringComparison.Ordinal) || sql.Contains("membership", StringComparison.Ordinal));
    }
}

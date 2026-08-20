using SecureAD.Audit.Capture;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// Inventory row B8: reading what a domain controller returns, and the range-retrieval rule.
///
/// <para>
/// <b>How this is tested without a directory.</b> There is no forest in CI, and the row's
/// load-bearing case is a group with more members than a controller will send at once. So these
/// tests put a <see cref="ValueLimitedServer"/> in front of the reader: an object holding ten
/// thousand members that serves them the way the LDAP policy says a controller does - at most
/// <c>MaxValRange</c> values per response, under a ranged attribute name, with the final block
/// marked by the wildcard.
/// </para>
/// <para>
/// <b>What that does and does not prove.</b> It exercises the real rule end to end: the
/// specifier the reader asks for, the blocks it joins, where it decides the values are complete,
/// and its refusal to call a partial read complete. What it cannot prove is that a production
/// domain controller formats its ranged names the way this model does. That is a claim about the
/// wire, it is owed to the lab session, and it is recorded as a finding rather than implied by a
/// green test here.
/// </para>
/// </summary>
public sealed class LdapEntryReaderTests
{
    private const string GroupDn = "CN=Domain Users,CN=Users,DC=contoso,DC=com";

    private static readonly CapturedAttribute Member =
        new("member", AttributeCardinality.MultiValued, AttributeStorage.Text);

    private static readonly CapturedAttribute SamAccountName =
        new("sAMAccountName", AttributeCardinality.SingleValued, AttributeStorage.Text);

    /// <summary>
    /// The case the row exists for. Ten thousand members, a controller that will send 1,500 at a
    /// time, and a reader that must come back with ten thousand rather than with 1,500.
    /// </summary>
    [Fact]
    public void AGroupLargerThanTheServersValueLimitIsReadInFull()
    {
        var server = new ValueLimitedServer(memberCount: 10_000, maxValRange: 1_500);

        var read = ReadEveryValue(server, Member);

        Assert.Equal(AttributeCompleteness.Complete, read.Completeness);
        Assert.Equal(10_000, read.Values.Count);
        Assert.Equal(server.Members, read.Values.Cast<string>());
    }

    /// <summary>
    /// The defect, stated as a test. A reader that stops at the first response reports a
    /// ten-thousand-member group as a group of a thousand - and the thing that makes that
    /// impossible here is that the first response does not say it is complete.
    /// </summary>
    [Fact]
    public void TheFirstResponseDoesNotClaimToBeAllOfThem()
    {
        var server = new ValueLimitedServer(memberCount: 10_000, maxValRange: 1_500);

        var first = server.Read(AttributeRange.FirstRound, Member).ValuesOf(Member);

        Assert.Equal(AttributeCompleteness.MoreToFetch, first.Completeness);
        Assert.NotNull(first.NextRange);
        Assert.Equal(1_000, first.Values.Count);
    }

    /// <summary>
    /// A controller that raised its policy still caps at 5,000 values on Windows Server 2008 and
    /// later, so the same group read against a permissive forest is still not read in one go.
    /// </summary>
    [Fact]
    public void TheHardcodedCeilingDoesNotLetALargeGroupArriveInOneResponse()
    {
        var server = new ValueLimitedServer(memberCount: 10_000, maxValRange: 5_000);

        var first = server.Read(AttributeRange.FirstRound, Member).ValuesOf(Member);

        Assert.Equal(AttributeCompleteness.MoreToFetch, first.Completeness);
        Assert.Equal(10_000, ReadEveryValue(server, Member).Values.Count);
    }

    /// <summary>
    /// A group that fits under the limit comes back under its own name, complete, and no range
    /// retrieval happens at all.
    /// </summary>
    [Fact]
    public void AGroupInsideTheLimitIsCompleteOnTheFirstResponse()
    {
        var server = new ValueLimitedServer(memberCount: 42, maxValRange: 1_500);

        var read = server.Read(range: null, Member).ValuesOf(Member);

        Assert.Equal(AttributeCompleteness.Complete, read.Completeness);
        Assert.Equal(42, read.Values.Count);
        Assert.Null(read.NextRange);
    }

    /// <summary>
    /// An attribute that did not come back is reported as not returned, and never as an attribute
    /// with no values. The two mean different things and one of them is a fact about permission.
    /// </summary>
    [Fact]
    public void AnAbsentAttributeIsNotReportedAsAnEmptyOne()
    {
        var entry = LdapEntryReader.ForValues(GroupDn, []);

        var read = entry.ValuesOf(Member);

        Assert.Equal(AttributeCompleteness.NotReturned, read.Completeness);
        Assert.Empty(read.Values);
    }

    /// <summary>
    /// A single-valued attribute is never looked for under a ranged name. Cardinality decides,
    /// and no attribute is tested by its own name.
    /// </summary>
    [Fact]
    public void ASingleValuedAttributeIsReadWithoutRanging()
    {
        var entry = LdapEntryReader.ForValues(
            GroupDn,
            [new("sAMAccountName", new object[] { "Domain Users" })]);

        var read = entry.ValuesOf(SamAccountName);

        Assert.Equal(AttributeCompleteness.Complete, read.Completeness);
        Assert.Equal("Domain Users", Assert.Single(read.Values));
    }

    /// <summary>
    /// A block that returns nothing while more values are outstanding is a failure, not the end.
    /// This is what replaces a cap on rounds: the loop is bounded by progress, so it cannot spin
    /// and cannot quietly settle for a prefix.
    /// </summary>
    [Fact]
    public void ABlockThatAdvancedByNothingIsAFailureAndNotAnEnding()
    {
        var soFar = new AttributeValues(
            "member", new object[] { "CN=a" }, AttributeCompleteness.MoreToFetch, new(1, 1_000));

        var empty = new AttributeValues(
            "member", [], AttributeCompleteness.MoreToFetch, new(1, 1_000));

        var joined = LdapEntryReader.Continue(soFar, empty);

        Assert.False(joined.IsSuccess);
        Assert.Equal("Capture.RangeRetrievalMadeNoProgress", joined.Error.Code);
    }

    /// <summary>
    /// A block that stopped carrying the attribute is a failure too. The controller had already
    /// said there were more values, so silence is not an ending.
    /// </summary>
    [Fact]
    public void ABlockThatStoppedCarryingTheAttributeIsAFailure()
    {
        var soFar = new AttributeValues(
            "member", new object[] { "CN=a" }, AttributeCompleteness.MoreToFetch, new(1, 1_000));

        var absent = new AttributeValues(
            "member", [], AttributeCompleteness.NotReturned, NextRange: null);

        var joined = LdapEntryReader.Continue(soFar, absent);

        Assert.False(joined.IsSuccess);
        Assert.Equal("Capture.RangeRetrievalStoppedAnswering", joined.Error.Code);
    }

    /// <summary>Values of one attribute are never joined onto another's.</summary>
    [Fact]
    public void ABlockAboutAnotherAttributeIsRefused()
    {
        var soFar = new AttributeValues(
            "member", new object[] { "CN=a" }, AttributeCompleteness.MoreToFetch, new(1, 1_000));

        var wrong = new AttributeValues(
            "memberOf", new object[] { "CN=b" }, AttributeCompleteness.Complete, NextRange: null);

        var joined = LdapEntryReader.Continue(soFar, wrong);

        Assert.False(joined.IsSuccess);
        Assert.Equal("Capture.RangeRetrievalAnsweredAboutAnotherAttribute", joined.Error.Code);
    }

    /// <summary>The range specifier is spelled the way Microsoft documents it.</summary>
    [Theory]
    [InlineData(0, 999, "member;range=0-999")]
    [InlineData(1000, 1999, "member;range=1000-1999")]
    public void TheSpecifierNamesTheAttributeAndTheBlock(int low, int high, string expected)
    {
        Assert.Equal(expected, new AttributeRange(low, high).SpecifierFor("member"));
    }

    /// <summary>The wildcard means "and all the rest", on a request and on a response alike.</summary>
    [Fact]
    public void TheWildcardIsHowABlockSaysItWasTheLast()
    {
        Assert.Equal("member;range=1500-*", new AttributeRange(1_500, null).SpecifierFor("member"));

        Assert.True(AttributeRange.TryReadSpecifier("member;range=1500-*", out var name, out var range));
        Assert.Equal("member", name);
        Assert.Equal(new AttributeRange(1_500, null), range);
    }

    /// <summary>A name with no range option is an ordinary attribute, not a block of zero.</summary>
    [Theory]
    [InlineData("member")]
    [InlineData("member;range=")]
    [InlineData("member;range=x-9")]
    [InlineData("member;range=9-1")]
    [InlineData(";range=0-9")]
    public void ANameThatCarriesNoUsableRangeIsNotReadAsOne(string returnedName)
    {
        Assert.False(AttributeRange.TryReadSpecifier(returnedName, out _, out var range));
        Assert.Null(range);
    }

    /// <summary>
    /// The next block starts where the values received end, rather than where the request asked
    /// them to. A controller entitled to serve fewer values than were asked for is followed, not
    /// skipped over.
    /// </summary>
    [Fact]
    public void TheNextBlockStartsWhereTheValuesReceivedEnd()
    {
        Assert.Equal(new AttributeRange(600, 1_599), new AttributeRange(0, 999).NextAfter(600));
        Assert.Equal(new AttributeRange(1_000, 1_999), AttributeRange.FirstRound.NextAfter(1_000));
    }

    /// <summary>A round is a thousand values, which is the size safe against every server.</summary>
    [Fact]
    public void ARoundAsksForAThousandValues()
    {
        Assert.Equal(1_000, AttributeRange.ValuesPerRound);
        Assert.Equal(new AttributeRange(0, 999), AttributeRange.FirstRound);
    }

    [Fact]
    public void TextIsDecodedAsUtf8AndInvalidBytesAreReportedRatherThanReplaced()
    {
        Assert.Equal("Ostschweiz", LdapEntryReader.AsText("Ostschweiz").Value);
        Assert.Equal("Ätna", LdapEntryReader.AsText(System.Text.Encoding.UTF8.GetBytes("Ätna")).Value);

        var broken = LdapEntryReader.AsText(new byte[] { 0xC3, 0x28 });

        Assert.False(broken.IsSuccess);
        Assert.Equal("Capture.AttributeValueNotReadable", broken.Error.Code);
    }

    [Fact]
    public void AGuidIsSixteenBytesAndAnythingElseIsReported()
    {
        var guid = Guid.NewGuid();

        Assert.Equal(guid, LdapEntryReader.AsGuid(guid.ToByteArray()).Value);
        Assert.False(LdapEntryReader.AsGuid(new byte[] { 1, 2, 3 }).IsSuccess);
        Assert.False(LdapEntryReader.AsGuid("not bytes").IsSuccess);
    }

    [Fact]
    public void ASidIsReadIntoItsStringForm()
    {
        var sid = new System.Security.Principal.SecurityIdentifier("S-1-5-32-544");
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);

        Assert.Equal("S-1-5-32-544", LdapEntryReader.AsSid(bytes).Value);
        Assert.False(LdapEntryReader.AsSid(new byte[] { 9 }).IsSuccess);
    }

    [Fact]
    public void AWholeNumberIsReadAtSixtyFourBitsAndTextThatIsNotOneIsReported()
    {
        Assert.Equal(133_000_000_000_000_000L, LdapEntryReader.AsInteger("133000000000000000").Value);
        Assert.Equal(-1L, LdapEntryReader.AsInteger("-1").Value);
        Assert.False(LdapEntryReader.AsInteger("yesterday").IsSuccess);
    }

    /// <summary>
    /// Asking for a block of something already complete is a defect in the loop rather than an
    /// outcome of a request, so it throws rather than returning a failure.
    /// </summary>
    [Fact]
    public void ContinuingSomethingAlreadyCompleteIsADefect()
    {
        var complete = new AttributeValues(
            "member", new object[] { "CN=a" }, AttributeCompleteness.Complete, NextRange: null);

        Assert.Throws<InvalidOperationException>(
            () => LdapEntryReader.Continue(complete, complete));
    }

    /// <summary>
    /// Runs a whole retrieval against the server model, the way the capture loop will: ask,
    /// join, ask again with the block the answer named, until the answer says it is complete.
    /// </summary>
    private static AttributeValues ReadEveryValue(
        ValueLimitedServer server, CapturedAttribute attribute)
    {
        var read = server.Read(AttributeRange.FirstRound, attribute).ValuesOf(attribute);

        while (read.Completeness == AttributeCompleteness.MoreToFetch)
        {
            var block = server.Read(read.NextRange, attribute).ValuesOf(attribute);
            var joined = LdapEntryReader.Continue(read, block);

            Assert.True(joined.IsSuccess, joined.IsSuccess ? "" : joined.Error.Description);
            read = joined.Value;
        }

        return read;
    }

    /// <summary>
    /// A domain controller as the LDAP policy describes one: it will not put more than
    /// <c>MaxValRange</c> values of one attribute in one response, it answers a ranged request
    /// under the ranged name it served, and it marks the final block with the wildcard.
    ///
    /// <para>
    /// This is a model and it is stated as one. It is the behaviour the documents say a
    /// controller has; whether a production controller matches it in every detail of spelling is
    /// the part these tests cannot reach.
    /// </para>
    /// </summary>
    private sealed class ValueLimitedServer(int memberCount, int maxValRange)
    {
        public IReadOnlyList<string> Members { get; } =
            Enumerable.Range(0, memberCount)
                .Select(i => $"CN=User{i:D5},CN=Users,DC=contoso,DC=com")
                .ToArray();

        public LdapEntryReader Read(AttributeRange? range, CapturedAttribute attribute)
        {
            var low = range?.Low ?? 0;
            var asked = range?.High is null ? Members.Count - low : range.High.Value - low + 1;
            var served = Math.Min(Math.Min(asked, maxValRange), Members.Count - low);

            var values = Members.Skip(low).Take(served).Cast<object>().ToArray();
            var isLastBlock = low + served >= Members.Count;

            // Under the limit and asked for plainly, a controller answers under the plain name.
            if (range is null && isLastBlock && Members.Count <= maxValRange)
            {
                return LdapEntryReader.ForValues(
                    GroupDn, [new(attribute.LdapDisplayName, values)]);
            }

            var servedRange = isLastBlock
                ? new AttributeRange(low, null)
                : new AttributeRange(low, low + served - 1);

            return LdapEntryReader.ForValues(
                GroupDn, [new(servedRange.SpecifierFor(attribute.LdapDisplayName), values)]);
        }
    }
}

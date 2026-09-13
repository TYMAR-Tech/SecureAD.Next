using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// Putting back together what a sink accumulates in memory, which the shard database does not
/// carry.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two things outlive a partition inside a sink, and under the fan-out there are nine of
/// each.</b> The Group Policy inventory and the tally of descriptors the forest held that could
/// not be parsed. The rows themselves are in the shard database and are carried by
/// <see cref="BundleMerge"/>; these two are not, and without
/// <see cref="BundleCaptureSink.Absorb"/> the run would reach SYSVOL holding only whatever the
/// serial prologue happened to see.
/// </para>
/// <para>
/// <b>The inventory is the half that would produce a wrong answer rather than an error</b>, for
/// the reason set out in <c>docs/decisions/0044</c>; <c>GpoInventoryTests</c> is where the two
/// lists it lives in are held apart. What is tested here is that the sink carries it at all.
/// </para>
/// </remarks>
public sealed class BundleCaptureSinkTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-sink-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started =
        new(2026, 9, 13, 9, 0, 0, TimeSpan.Zero);

    private static readonly Guid PolicyGuid =
        Guid.Parse("31b2f340-016d-11d2-945f-00c04fb984f9");

    private readonly List<BundleWriter> _writers = [];

    // ---------------------------------------------------------------------------------------
    // What a merged sink carries
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void AnAbsorbedSinksPoliciesJoinTheInventory()
    {
        var forest = SinkOn(BundleShard.Whole);
        var domain = SinkOn(BundleShard.Number(1));

        Observe(domain, PolicyGuid);

        forest.Absorb(domain);

        var policy = Assert.Single(forest.Policies.Policies);

        Assert.Equal(PolicyGuid, policy.GpoGuid);
    }

    /// <summary>
    /// The tally of descriptors that could not be read is added rather than replaced.
    /// </summary>
    /// <remarks>
    /// A run-wide figure, and the arithmetic is the point: nine domains each reporting their own
    /// would leave a run stating whichever number arrived last. A production domain returned 19,927
    /// objects with no readable descriptor out of 100,000 (<c>F-S20-16</c>), so this is a figure an
    /// operator acts on rather than a curiosity.
    /// </remarks>
    [Fact]
    public void AnAbsorbedSinksUnreadableDescriptorsAreAddedToTheTally()
    {
        var forest = SinkOn(BundleShard.Whole);
        var first = SinkOn(BundleShard.Number(1));
        var second = SinkOn(BundleShard.Number(2));

        WithdrawnDescriptors(first, "DC=contoso,DC=com", "One");
        WithdrawnDescriptors(second, "DC=fabrikam,DC=com", "Two", "Three");

        forest.Absorb(first);
        forest.Absorb(second);

        Assert.Equal(3, forest.UnreadableDescriptors);
    }

    /// <summary>
    /// The negative control for the tally: a sink that read every descriptor adds nothing.
    /// </summary>
    /// <remarks>
    /// Without it the test above would also pass against a merge that counted objects, or
    /// partitions, or anything else that happened to come to three.
    /// </remarks>
    [Fact]
    public void AbsorbingASinkThatReadEveryDescriptorAddsNothingToTheTally()
    {
        var forest = SinkOn(BundleShard.Whole);
        var domain = SinkOn(BundleShard.Number(1));

        ReadableDescriptors(domain, "DC=contoso,DC=com", "One");

        forest.Absorb(domain);

        Assert.Equal(0, forest.UnreadableDescriptors);
    }

    // ---------------------------------------------------------------------------------------
    // What is refused
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void ASinkRefusesToAbsorbItself()
    {
        var sink = SinkOn(BundleShard.Whole);

        var refusal = Assert.Throws<InvalidOperationException>(() => sink.Absorb(sink));

        Assert.Contains("counted twice", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A sink with a partition still open refuses the merge.
    /// </summary>
    /// <remarks>
    /// The open attempt holds an inventory checkpoint, and <c>AbortPartition</c> rolls the
    /// inventory back to it. Policies folded in underneath would sit inside the range that rolls
    /// back, so a restart of the open partition would discard another domain's policies - and
    /// shrink the SYSVOL denominator without anything failing.
    /// </remarks>
    [Fact]
    public void ASinkWithAPartitionOpenRefusesToAbsorbAnother()
    {
        var forest = SinkOn(BundleShard.Whole);
        var domain = SinkOn(BundleShard.Number(1));

        forest.BeginPartition(
            Unit("DC=contoso,DC=com"), ConnectionSecurityLevel.SignedAndSealed, false);

        var refusal = Assert.Throws<InvalidOperationException>(() => forest.Absorb(domain));

        Assert.Contains("while a partition is open", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ASinkBeingAbsorbedWithAPartitionOpenIsRefused()
    {
        var forest = SinkOn(BundleShard.Whole);
        var domain = SinkOn(BundleShard.Number(1));

        domain.BeginPartition(
            Unit("DC=fabrikam,DC=com"), ConnectionSecurityLevel.SignedAndSealed, false);

        Assert.Throws<InvalidOperationException>(() => forest.Absorb(domain));
    }

    [Fact]
    public void ASinkRefusesToAbsorbNothing()
    {
        var sink = SinkOn(BundleShard.Whole);

        Assert.Throws<ArgumentNullException>(() => sink.Absorb(null!));
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A sink over a real writer, because the sink's whole job is mapping onto what the bundle
    /// expects and a stand-in would be testing this test's idea of that.
    /// </summary>
    private BundleCaptureSink SinkOn(BundleShard shard)
    {
        var writer = BundleWriter.Create(
            Path.Combine(_directory, "shard" + shard.Index), Started, shard);

        _writers.Add(writer);

        return new BundleCaptureSink(writer, TimeProvider.System);
    }

    /// <summary>Reads one policy object into a sink, as a capture pass would.</summary>
    private static void Observe(BundleCaptureSink sink, Guid policy)
    {
        sink.BeginPartition(
            Unit("DC=contoso,DC=com"), ConnectionSecurityLevel.SignedAndSealed, false);

        sink.Receive(CapturedObject.Create(
            $"CN={{{policy}}},CN=Policies,CN=System,DC=contoso,DC=com",
            [
                Attribute("objectClass", "top", "container", "groupPolicyContainer"),
                Attribute("displayName", "Default Domain Policy"),
                Attribute("gPCFileSysPath", @"\\contoso.com\SysVol\contoso.com\Policies"),
                GuidAttribute(policy),
            ]));

        sink.CompletePartition(Coverage("DC=contoso,DC=com"));
    }

    /// <summary>
    /// Objects whose <c>nTSecurityDescriptor</c> the controller did not return, which is what the
    /// tally counts.
    /// </summary>
    private static void WithdrawnDescriptors(
        BundleCaptureSink sink, string domain, params string[] names) =>
        ReceiveAll(
            sink,
            domain,
            names,
            () => new AttributeValues(
                "nTSecurityDescriptor", [], AttributeCompleteness.NotReturned, NextRange: null));

    /// <summary>The same objects with a descriptor that did arrive and did parse.</summary>
    private static void ReadableDescriptors(
        BundleCaptureSink sink, string domain, params string[] names) =>
        ReceiveAll(
            sink,
            domain,
            names,
            () => new AttributeValues(
                "nTSecurityDescriptor",
                [SelfRelativeDescriptor()],
                AttributeCompleteness.Complete,
                NextRange: null));

    /// <summary>
    /// One partition, however many objects inside it. A second partition on the same naming context
    /// is refused by the writer, and rightly: two rows for one pair would be two accounts of what
    /// was read.
    /// </summary>
    private static void ReceiveAll(
        BundleCaptureSink sink,
        string domain,
        IReadOnlyList<string> names,
        Func<AttributeValues> descriptor)
    {
        sink.BeginPartition(Unit(domain), ConnectionSecurityLevel.SignedAndSealed, false);

        foreach (var name in names)
        {
            sink.Receive(CapturedObject.Create(
                $"CN={name},{domain}",
                [
                    Attribute("objectClass", "top", "user"),
                    GuidAttribute(Guid.NewGuid()),
                    descriptor(),
                ]));
        }

        sink.CompletePartition(Coverage(domain));
    }

    /// <summary>
    /// The smallest well-formed self-relative security descriptor: a revision, no owner, no group
    /// and no lists. Enough to be parsed rather than counted as unreadable, which is the only
    /// property the negative control needs of it.
    /// </summary>
    private static byte[] SelfRelativeDescriptor() =>
    [
        1, 0, 0, 0x80,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    private static CaptureUnit Unit(string namingContextDn) =>
        CaptureUnit.Create(namingContextDn, NamingContextKind.Domain, "dc01.contoso.com").Value!;

    private static PartitionCoverage Coverage(string namingContextDn) => new(
        namingContextDn,
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        PagesRead: 1,
        ObjectsRead: 1,
        AttributeBlocksFetched: 0,
        ContinuationReferences: [],
        ReferralsSuppressed: false);

    private static AttributeValues Attribute(string name, params string[] values) =>
        new(name, values, AttributeCompleteness.Complete, NextRange: null);

    private static AttributeValues GuidAttribute(Guid value) =>
        new("objectGUID", [value.ToByteArray()], AttributeCompleteness.Complete, NextRange: null);

    public void Dispose()
    {
        foreach (var writer in _writers)
        {
            writer.Dispose();
        }

        SqliteConnection.ClearAllPools();

        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }
}

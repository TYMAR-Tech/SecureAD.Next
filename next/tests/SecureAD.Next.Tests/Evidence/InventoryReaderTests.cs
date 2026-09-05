using SecureAD.Evidence;
using SecureAD.Evidence.Inventory;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Naming;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// Counting a bundle: which class each object is counted as, which domain it is counted against,
/// and what the counts refuse to claim.
/// </summary>
/// <remarks>
/// <para>
/// <b>Against a real bundle written by <see cref="BundleWriter"/> rather than a fake source.</b>
/// <c>DashboardViewModelTests</c> proves the screen keeps its silences apart, but it is handed
/// counts that were never computed - so every one of its assertions would pass over a counting
/// query that was wrong in every particular. <c>F-S45-7</c> was a false claim that survived a
/// thorough fixture suite for exactly this reason.
/// </para>
/// <para>
/// <b>The class rule is the thing most worth proving.</b> <c>objectClass</c> is multi-valued and
/// arrives least specific first, so a computer account's chain contains <c>user</c>. A query that
/// matched any value in the chain would report every workstation and every domain controller in
/// the forest as a user account, and the resulting figure would look entirely ordinary.
/// </para>
/// </remarks>
public sealed class InventoryReaderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-inventory-" + Guid.NewGuid().ToString("N"));

    private static readonly DateTimeOffset Started = new(2026, 9, 5, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 9, 5, 11, 0, 0, TimeSpan.Zero);

    private const string DomainDn = "DC=contoso,DC=com";
    private const string Domain = "contoso.com";

    // -------------------------------------------------------------------------------------------
    // Which class an object is counted as.

    /// <summary>
    /// A computer account is counted as a computer and not also as a user, though its
    /// <c>objectClass</c> chain contains <c>user</c>.
    /// </summary>
    /// <remarks>
    /// <b>The single most consequential assertion in this suite.</b> Counting any value in the
    /// chain rather than the most specific one inflates the user count by the whole computer
    /// estate, which on a real forest is a plausible-looking number that nobody would question.
    /// </remarks>
    [Fact]
    public void AComputerIsNotCountedAsAUser()
    {
        WriteObjects(
            Object("CN=Alice," + DomainDn, 1, "top", "person", "organizationalPerson", "user"),
            Object(
                "CN=WS01," + DomainDn, 2,
                "top", "person", "organizationalPerson", "user", "computer"));

        var counts = CountsFor(Domain);

        Assert.Equal(1, counts.Users);
        Assert.Equal(1, counts.Computers);
    }

    /// <summary>
    /// A group managed service account is counted as neither a user nor a computer, though its
    /// chain contains both.
    /// </summary>
    /// <remarks>
    /// The negative control for the test above. A rule that took the most specific class only
    /// because the fixtures happened to end in <c>user</c> or <c>computer</c> would pass that one
    /// and fail this.
    /// </remarks>
    [Fact]
    public void AGroupManagedServiceAccountIsCountedAsNeither()
    {
        WriteObjects(Object(
            "CN=svc-sql," + DomainDn, 1,
            "top", "person", "organizationalPerson", "user", "computer",
            "msDS-GroupManagedServiceAccount"));

        var counts = CountsFor(Domain);

        Assert.Equal(0, counts.Users);
        Assert.Equal(0, counts.Computers);
    }

    /// <summary>Groups and organisational units are counted as themselves.</summary>
    [Fact]
    public void GroupsAndOrganisationalUnitsAreCounted()
    {
        WriteObjects(
            Object("CN=Admins," + DomainDn, 1, "top", "group"),
            Object("OU=People," + DomainDn, 2, "top", "organizationalUnit"),
            Object("OU=Staff,OU=People," + DomainDn, 3, "top", "organizationalUnit"));

        var counts = CountsFor(Domain);

        Assert.Equal(1, counts.Groups);
        Assert.Equal(2, counts.OrganisationalUnits);
    }

    /// <summary>
    /// An object of a kind this screen does not name is counted by nothing, rather than folded into
    /// the nearest kind that is named.
    /// </summary>
    /// <remarks>
    /// A container or a contact is a real object, and adding it to the group count to avoid losing
    /// it would make the group figure say something the directory does not.
    /// </remarks>
    [Fact]
    public void AnObjectOfAnUnnamedKindIsCountedByNothing()
    {
        WriteObjects(
            Object("CN=Users," + DomainDn, 1, "top", "container"),
            Object("CN=Someone," + DomainDn, 2, "top", "person", "contact"));

        var counts = CountsFor(Domain);

        Assert.Equal(0, counts.OfTheseKinds);
    }

    // -------------------------------------------------------------------------------------------
    // What the counts refuse to claim.

    /// <summary>
    /// A domain read in full that holds none of the counted kinds is counted, and counted as zero.
    /// </summary>
    /// <remarks>
    /// The control that keeps the assertions about unread domains honest: without it, a reader that
    /// counted nothing at all would satisfy every one of them.
    /// </remarks>
    [Fact]
    public void ADomainReadAndFoundEmptyIsCountedAsZero()
    {
        WriteObjects();

        var inventory = Read();
        var domain = Only(inventory);

        Assert.True(domain.WasCounted);
        Assert.True(domain.TryGetCounts(out var counts));
        Assert.Equal(0, counts!.OfTheseKinds);
    }

    /// <summary>
    /// A domain the operator excluded is not counted, even though the object table holds nothing
    /// for it either.
    /// </summary>
    /// <remarks>
    /// <b>This is where the distinction is actually made.</b> Both an empty domain and an excluded
    /// one produce no rows, so the reader cannot tell them apart from the objects - it must take
    /// the answer from the coverage, and this proves it does.
    /// </remarks>
    [Fact]
    public void ADomainThatWasExcludedIsNotCountedAtAll()
    {
        WriteBundle(_ => { }, TwoDomainsExcluding("eu.contoso.com"));

        var inventory = Read();
        var excluded = DomainNamed(inventory, "eu.contoso.com");

        Assert.False(excluded.WasCounted);
        Assert.False(excluded.TryGetCounts(out var counts));
        Assert.Null(counts);
        Assert.Equal(
            DomainReadOutcome.ExcludedByChoice, excluded.Coverage.Outcome);
    }

    // -------------------------------------------------------------------------------------------
    // The confidential-attribute caveat.

    /// <summary>
    /// A domain read over an encrypted connection carries no caveat.
    /// </summary>
    [Fact]
    public void AnEncryptedReadCarriesNoCaveat()
    {
        WriteObjects(Object("CN=Alice," + DomainDn, 1, "top", "user"));

        Assert.False(Only(Read()).MayBeMissingConfidentialValues);
    }

    /// <summary>
    /// A domain read over a merely signed connection is flagged, because a 2025 controller may have
    /// stripped confidential attributes from it without saying so.
    /// </summary>
    /// <remarks>
    /// Signed rather than unprotected on purpose: <c>ConnectionSecurityLevel.Signed</c> requires no
    /// declared allowance, so an ordinary run can land here with no operator action
    /// (<c>F-S24-1</c>).
    /// </remarks>
    [Fact]
    public void AReadOverASignedConnectionIsFlagged()
    {
        WriteBundle(
            writer => writer.WriteObject(new EvidenceObject(
                PartitionRead(ConnectionSecurityLevel.Signed),
                "CN=Alice," + DomainDn,
                GuidNumbered(1),
                [Classes("top", "user")],
                Started)),
            OneDomainRead(),
            PartitionRead(ConnectionSecurityLevel.Signed));

        Assert.True(Only(Read()).MayBeMissingConfidentialValues);
    }

    // -------------------------------------------------------------------------------------------
    // Policies.

    /// <summary>
    /// The policy figures are read of declared, taken from what the run recorded for SYSVOL.
    /// </summary>
    [Fact]
    public void PoliciesAreCountedAsReadOfDeclared()
    {
        WriteBundle(_ => { }, OneDomainReadWithPolicies(
            GpoCoverage.Read(GuidNumbered(1), "Default Domain Policy", @"\\contoso.com\sysvol\1"),
            GpoCoverage.Read(GuidNumbered(2), "Workstations", @"\\contoso.com\sysvol\2"),
            GpoCoverage.Unreadable(
                GuidNumbered(3), "Servers", @"\\contoso.com\sysvol\3", "Access is denied.")));

        var inventory = Read();

        Assert.Equal(3, inventory.PoliciesDeclared);
        Assert.Equal(2, inventory.PoliciesRead);
        Assert.Equal(1, inventory.PoliciesNotRead);
        Assert.False(inventory.AllPoliciesRead);
    }

    /// <summary>
    /// A policy read only in part counts as not read, because part of a policy is not the policy.
    /// </summary>
    [Fact]
    public void APartlyReadPolicyDoesNotCountAsRead()
    {
        WriteBundle(_ => { }, OneDomainReadWithPolicies(
            GpoCoverage.PartiallyRead(
                GuidNumbered(1), "Default Domain Policy", @"\\contoso.com\sysvol\1",
                "The scripts folder was refused.")));

        var inventory = Read();

        Assert.Equal(1, inventory.PoliciesDeclared);
        Assert.Equal(0, inventory.PoliciesRead);
    }

    // -------------------------------------------------------------------------------------------
    // The suite's own self-test.

    /// <summary>
    /// Proves this suite is reading a bundle that actually holds objects.
    /// </summary>
    /// <remarks>
    /// <b>Failure class 1.</b> Every assertion above about a class not being counted would pass
    /// against a reader that returned zero for everything, or against a writer that silently stored
    /// nothing. This fails unless objects were written and found.
    /// </remarks>
    [Fact]
    public void TheBundleUnderTestReallyHoldsTheObjects()
    {
        WriteObjects(
            Object("CN=Alice," + DomainDn, 1, "top", "user"),
            Object("CN=WS01," + DomainDn, 2, "top", "user", "computer"),
            Object("CN=Admins," + DomainDn, 3, "top", "group"),
            Object("OU=People," + DomainDn, 4, "top", "organizationalUnit"));

        Assert.Equal(4, CountsFor(Domain).OfTheseKinds);
    }

    // -------------------------------------------------------------------------------------------

    private ForestInventory Read()
    {
        var opening = BundleReader.Open(_directory);
        Assert.True(opening.IsSuccess);

        using var reader = opening.Value;

        var read = reader.ReadInventory();
        Assert.True(read.IsSuccess);

        return read.Value;
    }

    private ObjectCounts CountsFor(string domain)
    {
        var inventory = Read();
        var found = DomainNamed(inventory, domain);

        Assert.True(found.TryGetCounts(out var counts));
        return counts!;
    }

    private static DomainInventory Only(ForestInventory inventory) =>
        Assert.Single(inventory.Domains);

    private static DomainInventory DomainNamed(ForestInventory inventory, string domain) =>
        inventory.Domains.Single(d =>
            string.Equals(d.DomainFqdn, domain, StringComparison.OrdinalIgnoreCase));

    private void WriteObjects(params EvidenceObject[] objects) =>
        WriteBundle(
            writer =>
            {
                foreach (var captured in objects)
                    writer.WriteObject(captured);
            },
            OneDomainRead());

    private void WriteBundle(Action<BundleWriter> write, RunCoverage coverage) =>
        WriteBundle(write, coverage, PartitionRead(ConnectionSecurityLevel.SignedAndSealed));

    private void WriteBundle(
        Action<BundleWriter> write, RunCoverage coverage, PartitionCoverage partition)
    {
        using var writer = BundleWriter.Create(_directory, Started);
        writer.WriteCoverage(partition);
        write(writer);
        writer.Complete(coverage, Finished);
    }

    private static PartitionCoverage PartitionRead(ConnectionSecurityLevel security) => new(
        DomainDn, NamingContextKind.Domain, "dc01.contoso.com", security, 3, 10, 0, [], false);

    private static RunCoverage OneDomainRead() =>
        Coverage([DomainCoverage.Read(Domain)], [Domain], SysvolCoverage.Of([]));

    private static RunCoverage OneDomainReadWithPolicies(params GpoCoverage[] policies) =>
        Coverage([DomainCoverage.Read(Domain)], [Domain], SysvolCoverage.Of(policies));

    private static RunCoverage TwoDomainsExcluding(string excluded) =>
        RunCoverage.Of(
            CoverageId.ForDomainsExcluding(Domain, [Domain, excluded], [excluded]),
            [
                DomainCoverage.Read(Domain),
                DomainCoverage.Excluded(
                    excluded, ExclusionKind.ByChoice, "It is being decommissioned."),
            ],
            ForestPartitions(),
            SysvolCoverage.Of([]));

    private static RunCoverage Coverage(
        DomainCoverage[] domains, string[] declared, SysvolCoverage sysvol) =>
        RunCoverage.Of(
            CoverageId.ForDomains(Domain, declared), domains, ForestPartitions(), sysvol);

    private static ForestPartitionCoverage[] ForestPartitions() =>
    [
        ForestPartitionCoverage.Read(
            "CN=Configuration," + DomainDn, NamingContextKind.Configuration),
        ForestPartitionCoverage.Read(
            "CN=Schema,CN=Configuration," + DomainDn, NamingContextKind.Schema),
    ];

    private static EvidenceObject Object(string dn, int number, params string[] classes) =>
        new(
            PartitionRead(ConnectionSecurityLevel.SignedAndSealed),
            dn,
            GuidNumbered(number),
            [Classes(classes)],
            Started);

    private static EvidenceAttribute Classes(params string[] classes) =>
        new(
            "objectClass",
            StoredAttributeCompleteness.Complete,
            [.. classes.Select(EvidenceValue.OfText)]);

    private static Guid GuidNumbered(int n) => Guid.Parse($"00000000-0000-0000-0000-{n:D12}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }
}

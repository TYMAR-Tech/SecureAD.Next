using SecureAD.Audit.Capture;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Connect;

/// <summary>
/// One domain the forest says it has, and where a run can reach it.
/// </summary>
/// <param name="NamingContext">
/// The domain partition's distinguished name, as the forest's own cross-reference records it.
/// </param>
/// <param name="DnsName">
/// The domain's DNS name - <c>east.example.com</c>. It is both the name a person recognises and a
/// name that resolves to controllers holding the domain, so a run that was given one controller can
/// reach the rest of the forest without being told how.
/// </param>
internal sealed record ForestDomain(string NamingContext, string DnsName);

/// <summary>
/// What the forest says its partitions are, read from its own cross-references.
/// </summary>
/// <remarks>
/// <para>
/// This finishes inventory row A7, and it exists because of <c>F-S28-1</c>: without it a run planned
/// from one controller's <c>namingContexts</c> reads that controller's own domain, finds nothing
/// left over to report as unread, and seals a bundle claiming to cover a forest it saw one domain
/// of.
/// </para>
/// <para>
/// <b>Every classification here comes from the forest, never from the shape of a name.</b> A
/// partition list alone cannot tell a domain from an application partition, because
/// <c>DC=DomainDnsZones,DC=example,DC=com</c> is spelled exactly as a domain is. A component that
/// guessed from the name would be right on every forest anybody builds to test it and wrong at a
/// customer.
/// </para>
/// <para>
/// <b>The rule is Microsoft's and it is quoted rather than remembered.</b> A cross-reference
/// representing a domain has both <c>ADS_SYSTEMFLAG_CR_NTDS_NC</c> (<c>0x1</c>) and
/// <c>ADS_SYSTEMFLAG_CR_NTDS_DOMAIN</c> (<c>0x2</c>) set in <c>systemFlags</c>; one representing an
/// application directory partition has <c>NTDS_NC</c> set and <c>NTDS_DOMAIN</c> clear, and so do
/// the cross-references for the configuration and schema partitions
/// (<see href="https://learn.microsoft.com/windows/win32/ad/enumerating-application-directory-partitions-in-a-forest">Enumerating
/// Application Directory Partitions in a Forest</see>).
/// </para>
/// <para>
/// <b>Anything that is not a domain is recorded rather than dropped.</b> A partition this run will
/// not read is a coverage entry per
/// <c>docs/decisions/0052-the-domain-is-the-only-unit-of-scope.md</c>, and silence about it is the one
/// thing an audit tool cannot produce. The configuration and schema partitions are excluded from
/// that list because they are read - they are simply reached from the RootDSE rather than from here.
/// </para>
/// </remarks>
internal sealed class ForestPartitions
{
    /// <summary><c>ADS_SYSTEMFLAG_CR_NTDS_NC</c>: the naming context is held in Active Directory.</summary>
    private const int NamingContextIsInDirectory = 0x1;

    /// <summary><c>ADS_SYSTEMFLAG_CR_NTDS_DOMAIN</c>: the naming context is a domain.</summary>
    private const int NamingContextIsADomain = 0x2;

    private static readonly CapturedAttribute NamingContextName =
        new("nCName", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private static readonly CapturedAttribute DnsRoot =
        new("dnsRoot", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private static readonly CapturedAttribute SystemFlags =
        new("systemFlags", AttributeCardinality.SingleValued, AttributeStorage.Text);

    private ForestPartitions(
        IReadOnlyList<ForestDomain> domains, IReadOnlyList<string> partitionsNotRead)
    {
        Domains = domains;
        PartitionsNotRead = partitionsNotRead;
    }

    /// <summary>
    /// Every domain the forest declares, in the order the controller returned them.
    /// </summary>
    /// <remarks>
    /// This is the denominator a run's coverage is measured against. A capture that reads fewer than
    /// these has left part of a forest unread and must say so.
    /// </remarks>
    internal IReadOnlyList<ForestDomain> Domains { get; }

    /// <summary>
    /// Partitions the forest declares that a run does not read - the application directory
    /// partitions, of which the DNS zone partitions are the ones every forest has.
    /// </summary>
    /// <remarks>
    /// Not read per <c>docs/decisions/0042-dns-zones-and-records-are-out-of-scope.md</c>, which also
    /// requires the bundle to record them: a reader who cannot see that these exist cannot tell a
    /// forest whose DNS partitions were skipped from a forest that has none. This is one of two
    /// places that decision is enforced; the other is
    /// <c>CapturedAttributeCatalog.UnreadObjectClasses</c>.
    /// </remarks>
    internal IReadOnlyList<string> PartitionsNotRead { get; }

    /// <summary>
    /// Asks the forest what partitions it has.
    /// </summary>
    /// <remarks>
    /// Any domain controller in the forest can answer, because every one of them holds the
    /// configuration partition. That is what lets a run be pointed at a single controller and still
    /// discover a forest of nine domains.
    /// </remarks>
    /// <param name="channel">A connection to any controller in the forest.</param>
    /// <param name="configurationNamingContext">
    /// The configuration partition, as the controller named it in its RootDSE.
    /// </param>
    /// <param name="schemaNamingContext">
    /// The schema partition, as the controller named it in its RootDSE. Needed only so that its own
    /// cross-reference is not reported as a partition the run declined to read.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    internal static async Task<Result<ForestPartitions>> ReadAsync(
        IDirectoryChannel channel,
        string configurationNamingContext,
        string schemaNamingContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationNamingContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaNamingContext);

        var container = "CN=Partitions," + configurationNamingContext;

        DirectoryPage page;

        try
        {
            page = await channel
                .SendAsync(
                    CaptureSearchRequestFactory.ForCrossReferences(container), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (System.DirectoryServices.Protocols.DirectoryException exception)
        {
            // DirectoryException rather than LdapException, for the reason RetryPolicy.FailureFor
            // records: a non-success server result arrives as a DirectoryOperationException, which
            // is not an LdapException, so the narrower catch let it escape as an unclassified
            // exception instead of the named refusal this method exists to produce.
            return Result<ForestPartitions>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "CrossReferencesCouldNotBeRead",
                ErrorSeverity.Failed,
                $"The cross-references in '{container}' could not be read from "
                + $"{channel.DomainController}: {exception.Message}. They are the forest's own "
                + "record of which partitions it has, and without them a run cannot tell how much "
                + "of the forest it is reading - so no run is planned rather than one being "
                + "planned against a single controller's view.",
                channel.DomainController));
        }

        var domains = new List<ForestDomain>();
        var notRead = new List<string>();

        foreach (var crossReference in page.Entries)
        {
            var namingContextRead = SingleTextValue(crossReference, NamingContextName);
            if (!namingContextRead.IsSuccess)
            {
                return Result<ForestPartitions>.Failure(namingContextRead.Error!);
            }

            if (namingContextRead.Value is not { } namingContext)
            {
                // A cross-reference without an nCName refers to an external directory rather than a
                // partition of this forest. There is nothing here for a capture to read.
                continue;
            }

            if (Same(namingContext, configurationNamingContext)
                || Same(namingContext, schemaNamingContext))
            {
                continue;
            }

            var flagsRead = SingleTextValue(crossReference, SystemFlags);
            if (!flagsRead.IsSuccess)
            {
                return Result<ForestPartitions>.Failure(flagsRead.Error!);
            }

            if (flagsRead.Value is not { } flags || !int.TryParse(flags, out var systemFlags))
            {
                return Result<ForestPartitions>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "CrossReferenceDidNotStateItsKind",
                    ErrorSeverity.Failed,
                    $"The cross-reference for '{namingContext}' on {channel.DomainController} "
                    + "carries no readable systemFlags. That attribute is the only thing that "
                    + "distinguishes a domain from an application partition, and deciding from "
                    + "the shape of the name instead would be this product guessing what the "
                    + "forest contains.",
                    channel.DomainController));
            }

            if (!IsNamingContextInDirectory(systemFlags))
                continue;

            if (!IsDomain(systemFlags))
            {
                notRead.Add(namingContext);
                continue;
            }

            var dnsNameRead = SingleTextValue(crossReference, DnsRoot);
            if (!dnsNameRead.IsSuccess)
            {
                return Result<ForestPartitions>.Failure(dnsNameRead.Error!);
            }

            if (dnsNameRead.Value is not { } dnsName)
            {
                return Result<ForestPartitions>.Failure(AuditError.Create(
                    ErrorCategory.Capture,
                    "DomainDidNotStateItsDnsName",
                    ErrorSeverity.Failed,
                    $"The cross-reference for the domain '{namingContext}' on "
                    + $"{channel.DomainController} carries no dnsRoot. Every domain has one, and "
                    + "it is how this run reaches a controller holding that domain - so a domain "
                    + "without one would be a domain the run could not read and would have to "
                    + "leave out.",
                    channel.DomainController));
            }

            domains.Add(new ForestDomain(namingContext, dnsName));
        }

        if (domains.Count == 0)
        {
            return Result<ForestPartitions>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "ForestDeclaredNoDomains",
                ErrorSeverity.Failed,
                $"{channel.DomainController} returned cross-references naming no domain at all. "
                + "Every forest has at least one, so this is an answer that cannot be right, and "
                + "planning a run against it would produce a bundle covering nothing.",
                channel.DomainController));
        }

        return new ForestPartitions(domains, notRead);
    }

    /// <summary>
    /// Whether a cross-reference's <c>systemFlags</c> says its partition is a domain.
    /// </summary>
    /// <remarks>
    /// Both bits are required. Testing only the domain bit would be testing a bit whose meaning is
    /// defined for cross-references held in the directory, on a cross-reference that may not be one.
    /// </remarks>
    private static bool IsDomain(int systemFlags) =>
        (systemFlags & (NamingContextIsInDirectory | NamingContextIsADomain))
            == (NamingContextIsInDirectory | NamingContextIsADomain);

    private static bool IsNamingContextInDirectory(int systemFlags) =>
        (systemFlags & NamingContextIsInDirectory) != 0;

    /// <summary>
    /// One text value of an attribute, or null where the entry did not carry one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Values are converted rather than filtered by type, and that distinction cost a lab
    /// session.</b> A live directory returns attribute values as raw bytes, so this once read them
    /// with <c>OfType&lt;string&gt;()</c> and found nothing in every single one - which was reported
    /// as a controller that had not published attributes it certainly had.
    /// <see cref="LdapEntryReader.AsText"/> is the conversion the product already owns, and it
    /// accepts either shape.
    /// </para>
    /// <para>
    /// <b>A value that is present and unreadable is a failure, never an absence.</b> Null here
    /// means the entry did not carry the attribute; bytes that are not valid text produce an error
    /// instead, because reporting them as absent would be
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>'s forbidden case - a failure of
    /// the query rendered as a fact about the directory.
    /// </para>
    /// </remarks>
    internal static Result<string?> SingleTextValue(
        LdapEntryReader entry, CapturedAttribute attribute)
    {
        var values = entry.ValuesOf(attribute);

        if (values.Completeness != AttributeCompleteness.Complete || values.Values.Count == 0)
            return Result<string?>.Success(null);

        var text = LdapEntryReader.AsText(values.Values[0]);
        if (!text.IsSuccess)
        {
            return Result<string?>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "AttributeCouldNotBeReadAsText",
                ErrorSeverity.Failed,
                $"'{attribute.LdapDisplayName}' was returned on '{entry.DistinguishedName}' and "
                + $"could not be read as text: {text.Error!.Description} A value that is present "
                + "and unreadable is not an absent value, and reporting it as one would make a "
                + "failure of this product look like a fact about the directory.",
                entry.DistinguishedName));
        }

        return Result<string?>.Success(
            string.IsNullOrWhiteSpace(text.Value) ? null : text.Value);
    }

    private static bool Same(string left, string right) =>
        string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}

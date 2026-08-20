using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;

namespace SecureAD.Audit.Connect;

/// <summary>
/// Which controller holds an operations master role, where the forest was willing to say.
/// </summary>
/// <param name="HostName">
/// The role holder's DNS host name, or <see langword="null"/> where the forest named a holder this
/// run could not match to a candidate.
/// </param>
/// <param name="OwnerDn">
/// The <c>nTDSDSA</c> distinguished name the forest gave as the holder, exactly as it gave it.
/// </param>
public sealed record RoleHolder(string? HostName, string OwnerDn);

/// <summary>
/// What is known about a domain's PDC emulator, which is three things and not two.
/// </summary>
/// <remarks>
/// <b>Not yet known is not the same as holds no role.</b> A domain whose PDC emulator has not been
/// established has every one of its controllers looking, to a ranker, exactly like a controller that
/// holds no role - so the busiest machine in that domain sorts equal with the quietest and may well
/// be pinned. Collapsing these two states is the failure this enumeration exists to prevent: the run
/// would carry on and read a whole domain from its PDC emulator with nothing recording that it had.
/// </remarks>
public enum PdcEmulatorKnowledge
{
    /// <summary>
    /// Nothing has asked yet. This is the state discovery leaves every domain other than the one
    /// the bootstrap connection is in, and preflight is what replaces it.
    /// </summary>
    NotYetEstablished = 0,

    /// <summary>The forest named the holder and this run matched it to a candidate.</summary>
    Established = 1,

    /// <summary>
    /// The read was attempted and did not answer. The domain is still audited; what is lost is the
    /// ability to rank its PDC emulator last, and the run says so rather than ranking as though the
    /// question had been asked and answered.
    /// </summary>
    CouldNotBeRead = 2,
}

/// <summary>
/// One domain's PDC emulator, and how firmly that is known.
/// </summary>
/// <param name="NamingContext">The domain this concerns.</param>
/// <param name="Knowledge">Whether the holder is established, unread, or not yet asked for.</param>
/// <param name="Holder">
/// The holder, present only when <paramref name="Knowledge"/> is
/// <see cref="PdcEmulatorKnowledge.Established"/>.
/// </param>
public sealed record DomainPdcEmulator(
    string NamingContext, PdcEmulatorKnowledge Knowledge, RoleHolder? Holder);

/// <summary>
/// The operations master roles of a forest, so that a run can avoid reading a domain from the
/// machine least able to spare the time.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a run cares.</b> Ranking a domain's controllers puts a role holder last, the PDC emulator
/// above all: it carries time synchronisation, password change chaining, account lockout evaluation
/// and Group Policy editing for the whole domain, and a forest-wide audit is a read measured in
/// hours. Pointing one at the PDC emulator is the single clearly bad choice available to selection,
/// and it is the choice a ranker makes by accident when it cannot tell which machine that is. That
/// is <c>docs/decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md</c>.
/// </para>
/// <para>
/// <b>Two of these roles are free and the rest are not.</b> The schema master and the domain naming
/// master are recorded in the schema and configuration partitions, which every controller in the
/// forest holds a full replica of - so both are answered by the one connection discovery already
/// has open, and reading them costs nothing and contacts nobody. A domain's PDC emulator is recorded
/// on that domain's own naming context head, which a controller of a different domain does not hold.
/// Referral chasing is off, so asking for it yields a failure rather than a quiet answer from
/// another machine, and establishing it for a foreign domain costs a connection to that domain.
/// </para>
/// <para>
/// <b>So the PDC emulator is established during preflight, not during discovery.</b> Preflight
/// already opens a connection to each domain, which makes the read free there and a per-domain
/// connection charge here - paid before anything is on screen, and worst in exactly the broken
/// forests where an operator is least willing to wait. Discovery therefore leaves every foreign
/// domain at <see cref="PdcEmulatorKnowledge.NotYetEstablished"/> and preflight replaces it. That is
/// <c>docs/decisions/0055-the-pdc-emulator-is-established-at-preflight.md</c>.
/// </para>
/// <para>
/// <b>Nothing here guesses.</b> A holder the forest names but this run cannot match to a candidate
/// is carried as a <see cref="RoleHolder"/> with no host name rather than dropped, per
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>: an absence the product created may
/// not be presented as a fact about the forest.
/// </para>
/// </remarks>
public sealed class ForestRoles
{
    private static readonly CapturedAttribute RoleOwner =
        new("fSMORoleOwner", AttributeCardinality.SingleValued, AttributeStorage.Text);

    /// <summary>
    /// Roles from values already in hand, rather than from a read.
    /// </summary>
    /// <remarks>
    /// <see cref="ReadAsync"/> is how a run obtains these. This exists because the type is published
    /// on <c>ForestPlan</c> and a caller holding one must be able to state it without opening a
    /// connection.
    /// </remarks>
    /// <param name="schemaMaster">The schema master, or null where the schema head named none.</param>
    /// <param name="domainNamingMaster">
    /// The domain naming master, or null where the Partitions container named none.
    /// </param>
    /// <param name="pdcEmulators">
    /// One entry per domain. Every domain appears, including the ones nothing has been asked about.
    /// </param>
    public ForestRoles(
        RoleHolder? schemaMaster,
        RoleHolder? domainNamingMaster,
        IReadOnlyList<DomainPdcEmulator> pdcEmulators)
    {
        ArgumentNullException.ThrowIfNull(pdcEmulators);

        SchemaMaster = schemaMaster;
        DomainNamingMaster = domainNamingMaster;
        PdcEmulators = pdcEmulators;
    }

    /// <summary>
    /// The controller holding the schema master role, or <see langword="null"/> where the schema
    /// head named no holder at all.
    /// </summary>
    public RoleHolder? SchemaMaster { get; }

    /// <summary>
    /// The controller holding the domain naming master role, or <see langword="null"/> where the
    /// Partitions container named no holder at all.
    /// </summary>
    public RoleHolder? DomainNamingMaster { get; }

    /// <summary>
    /// One entry per domain, stating what is known about its PDC emulator. Every domain appears,
    /// including the ones nothing has been asked about yet.
    /// </summary>
    public IReadOnlyList<DomainPdcEmulator> PdcEmulators { get; }

    /// <summary>
    /// Whether every domain's PDC emulator has actually been established, so that ranking can act
    /// on the whole answer rather than on part of one.
    /// </summary>
    /// <remarks>
    /// False is the ordinary state at the end of discovery, because discovery deliberately asks no
    /// domain. It stays false for any domain preflight could not read, and that is the case worth
    /// carrying: those domains are ranked without knowing which of their controllers is the busiest,
    /// so the run may read one from its PDC emulator. A caller that reads <see cref="PdcEmulators"/>
    /// without this cannot tell a forest that answered every question from one that answered none -
    /// both are a full list of domains.
    /// </remarks>
    public bool IsComplete =>
        PdcEmulators.All(pdc => pdc.Knowledge == PdcEmulatorKnowledge.Established);

    /// <summary>
    /// Whether a controller holds any role this run has established.
    /// </summary>
    /// <remarks>
    /// False for a controller in a domain whose PDC emulator is
    /// <see cref="PdcEmulatorKnowledge.NotYetEstablished"/>, which is a true statement about what is
    /// known and not a statement about the controller. A caller ranking on this must read
    /// <see cref="PdcEmulators"/> as well, or it will treat an unasked question as a clean answer.
    /// </remarks>
    /// <param name="hostName">The controller's DNS host name.</param>
    public bool HoldsAnEstablishedRole(string hostName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hostName);

        if (Matches(SchemaMaster, hostName) || Matches(DomainNamingMaster, hostName))
        {
            return true;
        }

        return PdcEmulators.Any(pdc =>
            pdc.Knowledge == PdcEmulatorKnowledge.Established && Matches(pdc.Holder, hostName));
    }

    /// <summary>
    /// Reads the forest-level roles from the connection discovery already has open, and leaves every
    /// domain's PDC emulator for preflight to establish.
    /// </summary>
    /// <param name="channel">The bootstrap connection. No second connection is opened.</param>
    /// <param name="configurationNamingContext">
    /// The configuration partition, as the controller named it in its RootDSE.
    /// </param>
    /// <param name="schemaNamingContext">The schema partition, from the same RootDSE.</param>
    /// <param name="topology">The candidate list, used to match an owner name to a host name.</param>
    /// <param name="domainNamingContexts">Every domain the forest has, from its cross-references.</param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public static async Task<Result<ForestRoles>> ReadAsync(
        IDirectoryChannel channel,
        string configurationNamingContext,
        string schemaNamingContext,
        ForestTopology topology,
        IEnumerable<string> domainNamingContexts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentException.ThrowIfNullOrWhiteSpace(configurationNamingContext);
        ArgumentException.ThrowIfNullOrWhiteSpace(schemaNamingContext);
        ArgumentNullException.ThrowIfNull(topology);
        ArgumentNullException.ThrowIfNull(domainNamingContexts);

        var schemaMaster = await ReadRoleOwnerAsync(
            channel, schemaNamingContext, topology, cancellationToken).ConfigureAwait(false);

        if (!schemaMaster.IsSuccess)
        {
            return Result<ForestRoles>.Failure(schemaMaster.Error!);
        }

        var domainNamingMaster = await ReadRoleOwnerAsync(
            channel, "CN=Partitions," + configurationNamingContext, topology, cancellationToken)
            .ConfigureAwait(false);

        if (!domainNamingMaster.IsSuccess)
        {
            return Result<ForestRoles>.Failure(domainNamingMaster.Error!);
        }

        var pdcEmulators = domainNamingContexts
            .Select(namingContext => new DomainPdcEmulator(
                namingContext, PdcEmulatorKnowledge.NotYetEstablished, Holder: null))
            .ToList();

        return new ForestRoles(schemaMaster.Value, domainNamingMaster.Value, pdcEmulators);
    }

    /// <summary>
    /// Establishes one domain's PDC emulator over a connection to a controller of that domain,
    /// which is preflight's connection rather than a new one.
    /// </summary>
    /// <remarks>
    /// A read that fails leaves the domain at <see cref="PdcEmulatorKnowledge.CouldNotBeRead"/>
    /// rather than failing the run. The domain is still audited; what is lost is the ability to keep
    /// the audit off its busiest machine, and that loss is recorded rather than absorbed.
    /// </remarks>
    /// <param name="channel">A connection to a controller holding <paramref name="namingContext"/>.</param>
    /// <param name="namingContext">The domain whose PDC emulator is being established.</param>
    /// <param name="topology">The candidate list, used to match an owner name to a host name.</param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    public static async Task<DomainPdcEmulator> EstablishPdcEmulatorAsync(
        IDirectoryChannel channel,
        string namingContext,
        ForestTopology topology,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContext);
        ArgumentNullException.ThrowIfNull(topology);

        var owner = await ReadRoleOwnerAsync(channel, namingContext, topology, cancellationToken)
            .ConfigureAwait(false);

        if (!owner.IsSuccess || owner.Value is not { } holder)
        {
            return new DomainPdcEmulator(
                namingContext, PdcEmulatorKnowledge.CouldNotBeRead, Holder: null);
        }

        return new DomainPdcEmulator(namingContext, PdcEmulatorKnowledge.Established, holder);
    }

    /// <summary>
    /// Replaces what is known about one domain's PDC emulator, leaving every other domain alone.
    /// </summary>
    /// <remarks>
    /// A domain these roles were not read for is rejected rather than ignored. The domain list comes
    /// from the forest's own cross-references, so a name absent from it is a caller error; returning
    /// an unchanged copy instead would make a re-pin that silently did nothing look exactly like one
    /// that worked.
    /// </remarks>
    /// <param name="established">The answer preflight came back with.</param>
    public ForestRoles With(DomainPdcEmulator established)
    {
        ArgumentNullException.ThrowIfNull(established);

        if (!PdcEmulators.Any(pdc => string.Equals(
                pdc.NamingContext, established.NamingContext, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ArgumentException(
                $"'{established.NamingContext}' is not a domain these roles were read for. The "
                + "domain list comes from the forest's own cross-references, so a name absent from "
                + "it is a caller error rather than a domain the forest gained.",
                nameof(established));
        }

        var replaced = PdcEmulators
            .Select(pdc => string.Equals(
                pdc.NamingContext, established.NamingContext, StringComparison.OrdinalIgnoreCase)
                ? established
                : pdc)
            .ToList();

        return new ForestRoles(SchemaMaster, DomainNamingMaster, replaced);
    }

    /// <summary>
    /// Reads one object's <c>fSMORoleOwner</c> and matches the answer to a candidate.
    /// </summary>
    /// <remarks>
    /// A failed read is a failure of this method rather than of the run, and the caller decides what
    /// that costs. An object that names no holder is a success carrying no holder: the forest was
    /// asked and said nothing, which is different from not having been asked.
    /// </remarks>
    private static async Task<Result<RoleHolder?>> ReadRoleOwnerAsync(
        IDirectoryChannel channel,
        string roleObjectDn,
        ForestTopology topology,
        CancellationToken cancellationToken)
    {
        DirectoryPage page;

        try
        {
            page = await channel
                .SendAsync(CaptureSearchRequestFactory.ForRoleOwner(roleObjectDn), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (LdapException exception)
        {
            return Result<RoleHolder?>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "RoleOwnerCouldNotBeRead",
                ErrorSeverity.Failed,
                $"{channel.DomainController} could not be asked which controller holds the "
                + $"operations master role recorded on {roleObjectDn}: {exception.Message}. "
                + "Without it a run cannot tell that machine apart from any other, so it may read "
                + "an entire domain from the one machine in it least able to spare the time.",
                channel.DomainController));
        }

        if (page.Entries.Count != 1)
        {
            return Result<RoleHolder?>.Failure(AuditError.Create(
                ErrorCategory.Capture,
                "RoleObjectWasNotOneEntry",
                ErrorSeverity.Failed,
                $"{channel.DomainController} answered a base-scope read of {roleObjectDn} with "
                + $"{page.Entries.Count} entries. Exactly one is the only answer that means "
                + "anything.",
                channel.DomainController));
        }

        var ownerRead = ForestPartitions.SingleTextValue(page.Entries[0], RoleOwner);
        if (!ownerRead.IsSuccess)
        {
            return Result<RoleHolder?>.Failure(ownerRead.Error!);
        }

        if (ownerRead.Value is not { } ownerDn)
        {
            return Result<RoleHolder?>.Success(null);
        }

        var holder = topology.Controllers.FirstOrDefault(controller => string.Equals(
            controller.DirectoryServiceDn, ownerDn, StringComparison.OrdinalIgnoreCase));

        return Result<RoleHolder?>.Success(new RoleHolder(holder?.HostName, ownerDn));
    }

    private static bool Matches(RoleHolder? holder, string hostName) =>
        holder?.HostName is { } host && string.Equals(host, hostName, StringComparison.OrdinalIgnoreCase);
}

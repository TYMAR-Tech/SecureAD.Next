using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// One row of the New Audit table, whatever kind of domain it is about.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two kinds of domain, one table, and that became possible only when the table was
/// trimmed.</b> While the columns carried the site, the connection and the four preflight answers,
/// a domain the forest names no controller for had nothing to put in any of them - it would have
/// been a row of blanks reading as six negative answers, which is the resemblance
/// <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> forbids. The table now asks
/// four questions that both kinds can answer honestly.
/// </para>
/// <para>
/// <b>Why they belong in one table.</b> A domain missing from an audit with nothing saying it is
/// missing is the one outcome this product must not produce. Kept in a separate list beneath the
/// table, an unreadable domain disappeared from the domain screen the moment that list moved
/// elsewhere. In the table it cannot.
/// </para>
/// <para>
/// <b>What a row refuses is as important as what it answers.</b> A domain with no controller has
/// no controller to name and no inclusion to change, and it says so rather than offering a control
/// that would do nothing.
/// </para>
/// </remarks>
internal abstract partial class AuditRowViewModel : ObservableObject
{
    /// <summary>The domain partition this row is about.</summary>
    public abstract string NamingContext { get; }

    /// <summary>What to call this domain on screen.</summary>
    public abstract string Domain { get; }

    /// <summary>
    /// The controller this domain would be read from, or that the forest names none.
    /// </summary>
    public abstract string Controller { get; }

    /// <summary>Whether this domain is in the run, and if not, which kind of exclusion it is.</summary>
    public abstract DomainInclusion Inclusion { get; protected set; }

    /// <summary>What the operator stated for it, or null where nothing has been stated.</summary>
    public abstract ExclusionAttestation? Attestation { get; protected set; }

    /// <summary>Whether this domain is in the run, for the tick box on the row.</summary>
    public abstract bool IsIncluded { get; set; }

    /// <summary>
    /// Whether the operator may change whether this domain is in the run.
    /// </summary>
    /// <remarks>
    /// False for a domain the forest names no controller for. There is nothing to put it back
    /// into, and a tick box that did nothing would be the screen offering a choice the product
    /// cannot honour.
    /// </remarks>
    public abstract bool MayChangeInclusion { get; }

    /// <summary>
    /// Whether the operator may name a controller for this domain himself.
    /// </summary>
    /// <remarks>
    /// False where the forest names none: an override box on such a row would invite him to type a
    /// host the run has already established cannot serve the domain.
    /// </remarks>
    public abstract bool MayNameAController { get; }

    /// <summary>Whether anything about this domain is worth an operator's attention.</summary>
    public abstract bool NeedsAttention { get; }

    /// <summary>Whether this domain has been left out with nothing stated for it.</summary>
    public bool IsExcludedWithoutAttestation =>
        Inclusion != DomainInclusion.Included && Attestation is null;

    public virtual string ReadinessText => IsExcludedWithoutAttestation
        ? "Exclusion needs authorization" : Inclusion != DomainInclusion.Included ? "Excluded" : "Not checked";

    internal void RefreshReadiness() => OnPropertyChanged(nameof(ReadinessText));
}

using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>
/// A row for a domain the forest declares and names no writable controller for.
/// </summary>
/// <remarks>
/// <para>
/// <b>It is a row of the table, not a note beneath it.</b> A domain missing from an audit with
/// nothing saying it is missing is the one outcome this product must not produce, and a line under
/// the table disappeared the moment that area was cleared. In the table it cannot go missing, and
/// an operator counting rows gets the number the forest declared rather than the number that
/// happened to be readable.
/// </para>
/// <para>
/// <b>It refuses what it cannot answer.</b> There is no controller to name and no inclusion to
/// change: the run cannot read this domain whatever the operator ticks, and a control that did
/// nothing would offer a choice the product cannot honour. What it does carry is the attestation,
/// because <c>docs/decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md</c> makes
/// this an exclusion rather than a gap.
/// </para>
/// <para>
/// <b>It never reads as a domain that failed mid-run.</b> Its controller cell says the forest names
/// none, which is a fact about the forest rather than about a read that was attempted - the
/// distinction <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> exists to keep.
/// </para>
/// </remarks>
internal sealed partial class ExcludedDomainViewModel : AuditRowViewModel
{
    /// <summary>Creates the row for one domain that cannot be read.</summary>
    /// <param name="namingContext">The domain partition the forest declared.</param>
    /// <param name="dnsName">
    /// The DNS name the forest paired with it, or null where the two could not be paired. Never
    /// derived from the naming context - that would be inventing a name the forest did not give.
    /// </param>
    public ExcludedDomainViewModel(string namingContext, string? dnsName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(namingContext);

        NamingContext = namingContext;
        DnsName = dnsName;
    }

    /// <inheritdoc />
    public override string NamingContext { get; }

    /// <summary>The DNS name the forest declared, where it declared one.</summary>
    public string? DnsName { get; }

    /// <inheritdoc />
    public override string Domain => DnsName ?? NamingContext;

    /// <summary>
    /// That the forest names no controller for this domain.
    /// </summary>
    /// <remarks>
    /// Said rather than left blank. An empty cell in a column of host names reads as a value that
    /// failed to load, and this is not a failure to find something out - it is something the run
    /// found out.
    /// </remarks>
    public override string Controller => "None named by the forest";

    /// <inheritdoc />
    public override DomainInclusion Inclusion { get; protected set; } =
        DomainInclusion.ExcludedForWantOfCandidates;

    /// <inheritdoc />
    public override ExclusionAttestation? Attestation { get; protected set; }

    /// <summary>
    /// Always false, and not settable to anything else.
    /// </summary>
    /// <remarks>
    /// The setter is deliberately silent rather than throwing: a tick box bound two-way writes back
    /// on load, and a row that threw when a disabled control was touched would turn a harmless
    /// press into a crash. The box is disabled through <see cref="MayChangeInclusion"/>; this makes
    /// certain of it.
    /// </remarks>
    public override bool IsIncluded
    {
        get => false;
        set { }
    }

    /// <summary>There is nothing to put this domain back into.</summary>
    public override bool MayChangeInclusion => false;

    /// <summary>The forest names no controller, so there is none to prefer over another.</summary>
    public override bool MayNameAController => false;

    /// <summary>
    /// Always true: a domain the audit cannot read is worth an operator's attention whether or not
    /// he has already accounted for it.
    /// </summary>
    public override bool NeedsAttention => true;

    /// <summary>Why this domain cannot be read, said plainly.</summary>
    public string Explanation =>
        "The forest declares this domain but names no writable controller for it, so this run "
        + "cannot read it.";

    /// <summary>Whether somebody has answered for it.</summary>
    public bool IsAttested => Attestation is not null;

    /// <summary>Records what the operator stated for this domain.</summary>
    /// <param name="attestation">What he stated.</param>
    public void AttestUnder(ExclusionAttestation attestation)
    {
        ArgumentNullException.ThrowIfNull(attestation);

        Attestation = attestation;

        OnPropertyChanged(nameof(Attestation));
        OnPropertyChanged(nameof(IsExcludedWithoutAttestation));
        OnPropertyChanged(nameof(IsAttested));
        RefreshReadiness();
    }
}

/// <summary>
/// One domain leaving a run, as the review screen lists it before the run commits.
/// </summary>
/// <remarks>
/// <para>
/// <b>The kind travels with it.</b> Both kinds of exclusion appear in one list, so if the kind were
/// left to be inferred from where a row came from it would be lost the moment the list was built -
/// and <c>docs/decisions/0063-excluded-never-looks-like-unreachable.md</c> requires the two be told
/// apart wherever they are shown.
/// </para>
/// <para>
/// <b>A null attestation is shown, not skipped.</b> It is the state that stops the run, and the
/// review is where an operator finds out which domain he still owes an answer for.
/// </para>
/// </remarks>
/// <param name="Domain">The domain, as it is named on screen.</param>
/// <param name="Kind">Which kind of exclusion this is.</param>
/// <param name="Attestation">What was stated for it, or null where nothing has been.</param>
internal sealed record ExclusionView(
    string Domain,
    DomainInclusion Kind,
    ExclusionAttestation? Attestation)
{
    /// <summary>Why this domain is leaving the run, in a few words.</summary>
    public string Why => Kind == DomainInclusion.ExcludedForWantOfCandidates
        ? "The forest names no writable controller for it."
        : "You took it out.";

    /// <summary>What was stated for it, or that nothing has been.</summary>
    public string Stated => Attestation is null
        ? "Nothing stated yet. The run will not start until this is answered."
        : ExclusionReasons.Wording(Attestation.Reason);

    /// <summary>Who authorised it, or null while nobody has.</summary>
    public string? AuthorisedBy => Attestation?.AuthorisedBy;

    /// <summary>What the operator added in his own words, where he added anything.</summary>
    public string? Note => Attestation?.Note;

    /// <summary>Whether this exclusion is still without a name against it.</summary>
    public bool IsUnattested => Attestation is null;

    /// <summary>Whether somebody has answered for this exclusion.</summary>
    /// <remarks>
    /// A boolean rather than letting the view test <see cref="Attestation"/> for null through a
    /// visibility converter. <c>Shown</c> is a <c>BooleanToVisibilityConverter</c>: handed anything
    /// else it fails, and a failed binding falls back to <i>visible</i> - which would put an empty
    /// authorising name on screen and present an unanswered exclusion as answered.
    /// </remarks>
    public bool IsAttested => Attestation is not null;

    /// <summary>Whether the operator wrote anything in his own words.</summary>
    public bool HasNote => !string.IsNullOrWhiteSpace(Note);
}

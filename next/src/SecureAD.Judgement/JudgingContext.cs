using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;

namespace SecureAD.Judgement;

/// <summary>
/// A kind of derived fact a rule can declare it reads.
/// </summary>
/// <remarks>
/// <para>
/// <b>Declared rather than discovered, for the reason <c>docs/decisions/0083</c> gives for
/// attributes.</b> A rule that quietly reaches for a derived fact nobody wrote down is stamped
/// coverage-complete on a bundle that never carried it. Naming the kind here lets a judging refuse
/// before it starts, rather than reporting an unanswerable question object by object.
/// </para>
/// <para>
/// <b>One value per product, not one per rule.</b> The set is small because each member is a whole
/// Derivation phase, and a phase either ran or did not. A finer vocabulary would invite a rule to
/// declare a fragment of a phase and leave the judging unable to tell whether it was satisfied.
/// </para>
/// <para>
/// <b>The reference time is not a member of this enum, and that is the point.</b> Everything named
/// here is produced by a Derivation phase and can be absent. The time a judging evaluates against
/// is neither: it is recorded on the judgement itself and is always present. It therefore lives on
/// <see cref="JudgingContext"/> as a plain non-nullable value, and a rule never has to ask whether
/// it was offered one.
/// </para>
/// </remarks>
public enum DerivedFactKind
{
    /// <summary>
    /// Per-principal AdminSDHolder protection: whether a principal is protected, not protected, or
    /// undecided, with the basis and membership path that settled it. Produced by the Derivation
    /// phase named in <c>docs/decisions/0090</c>.
    /// </summary>
    ProtectedPrincipals,

    /// <summary>
    /// Per-attribute visibility: whether this forest's schema carries an attribute, and whether it
    /// has marked it confidential so that the directory withholds it silently. Produced by the
    /// Derivation phase named in <c>AttributeVisibilityDeriver.PhaseName</c>.
    /// </summary>
    /// <remarks>
    /// <b>Declared so that its absence stops the run rather than every object.</b> A rule reading a
    /// LAPS timestamp treats an absent value as a fact about a machine, and it may only do that
    /// once it knows the forest was not withholding the attribute. Without the answer SEC-091
    /// degrades to silence and SEC-094 degrades to a wall of false findings, so
    /// <c>docs/decisions/0091</c> refuses the judging instead.
    /// </remarks>
    AttributeVisibility,

    /// <summary>
    /// Expanding one principal to everything nested inside it, with the path that reached each.
    /// Produced by the Derivation phase named in
    /// <c>MembershipNestingPass.PhaseName</c>.
    /// </summary>
    /// <remarks>
    /// <b>Declared because a rule reading this treats what it finds as a fact about who holds a
    /// right.</b> A group nobody expanded and a group with nothing in it are opposite answers, and a
    /// rule handed the second when the first is true would report a scoped delegation as safe. That
    /// is worse than silence, so <c>docs/decisions/0091</c> refuses the judging instead.
    /// </remarks>
    PrincipalExpansion,
}

/// <summary>
/// Everything a rule is offered alongside the object it is judging: the time the judging is
/// evaluated against, and the derived facts the rule declared it reads.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a package rather than more parameters.</b> A rule reading derived facts needs the object,
/// its security descriptor and a lookup keyed by scoped SID; a rule about staleness needs a
/// reference time; and the next such rule will need something else again. Widening <c>Judge</c>
/// once per rule would rewrite every rule each time. The package grows; the signature does not.
/// </para>
/// <para>
/// <b>The derived facts are nullable and a rule must not assume otherwise.</b> A judging that ran
/// against evidence alone hands over a package carrying no derivation at all. That is a legitimate
/// state - the two delegation rules declare no derived facts and are unaffected by it - so the
/// absence is modelled rather than guarded by a convention nobody can see.
/// </para>
/// <para>
/// <b>What guarantees a derived fact is populated is the declaration, not this type.</b> A rule
/// whose definition names <see cref="DerivedFactKind.ProtectedPrincipals"/> is never offered a
/// package without it, because <c>JudgingRun</c> refuses the whole judging first. That refusal is
/// what makes reading those properties safe for a rule that declared them.
/// </para>
/// <para>
/// <b><see cref="AsOf"/> is not nullable and there is no way to build a context without one.</b>
/// A rule about staleness that read the clock would give a different answer every time the same
/// sealed evidence was opened, and nothing in the bundle would say why - which is the reason
/// <c>JudgementSchema</c> records <c>evaluation_as_of</c> beside every judgement. Carrying the
/// recorded time here, rather than leaving each rule to find one, is what makes re-judging a sealed
/// bundle reproducible instead of merely usually reproducible. A rule that reads
/// <c>DateTimeOffset.UtcNow</c> is wrong on sight.
/// </para>
/// </remarks>
/// <param name="AsOf">
/// The reference time this judging is evaluated against, as recorded on the judgement. Every rule
/// asking whether something has expired asks relative to this and never to the clock.
/// </param>
/// <param name="ProtectedPrincipals">
/// The stored protected-principal derivation, or null where the phase did not run or was not asked
/// for.
/// </param>
/// <param name="Permissions">
/// Reads the security descriptor of one object by distinguished name. Null where the judging was not
/// given a way to read permissions.
/// </param>
/// <param name="AttributeVisibility">
/// Which attributes this forest withholds, or null where the phase did not run or was not asked
/// for.
/// </param>
/// <param name="MembersOfPrincipal">
/// Expands one principal, given its SID and the scope that SID is unique within, to everything
/// nested inside it. Null where the judging was not given a derivation to walk.
/// </param>
/// <param name="SchemaGuids">
/// This forest's schema GUID catalogue, over the shipped one, or null where no bundle was opened.
///
/// <para>
/// <b>A rule needs this to read an object-specific access control entry at all.</b> Such an entry
/// names the attribute it is scoped to by <i>schema GUID</i> and never by name, so without the
/// catalogue a rule cannot tell an entry limited to one attribute from an entry over another. It is
/// not a derived fact and is therefore not a <see cref="DerivedFactKind"/>: every bundle carries the
/// rows, and <c>docs/decisions/0014</c> settles that the answer states which layer it came from.
/// </para>
/// <para>
/// <b>The captured layer is the one that matters here.</b> A forest that never ran
/// <c>Update-LapsADSchema</c> has no LAPS attribute at all, and an answer from the shipped table
/// would claim otherwise - which is the same mistake as reading a value out of a schema nobody read.
/// </para>
/// </param>
public sealed record JudgingContext(
    DateTimeOffset AsOf,
    StoredProtectedPrincipalDerivation? ProtectedPrincipals,
    Func<string, ObjectPermissions?>? Permissions,
    StoredAttributeVisibility? AttributeVisibility,
    Func<string, string, PrincipalExpansion>? MembersOfPrincipal,
    SchemaGuidCatalog? SchemaGuids)
{
    /// <summary>
    /// A context carrying a reference time and nothing derived, which is what an Evidence-only
    /// judging hands over.
    /// </summary>
    /// <remarks>
    /// <b>This replaced a property named <c>None</c> on 2026-09-03.</b> A parameterless "nothing
    /// here" could be written by a caller that had not thought about time, and a staleness rule
    /// handed one would have had to invent a reference point. Requiring the time to name itself
    /// means there is no such thing as a judging without one.
    /// </remarks>
    /// <param name="asOf">The reference time this judging is evaluated against.</param>
    public static JudgingContext At(DateTimeOffset asOf) =>
        new(asOf, null, null, null, null, null);
}

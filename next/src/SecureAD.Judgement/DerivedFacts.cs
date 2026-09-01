using SecureAD.Derivation;
using SecureAD.Evidence;

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
/// </remarks>
public enum DerivedFactKind
{
    /// <summary>
    /// Per-principal AdminSDHolder protection: whether a principal is protected, not protected, or
    /// undecided, with the basis and membership path that settled it. Produced by the Derivation
    /// phase named in <c>docs/decisions/0090</c>.
    /// </summary>
    ProtectedPrincipals,
}

/// <summary>
/// The derived facts offered to a rule alongside the object it is judging.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a package rather than more parameters.</b> A rule reading derived facts needs the object,
/// its security descriptor and a lookup keyed by scoped SID, and the next such rule will need
/// something else again. Widening <c>Judge</c> once per rule would rewrite every rule each time.
/// The package grows; the signature does not.
/// </para>
/// <para>
/// <b>Everything on it is nullable, and a rule must not assume otherwise.</b> A judging that ran
/// against evidence alone hands over a package with nothing in it. That is a legitimate state - the
/// two delegation rules declare no derived facts and are unaffected by it - so the absence is
/// modelled rather than guarded by a convention nobody can see.
/// </para>
/// <para>
/// <b>What guarantees it is populated is the declaration, not this type.</b> A rule whose definition
/// names <see cref="DerivedFactKind.ProtectedPrincipals"/> is never offered a package without it,
/// because <c>JudgingRun</c> refuses the whole judging first. That refusal is what makes reading
/// these properties safe for a rule that declared them.
/// </para>
/// </remarks>
/// <param name="ProtectedPrincipals">
/// The stored protected-principal derivation, or null where the phase did not run or was not asked
/// for.
/// </param>
/// <param name="Permissions">
/// Reads the security descriptor of one object by distinguished name. Null where the judging was not
/// given a way to read permissions.
/// </param>
public sealed record DerivedFacts(
    StoredProtectedPrincipalDerivation? ProtectedPrincipals,
    Func<string, ObjectPermissions?>? Permissions)
{
    /// <summary>Nothing derived was offered, which is what an Evidence-only judging hands over.</summary>
    public static DerivedFacts None { get; } = new(null, null);
}

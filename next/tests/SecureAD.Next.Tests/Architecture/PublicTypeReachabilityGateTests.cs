using System.Reflection;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 5b: every public type is reachable from something a person can launch.
/// </summary>
/// <remarks>
/// <para>
/// <b>The failure this exists to catch is not "nothing mentions this".</b> The predecessor's six
/// unreachable grids mention plenty, and mention each other; twenty-eight of its commands were
/// bound to nothing. Gate 5 was first written as <i>every public type has a production consumer</i>
/// and, on 2026-08-10, passed against all fourteen public types in the rebuild while nothing in the
/// tree was used by anything that ran - because types reference each other, which satisfies that
/// wording. <b>That is worse than an absent gate: an absent gate is visibly missing, and one that
/// always says yes looks like protection.</b> The question that separates the two is whether a root
/// can get there, which is what <see cref="ReachabilityTrace"/> measures. `P-182`, `F-S7-42`.
/// </para>
/// <para>
/// <b>The pair below is self-guarding in both directions, and that is the argument for its shape.</b>
/// If the walk broke and reached nothing, <see cref="EveryPublicTypeIsReachableOrExempt"/> fails
/// naming hundreds of types. If it over-approximated and reached everything, every exemption would
/// become unnecessary and <see cref="NoExemptionIsStillReachable"/> fails. Neither direction can
/// pass quietly, which is exactly what the original wording could not say about itself. The scanner
/// self-tests are carried anyway, per the standing rule that a gate must not be able to pass by
/// looking at nothing.
/// </para>
/// <para>
/// <b>What a failure here means.</b> Either a type became dead surface and should be deleted, or a
/// screen that was going to use it has not been built and the entry belongs below with a reason.
/// Adding an exemption is a decision; it is not the way to make the build go green.
/// </para>
/// </remarks>
public sealed class PublicTypeReachabilityGateTests
{
    /// <summary>One public type nothing running can reach, and why that is intended.</summary>
    /// <param name="FullName">The exact type name, so a rename fails rather than slips through.</param>
    /// <param name="Reason">Why it is allowed to be unreachable today.</param>
    private sealed record Exempt(string FullName, string Reason);

    /// <summary>
    /// Types whose callers are deliberately deferred by the owner-approved scope. Each is planned
    /// work whose caller does not exist yet, not surface anyone has abandoned.
    /// </summary>
    /// <remarks>
    /// Held here as code rather than in a document, per `P-184`: a gate whose input lives in
    /// markdown is a test holding a document to the code, which the owner's rule of 2026-09-12
    /// forbids.
    /// </remarks>
    private static readonly Exempt[] Exemptions =
    [
        // Run comparison and drift. A complete component with no door: the run library, a compare
        // window, acceptance import and baseline marking would all call RunComparability, and none
        // of them is built. Its own remarks record why it matters that they share one answer - the
        // predecessor had five of these and they disagreed, so an operator who decommissioned a
        // domain lost remediation tracking. Kept so a sixth is not written when the screen arrives.
        new("SecureAD.Evidence.Run.RunComparability", "Run comparison: no screen calls it yet."),
        new("SecureAD.Evidence.Run.RunSummary", "Run comparison: input to RunComparability."),
        new("SecureAD.Evidence.Run.ComparabilityVerdict", "Run comparison: its answer."),
        new("SecureAD.Evidence.Run.ComparabilityOutcome", "Run comparison: the verdict's kind."),
        new("SecureAD.Evidence.Run.BaselineVerdict", "Run comparison: baseline eligibility."),
        new("SecureAD.Evidence.Run.DriftCardShape", "Run comparison: how a drift card renders."),
        new("SecureAD.Evidence.Run.ProfileId", "Run comparison: identifies the compared forest."),
        new("SecureAD.Evidence.Run.RunStateNames", "Run comparison: names the states it reports."),
        new("SecureAD.Evidence.UnresolvedReferenceKind", "Run comparison: reported by a summary."),

        // Tier 0 ownership takeover. The owner approved the assessment in principle and explicitly
        // not its implementation, so these are the result and binding shapes ahead of the evaluator
        // that will fill them. OwnershipCandidateAssessment can currently only hold Unknown.
        new("SecureAD.Judgement.OwnershipAssessmentResult", "Ownership takeover: approved, unbuilt."),
        new("SecureAD.Judgement.OwnershipAssessmentBinding", "Ownership takeover: approved, unbuilt."),
        new("SecureAD.Judgement.OwnershipAssessmentAvailability", "Ownership takeover: approved, unbuilt."),
        new("SecureAD.Judgement.OwnershipAssessmentOrigin", "Ownership takeover: approved, unbuilt."),
        new("SecureAD.Judgement.OwnershipCandidateAssessment", "Ownership takeover: approved, unbuilt."),

        // Stage 7 checkpoint 1 explicitly approves saved inputs and passive API readback, not a
        // screen or path evaluator. Do not manufacture a host call merely to satisfy this gate.
        new("SecureAD.Judgement.PathInputs", "Stage 7 checkpoint 1: passive readback is approved; its screen/path-analysis consumer is deferred."),

        // Findings storage. StoredFindings documents its own status: the reader that built it was
        // removed when decision 0085 moved findings out of the sealed evidence, and the judgement
        // store that will build it has no shape yet. Kept because the guarantee it carries - that
        // "nothing was found" and "nobody looked" must not render alike - is what that store owes.
        new("SecureAD.Evidence.Findings.StoredFindings", "Findings storage: awaits the judgement store."),
        new("SecureAD.Evidence.Findings.EvaluatedRule", "Findings storage: part of StoredFindings."),
        new("SecureAD.Evidence.Findings.LapsPlatformCatalog", "Findings storage: read beside findings."),

        // Group Policy client-side extensions. Would let SYSVOL capture fetch only the GPOs holding
        // settings this product analyses, instead of every GPO in the forest over SMB. A saving
        // that matters at nine domains and is invisible in the laboratory. Not wired in yet.
        new("SecureAD.Kernel.GroupPolicy.GpoClientSideExtensions", "GPO filtering: optimisation not wired in."),
        new("SecureAD.Kernel.GroupPolicy.GpoClientSideExtensionCatalog", "GPO filtering: the known CSE GUIDs."),
        new("SecureAD.Kernel.GroupPolicy.ParsedCseList", "GPO filtering: what the parse returns."),
    ];

    /// <summary>The assemblies a person can launch. Every method in them is a root.</summary>
    /// <remarks>
    /// The window is named by a type inside it. The command line has to be loaded by name because
    /// every type in it is internal - which is the property
    /// <see cref="CommandLineSurfaceGateTests"/> exists to hold - and the name is
    /// <c>securead-cli</c> rather than <c>securead</c> so it cannot collide with the window's own
    /// assembly on a case-insensitive filesystem.
    /// </remarks>
    private static IReadOnlyList<Assembly> Applications() =>
    [
        typeof(SecureAD.Shell.ViewModels.ShellViewModel).Assembly,
        Assembly.Load("securead-cli"),
    ];

    private static ReachabilityTrace Trace() =>
        ReachabilityTrace.Walk(Applications(), RebuildAssemblies.All);

    private static IReadOnlyList<Type> ExportedTypes() =>
        [.. RebuildAssemblies.All
            .SelectMany(a => a.GetExportedTypes())
            .Where(t => !t.IsNested || t.IsNestedPublic)];

    /// <summary>
    /// The gate. Every public type of the walked libraries is reachable from a root, or is named
    /// below with a reason.
    /// </summary>
    [Fact]
    public void EveryPublicTypeIsReachableOrExempt()
    {
        var trace = Trace();
        var exempt = Exemptions.Select(e => e.FullName).ToHashSet(StringComparer.Ordinal);

        var unreachable = ExportedTypes()
            .Where(t => !trace.ReachableTypes.Contains(t))
            .Where(t => t.FullName is null || !exempt.Contains(t.FullName))
            .Select(t => "  " + t.FullName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unreachable.Count == 0,
            "Public types nothing running can reach. Starting from every method of the window and "
            + "the command line, no path arrives at these. Either the type is dead surface and "
            + "should be deleted, or the screen that will use it has not been built and it belongs "
            + "in the exemption list in this file with a reason. Adding an exemption is a decision, "
            + "not a way to make the build green:"
            + Environment.NewLine + string.Join(Environment.NewLine, unreachable));
    }

    /// <summary>
    /// The decay test. An exemption whose type has become reachable is protecting nothing, and an
    /// exemption nobody revisits is how a carve-out becomes permanent.
    /// </summary>
    [Fact]
    public void NoExemptionIsStillReachable()
    {
        var trace = Trace();
        var reachable = trace.ReachableTypes
            .Select(t => t.FullName)
            .Where(name => name is not null)
            .ToHashSet(StringComparer.Ordinal)!;

        var settled = Exemptions
            .Where(e => reachable.Contains(e.FullName))
            .Select(e => $"  {e.FullName} - exempted because: {e.Reason}")
            .OrderBy(line => line, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            settled.Count == 0,
            "Exempted types that something running now reaches. The screen these were waiting for "
            + "has been built, so the exemption is protecting nothing. Remove these entries from "
            + "the exemption list in this file:"
            + Environment.NewLine + string.Join(Environment.NewLine, settled));
    }

    /// <summary>
    /// An exemption naming a type that no longer exists is a stale carve-out, and would silently
    /// widen the gate the day a real type was given that name.
    /// </summary>
    [Fact]
    public void EveryExemptionNamesATypeThatExists()
    {
        var exported = ExportedTypes()
            .Select(t => t.FullName)
            .Where(name => name is not null)
            .ToHashSet(StringComparer.Ordinal)!;

        var phantom = Exemptions
            .Where(e => !exported.Contains(e.FullName))
            .Select(e => "  " + e.FullName)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            "The exemption list names public types that do not exist. They were renamed or deleted, "
            + "so the entries should go too:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>Every exemption says why, because a carve-out without a reason cannot be reviewed.</summary>
    [Fact]
    public void EveryExemptionCarriesAReason()
    {
        var silent = Exemptions
            .Where(e => string.IsNullOrWhiteSpace(e.Reason))
            .Select(e => "  " + e.FullName)
            .ToList();

        Assert.True(
            silent.Count == 0,
            "Exemptions with no reason recorded:"
            + Environment.NewLine + string.Join(Environment.NewLine, silent));
    }

    /// <summary>
    /// The scanner self-test. Without it the gate above passes by walking nothing and finding no
    /// unreachable types in it, which is the failure this repository has committed before - gate 5's
    /// own first wording among them.
    /// </summary>
    [Fact]
    public void TheGateWalksTheRealProductAndReachesIt()
    {
        var trace = Trace();

        Assert.True(
            Applications().Count == 2,
            "The walk should start from the window and the command line.");

        Assert.True(
            trace.RootMethodCount > 500,
            $"Only {trace.RootMethodCount} root methods were found. The application assemblies "
            + "should contribute far more, so the walk is reading the wrong thing.");

        Assert.True(
            trace.WalkedMethodCount > trace.RootMethodCount,
            $"The walk visited {trace.WalkedMethodCount} methods from {trace.RootMethodCount} "
            + "roots, so it never left the applications and reached no library at all.");

        Assert.True(
            ExportedTypes().Count > 100,
            "Almost no public types were found to check, so the gate is measuring nothing.");

        Assert.True(Exemptions.Length > 0, "The exemption list is empty, so the decay test checks nothing.");

        // A positive control naming types that must always be reachable: the kernel's own
        // vocabulary, the writer every capture uses, and the catalogue holding every rule. Each is
        // reached by a different mechanism - direct call, an async state machine, and a type
        // initialiser - so this fails if any one of the three traversals stops working.
        foreach (var alive in new[]
        {
            typeof(SecureAD.Kernel.Result<int>).GetGenericTypeDefinition(),
            typeof(SecureAD.Evidence.BundleWriter),
            typeof(SecureAD.Judgement.RuleCatalogue),
        })
        {
            Assert.True(
                trace.ReachableTypes.Contains(alive),
                $"{alive.FullName} is not reachable, which cannot be true of a working product. "
                + "The walk has stopped following something - state machines, type initialisers "
                + "and virtual dispatch are the three it depends on.");
        }
    }
}

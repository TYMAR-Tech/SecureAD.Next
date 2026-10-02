using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 4: no public member hands back an answer that cannot say whether it was reached.
///
/// <para>
/// <b>What went wrong before.</b> A method returns a bare number and the caller cannot tell
/// <i>"I looked, and there is nothing"</i> from <i>"I could not compute this"</i>. Both are zero.
/// Both render as an empty grid or a count of nought. Four members of the old product's
/// <c>GridSummaryQueryService</c> did exactly this - <c>GetUnusualOwnerCount</c>,
/// <c>GetDangerousAceCount</c>, <c>GetDangerousAceGridCount</c> and
/// <c>GetSuppressedFindingCount</c>, each ending <c>catch (SqliteException) { return 0; }</c> - and
/// their zeros printed in an exported report's executive summary directly beneath a banner warning
/// that sections might be missing. A reader weighing a vague warning against a precise number
/// believes the number.
/// </para>
/// <para>
/// This is the one failure an audit tool cannot have, because a customer makes a security decision
/// on the strength of it. A screen reporting <i>"no dangerous permissions found"</i> when the truth
/// was <i>"this check never ran"</i> is worse than a screen that reports nothing at all, and the
/// customer has no way to tell the difference.
/// </para>
/// <para>
/// The requirement is stated in <c>docs/next/README.md</c> Â§ Gates: no public method returns a bare
/// count; it returns a vouched type or a <c>Result&lt;T&gt;</c>. The product's position on what the
/// answer must then say is not invented here - it is taken from
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c>, which forbids rendering
/// unavailable output as an empty result, and from
/// <c>docs/decisions/0004-unknown-counts-name-the-failed-phase.md</c>, which requires an
/// unvouchable count to render as unknown <i>naming the phase responsible</i>.
/// </para>
/// <para>
/// <b>Reflection, not a text scan.</b> The question here is <i>what does this member return</i>,
/// and a return type is a fact the compiler holds. A text scan cannot resolve <c>var</c>, cannot
/// tell a return type from a parameter type of the same name, and cannot tell a public member from
/// a private one - and this gate is stated for the public surface. The comparable choice is made
/// the other way in <see cref="NullDefaultGateTests"/>, deliberately, because there the subject is
/// a syntax form that must not exist and reflection can only inspect what compiled.
/// </para>
/// <para>
/// <b>What it does not do.</b> It is a rule about shapes, not about honesty. A method that returns
/// a properly vouched type and then fills it in wrongly passes here. It also does not police
/// <c>bool</c>: <c>false</c> carries the same ambiguity as <c>0</c> in principle, but no name shape
/// separates "the predicate ran and said no" from "the predicate did not run" - both are
/// <c>Is*</c> and <c>Has*</c> - so a rule over <c>bool</c> would fire on
/// <c>Result&lt;T&gt;.IsSuccess</c> and <c>GenericRightsExpander.HasGenericRights</c> and be
/// switched off within a week. That limit was recorded as a finding in docs/next/S-6-vouched-returns.md,
/// since deleted, rather than pretended away.
/// </para>
/// </summary>
public sealed class UnvouchedResultGateTests
{
    /// <summary>
    /// Assemblies making up the rebuild's production surface. Held once in
    /// <see cref="RebuildAssemblies"/>, which carries the self-test naming the three assemblies a
    /// type move must not change - see <c>F-S24-4</c>.
    /// </summary>
    private static IEnumerable<Assembly> ProductionAssemblies() => RebuildAssemblies.All;

    /// <summary>
    /// Member-name shapes that mean "a quantity of things found". Anchored globs, the form
    /// <c>CONCEPT-REGISTRY.md</c> already uses, where <c>*</c> stands for the rest of a name.
    ///
    /// <para>
    /// The name is the only evidence available, and that is the crux of this gate. An <c>int</c>
    /// carries no units: <c>GenericRightsExpander.Expand</c> returns an <c>int</c> that is a Windows
    /// access mask, and <c>CanonicalAceComparer.Compare</c> returns an <c>int</c> that is an
    /// ordering. Forbidding either would be nonsense, and a rule that fired on every <c>int</c> in
    /// the tree would be switched off. So the gate fires where a name claims to be a count and the
    /// type cannot say whether the count is real.
    /// </para>
    /// </summary>
    private static readonly string[] CountShapes =
    [
        "Count", "Count*", "*Count", "*Counts", "NumberOf*", "Total", "Total*", "*Total",
        "*Totals", "Tally", "Tally*", "*Tally",
    ];

    /// <summary>
    /// Member names that constitute a type vouching for its own completeness: alongside the answer
    /// it carries a statement of whether the answer was reached.
    ///
    /// <para>
    /// The rebuild already answers gate 4 this way in three places, which is why the shapes are
    /// these and not others. <c>ParsedSecurityDescriptor</c> and <c>AceNormalizationResult</c> each
    /// carry <c>Errors</c> beside their ACE lists, so an empty list with a populated <c>Errors</c>
    /// is visibly not an empty DACL. <c>PermissionAssessment</c> carries a <c>Verdict</c> whose
    /// fourth value is <c>CannotClassify</c>, so "not assessed" cannot be read as "safe".
    /// </para>
    /// <para>
    /// <c>*AreComplete</c> was added by <c>D1</c> of <c>F-S29-3</c>. It is the same pattern named
    /// for its subject rather than for the type: <c>PartitionCoverage.ContinuationReferences</c> is
    /// vouched for by <c>ContinuationReferencesAreComplete</c>, so the collection and the statement
    /// about it cannot be read apart. Widening a gate deserves the objection, and the answer is that
    /// the alternative was a fifth entry in the exemption list below - whose own comment says an
    /// entry not justified by a compiled table that cannot fail does not belong.
    /// </para>
    /// <para>
    /// <c>*WereAsked</c> was added by <c>S-40</c> for <c>preflight.json</c>'s contract types, and on
    /// merit rather than as an exemption: a statement of whether the question was put is exactly
    /// what this gate asks for, said in the past tense. The names it admits -
    /// <c>AllQuestionsWereAsked</c> and <c>AllDomainsWereAsked</c> - replaced <c>IsComplete</c> on
    /// those two types because that file is read by auditors who were not present, and a field
    /// called "complete" reading true beside a <c>SelectionWasInformed</c> of false invites the
    /// conclusion that nothing about the run was missing. In-memory types keep <c>IsComplete</c>;
    /// only the file's own contract changed.
    /// </para>
    /// </summary>
    private static readonly string[] VouchShapes =
    [
        // Portable summaries carry sanitized, counted errors as Problems. Readback failures must
        // reach that list too; PortableSummaryContentTests holds that behavior, not this name scan.
        "Errors", "Problems", "Warnings", "Verdict", "Verdicts", "IsComplete", "Completeness",
        "*AreComplete", "*WereAsked", "FailedPhase", "FailedPhases", "DidNotRun",
    ];

    /// <summary>
    /// The types allowed to hand back a bare collection, and the reason each is allowed to.
    ///
    /// <para>
    /// <c>SchemaGuidCatalog</c> is a table compiled into the assembly. It reads nothing, opens
    /// nothing and cannot fail, so an empty result from <c>FindByGuid</c> means one thing only:
    /// the GUID is not in the table. Decision 0002 asks for exactly this test - "state what the
    /// reader should conclude from it, and if nothing could mean either a fact about the domain or
    /// a failure of the query, the guard must distinguish them" - and here nothing means only the
    /// former.
    /// </para>
    /// <para>
    /// It expires the moment that stops being true, which
    /// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> makes a certainty rather
    /// than a possibility: a catalogue that can be loaded from a live schema partition can fail to
    /// load, and an empty catalogue then means either an empty answer or an unread partition.
    /// <see cref="TheCatalogueExemptionsHaveNotComeDue"/> fails the build on that day.
    /// </para>
    /// </summary>
    private static readonly string[] ExemptTypes =
        [
            "SchemaGuidCatalog", "CapturedAttributeCatalog", "ConnectionSecurityLadder",
            "BundleSchema", "GpoClientSideExtensionCatalog", "DirectoryTime",
            "WellKnownSidCatalog", "RuleCatalogue", "RuleGuidanceCatalogue",
            "PrivilegedSidCatalogue", "LapsPasswordAttributeCatalogue",
            // 0101 moves the existing constant selections here. No I/O or discovered collections;
            // the same expiry checks apply if this registry ever starts loading its data.
            "PrincipalClassificationRegistry",
        ];

    /// <summary>
    /// <b>The tenth entry, added 2026-09-02 with SEC-027</b>, on the identical reason.
    /// <c>PrivilegedSidCatalogue</c> is the two tables of security identifiers this product treats
    /// as privileged when it finds one in an account's SID history. Both are written out in the
    /// source, they read nothing and open nothing, and neither can fail: an empty answer would mean
    /// the product treats no identifier as privileged, which is not a state any query produces.
    ///
    /// <para>
    /// <b>It is a type of its own precisely because of this gate.</b> The tables were first fields
    /// on <c>PrivilegedSidHistory</c>, which also judges an object and can decline to - so exempting
    /// the type would have exempted the judging, which is exactly what gate 4 is for. Splitting the
    /// tables out was the alternative to an exemption that covered the thing the gate was pointing
    /// at, and it follows the precedent <c>GpoClientSideExtensionCatalog</c> set in August.
    /// </para>
    /// <para>
    /// <b>The claim that the tables are right is held elsewhere</b>, which matters because an
    /// exemption from this gate must not become an exemption from being checked at all.
    /// <c>PrivilegedSidHistoryTests.EveryPrivilegedIdentifierIsOneMicrosoftDocuments</c> requires
    /// every value in both tables to resolve in <see cref="WellKnownSidCatalog"/>, which is itself
    /// pinned to Microsoft's published table. That check has already fired once in earnest, on the
    /// day the rule was written.
    /// </para>
    /// </summary>

    /// <summary>
    /// <b>The ninth entry, added 2026-09-01 with the operator guidance</b>, on the same reason as
    /// <c>RuleCatalogue</c> beside it. <c>RuleGuidanceCatalogue.All</c> is written out in the
    /// source: it constructs the entries and returns them, reading nothing and opening nothing.
    ///
    /// <para>
    /// <b>An empty answer is not a state this can reach</b>, so it cannot hand back nothing while
    /// meaning <i>I could not tell</i>. And an entry that is genuinely absent is caught by
    /// <c>RuleGuidanceTests.EveryRuleHasGuidance</c> rather than being rendered as a finding with no
    /// advice, which is the consequence gate 4 exists to prevent.
    /// </para>
    /// <para>
    /// <b>The exemption expires on the same condition</b>: if the guidance is ever loaded from a
    /// file or assembled by reflection, an empty list can mean a failed load, and that ambiguity is
    /// what this gate refuses. <see cref="TheCatalogueExemptionsHaveNotComeDue"/> holds it.
    /// </para>
    /// </summary>

    /// <summary>
    /// <b>The eighth entry, added 2026-08-26 when the rule set moved out of the shell</b>, on the
    /// same reason as the seven before it. <c>RuleCatalogue.All</c> is a list written out in the
    /// source: it constructs the rules and returns them, reading nothing and opening nothing.
    ///
    /// <para>
    /// <b>An empty answer is not a state this can reach.</b> There is no query behind it and no file
    /// to fail to load, so it cannot hand back nothing while meaning <i>I could not tell</i> - the
    /// distinction gate 4 exists to force. If it were ever empty the product would ship judging no
    /// rules at all, and that is caught upstream: a judging where no rule ran is refused rather than
    /// reported as a clean forest, by <c>JudgementReader</c>.
    /// </para>
    /// <para>
    /// <b>The exemption expires if the list ever becomes discovered rather than written.</b> A set
    /// assembled by reflection, or loaded from a file, can be empty because it failed to load -
    /// which is exactly the ambiguity this gate refuses. <c>docs/decisions/0082</c> makes that
    /// unlikely rather than impossible, so it is stated here as the condition on the exemption
    /// rather than assumed.
    /// </para>
    /// </summary>

    /// <summary>
    /// <b>The seventh entry, added with the well-known SID catalogue</b>, on the identical reason.
    /// <c>WellKnownSidCatalog.AllSids</c> and <c>AllRelativeIdentifiers</c> are the values MS-DTYP
    /// 2.4.2.4 publishes, written out in the source. They read nothing and cannot fail: an empty
    /// answer would mean this build knows no well-known SIDs at all, which is not a state any query
    /// produces, and <c>FindBySid</c> returning null means only that the SID is not a well-known
    /// one and should be looked for among the captured objects.
    ///
    /// <para>
    /// <b>The claim that the table is right is held elsewhere</b>, which matters because an
    /// exemption from this gate must not become an exemption from being checked at all.
    /// <c>WellKnownSidCatalogMicrosoftAnchorTests</c> pins every value to Microsoft's published
    /// table, and <c>next/tools/harvest-ms-dtyp-well-known-sids.ps1</c> is how those values were
    /// sourced and how they are re-checked.
    /// </para>
    /// </summary>

    /// <summary>
    /// <b>The sixth entry, added 2026-08-18 with S-51</b>, on the identical reason.
    /// <c>DirectoryTime.Attributes</c> is the table of which captured attributes are timestamps and
    /// in which of Microsoft's two syntaxes. It is written out in the source, it reads nothing and
    /// it cannot fail: an empty answer would mean this build words no timestamps at all, which is
    /// not a state any query produces. The table exists precisely because the alternative - judging
    /// the syntax from the value - is what goes wrong, since a generalized time parses perfectly
    /// well as an interval and lands in the seventeenth century.
    /// </summary>

    /// <summary>
    /// The second exemption, added 2026-08-11 with inventory row B2, on exactly the same terms.
    ///
    /// <para>
    /// <c>CapturedAttributeCatalog</c> is the list of attributes capture asks a domain controller
    /// for. It is a table compiled into the assembly, it reads nothing, and it cannot fail: an empty
    /// answer from <c>AttributesJustifiedBy</c> means only that the class adds nothing to the universal set,
    /// and in fact it cannot even be empty, because the universal set is always returned.
    /// </para>
    /// <para>
    /// <b>Widening an allowlist is how a gate dies</b>, so it is worth saying plainly that this is
    /// the second entry and not the tenth, that the reason is identical rather than merely similar,
    /// and that <see cref="TheCatalogueExemptionsAreStillEarningTheirPlace"/> and
    /// <see cref="TheCatalogueExemptionsHaveNotComeDue"/> both cover every entry rather than the
    /// first one. A third entry whose reason is not "a compiled table that cannot fail" does not
    /// belong here.
    /// </para>
    /// <para>
    /// <b>The third entry, added 2026-08-12 with inventory row A2</b>, on the identical reason.
    /// <c>ConnectionSecurityLadder</c> is the list of ways this product will connect to a domain
    /// controller. It is four rows written out in the source, it reads nothing, and it cannot fail;
    /// <c>PermittedBy</c> filters that list against what the run declared and cannot return an
    /// empty one, because three of the four rungs are permitted unconditionally. There is no state
    /// of the world in which an empty answer from either member means "the question failed".
    /// </para>
    /// <para>
    /// <b>The fourth entry, added 2026-08-12 with inventory row C1</b>, on the identical reason.
    /// <c>BundleSchema.TableNames</c> is the list of tables a bundle contains. It is written out
    /// in the source beside the DDL that creates them, it reads nothing, and it cannot fail: an
    /// empty answer would mean a bundle with no tables, which is not a state any query produces.
    /// It is checked against a real database by <c>BundleDocumentationTests</c> rather than
    /// trusted, so the claim that it describes what exists is held by something other than this
    /// exemption.
    /// </para>
    /// <para>
    /// <b>The fifth entry, added 2026-08-13 with inventory row B16</b>, on the identical reason.
    /// <c>GpoClientSideExtensionCatalog.AnalyzableCses</c> is the two Group Policy client-side
    /// extensions whose on-disk settings this product parses. It is written out in the source, it
    /// reads nothing, and it cannot fail: an empty answer would mean the product parses no policy
    /// files at all, which is not a state any query produces.
    /// </para>
    /// <para>
    /// <b>It exists as a separate type because this exemption is granted per type rather than per
    /// member.</b> The table used to sit on <c>GpoClientSideExtensions</c> beside the parsing of
    /// <c>gPCMachineExtensionNames</c>, and exempting that type would have exempted the parse -
    /// which reads an attribute, can fail, and is exactly what gate 4 is for. Splitting the table
    /// out was the alternative to an exemption that would have covered the thing the gate was
    /// pointing at. The parse now returns <see cref="SecureAD.Kernel.GroupPolicy.ParsedCseList"/>
    /// and is held by the gate like anything else.
    /// </para>
    /// </summary>
    private static bool IsExempt(string typeName) =>
        ExemptTypes.Contains(typeName, StringComparer.Ordinal);

    /// <summary>
    /// Member-name shapes that mean the catalogue acquired a way to fail. Any of them appearing on
    /// the exempt type ends the exemption.
    /// </summary>
    private static readonly string[] FallibleShapes =
    [
        "Load*", "Read*", "From*", "Fetch*", "Download*", "Refresh*", "Open*",
    ];

    /// <summary>
    /// The first fire. A member whose name claims a count, returning a number that cannot say
    /// whether the count was reached.
    ///
    /// <para>
    /// <b>Members of a vouched type are excluded, added 2026-08-18 with <c>ObjectPage.Total</c>.</b>
    /// The reason is the one the collection fire below already gives in the same words: the
    /// container carries the statement, so the number is not on its own.
    /// <c>ObjectPage.ObjectsAreComplete</c> sits beside <c>Total</c> and says whether the listing
    /// was read in full, which is exactly what this gate asks a count to be able to say. Without
    /// the exclusion the only way past the gate is to rename the member out of the shape list,
    /// which would leave the number just as unvouched and the gate blind to it - a worse outcome
    /// than the one being prevented.
    /// </para>
    /// </summary>
    [Fact]
    public void NoPublicMemberReturnsABareCount()
    {
        var offenders = PublicMembers()
            .Where(m => IsCountShaped(m.Member.Name))
            .Where(m => IsBareNumber(m.Returns))
            .Where(m => !IsVouched(m.Type))
            .Where(m => !VouchedByContainment.Value.Contains(m.Type))
            .Select(m => $"  {ReadableName(m.Type)}.{m.Member.Name} returns {ReadableName(m.Returns)}")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Public members returning a bare count (docs/next/README.md, gate 4). A number on "
            + "its own cannot say whether it was measured, so 'I looked and found none' and 'I "
            + "could not compute this' arrive at the caller identically and print as the same "
            + "reassuring zero. The old product did this in four places and the zeros reached an "
            + "exported report. Return a vouched type carrying the outcome beside the number, or "
            + "a Result<T>. Per docs/decisions/0004, a count the run cannot vouch for renders as "
            + "unknown and names the phase responsible, which a bare int cannot do and a nullable "
            + "int cannot do either:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The second fire. A collection handed back by a type that says nothing about whether it
    /// managed to look.
    ///
    /// <para>
    /// Members of a vouched type are excluded because the container already carries the statement:
    /// <c>AceNormalizationResult.Aces</c> is empty beside an <c>Errors</c> list that is not, and a
    /// reader can tell. That is the whole point of the pattern, so policing the component as well
    /// as the container would fire on the rebuild's own correct code.
    /// </para>
    /// <para>
    /// Leaves of a vouched type are excluded for the same reason one step down - see
    /// <see cref="VouchedByContainment"/>. A <c>RestrictedGroup</c> can only be had from a
    /// <c>ParsedSecurityTemplate</c>, so whoever holds one is already holding the statement about
    /// whether the template was read.
    /// </para>
    /// </summary>
    [Fact]
    public void NoPublicMemberReturnsACollectionThatCannotSayWhetherItLooked()
    {
        var offenders = PublicMembers()
            .Where(m => IsCollection(m.Returns))
            .Where(m => !IsVouched(m.Type))
            .Where(m => !IsExempt(ReadableName(m.Type)))
            .Where(m => !VouchedByContainment.Value.Contains(m.Type))
            .Select(m => $"  {ReadableName(m.Type)}.{m.Member.Name} returns {ReadableName(m.Returns)}")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Public members returning a collection from a type that cannot say whether it looked "
            + "(docs/next/README.md, gate 4). An empty list and a failed query render as the same "
            + "empty grid. Per docs/decisions/0002, unavailable output is never rendered as an "
            + "empty result and never phrased as a statement about the directory. Either carry an "
            + "Errors or Verdict member on the declaring type, as ParsedSecurityDescriptor and "
            + "AceNormalizationResult do, or return Result<T>:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The containment rule finds the leaves it was written for. Without this it could quietly
    /// match nothing - or everything - and the collection fire above would look healthy either
    /// way, which is the failure every scanner self-test here exists to catch.
    /// </summary>
    [Fact]
    public void TheContainmentRuleFindsTheLeavesItIsFor()
    {
        Assert.Contains(typeof(SecureAD.Kernel.GroupPolicy.RestrictedGroup), VouchedByContainment.Value);
        Assert.Contains(typeof(SecureAD.Kernel.GroupPolicy.RegistryPolicyEntry), VouchedByContainment.Value);
    }

    /// <summary>
    /// And it refuses a type nothing produces. An entry point is reached by being called, not by
    /// being handed back, so nothing vouches for it and the rule must not pretend otherwise -
    /// a containment rule that cleared every type would be an exemption list with no entries in it
    /// and no way to see that.
    /// </summary>
    [Fact]
    public void TheContainmentRuleRefusesATypeNothingProduces()
    {
        Assert.DoesNotContain(
            typeof(SecureAD.Kernel.Security.SecurityDescriptorParser), VouchedByContainment.Value);
    }

    [Theory]
    [InlineData(typeof(SecureAD.Evidence.Run.CaptureSummary))]
    [InlineData(typeof(SecureAD.Evidence.Run.DerivationSummary))]
    [InlineData(typeof(SecureAD.Evidence.Run.JudgingSummary))]
    public void SummaryProblemsCarryTheOutcome(Type summary) => Assert.True(IsVouched(summary));

    [Fact]
    public void RecordedProblemCountsKeepTheirContainersOutcome() =>
        Assert.Contains(typeof(SecureAD.Evidence.Run.ProblemCount), VouchedByContainment.Value);

    [Theory]
    [InlineData(typeof(ProblemContainer), true)]
    [InlineData(typeof(NothingVouching), false)]
    public void ACountLeafRequiresEveryProducerToCarryAnOutcome(Type secondProducer, bool expected)
    {
        var leaves = VouchedLeaves(
        [
            (typeof(ProblemContainer), typeof(IReadOnlyList<CountLeaf>)),
            (secondProducer, typeof(CountLeaf)),
        ]);

        Assert.Equal(expected, leaves.Contains(typeof(CountLeaf)));
    }

    [Fact]
    public void AProducerCannotVouchForItself() => Assert.DoesNotContain(
        typeof(ProblemContainer), VouchedLeaves([(typeof(ProblemContainer), typeof(ProblemContainer))]));

    [Fact]
    public void AStateNameAloneDoesNotVouchForCounts() => Assert.False(IsVouched(typeof(StateOnly)));

    private sealed record CountLeaf(int Count);
    private sealed record ProblemContainer(IReadOnlyList<SecureAD.Kernel.AuditError> Problems);
    private sealed record StateOnly(string State, int Count);

    /// <summary>
    /// Every leaf it clears really is produced only by types that vouch. Stated as its own
    /// assertion rather than trusted from the construction above, because the construction is the
    /// thing that could be wrong.
    /// </summary>
    [Fact]
    public void EveryContainmentVouchedLeafHasOnlyVouchedProducers()
    {
        foreach (var leaf in VouchedByContainment.Value)
        {
            var producers = PublicMembers()
                .Where(m => m.Type != leaf)
                .Where(m => ExposedTypesOf(m.Returns).Contains(leaf))
                .Select(m => m.Type)
                .Distinct()
                .ToList();

            Assert.NotEmpty(producers);
            Assert.All(
                producers,
                p => Assert.True(
                    IsVouched(p) || IsExempt(ReadableName(p)),
                    $"{ReadableName(leaf)} is cleared by containment but {ReadableName(p)} "
                    + "hands it back without vouching for it."));
        }
    }

    /// <summary>
    /// The type-carried statement finds the types it was written for, and finds them by the new
    /// route rather than the old one.
    ///
    /// <para>
    /// Asserting only that <c>Tier0Classification</c> is vouched would pass just as well if the
    /// widening did nothing and the name rule had quietly started matching, so the second assertion
    /// states that the name rule does <i>not</i> clear it. Without that this test would be a check
    /// that passes while measuring nothing.
    /// </para>
    /// </summary>
    [Fact]
    public void TheTypeCarriedStatementFindsTheTypesItIsFor()
    {
        Assert.False(DeclaresVouchingName(typeof(SecureAD.Derivation.Tier0Classification)));
        Assert.True(IsVouched(typeof(SecureAD.Derivation.Tier0Classification)));

        Assert.False(DeclaresVouchingName(typeof(SecureAD.Judgement.OwnershipScopeSelection)));
        Assert.True(IsVouched(typeof(SecureAD.Judgement.OwnershipScopeSelection)));

        Assert.True(IsVouched(typeof(OneLevelAway)));
    }

    /// <summary>
    /// And it reaches one level and no further, which is the whole of what keeps it a gate. A rule
    /// that chained would clear almost every type in the product, because most of them transitively
    /// hold something carrying an <c>Errors</c> or an <c>IsComplete</c> somewhere below.
    /// </summary>
    [Fact]
    public void TheTypeCarriedStatementDoesNotReachTwoLevels()
    {
        Assert.False(IsVouched(typeof(TwoLevelsAway)));
        Assert.False(IsVouched(typeof(NothingVouching)));
    }

    /// <summary>A type holding a statement one member away, which is the shape the widening admits.</summary>
    private sealed record OneLevelAway(SecureAD.Derivation.Tier0Coverage Coverage);

    /// <summary>The same statement two members away, which it must not admit.</summary>
    private sealed record TwoLevelsAway(OneLevelAway Inner);

    /// <summary>A type carrying no statement at any depth, so neither rule may clear it.</summary>
    private sealed record NothingVouching(string Name, int Size);

    /// <summary>
    /// The scanner self-test. Without it both fires above pass by reflecting over an empty set of
    /// members and reporting a surface in perfect order - which is the worst thing a gate can do,
    /// and which this repository has done three times.
    /// </summary>
    [Fact]
    public void TheGateReadsTheRealPublicSurface()
    {
        var members = PublicMembers().ToList();

        Assert.True(members.Count > 0, "Reflected over no public members in the production assemblies.");

        Assert.Contains(
            members,
            m => ReadableName(m.Type) == nameof(SecureAD.Kernel.Security.GenericRightsExpander)
                 && m.Member.Name == nameof(SecureAD.Kernel.Security.GenericRightsExpander.Expand));

        Assert.Contains(
            members,
            m => ReadableName(m.Type) == nameof(SecureAD.Kernel.Schema.SchemaGuidCatalog)
                 && m.Member.Name == nameof(SecureAD.Kernel.Schema.SchemaGuidCatalog.FindByGuid));

        Assert.Contains(members, m => IsBareNumber(m.Returns));
        Assert.Contains(members, m => IsCollection(m.Returns));
        Assert.Contains(members, m => IsVouched(m.Type));
    }

    /// <summary>
    /// The self-test for the <c>*AreComplete</c> shape added by <c>D1</c>. A vouch shape that
    /// matches nothing in the tree widens the gate while vouching for no type, which is the shape of
    /// failure gate 5 was rewritten for.
    /// </summary>
    [Fact]
    public void TheAreCompleteShapeVouchesForARealType()
    {
        Assert.True(
            IsVouched(typeof(SecureAD.Evidence.PartitionCoverage)),
            "PartitionCoverage.ContinuationReferencesAreComplete is what the *AreComplete shape was "
            + "added for. If it no longer matches, the shape is vouching for nothing.");

        Assert.Contains(
            PublicMembers(),
            m => m.Member.Name == nameof(
                SecureAD.Evidence.PartitionCoverage.ContinuationReferencesAreComplete));
    }

    /// <summary>
    /// The gate is shown against the members the old product actually declared, rather than
    /// against invented ones. A gate that would not have caught the defect it exists for has not
    /// been shown to work.
    ///
    /// <para>
    /// All four are <c>public int</c> on <c>GridSummaryQueryService</c>, and all four end
    /// <c>catch (SqliteException) { return 0; }</c>
    /// (<c>git grep -n "catch (SqliteException) { return 0; }" -- src</c>). They are the members
    /// decision 0004 was written about. A shape narrowed until it would no longer have caught them
    /// fails here.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData("GetUnusualOwnerCount")]
    [InlineData("GetDangerousAceCount")]
    [InlineData("GetDangerousAceGridCount")]
    [InlineData("GetSuppressedFindingCount")]
    [InlineData("QueryControlTypeCounts")]
    [InlineData("QuerySourcePrincipalCounts")]
    public void TheGateWouldHaveCaughtTheDefectsThatMotivatedIt(string member)
    {
        Assert.True(
            IsCountShaped(member),
            $"'{member}' is one of the members whose swallowed SqliteException put a false zero "
            + "into an exported report. The count shapes must keep claiming it.");
    }

    /// <summary>
    /// The line between a count and a number that merely happens to be an integer. This is where
    /// the gate lives or dies: firing on every <c>int</c> in the tree would forbid an access mask
    /// and a comparison result, and get the gate switched off.
    /// </summary>
    [Theory]
    [InlineData("Count", true)]
    [InlineData("FindingCount", true)]
    [InlineData("NumberOfFindings", true)]
    [InlineData("TotalEdges", true)]
    [InlineData("Expand", false)]
    [InlineData("HasGenericRights", false)]
    [InlineData("Compare", false)]
    [InlineData("Version", false)]
    [InlineData("ControlFlags", false)]
    [InlineData("Discount", false)]
    public void ACountIsRecognisedByItsNameAndNothingElse(string member, bool expected)
    {
        Assert.Equal(expected, IsCountShaped(member));
    }

    /// <summary>
    /// What counts as a number that cannot vouch for itself.
    ///
    /// <para>
    /// A nullable integer is included, and that is a deliberate re-derivation rather than an
    /// oversight. <c>int?</c> distinguishes "could not compute" from "found none", which is better
    /// than <c>int</c> - but decision 0004 requires an unvouchable count to render as unknown
    /// <i>naming the phase responsible</i>, and a bare <c>null</c> names nothing. The old
    /// product's <c>ExecuteCountQuery</c> returned <c>int?</c> and is the nearest thing the old
    /// code had to getting this right; it still could not tell a reader which phase had failed.
    /// </para>
    /// <para>
    /// <c>bool</c> is excluded, and the reason is on the class above rather than here because it is
    /// a scope decision and not a detail.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(typeof(int), true)]
    [InlineData(typeof(long), true)]
    [InlineData(typeof(int?), true)]
    [InlineData(typeof(ushort), true)]
    [InlineData(typeof(bool), false)]
    [InlineData(typeof(string), false)]
    [InlineData(typeof(SecureAD.Kernel.Security.PermissionVerdict), false)]
    [InlineData(typeof(SecureAD.Kernel.Result<int>), false)]
    public void ABareNumberIsOneThatCarriesNoOutcomeWithIt(Type returns, bool expected)
    {
        Assert.Equal(expected, IsBareNumber(returns));
    }

    /// <summary>
    /// A vouched type states its own completeness. Checked against the three the rebuild already
    /// has and against two that are deliberately not vouched, so the predicate is shown to
    /// discriminate rather than to say yes.
    /// </summary>
    [Theory]
    [InlineData(typeof(SecureAD.Kernel.Security.ParsedSecurityDescriptor), true)]
    [InlineData(typeof(SecureAD.Kernel.Security.AceNormalizationResult), true)]
    [InlineData(typeof(SecureAD.Kernel.Security.PermissionAssessment), true)]
    [InlineData(typeof(SecureAD.Kernel.Schema.SchemaGuidCatalog), false)]
    [InlineData(typeof(SecureAD.Kernel.Security.CanonicalAce), false)]
    public void AVouchedTypeSaysWhetherItsAnswerWasReached(Type type, bool expected)
    {
        Assert.Equal(expected, IsVouched(type));
    }

    /// <summary>
    /// The allowlist-decay test, first half. An exemption that is no longer needed must fail rather
    /// than quietly become permanent: if a catalogue stops handing back a collection, whether
    /// because the table moved or because it was emptied, the exemption goes with it. Every entry in
    /// the allowlist is checked, so a second exemption cannot ride along behind the first.
    /// </summary>
    [Fact]
    public void TheCatalogueExemptionsAreStillEarningTheirPlace()
    {
        var idle = ExemptTypes
            .Where(exempt => !PublicMembers()
                .Any(m => ReadableName(m.Type) == exempt && IsCollection(m.Returns)))
            .ToList();

        Assert.True(
            idle.Count == 0,
            string.Join(", ", idle) + " is exempt from the collection half of gate 4 and returns "
            + "no collection. Either the table moved, in which case the exemption follows it, or "
            + "the exemption is dead and should go.");
    }

    /// <summary>
    /// The allowlist-decay test, second half, and the one that actually matters. The exemption
    /// rests on a claim - that the catalogue cannot fail - and this is the check that the claim is
    /// still true.
    ///
    /// <para>
    /// It fires when the catalogue gains any way to fail: a member returning
    /// <c>Result&lt;T&gt;</c>, or a member whose name says it acquires its entries from somewhere.
    /// Per <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> capture reads the
    /// schema partition, so this is a trigger that is coming rather than one that might.
    /// </para>
    /// </summary>
    [Fact]
    public void TheCatalogueExemptionsHaveNotComeDue()
    {
        var fallible = PublicMembers()
            .Where(m => IsExempt(ReadableName(m.Type)))
            .Where(m => IsResult(m.Returns) || FallibleShapes.Any(s => Matches(s, m.Member.Name)))
            .Select(m => $"  {ReadableName(m.Type)}.{m.Member.Name} returns {ReadableName(m.Returns)}")
            .ToList();

        Assert.True(
            fallible.Count == 0,
            "A catalogue is exempt from gate 4 because it is a table compiled into the assembly "
            + "that reads nothing and cannot fail, so an empty answer means only that the entry is "
            + "not in the table. It has acquired a way to fail, so an empty answer now means "
            + "either that or an unread source, and the exemption has come due. Remove it and give "
            + "the catalogue a vouched return:"
            + Environment.NewLine + string.Join(Environment.NewLine, fallible));
    }

    /// <summary>
    /// The line between a raw value that happens to be bytes and a collection of things found.
    /// This exists because the collection shape was narrowed to let <c>byte[]</c> through on
    /// 2026-08-12, and a narrowing with nothing holding its edge is how a gate stops measuring.
    /// </summary>
    [Theory]
    [InlineData(typeof(byte[]), false)]
    [InlineData(typeof(string), false)]
    [InlineData(typeof(int), false)]
    [InlineData(typeof(int[]), true)]
    [InlineData(typeof(List<byte>), true)]
    [InlineData(typeof(IReadOnlyList<byte>), true)]
    [InlineData(typeof(SecureAD.Kernel.Security.CanonicalAce[]), true)]
    [InlineData(typeof(IReadOnlyList<string>), true)]
    public void TheCollectionShapeStillFiresOnRealCollections(Type type, bool isCollection)
    {
        Assert.Equal(isCollection, IsCollection(type));
    }

    /// <summary>A count-shaped name: matched against the whole name, never as a substring.</summary>
    private static bool IsCountShaped(string memberName) =>
        CountShapes.Any(shape => Matches(shape, memberName));

    /// <summary>
    /// A number carrying nothing beside it. Nullable integers are included; see
    /// <see cref="ABareNumberIsOneThatCarriesNoOutcomeWithIt"/> for why.
    /// </summary>
    private static bool IsBareNumber(Type type)
    {
        var underlying = Nullable.GetUnderlyingType(type) ?? type;

        return !underlying.IsEnum
               && Type.GetTypeCode(underlying) is TypeCode.Byte or TypeCode.SByte
                   or TypeCode.Int16 or TypeCode.UInt16 or TypeCode.Int32 or TypeCode.UInt32
                   or TypeCode.Int64 or TypeCode.UInt64;
    }

    /// <summary>A sequence of things. <c>string</c> is one to the runtime and is not one here.</summary>
    /// <remarks>
    /// <para>
    /// <c>byte[]</c> is excluded on exactly the same reasoning as <c>string</c>, and it is worth
    /// stating because narrowing a gate is how a gate dies. This rule fires on <i>a collection of
    /// things that were found</i>, where empty is ambiguous between "I looked and there were none"
    /// and "I could not look". Raw bytes in this product are never that: an <c>objectSid</c>, an
    /// <c>objectGUID</c> and a security descriptor are each <b>one value</b> that happens to be
    /// stored as bytes, and an empty one is a malformed value rather than an empty answer.
    /// </para>
    /// <para>
    /// The narrowing is deliberately to <c>byte[]</c> and not to arrays in general, because
    /// <c>CanonicalAce[]</c> would be exactly the thing this gate is for.
    /// <see cref="TheCollectionShapeStillFiresOnRealCollections"/> holds that line.
    /// </para>
    /// </remarks>
    private static bool IsCollection(Type type) =>
        type != typeof(string)
        && type != typeof(byte[])
        && typeof(IEnumerable).IsAssignableFrom(type);

    private static bool IsResult(Type type) =>
        type.IsGenericType && type.GetGenericTypeDefinition() == typeof(SecureAD.Kernel.Result<>);

    /// <summary>
    /// A type that states its own completeness, by declaring a member that says whether the answer
    /// beside it was reached.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The statement may be carried in a name or in a type, and 2026-09-12 added the second.</b>
    /// The original rule read member names only, and the Tier-0 work carries its statement in a
    /// dedicated type instead: <c>Tier0Classification</c> declares a <c>Coverage</c> of type
    /// <see cref="SecureAD.Derivation.Tier0Coverage"/>, which holds three separate boundaries and a
    /// set of limitations and declares <c>IsComplete</c> itself. A caller holding the classification
    /// is holding that statement. The gate could not see it, because <c>Coverage</c> is not one of
    /// the shapes.
    /// </para>
    /// <para>
    /// <b>Widening a gate is how a gate dies, so it is worth saying what forced this one.</b> The
    /// alternative was a forwarding <c>bool</c> on each type, and it was tried: gate 4b refused two
    /// of them within a minute as members that could only ever say one thing. They could not vary
    /// because <c>Tier0Classifier</c> records asset, control and dependency qualification as
    /// unsupported on every classification it makes - Stage 6 has not built them - so
    /// <c>Tier0Coverage.IsComplete</c> is false for every classification in the product today. A
    /// name that promises to vary on a value that cannot is exactly <c>P-62</c>, so satisfying this
    /// gate that way would have created the defect its sibling exists to catch.
    /// </para>
    /// <para>
    /// <b>It reaches exactly one level, deliberately.</b> Made recursive it would clear almost
    /// everything, since most types transitively hold something with an <c>Errors</c> somewhere, and
    /// a gate that clears everything is an allowlist with no entries and no way to see that. One
    /// level says the statement is a single member away, which is where a reader will look for it.
    /// <see cref="TheTypeCarriedStatementFindsTheTypesItIsFor"/> and
    /// <see cref="TheTypeCarriedStatementDoesNotReachTwoLevels"/> hold both halves of that.
    /// </para>
    /// </remarks>
    private static bool IsVouched(Type type) =>
        DeclaresVouchingName(type) || DeclaredMemberTypes(type).Any(DeclaresVouchingName);

    /// <summary>A member whose own name is one of the vouching shapes.</summary>
    private static bool DeclaresVouchingName(Type type) =>
        type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static
                        | BindingFlags.DeclaredOnly)
            .Any(m => VouchShapes.Any(shape => Matches(shape, m.Name)));

    /// <summary>
    /// The types this one declares members of. Nullable wrappers are unwrapped, because a coverage
    /// that may be absent still states what it states when it is there.
    /// </summary>
    private static IEnumerable<Type> DeclaredMemberTypes(Type type) =>
        type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Select(m => m switch
            {
                PropertyInfo property when property.GetMethod is not null
                                           && property.GetIndexParameters().Length == 0
                    => property.PropertyType,
                FieldInfo field => field.FieldType,
                _ => null,
            })
            .Where(t => t is not null)
            .Select(t => Nullable.GetUnderlyingType(t!) ?? t!)
            .Where(t => t != type);

    /// <summary>
    /// The leaf types whose vouching is carried by whatever produces them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this is not a fourth exemption.</b> <c>RestrictedGroup</c> is one entry parsed out of
    /// a <c>GptTmpl.inf</c> security template, and the only way to obtain one is
    /// <c>ParsedSecurityTemplate</c>, which carries <c>Errors</c>. Its <c>Members</c> list being
    /// empty therefore cannot mean <i>the read failed</i> - the reader holding it is already
    /// looking at the statement that says whether the read failed. The same is true of
    /// <c>RegistryPolicyEntry</c> inside <c>ParsedRegistryPolicy</c>. The ambiguity gate 4 exists
    /// to prevent genuinely does not arise, and the gate could not see it because it examines a
    /// declaring type on its own.
    /// </para>
    /// <para>
    /// <b>The rule is strict on purpose: every type that exposes the leaf must be vouched, not
    /// merely one of them.</b> A leaf reachable both through a vouched container and through some
    /// bare method would give a caller a way to hold it with no statement attached, and that caller
    /// is the one the gate is protecting. So a second, unvouched producer turns the leaf back into
    /// an offender.
    /// </para>
    /// <para>
    /// <b>It carries no allowlist and so needs no decay test.</b> Nothing is written down to go
    /// stale: the answer is computed from the code every run. A container that loses its
    /// <c>Errors</c> stops vouching, its leaves stop being covered, and the build fails - which is
    /// what a decay test would have been for.
    /// </para>
    /// </remarks>
    private static readonly Lazy<HashSet<Type>> VouchedByContainment = new(() =>
        VouchedLeaves(PublicMembers().Select(member => (member.Type, member.Returns))));

    private static HashSet<Type> VouchedLeaves(IEnumerable<(Type Type, Type Returns)> members)
    {
        var exposersOf = new Dictionary<Type, List<Type>>();
        foreach (var member in members)
        {
            foreach (var exposed in ExposedTypesOf(member.Returns))
            {
                if (exposed == member.Type)
                {
                    continue; // a type handing back itself vouches for nothing
                }

                if (!exposersOf.TryGetValue(exposed, out var list))
                {
                    list = [];
                    exposersOf[exposed] = list;
                }

                list.Add(member.Type);
            }
        }

        return exposersOf
            .Where(pair => pair.Value.Count > 0)
            .Where(pair => pair.Value.All(
                container => IsVouched(container) || IsExempt(ReadableName(container))))
            .Select(pair => pair.Key)
            .ToHashSet();
    }

    /// <summary>
    /// The types a member hands back: what it returns, and - when that is a collection - what the
    /// collection holds.
    /// </summary>
    private static IEnumerable<Type> ExposedTypesOf(Type returns)
    {
        yield return returns;

        if (returns.IsArray)
        {
            var element = returns.GetElementType();
            if (element is not null)
            {
                yield return element;
            }

            yield break;
        }

        if (returns.IsGenericType)
        {
            foreach (var argument in returns.GetGenericArguments())
            {
                yield return argument;
            }
        }
    }

    /// <summary>
    /// Turns a shape into an anchored pattern. <c>*</c> is the only wildcard and stands for the
    /// rest of a name. The same rule, and for the same reason, as the concept registry's shapes:
    /// a substring match would report <c>Discount</c> as a count, and a gate that is wrong on day
    /// one gets switched off.
    /// </summary>
    private static bool Matches(string shape, string memberName) =>
        Regex.IsMatch(
            memberName,
            "^" + string.Join("[A-Za-z0-9_]*", shape.Split('*').Select(Regex.Escape)) + "$",
            RegexOptions.CultureInvariant);

    /// <summary>
    /// Every public method and property on a public type, with what it returns.
    ///
    /// <para>
    /// Constructors are excluded because they return their own type by definition. Compiler-written
    /// members are excluded for the reason <c>ConceptRegistryTests</c> gives: a gate firing on
    /// <c>get_Entries</c> or on a record's <c>Deconstruct</c> would be policing the compiler.
    /// Enums are excluded because their members are a vocabulary rather than an answer.
    /// </para>
    /// </summary>
    private static IEnumerable<(Type Type, MemberInfo Member, Type Returns)> PublicMembers() =>
        PublicTypes()
            .Where(t => !t.IsEnum)
            .SelectMany(t => t
                .GetMembers(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance
                            | BindingFlags.DeclaredOnly)
                .Where(m => !CompilerWritten.Contains(m.Name))
                .Where(m => !m.Name.Contains('<', StringComparison.Ordinal))
                .Select(m => (Type: t, Member: m, Returns: ReturnTypeOf(m)))
                .Where(x => x.Returns is not null)
                .Select(x => (x.Type, x.Member, x.Returns!)));

    private static Type? ReturnTypeOf(MemberInfo member) => member switch
    {
        PropertyInfo property => property.PropertyType,
        FieldInfo field => field.FieldType,
        MethodInfo method when !method.IsSpecialName && method.ReturnType != typeof(void)
            => method.ReturnType,
        _ => null,
    };

    /// <summary>Names the compiler generates for a record, which no author wrote.</summary>
    private static readonly HashSet<string> CompilerWritten = new(StringComparer.Ordinal)
    {
        "Equals", "GetHashCode", "ToString", "Deconstruct", "Clone", "PrintMembers",
        "op_Equality", "op_Inequality", "EqualityContract", "GetType",
    };

    private static IEnumerable<Type> PublicTypes() =>
        ProductionAssemblies()
            .SelectMany(a => a.GetTypes())
            .Where(t => t.IsPublic || t.IsNestedPublic)
            .Where(t => t.GetCustomAttribute<CompilerGeneratedAttribute>() is null)
            .Where(t => !t.Name.Contains('<', StringComparison.Ordinal));

    /// <summary>The name as a person would write it: the runtime reports <c>Result</c> as <c>Result`1</c>.</summary>
    private static string ReadableName(Type type)
    {
        var name = type.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }
}

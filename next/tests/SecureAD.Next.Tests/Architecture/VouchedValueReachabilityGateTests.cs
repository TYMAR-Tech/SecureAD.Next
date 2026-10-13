using System.Collections;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 4b: a member that vouches for an answer must be able to say both things.
///
/// <para>
/// <b>What went wrong before.</b> Gate 4 - <see cref="UnvouchedResultGateTests"/> - accepts a type
/// as vouched when it declares a member whose <i>name</i> matches one of eleven shapes. That is a
/// rule about shapes and it says so in its own summary. A member with the right name and a value
/// that cannot vary satisfies it completely. <c>ObjectAttributes.AttributesAreComplete</c> was
/// exactly that: computed as <c>attributes.Count == CapturedAttributeCatalog.All.Count</c> where
/// both sides derived from the same catalogue by a partition, so it read <c>true</c> on every
/// object the product ever built. Gate 4 counted the type as vouched, every count and collection
/// hanging off it was excused on the strength of that vouching, and nothing had been measured.
/// The defect is recorded as <c>P-62</c> and the flag was removed on 2026-08-22.
/// </para>
/// <para>
/// A constant completeness flag is the first category in <c>.github/copilot-instructions.md</c> -
/// a check that passes while measuring nothing - and it is worse than an absent one, because
/// everything downstream of it looks verified. A customer reads <i>"complete"</i> beside a list of
/// permissions and concludes the list is the whole list.
/// </para>
/// <para>
/// <b>Why this drives the product rather than reading the tests.</b> The obvious gate is to scan
/// the test sources for an assertion of each value. It was refused. Ask the question
/// <c>.github/copilot-instructions.md</c> requires - <i>what change to the product would make this
/// gate fail?</i> - and the answer for a source scan is <i>none</i>: it fails when somebody edits a
/// test, and it passes when somebody adds one, whatever the product does. That is a prose-shape
/// gate. This gate reads nothing under <c>next/tests</c>. It calls the type's own public
/// constructors and factories, and asks whether any inputs it can supply produce <c>true</c> and
/// any produce <c>false</c>. No test can satisfy it and no test can break it; only the product can.
/// </para>
/// <para>
/// <b>Why it would have caught P-62 and a literal check would not.</b> A cheaper gate reads the
/// getter's IL and fails a body that is <c>ldc.i4.1; ret</c>. That is real and it is kept below as
/// <see cref="NoVouchingMemberIsALiteral"/>, because it fires on types this driver cannot build.
/// But it would have passed <c>AttributesAreComplete</c> without a murmur: that getter was a
/// genuine comparison between two expressions, and nothing local to it was constant. What made it
/// constant was the relationship between its two sides, and the only way to see that from outside
/// is to try to make it false and fail.
/// </para>
/// <para>
/// <b>It polices booleans only, and that is not a narrowing.</b> The non-boolean vouchers are
/// <c>Errors</c> lists and <c>Completeness</c> enums. An enum with one member would be the same
/// defect, but the compiler and gate 4's own reading of these types already make that visible,
/// whereas a <c>bool</c> is exactly where a constant hides in plain sight: it has the right type,
/// the right name, and reads as an answer.
/// </para>
/// </summary>
public sealed class VouchedValueReachabilityGateTests
{
    /// <summary>
    /// The vouching name shapes, held identically to <see cref="UnvouchedResultGateTests"/>.
    ///
    /// <para>
    /// <b>Copied rather than shared, deliberately.</b> The alternative was to widen gate 4's
    /// private table to <c>internal</c> so this file could read it, and that would couple the two
    /// gates such that a change made for one silently changes the other. They are held together by
    /// <see cref="TheTwoGatesAgreeOnWhatVouchingLooksLike"/> instead, which fails if either list
    /// moves without the other - a check that is visible, rather than a coupling that is not.
    /// </para>
    /// </summary>
    private static readonly string[] VouchShapes =
    [
        "Errors", "Problems", "Warnings", "Verdict", "Verdicts", "IsComplete", "Completeness",
        "*AreComplete", "*WereAsked", "FailedPhase", "FailedPhases", "DidNotRun",
    ];

    /// <summary>
    /// The headline fire. A boolean voucher that only ever said one thing.
    ///
    /// <para>
    /// The gate builds the declaring type every way its own public surface allows and reads the
    /// member on each result. Witnessing both values passes. Witnessing one value only is this
    /// failure: the member has the shape of a statement and the behaviour of a constant, and every
    /// count and collection gate 4 excused on its account was excused for nothing.
    /// </para>
    /// <para>
    /// <b>A false failure here is not fixed with an exemption.</b> If a member is genuinely
    /// variable and the driver could not find the input that flips it, the driver is short a
    /// candidate value for that parameter type, and that is what to change. An entry excusing the
    /// member would put back exactly the blind spot this gate exists to close.
    /// </para>
    /// </summary>
    [Fact]
    public void EveryBooleanVoucherIsReachableAsBothValues()
    {
        var offenders = BooleanVouchers()
            .Where(v => !BeyondTheDriver.Contains($"{ReadableName(v.Type)}.{v.Name}",
                                                  StringComparer.Ordinal))
            .Select(v => (Voucher: v, Witnessed: WitnessedValuesOf(v.Type, v.Read)))
            .Where(x => x.Witnessed.Count == 1)
            .Select(x =>
                $"  {ReadableName(x.Voucher.Type)}.{x.Voucher.Name} was only ever "
                + $"{x.Witnessed.Single().ToString().ToLowerInvariant()}")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Vouching members that cannot say both things (docs/next/README.md, gate 4b). Each of "
            + "these carries a name gate 4 accepts as a statement of whether an answer was "
            + "reached, but the product was built every way its own public constructors and "
            + "factories allow and the member never changed. A completeness flag that is always "
            + "true is worse than no flag at all: gate 4 excuses every count and collection on the "
            + "type because of it, so the whole type reads as verified while nothing was measured. "
            + "This is what P-62 was - ObjectAttributes.AttributesAreComplete compared a partition "
            + "of a catalogue against the catalogue it was partitioned from. Make the member "
            + "compute something the inputs can change, or delete it and let gate 4 fire honestly:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    /// <summary>
    /// The vouchers this driver cannot settle, and why each one is out of its reach.
    ///
    /// <para>
    /// <b>An exact set, not a floor.</b> The temptation is to assert that no more than some number
    /// of vouchers are undecided, and that is the shape <c>LabConfirmationColumnTests</c> was
    /// re-anchored away from on 2026-08-22: a threshold obliges somebody to edit it every time the
    /// tree moves, and every edit is an opportunity to edit it to nothing. This names them. A new
    /// undecided voucher fails here and has to be argued for in writing.
    /// </para>
    /// <para>
    /// <b>Undecided is not excused.</b> These members are not passed by this gate - they are
    /// declared unmeasured by it, which is a different statement and is why they are named here
    /// rather than quietly filtered out. Each is still held by
    /// <see cref="NoVouchingMemberIsALiteral"/>, which needs no instance.
    /// </para>
    /// </summary>
    [Fact]
    public void TheVouchersThisDriverCannotSettleAreTheOnesNamedHere()
    {
        var undecided = BooleanVouchers()
            .Where(v => WitnessedValuesOf(v.Type, v.Read).Count < 2)
            .Select(v => $"{ReadableName(v.Type)}.{v.Name}")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(BeyondTheDriver.OrderBy(t => t, StringComparer.Ordinal), undecided);
    }

    /// <summary>
    /// The list above decays in the safe direction, and this is what stops it decaying in the
    /// other one.
    ///
    /// <para>
    /// A name on that list is a claim that the driver cannot settle the member. If the driver
    /// improves - a better candidate value, a deeper reach - the claim becomes false, and a false
    /// claim there is an excused member that no longer needs excusing. The assertion above already
    /// fails in that case, because it compares the set exactly rather than checking containment;
    /// this states the same requirement in the direction a reader will look for it, and fails with
    /// a message that says what to do.
    /// </para>
    /// <para>
    /// It also catches a name that is simply wrong. An entry naming a member that no longer exists
    /// excuses nothing and reads as though it excuses something, which is the worst of both.
    /// </para>
    /// </summary>
    [Fact]
    public void NothingOnThatListIsStaleOrMisspelled()
    {
        var vouchers = BooleanVouchers()
            .ToDictionary(v => $"{ReadableName(v.Type)}.{v.Name}", v => v, StringComparer.Ordinal);

        foreach (var name in BeyondTheDriver)
        {
            Assert.True(
                vouchers.ContainsKey(name),
                $"'{name}' is named as beyond the driver's reach and is not a boolean vouching "
                + "member of the product. Either it was renamed, in which case follow it, or it "
                + "was removed, in which case delete this entry: a name that matches nothing "
                + "excuses nothing and reads as though it excuses something.");

            var voucher = vouchers[name];

            Assert.True(
                WitnessedValuesOf(voucher.Type, voucher.Read).Count < 2,
                $"'{name}' is named as beyond the driver's reach, and the driver has just settled "
                + "it as both values. The entry is now false and must be deleted, which puts the "
                + "member back under the gate where it belongs.");
        }
    }

    /// <summary>
    /// Vouchers the driver cannot settle, each with the reason and, where the member does have a
    /// value the driver never saw, the line of the product that assigns it.
    ///
    /// <para>
    /// <c>IDirectoryChannel.IsComplete</c> is declared on an interface, which has no instances at
    /// all. It is the contract every channel honours, and the implementations that carry real
    /// behaviour are reached on their own account.
    /// </para>
    /// <para>
    /// <c>ControllerSelection</c> and <c>LdapDirectoryChannel</c> expose no public constructor and
    /// no public static factory returning themselves - they are produced by a connect sequence that
    /// needs a directory to talk to. Reaching them means standing up the fake channel the connect
    /// tests already use, which would make this gate depend on a test fixture and is the coupling
    /// the class summary refuses.
    /// </para>
    /// <para>
    /// <b><c>GpoInventory.DeclaredPoliciesAreComplete</c> is the weakest entry here and is worth
    /// stating plainly.</b> Unlike the other three the driver does build the type, and reads the
    /// flag as true. It goes false at
    /// <c>next/src/SecureAD.Audit/Sysvol/GpoInventory.cs:103</c>, where <c>Observe</c> adds to
    /// <c>_unlocatable</c>; reaching that line needs a <c>CapturedObject</c> whose object class is
    /// the literal <c>groupPolicyContainer</c> and which carries a usable object GUID but no file
    /// system path. That is two particular strings in two particular nested places, and a driver
    /// that guessed them would be a driver carrying a copy of the product's constants. The entry
    /// therefore rests on a reading of the code, cited above, which is exactly the kind of claim
    /// P-62 taught this repository to distrust - so it is written down as a weakness rather than
    /// presented as a result.
    /// </para>
    /// <para>
    /// <b><c>Tier0RelevanceRelation.IsComplete</c>, added 2026-09-12 with <c>P-154</c>'s gate 4
    /// work.</b> The type has no public constructor, and its public factories cannot be driven
    /// either: <c>FromMembership</c> takes a <c>Tier0Classification</c>, whose own constructor is
    /// <c>internal</c>, so the driver has no way to synthesize an argument and witnesses no
    /// instances at all. That is the <c>ControllerSelection</c> case rather than the
    /// <c>GpoInventory</c> one - the driver builds nothing here, so it reads neither value, and this
    /// entry claims only that and not that the member is fixed.
    /// </para>
    /// <para>
    /// <b>The member does take both values, and the lines that assign them are cited rather than
    /// asserted.</b> It reads true from <c>FromMembership</c> at
    /// <c>next/src/SecureAD.Judgement/Tier0RelevanceRelation.cs:126</c>, which constructs with
    /// <c>Tier0State.Established</c> and <c>Tier0Limitations.None</c>, and false from
    /// <c>FromControlEdge</c> at line 144, which constructs with <c>Tier0State.Unknown</c> and two
    /// limitations. As with <c>GpoInventory</c>, that rests on a reading of the code and is written
    /// down as a weakness rather than presented as a result.
    /// </para>
    /// </summary>
    private static readonly string[] BeyondTheDriver =
    [
        "ControllerSelection.IsComplete",
        "GpoInventory.DeclaredPoliciesAreComplete",
        "IDirectoryChannel.IsComplete",
        "LdapDirectoryChannel.IsComplete",
        "Tier0RelevanceRelation.IsComplete",
    ];

    /// <summary>
    /// The second anchor, and the cheaper one: a getter whose whole body is a constant.
    ///
    /// <para>
    /// This needs no instance, so it covers the three vouchers named in
    /// <see cref="UnreachableVouchers"/> that the driver cannot build. It catches
    /// <c>=&gt; true</c> written directly, which is the crudest form of the defect and the one most
    /// likely to be written in a hurry. It does not catch P-62 and is not claimed to.
    /// </para>
    /// </summary>
    [Fact]
    public void NoVouchingMemberIsALiteral()
    {
        var offenders = BooleanVouchers()
            .Where(v => v.Member is PropertyInfo p && GetterIsALiteral(p))
            .Select(v => $"  {ReadableName(v.Type)}.{v.Name}")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Vouching members whose getter is a literal (docs/next/README.md, gate 4b). The whole "
            + "body of each of these is 'push a constant, return it'. It has the name of a "
            + "statement about whether an answer was reached and it is not reading anything:"
            + Environment.NewLine + string.Join(Environment.NewLine, offenders));
    }

    // ---------------------------------------------------------------------------------------
    // Scanner self-tests. Every gate carries one - docs/next/README.md, § Gates - because the
    // failure this repository has seen twice is a check that passes while measuring nothing, and
    // a gate is not exempt from being the thing it was built to catch.
    // ---------------------------------------------------------------------------------------

    /// <summary>A voucher written as a literal is caught, and a real one is not.</summary>
    [Theory]
    [InlineData(typeof(ConstantVoucher), true)]
    [InlineData(typeof(ComputedVoucher), false)]
    [InlineData(typeof(P62ShapedVoucher), false)]
    public void TheLiteralScanFiresOnALiteralAndNotOnAComputation(Type fixtureType, bool isLiteral)
    {
        var member = fixtureType.GetProperties()
            .Single(p => p.PropertyType == typeof(bool)
                         && VouchShapes.Any(s => Matches(s, p.Name)));

        Assert.Equal(isLiteral, GetterIsALiteral(member));
    }

    /// <summary>
    /// The driver witnesses both values of a real computation, and only one of a constant.
    ///
    /// <para>
    /// <c>P62ShapedVoucher</c> is the point of this gate, reproduced. Its flag compares a list
    /// against the catalogue that list was taken from, exactly as
    /// <c>ObjectAttributes.AttributesAreComplete</c> did, so no constructor argument can make it
    /// false. It is not a literal and the IL scan above passes it; the driver does not.
    /// </para>
    /// </summary>
    [Theory]
    [InlineData(typeof(ComputedVoucher), 2)]
    [InlineData(typeof(ConstantVoucher), 1)]
    [InlineData(typeof(P62ShapedVoucher), 1)]
    [InlineData(typeof(MutatedVoucher), 2)]
    [InlineData(typeof(IUnbuildableVoucher), 0)]
    public void TheDriverSeparatesAComputationFromAConstant(Type fixtureType, int expectedValues)
    {
        var member = fixtureType.GetProperties()
            .Single(p => p.PropertyType == typeof(bool)
                         && VouchShapes.Any(s => Matches(s, p.Name)));

        Assert.Equal(expectedValues, WitnessedValuesOf(fixtureType, i => member.GetValue(i)).Count);
    }

    /// <summary>
    /// The synthesizer reaches all the way through the product's nesting.
    ///
    /// <para>
    /// The first version of this driver capped recursion at two levels, and a <c>RunCoverage</c>
    /// is four deep: it holds a <c>SysvolCoverage</c>, which holds <c>GpoCoverage</c> values, which
    /// hold their own scalars. Past the cap the synthesizer returned null, the lists came back
    /// empty, and empty lists read as a complete run - so the gate would have reported everything
    /// as fine having built nothing. That is the failure this gate exists to catch, committed by
    /// the gate itself, and it is the reason a cap needs a test rather than a comment.
    /// </para>
    /// </summary>
    [Fact]
    public void TheDriverReachesThroughTheProductsNesting()
    {
        var sysvol = Synthesize(typeof(SecureAD.Evidence.Run.SysvolCoverage), Variant.High, depth: 0);

        Assert.NotNull(sysvol);
        Assert.NotEmpty(((SecureAD.Evidence.Run.SysvolCoverage)sysvol).Policies);
    }

    /// <summary>
    /// The driver is looking at a real population, not an empty one.
    ///
    /// <para>
    /// The way this gate dies quietly is for <see cref="BooleanVouchers"/> to stop matching - a
    /// binding flag dropped, an assembly renamed - at which point every test above passes over
    /// nothing. This is gate 5's original failure, which passed against fourteen public types while
    /// nothing in the tree was reachable. The figure was 24 when measured on 2026-08-22, 26 from
    /// 2026-08-25 - <c>StoredJudgement.DidNotRun</c> arrived with the judgement store and
    /// <c>BundleObjects.IsComplete</c> with the streaming object reader - 27 from 2026-08-26 with
    /// <c>FindingsPage.DidNotRun</c>, and 28 later the same day with
    /// <c>FindingsFilterValues.DidNotRun</c>, which the unvouched-result gate demanded when the
    /// findings filters were built: two empty lists mean either a quiet forest or a bundle nobody
    /// judged. 29 from 2026-08-28 with <c>DerivationCompleteness.IsComplete</c>, which arrived when
    /// the derive stage joined <c>RebuildAssemblies</c> - it was written before that and so had
    /// never been driven. It passes on merit rather than by the widening: the driver builds a
    /// derivation both ways its own factories allow and the member reads both true and false.
    /// 31 from 2026-08-28 with <c>HeuristicCharacter.IsComplete</c> and
    /// <c>AdminSdExclusionMask.IsComplete</c>, which arrived with the reader for the forest's own
    /// heuristics. Both say whether anything was read at all, which is the distinction that reader
    /// exists for: a forest that stated nothing and a forest nobody asked are different facts.
    /// 33 from 2026-08-30 with <c>StoredProtectedPrincipalDerivation.IsComplete</c> and
    /// <c>StoredProtectedPrincipalFact.IsComplete</c>, so the persisted product and each fact carry
    /// their uncertainty beside collections a caller may otherwise mistake for complete answers.
    /// Regenerated by <c>next/tools/measure-vouching-sites.ps1</c>, which was widened to
    /// the judgement assembly in the same change, having been pointed at three of the four.
    /// 35 from 2026-09-02 with <c>SidReading.IsComplete</c> and
    /// <c>PrivilegedSidHistoryEvidence.IsComplete</c>, both of which the unvouched-result gate
    /// demanded when SEC-027 was built: a list of security identifiers read off an attribute is a
    /// collection whose emptiness means either <i>the object carried none</i> or <i>none of them
    /// could be decoded</i>, and those are opposite facts. Both pass on merit - the SEC-027 tests
    /// read each one true and false, from an account whose history decoded whole and one carrying a
    /// value that did not.
    /// 37 from 2026-09-02 with <c>TextReading.IsComplete</c> and
    /// <c>KerberoastableAccountEvidence.IsComplete</c>, which SEC-021 needed for the same reason:
    /// a list of service names read off an attribute is a collection whose emptiness means either
    /// <i>the account claims to run nothing</i> or <i>nothing could be read</i>. The second forced a
    /// better rule than the one first written - a privileged account with one readable service name
    /// is now reported beside a count of what was not read, where the rule had refused the whole
    /// object and lost a Critical finding over an unreadable sibling.
    /// 39 from 2026-09-03 with <c>SchemaAttributeReading.SchemaAttributesWereAsked</c> and
    /// <c>StoredAttributeVisibility.SchemaAttributesWereAsked</c>, which SEC-091 and SEC-094 needed
    /// because both treat an <i>absent</i> LAPS timestamp as a fact about a machine. That is only
    /// safe once the forest is known not to be withholding the attribute, and a list of schema
    /// definitions is a collection whose emptiness means either <i>this forest defines no
    /// attributes</i> - impossible - or <i>nobody read the schema partition</i>. Read false from a
    /// capture with no schema partition and true from one with it, so the flag is reached both
    /// ways rather than pinned at the value that happens to make the suite pass.
    /// 40 from 2026-09-03 with <c>LapsPage.ComputersAreComplete</c>, which the LAPS inventory needs
    /// for the reason <c>ObjectPage.ObjectsAreComplete</c> needs its own: widen the scope over a
    /// branch the run could not read and the list is short by an unknown number of machines, and a
    /// shorter list of unmanaged computers is indistinguishable from a rollout that is further
    /// along than it is. Read true from a whole listing and false from one whose domain coverage
    /// says a domain was not read.
    /// 41 from 2026-09-03 with <c>StoredRuleExecutions.DidNotRun</c>, which the rules screen needs
    /// because it hands a caller the executions without the findings. An empty list of executions
    /// means either a bundle nobody judged or a judging that recorded nothing before it stopped,
    /// and a screen whose whole subject is what was checked would draw the same thing for both.
    /// Read true from a bundle with no judging and false from one carrying executions.
    /// 42 from 2026-09-03 with <c>StoredNestingCycleProduct.IsComplete</c>, which the membership
    /// expansion needed because a store with no cycle rows is either a forest with no loops in it
    /// or a bundle nobody expanded. Gate 4 found this one rather than a person: the first draft put
    /// each cycle in a one-field record, which became the declaring type of the only collection and
    /// could not say whether anyone had looked. Removing that wrapper moved the lists onto the type
    /// that carries the answer, which is where the vouching belongs. Read true from a store whose
    /// expansion succeeded and false from one whose expansion did not run.
    /// 43 and 44 from 2026-09-03 with <c>PrincipalExpansion.IsComplete</c> and
    /// <c>ExpandedPrincipal.IsComplete</c>, which the shared expansion foundation needs because
    /// four consumers rest on it - SEC-090, SEC-093, the membership cycle rule and the groups
    /// screen. An empty expansion means the group is empty, the principal was never captured, the
    /// nesting pass never ran, or the walk stopped at a budget, and the last three are not
    /// statements about the group. The per-member flag marks where a stopped walk left an
    /// unexplored subtree, so a reader can see the edge of the answer rather than infer it. Read
    /// true from a whole expansion and false from one stopped at a budget.
    /// 45 from 2026-09-03 with <c>LapsPasswordReaderEvidence.IsComplete</c>, which SEC-090 needs
    /// because the exposure it reports is found by walking group nesting. A walk that stopped at a
    /// budget can find no broad principal while one is still inside, so a finding must be able to
    /// say that the answer thinned out - and, just as importantly, a stored finding must carry that
    /// statement forward, since the nesting lives in the derivation and cannot be re-walked from
    /// the judgement store. Read true from a completed expansion and false from a truncated one.
    /// 46 and 47 from 2026-09-03 with <c>GpoRegistrySettings.IsComplete</c> and
    /// <c>LapsDecryptorEvidence.IsComplete</c>, both added for SEC-093. The first exists because
    /// this gate's sibling caught the rule reading an empty settings list as a policy that
    /// configures no decryptor, when it also covers a policy whose SYSVOL files could not be read
    /// and a bundle captured without SYSVOL - so the reader now hands back the outcome beside the
    /// entries. Read true from a policy whose files were read and false from one that was never
    /// offered to the SYSVOL pass. The second is SEC-090's reasoning applied to a second walk, with
    /// one addition: it is false where the configured decryptor could not be resolved at all, which
    /// is a finding this rule makes rather than a silence.
    /// 48 from 2026-09-05 with <c>EffectiveAccessResult.IsComplete</c>, which exists because working
    /// out what a trustee holds over an object has four answers and only one of them is a list. The
    /// descriptor may never have been read, the DACL may be null - which grants everyone everything
    /// and is the most open state an object can be in - or it may have declared entries that none of
    /// which parsed. All three arrive as an empty list of holders and would read as the safest
    /// object in the directory. Read true from a descriptor that was read with every declared entry
    /// parsed, and false from any of the three silences.
    /// 49 from 2026-09-05 with <c>OwnerImplicitRightsSetting.IsComplete</c>, which says whether the
    /// forest was asked whether it blocks an owner's implicit rights. A forest that never set
    /// <c>dSHeuristics</c> has a documented answer; a bundle whose configuration object was never
    /// read has none, and the two must not render alike. Read true from a character that was stated
    /// or defaulted by absence, and false from one never read.
    /// 50 and 51 from 2026-09-05 with <c>ObjectTakeoverEvidence.IsComplete</c> and
    /// <c>ObjectOwnershipEvidence.IsComplete</c>, both added for the ownership and takeover rules
    /// and both SEC-090's reasoning applied to a different walk. The first is false where the walk
    /// that found a broad principal inside a trustee stopped early, so a stored finding cannot
    /// imply that nothing else is inside. The second is false where the walk that decided an owner
    /// is not administrative did not finish, which matters more than it looks: the owner may hold
    /// administrative rights through a group the walk never reached, and reporting them as
    /// non-administrative would name an administrator as a problem.
    /// 52 from 2026-09-05 with <c>ForestInventory.AllDeclaredDomainsAreComplete</c>, added with the
    /// dashboard. It says whether the counts beside it are the whole forest or part of one. A total
    /// assembled from two domains of three is a smaller number, and a smaller number looks exactly
    /// like a smaller forest - so a caller must be able to tell a complete inventory from a partial
    /// one without inspecting every row. Read true where every declared domain was read in full,
    /// and false where any was excluded, partly read, or had no controller to read it.
    /// 53 and 54 from <c>91d4c1c</c>, when Tier-0 discovery began deciding which objects get a
    /// detailed control assessment, and unrecorded here until <c>P-154</c>.
    /// <c>Tier0Coverage.IsComplete</c> holds three independent boundaries apart - whether the
    /// captured input was whole, whether the analysis a basis needs is supported at all, and whether
    /// processing finished - because a classification that establishes nothing means <i>no
    /// qualifying evidence was found</i> in one case and <i>the question was never asked</i> in the
    /// others, and an object reported outside Tier 0 on the second reading is an object nobody
    /// looked at. <c>Tier0DiscoveryCoverage.IsComplete</c> says whether anything stopped the scan
    /// from inspecting all supported captured input, which matters for the reason its own remarks
    /// give: its counts are work accounting, so an object absent from every candidate was not
    /// examined and was not cleared. Both are read true from whole input with no limitations and
    /// false from a stopped or budgeted scan.
    /// 55 and 56 from 2026-09-12 with <c>P-154</c>'s gate 4 work.
    /// <c>OwnershipAuditCount.IsComplete</c> exists because a stored ownership count of nought
    /// reaches a caller identically from four situations - nobody asked about a target, the audit
    /// holds no ownership input, the target has no stored row, and a target genuinely assessed with
    /// nothing to report - and only the last is a fact about the directory. It is read true from a
    /// measured count and false from any count carrying a limit.
    /// <c>Tier0RelevanceRelation.IsComplete</c> exists because <c>Tier0Support</c> is handed out by
    /// this type as well as by <c>Tier0Classification</c>, and gate 4 clears a leaf only when every
    /// type that hands it out vouches for it. It is named on <see cref="BeyondTheDriver"/> rather
    /// than settled here, for the reason given there.
    /// 57 from 2026-09-13 with <c>RunResourceReading.IsComplete</c>, which says whether the peak
    /// memory and peak disk figures a run reports were watched for the whole run. Sampling can stop
    /// part way - the run's own directory becomes unreadable, a share drops - and the figures then
    /// hold the largest values seen before the watching stopped, which are floors rather than peaks.
    /// A floor presented as a peak is the reason this voucher exists: the whole purpose of the
    /// figures is to size the concurrency ceiling in <c>0041</c> from a real forest, and an
    /// understated peak would say a machine can take more parallelism than it can.
    /// <b>It is a stored value rather than a test for a null reason</b>, and that is this gate's
    /// doing: the first draft derived it from whether a reason string was present, which made an
    /// empty reason a third state meaning neither thing, and left the member reachable as false
    /// only. Read true from a watch that ran to the end and false from one that stopped.
    /// 68 adds <c>ListingCoverage.IsComplete</c> for saved LAPS readback: capture completeness
    /// belongs to the requested scope, not to the existence of saved inventory. Its public
    /// constructor accepts both values; direct <c>BundleReader.ReadListingCoverage</c> tests also
    /// read true for Base and false for a Subtree containing an excluded child domain.
    /// 69 adds <c>ClassifiedPermissionEntry.RightsAreComplete</c>: the saved wording voucher,
    /// not a statement of effective access. Storage checks it against the saved named-bit flags;
    /// the screen retains it in its wording. Direct saved-product tests read true for a named mask
    /// and false for a mask containing an unnamed bit, without replaying the wording on readback.
    /// 70 adds <c>RequesterResourceContext.IsComplete</c>: the resource-domain identity must occur
    /// in the bound forest declaration. Coordinated constructor inputs exercise a matching domain
    /// and an absent domain; neither result claims a complete authentication token.
    /// 71 adds <c>DelegationCoverage.IsComplete</c>: declared capture scope, excluded classes and
    /// unreadable/unattempted/incomplete permissions or descriptor errors remain independent of
    /// result paging. A fully read, gap-free capture is true; each recorded gap can make it false.
    /// 72 adds <c>CircularMembershipEvidence.IsComplete</c>: the recorded cycle inventory may
    /// be complete or partial independently of its positive witnesses; the constructor drives both.
    /// 73 adds <c>CircularMembershipLink.IsComplete</c>: a recorded relationship requires at
    /// least one original value; empty and nonempty witness collections drive both outcomes.
    /// 74 adds <c>CapturedMemberReferences.IsComplete</c>: only the displayed references were
    /// resolved, not a membership expansion; explicit resolved/unresolved rows drive both values.
    /// 75 adds <c>BroadGroupMembershipEvidence.IsComplete</c>: a supported positive
    /// membership can coexist with capture or scope gaps; complete inputs with no limits and
    /// incomplete inputs or a nonempty limitation collection drive opposite values.
    /// 76 and 77 add <c>ServiceAccountFindingEvidence.IsComplete</c> and
    /// <c>ServiceAdministrativeMembership.IsComplete</c>: unread account values and separately
    /// recorded membership/capture/processing gaps make established positives incomplete.
    /// 78 adds <c>AttributeWritePermissionEvidence.IsComplete</c>: positive permission proof
    /// remains incomplete when other permission, identity or account-state inputs have gaps.
    /// 79 adds <c>GroupMembershipReviewEvidence.IsComplete</c>: source-list review is qualified
    /// separately by captured-input gaps and the saved structural total's limitations.
    /// 80 adds <c>DelegationConfigurationEvidence.IsComplete</c>: captured configuration and
    /// shared resource-scope qualifications remain distinct from concrete requester authorization.
    /// 81 adds <c>ReplicationPermissionEvidence.IsComplete</c>: an established domain-root
    /// permission keeps other captured-input and expectedness gaps rather than claiming full coverage.
    /// </para>
    /// </summary>
    [Fact]
    public void TheDriverIsPointedAtTheProductsBooleanVouchers()
    {
        var found = BooleanVouchers().ToList();

        // Every term is a reason, not a total. Retain the pre-aggregation inventory, the per-right
        // proof voucher, the Tier-0 discovery pair, and the ownership-count and relevance-relation
        // pair. The failure names what it found because the count on its own says only that
        // something moved, and a failure that cannot say what moved makes raising the number the
        // cheapest way out - which is how a self-test stops being one. The expected total is held in
        // one place so the condition and the message cannot disagree, which they did on the first
        // draft of this check.
        var accountedFor = 58 + 1 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 2 + 1 + 1 + 2 + 1 + 1 + 1 + 1;

        Assert.True(
            found.Count == accountedFor,
            $"Gate 4b's voucher inventory has moved: expected {accountedFor}, found {found.Count}. "
            + "Every entry below must be accounted for by a term in the sum above and by a numbered "
            + "entry in this test's summary saying what the voucher is for and how it is read both "
            + "ways. Raising the number alone puts back the blindness the count exists to detect:"
            + Environment.NewLine
            + string.Join(
                Environment.NewLine,
                found.Select(v => $"  {v.Type.Name}.{v.Name}").OrderBy(t => t, StringComparer.Ordinal)));
        foreach (var name in new[] { "CapturedMembershipInput", "MemberAttribution", "MemberAttributionDetail", "MemberPermissionPage" })
            Assert.Contains(found, v => v.Type.Name == name && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "FullControlRight" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "PrincipalClassification" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ControlEdge" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ControlObjectEvaluation" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ControlEdgePage" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "MembershipRouteSummary" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "RuleVerdict" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ForestInventory"
                                    && v.Name == "AllDeclaredDomainsAreComplete");
        Assert.Contains(found, v => v.Type.Name == "GpoInventory"
                                    && v.Name == "DeclaredPoliciesAreComplete");
        Assert.Contains(found, v => v.Type.Name == "Tier0Coverage" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "Tier0DiscoveryCoverage" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "OwnershipAuditCount" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "Tier0RelevanceRelation" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ListingCoverage" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ClassifiedPermissionEntry" && v.Name == "RightsAreComplete");
        Assert.Contains(found, v => v.Type.Name == "RequesterResourceContext" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "CircularMembershipEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "BroadGroupMembershipEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "GroupMembershipReviewEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "DelegationConfigurationEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ReplicationPermissionEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ServiceAccountFindingEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "ServiceAdministrativeMembership" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "AttributeWritePermissionEvidence" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "CircularMembershipLink" && v.Name == "IsComplete");
        Assert.Contains(found, v => v.Type.Name == "CapturedMemberReferences" && v.Name == "IsComplete");
    }

    /// <summary>
    /// Gate 4 and gate 4b vouch on the same eleven shapes.
    ///
    /// <para>
    /// The tables are held separately - see <see cref="VouchShapes"/> for why - so something has to
    /// notice if they drift. A shape added to gate 4 alone would be a name that vouches without
    /// ever having to mean anything, which is the whole defect this gate was built for.
    /// </para>
    /// </summary>
    [Fact]
    public void TheTwoGatesAgreeOnWhatVouchingLooksLike()
    {
        var theirs = typeof(UnvouchedResultGateTests)
            .GetField("VouchShapes", BindingFlags.NonPublic | BindingFlags.Static)!
            .GetValue(null) as string[];

        Assert.Equal(VouchShapes.OrderBy(s => s, StringComparer.Ordinal),
                     theirs!.OrderBy(s => s, StringComparer.Ordinal));
    }

    // ---------------------------------------------------------------------------------------
    // The driver.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Every boolean member on a production type whose name gate 4 would accept as vouching.
    /// </summary>
    private static IEnumerable<(Type Type, MemberInfo Member, string Name, Func<object, object?> Read)>
        BooleanVouchers() =>
        RebuildAssemblies.All
            .SelectMany(a => a.GetTypes())
            .Where(t => t.IsPublic || t.IsNestedPublic)
            .Where(t => !t.IsEnum)
            .Where(t => t.GetCustomAttribute<CompilerGeneratedAttribute>() is null)
            .SelectMany(t => t
                .GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
                .Where(m => TypeOfMember(m) == typeof(bool))
                .Where(m => VouchShapes.Any(s => Matches(s, m.Name)))
                .Select(m => (Type: t, Member: m, m.Name, Read: ReaderFor(m))));

    private static Type? TypeOfMember(MemberInfo member) => member switch
    {
        PropertyInfo property when property.GetMethod is not null
                                   && property.GetIndexParameters().Length == 0
            => property.PropertyType,
        FieldInfo field => field.FieldType,
        _ => null,
    };

    private static Func<object, object?> ReaderFor(MemberInfo member) => member switch
    {
        PropertyInfo property => instance => property.GetValue(instance),
        FieldInfo field => instance => field.GetValue(instance),
        _ => _ => null,
    };

    /// <summary>
    /// The distinct values of a member across every instance the type's own public surface yields.
    ///
    /// <para>
    /// <b>Construction first, mutation only if it was not enough.</b> Most vouchers sit on records
    /// and are settled by the constructor sweep alone. <c>GpoInventory</c> is not: it is built
    /// empty and <c>DeclaredPoliciesAreComplete</c> only goes false once <c>Observe</c> has been
    /// handed a policy the directory would not place. Driving mutators unconditionally would mean
    /// calling arbitrary methods on every type in the product for no benefit, so it is the second
    /// pass and runs only where the first pass left the answer in doubt.
    /// </para>
    /// </summary>
    private static IReadOnlySet<bool> WitnessedValuesOf(Type type, Func<object, object?> read)
    {
        var seen = new HashSet<bool>();
        var instances = ConstructEveryWay(type).ToList();

        foreach (var instance in instances)
        {
            if (TryRead(instance, read) is { } value)
            {
                seen.Add(value);
            }
        }

        if (seen.Count >= 2)
        {
            return seen;
        }

        foreach (var instance in instances)
        {
            DriveMutators(type, instance);

            if (TryRead(instance, read) is { } value)
            {
                seen.Add(value);
            }
        }

        return seen;
    }

    private static bool? TryRead(object instance, Func<object, object?> read)
    {
        try
        {
            return read(instance) as bool?;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            // A getter that throws on these inputs has witnessed nothing, which is neither a pass
            // nor a failure. It is silence, and the driver reports silence as an unreachable
            // voucher rather than as a value.
            return null;
        }
    }

    /// <summary>
    /// Every instance obtainable by calling the type's own public constructors and its public
    /// static methods that return it.
    /// </summary>
    private static IEnumerable<object> ConstructEveryWay(Type type)
    {
        if (type == typeof(SecureAD.Evidence.CapturedMemberReferences))
        {
            yield return new SecureAD.Evidence.CapturedMemberReferences(
                [new("CN=Known,DC=example", Guid.NewGuid(), "CN=Known,DC=example", "Known", "group", "example")]);
            yield return new SecureAD.Evidence.CapturedMemberReferences(
                [new("CN=Missing,DC=example", null, null, null, null, null)]);
        }
        if (type == typeof(SecureAD.Judgement.RequesterResourceContext))
        {
            var domain = new SecureAD.Derivation.Tier0Target(Guid.NewGuid(), "DC=contoso,DC=com", "DC=contoso,DC=com",
                "contoso.com", "S-1-5-21-1-2-3", null);
            yield return new SecureAD.Judgement.RequesterResourceContext(domain, ["contoso.com"], new string('a', 64));
            yield return new SecureAD.Judgement.RequesterResourceContext(domain, [], new string('a', 64));
        }
        if (type == typeof(SecureAD.Evidence.Findings.ServiceAccountFindingEvidence))
        {
            var account = new SecureAD.Evidence.Findings.ServiceAccountAssociation(Guid.NewGuid(), "CN=Service,DC=contoso,DC=com", "contoso.com",
                DateTimeOffset.UnixEpoch, SecureAD.Evidence.EvidenceCompleteness.Complete, SecureAD.Evidence.Findings.ServiceAccountKind.SpnBearingUser,
                [new(0, "top", null), new(1, "user", null)], [new(0, "HTTP/service.contoso.com", null)], [new(0, "66048", null)], 66048, []);
            yield return new SecureAD.Evidence.Findings.ServiceAccountFindingEvidence(account, null);
            yield return new SecureAD.Evidence.Findings.ServiceAccountFindingEvidence(account with { MissingAttributes = ["userAccountControl"] }, null);
        }
        if (type == typeof(SecureAD.Evidence.Findings.GroupMembershipReviewEvidence))
        {
            var evidence = Assert.IsType<SecureAD.Evidence.Findings.GroupMembershipReviewEvidence>(
                Assert.Single(SecureAD.Next.Tests.Judgement.MembershipReviewRuleTests.ReadPublishedFindings(),
                    finding => finding.RuleId == "SEC-050").Evidence);
            yield return evidence;
            yield return evidence with { InputsComplete = false };
            yield return evidence with { KnownTotal = evidence.KnownTotal! with { Limitations = ["SourceLimited"] } };
        }
        if (type == typeof(SecureAD.Evidence.Findings.DelegationConfigurationEvidence))
        {
            var evidence = Assert.IsType<SecureAD.Evidence.Findings.DelegationConfigurationEvidence>(
                Assert.Single(SecureAD.Next.Tests.Judgement.DelegationConfigurationRuleTests.ReadPublishedFindings(),
                    finding => finding.RuleId == "SEC-012").Evidence);
            yield return evidence with { Scope = evidence.Scope with { Limitations = [] }, Limitations = [] };
            yield return evidence with { InputsComplete = false };
            yield return evidence with { Limitations = ["ServiceResourceUnresolved"] };
        }
        // The generic linear vectors cannot coordinate the nested expansion's stop/limits with
        // the outer availability flag. Exercise the real public getters; do not exempt them.
        if (type == typeof(SecureAD.Judgement.MemberAttributionDetail))
        {
            var expansion = new SecureAD.Judgement.MemberAttribution("S-1-5-21-1-2-3-2000", null, null,
                Guid.Empty, Guid.Empty, new(10, 10, 10, TimeSpan.FromSeconds(1)), SecureAD.Judgement.MemberAttributionStop.None,
                0, 0, 0, TimeSpan.Zero, null, [], [], [], []);
            yield return new SecureAD.Judgement.MemberAttributionDetail(true, expansion, []);
            yield return new SecureAD.Judgement.MemberAttributionDetail(false, expansion, []);
            yield return new SecureAD.Judgement.MemberAttributionDetail(true, expansion with { Stop = SecureAD.Judgement.MemberAttributionStop.NodeBudgetExceeded }, []);
        }
        foreach (var path in CreationPathsOf(type))
        {
            foreach (var arguments in ArgumentVectors(path.Parameters))
            {
                object? built;

                try
                {
                    built = path.Invoke(arguments);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    // Guard clauses reject most of what the synthesizer offers, and that is the
                    // point of offering a spread rather than one vector.
                    continue;
                }

                if (built is not null)
                {
                    yield return built;
                }
            }
        }
    }

    /// <summary>
    /// Every public way of obtaining an instance of a type: its constructors, and its static
    /// methods that hand one back.
    ///
    /// <para>
    /// <b>Factories are not an afterthought here.</b> The first run of this gate could not build
    /// <c>RunScope</c> or <c>RunCoverage</c> at all, because both are built out of
    /// <c>DomainCoverage</c>, which has no public constructor - it is reached only through
    /// <c>Read</c>, <c>PartiallyRead</c>, <c>NotRead</c> and <c>Excluded</c>. Any driver that
    /// looks for constructors alone is blind to a type whose author hid the constructor on
    /// purpose, which in this product is most of the interesting ones.
    /// </para>
    /// </summary>
    private static IEnumerable<(ParameterInfo[] Parameters, Func<object?[], object?> Invoke)>
        CreationPathsOf(Type type)
    {
        if (type.IsAbstract || type.IsInterface)
        {
            return [];
        }

        return type.GetConstructors()
            .Select(c => (Parameters: c.GetParameters(),
                          Invoke: (Func<object?[], object?>)(args => c.Invoke(args))))
            .Concat(type
                .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Where(m => m.ReturnType == type && !m.IsGenericMethodDefinition)
                .Select(m => (Parameters: m.GetParameters(),
                              Invoke: (Func<object?[], object?>)(args => m.Invoke(null, args)))))
            .ToList();
    }

    /// <summary>
    /// The three values the synthesizer offers for any parameter.
    ///
    /// <para>
    /// <b><see cref="Low"/> is the absent end</b> - an empty string, an empty list, a null, a zero.
    /// It is what a completeness flag reads when nothing was found, and it is also what most guard
    /// clauses reject, which is fine at the top of a call and fatal inside a list.
    /// </para>
    /// <para>
    /// <b><see cref="High"/>, <see cref="HighAlternate"/> and <see cref="HighContrary"/> are all
    /// valid, and differ along two separate axes.</b> The pair of the first two differ only in
    /// their scalar values - "high" against "other" - and are built by the same factory, so a list
    /// of them holds two distinguishable things of the same kind. <see cref="HighContrary"/> takes
    /// the type's <i>last</i> factory instead, so a list holding one of each holds two things of
    /// different kinds.
    /// </para>
    /// <para>
    /// <b>Both axes were forced by the product.</b> <c>CoverageId.ForDomains</c> rejects a list
    /// containing an empty string, so a spread cannot vary by becoming invalid. <c>RunScope.Of</c>
    /// then rejects a list covering the same domain twice - "a domain with two outcomes has no
    /// single answer" - so a spread cannot vary by repetition either. And it rejects an empty list
    /// outright, because an unread coverage table is not a forest with no domains, which means the
    /// driver cannot reach "complete" by passing nothing. What is left is what these variants do:
    /// two domains with different names and the same outcome reads as complete, and two with
    /// different outcomes reads as incomplete.
    /// </para>
    /// </summary>
    private enum Variant
    {
        Low,
        High,
        HighAlternate,
        HighContrary,
    }

    /// <summary>
    /// Argument vectors, combined linearly rather than as a cartesian product.
    ///
    /// <para>
    /// <b>Why linear.</b> <c>PreflightDomainRecord</c> takes thirteen parameters. Two candidates
    /// each is 8,192 constructions for one type, and the product has twenty-four vouchers. This
    /// takes an all-low vector, an all-high vector, and every single-parameter flip from each -
    /// <c>2 + 2n</c> rather than <c>2^n</c>, so that same type costs twenty-eight.
    /// </para>
    /// <para>
    /// <b>Why both baselines and not just the flips.</b> A member computed as <c>a &amp;&amp; b</c>
    /// is false at the all-low vector and false at either single flip from it. Without the all-high
    /// vector it would never be witnessed true, and the gate would report a false failure against
    /// a member that works. That is the case the two baselines exist for.
    /// </para>
    /// </summary>
    private static IEnumerable<object?[]> ArgumentVectors(ParameterInfo[] parameters)
    {
        var low = parameters.Select(p => Synthesize(p.ParameterType, Variant.Low, depth: 0)).ToArray();
        var high = parameters.Select(p => Synthesize(p.ParameterType, Variant.High, depth: 0)).ToArray();
        var contrary = parameters
            .Select(p => Synthesize(p.ParameterType, Variant.HighContrary, depth: 0)).ToArray();

        yield return (object?[])low.Clone();
        yield return (object?[])high.Clone();
        yield return (object?[])contrary.Clone();

        for (var i = 0; i < parameters.Length; i++)
        {
            var fromLow = (object?[])low.Clone();
            fromLow[i] = high[i];
            yield return fromLow;

            var fromHigh = (object?[])high.Clone();
            fromHigh[i] = low[i];
            yield return fromHigh;

            var contraryOne = (object?[])high.Clone();
            contraryOne[i] = contrary[i];
            yield return contraryOne;
        }
    }

    /// <summary>
    /// A value of the requested type in the requested variant.
    ///
    /// <para>
    /// Low and high are whatever most plausibly sit on opposite sides of a completeness test: an
    /// empty list against a populated one, a null against a value, zero against one. The pair
    /// matters more than the particular values - a voucher reads some quantity and compares it, so
    /// what the driver needs is two inputs that differ in the direction such a comparison looks.
    /// </para>
    /// </summary>
    private static object? Synthesize(Type type, Variant variant, int depth)
    {
        var high = variant != Variant.Low;
        var underlying = Nullable.GetUnderlyingType(type);

        if (underlying is not null)
        {
            return high ? Synthesize(underlying, variant, depth) : null;
        }

        if (type == typeof(string))
        {
            return variant switch
            {
                Variant.Low => string.Empty,
                Variant.High => "high",
                _ => "other",
            };
        }
        if (type == typeof(bool))
        {
            return high;
        }

        if (type.IsEnum)
        {
            var values = Enum.GetValues(type);

            if (values.Length == 0)
            {
                return null;
            }

            return values.GetValue(variant switch
            {
                Variant.Low => 0,
                Variant.High => values.Length - 1,
                _ => values.Length / 2,
            });
        }

        if (type == typeof(Guid))
        {
            return variant switch
            {
                Variant.Low => Guid.Empty,
                Variant.High => Guid.Parse("11111111-1111-1111-1111-111111111111"),
                _ => Guid.Parse("22222222-2222-2222-2222-222222222222"),
            };
        }

        if (type == typeof(DateTimeOffset))
        {
            return DateTimeOffset.UnixEpoch.AddDays(variant is Variant.Low ? 0 : 1);
        }

        if (type == typeof(DateTime))
        {
            return DateTime.UnixEpoch.AddDays(variant is Variant.Low ? 0 : 1);
        }

        if (type.IsPrimitive)
        {
            return Convert.ChangeType(
                variant switch { Variant.Low => 0, Variant.High => 1, _ => 2 },
                type,
                System.Globalization.CultureInfo.InvariantCulture);
        }

        if (KeyedElementsOf(type) is var (key, value))
        {
            // A keyed collection, which the product asks for where a count is held per state.
            // Built rather than left null: a type constructed with a null argument is not the
            // product's type, and a voucher read off one is a value the product cannot produce.
            var dictionary = (IDictionary)Activator.CreateInstance(
                typeof(Dictionary<,>).MakeGenericType(key, value))!;

            if (variant is not Variant.Low)
            {
                var synthesizedKey = Synthesize(key, Variant.High, depth + 1);
                var synthesizedValue = Synthesize(value, Variant.High, depth + 1);

                if (synthesizedKey is not null)
                    dictionary[synthesizedKey] = synthesizedValue;
            }

            return dictionary;
        }

        if (SequenceElementOf(type) is { } element)
        {
            // Low is empty; the populated forms are a spread rather than a single item. A
            // completeness flag reads across a list and asks whether any member of it failed, so a
            // list of one thing built the same way every time can only ever produce one answer.
            // High holds two of the same kind with different identities, which reads as complete;
            // HighContrary holds one of each kind, which does not.
            var spread = variant switch
            {
                Variant.Low => [],
                Variant.HighContrary => new[]
                {
                    Synthesize(element, Variant.High, depth + 1),
                    Synthesize(element, Variant.HighContrary, depth + 1),
                },
                _ => new[]
                {
                    Synthesize(element, Variant.High, depth + 1),
                    Synthesize(element, Variant.HighAlternate, depth + 1),
                },
            };

            var present = spread.Where(v => v is not null).ToArray();
            var list = Array.CreateInstance(element, present.Length);

            for (var i = 0; i < present.Length; i++)
            {
                list.SetValue(present[i], i);
            }

            return list;
        }

        // The cap is four because this product nests that far and no further: a RunCoverage holds
        // a SysvolCoverage, which holds GpoCoverage values, which hold their own strings. A cap of
        // two was the first attempt and it silently produced empty lists, which read to the gate
        // as a complete run - the exact false reassurance it exists to catch, committed by the
        // gate itself. TheDriverReachesThroughTheProductsNesting holds this line.
        if (depth >= 4)
        {
            return type.IsValueType ? Activator.CreateInstance(type) : null;
        }

        // A composite. No variant uses low arguments, because a guard clause rejects an empty
        // string and there is nothing to be learnt from a value that was never built. The variety
        // comes from the scalars, and for HighContrary also from taking the type's last creation
        // path rather than its first - which for DomainCoverage is Excluded rather than Read.
        var paths = CreationPathsOf(type).ToList();
        var order = variant is Variant.HighContrary ? Enumerable.Reverse(paths) : paths;
        var arguments = variant is Variant.Low ? Variant.High : variant;

        foreach (var path in order)
        {
            try
            {
                var built = path.Invoke(path.Parameters
                    .Select(p => Synthesize(p.ParameterType, arguments, depth + 1))
                    .ToArray());

                if (built is not null)
                {
                    return built;
                }
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                continue;
            }
        }

        return type.IsValueType ? Activator.CreateInstance(type) : null;
    }

    /// <summary>The element type of a sequence the driver can build, or null if it is not one.</summary>
    private static Type? SequenceElementOf(Type type)
    {
        if (type == typeof(string) || !typeof(IEnumerable).IsAssignableFrom(type))
        {
            return null;
        }

        if (type.IsArray)
        {
            return type.GetElementType();
        }

        // An array satisfies IReadOnlyList&lt;T&gt;, IReadOnlyCollection&lt;T&gt;, IEnumerable&lt;T&gt;
        // and IList&lt;T&gt;, which is every ungrouped sequence shape the product's constructors ask
        // for. A keyed collection is not one of them and is built by KeyedElementsOf instead.
        //
        // THIS WAS SingleOrDefault() AND IT THREW. Asked for the element type of a read-only
        // dictionary it found two generic arguments and raised "Sequence contains more than one
        // element", so the gate failed with a stack trace rather than a verdict - and a gate that
        // crashes on a shape it does not know cannot say "I could not build this". Found 2026-09-03
        // when LapsPage became the first type to hold a count per state.
        if (type.IsInterface && type.IsGenericType)
        {
            var arguments = type.GetGenericArguments();

            return arguments.Length == 1 ? arguments[0] : null;
        }

        return null;
    }

    /// <summary>
    /// The key and value types of a keyed collection the driver can build, or null if it is not one.
    /// </summary>
    private static (Type Key, Type Value)? KeyedElementsOf(Type type)
    {
        if (!type.IsInterface || !type.IsGenericType)
        {
            return null;
        }

        var definition = type.GetGenericTypeDefinition();

        if (definition != typeof(IReadOnlyDictionary<,>) && definition != typeof(IDictionary<,>))
        {
            return null;
        }

        var arguments = type.GetGenericArguments();

        return (arguments[0], arguments[1]);
    }

    /// <summary>
    /// Calls the type's own public instance methods, so an accumulator can accumulate something.
    ///
    /// <para>
    /// This is deliberately narrow. Only methods returning <c>void</c> are called, which is what a
    /// method that changes the object in place looks like and excludes every query, and only on
    /// instances the driver built itself from synthesized values. It runs solely for members the
    /// constructor sweep left with one value or none, so nothing is invoked on a type that had
    /// already answered.
    /// </para>
    /// </summary>
    private static void DriveMutators(Type type, object instance)
    {
        var mutators = type
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.ReturnType == typeof(void))
            .Where(m => !m.IsGenericMethodDefinition)
            .Where(m => m.GetParameters().All(p => !p.ParameterType.IsByRef));

        foreach (var mutator in mutators)
        {
            foreach (var arguments in ArgumentVectors(mutator.GetParameters()))
            {
                try
                {
                    mutator.Invoke(instance, arguments);
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    continue;
                }
            }
        }
    }

    /// <summary>
    /// Whether a getter's entire body is "push a constant, return it".
    ///
    /// <para>
    /// The two byte sequences are <c>ldc.i4.0; ret</c> and <c>ldc.i4.1; ret</c>. An auto-property's
    /// getter is <c>ldarg.0; ldfld; ret</c> and a computed one is longer still, so nothing but a
    /// literal is two bytes long.
    /// </para>
    /// </summary>
    private static bool GetterIsALiteral(PropertyInfo property)
    {
        var body = property.GetMethod?.GetMethodBody()?.GetILAsByteArray();

        return body is [0x16 or 0x17, 0x2A];
    }

    /// <summary>
    /// Turns a shape into an anchored pattern, on the same rule as gate 4: <c>*</c> is the only
    /// wildcard and stands for the rest of a name, never a substring.
    /// </summary>
    private static bool Matches(string shape, string memberName) =>
        Regex.IsMatch(
            memberName,
            "^" + string.Join("[A-Za-z0-9_]*", shape.Split('*').Select(Regex.Escape)) + "$",
            RegexOptions.CultureInvariant);

    private static string ReadableName(Type type)
    {
        var name = type.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }

    // ---------------------------------------------------------------------------------------
    // Fixtures for the scanner self-tests. These live in the test assembly and are invisible to
    // BooleanVouchers, which reads only the three production assemblies.
    // ---------------------------------------------------------------------------------------

    /// <summary>A voucher that is a constant and does not trouble to hide it.</summary>
    public sealed record ConstantVoucher(string Name)
    {
        public bool IsComplete => true;
    }

    /// <summary>A voucher that reads its input, as one should.</summary>
    public sealed record ComputedVoucher(IReadOnlyList<string> Missing)
    {
        public bool IsComplete => Missing.Count == 0;
    }

    /// <summary>
    /// P-62, reproduced: a comparison whose two sides are the same set, so it is a constant that
    /// looks like a computation. This is the fixture that decides whether the gate is worth having.
    /// </summary>
    public sealed record P62ShapedVoucher(string Name)
    {
        private static readonly string[] Catalogue = ["a", "b", "c"];

        public IReadOnlyList<string> Attributes { get; } = Catalogue;

        public bool AttributesAreComplete => Attributes.Count == Catalogue.Length;
    }

    /// <summary>An accumulator, built empty and made incomplete by being told something.</summary>
    public sealed class MutatedVoucher
    {
        private readonly List<string> _unlocatable = [];

        public bool IsComplete => _unlocatable.Count == 0;

        public void Observe(string name)
        {
            if (!string.IsNullOrEmpty(name))
            {
                _unlocatable.Add(name);
            }
        }
    }

    /// <summary>A voucher on an interface, which has no instances and witnesses nothing.</summary>
    public interface IUnbuildableVoucher
    {
        bool IsComplete { get; }
    }
}

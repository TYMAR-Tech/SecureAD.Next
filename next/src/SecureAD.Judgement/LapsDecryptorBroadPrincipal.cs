using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-093: a Group Policy Object whose authorized Windows LAPS password decryptor is, or contains
/// through nesting, a principal broad in every organisation.
/// </summary>
/// <remarks>
/// <para>
/// <b>Windows LAPS encrypts against exactly one principal.</b> Microsoft states that CNG DPAPI
/// supports several but that Windows LAPS supports "encrypting passwords against only a single
/// Windows Server Active Directory security principal", and that where more than one decryptor is
/// needed the answer is to "create a wrapper group that has all the relevant security principals as
/// members". So a group is the supported configuration, and the finding is about what ended up
/// inside it.
/// </para>
/// <para>
/// <b>Decryption is not governed by the access control list.</b> Microsoft separates the two
/// outright: being granted permission to query a password "doesn't automatically imply that the
/// user has permission to decrypt an encrypted password". SEC-090 examines the first gate and this
/// rule examines the second, and an estate can be tight on one and open on the other.
/// </para>
/// <para>
/// <b>The subject is the policy and never a machine.</b> Microsoft states the authorized decryptor
/// "can't be changed after a password is encrypted", so a stored password was encrypted against
/// whatever the policy named when it was written - a value the directory does not record. Naming
/// machines would assert something about the past that no evidence establishes. The owner settled
/// this on 2026-09-03, reasoning that the product cannot know whether the current decryptor applied
/// to a given machine at any point in time.
/// </para>
/// <para>
/// <b>An unconfigured setting is the safe state.</b> Microsoft: "If this setting isn't specified,
/// only members of the Domain Admins group in the device's domain can decrypt the password." A
/// policy that never mentions the value is therefore silent here, not a finding.
/// </para>
/// </remarks>
public sealed class LapsDecryptorBroadPrincipal : IRule
{
    private const string RuleId = "SEC-093";

    private const int RuleVersion = 1;

    /// <summary>
    /// The class this rule judges, tested as the object's <i>most derived</i> class.
    /// </summary>
    private const string JudgedClass = "groupPolicyContainer";

    /// <summary>
    /// The registry key a Windows LAPS Group Policy writes its settings under, matched as a suffix.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Microsoft assigns each LAPS policy mechanism its own root, and states that settings are
    /// "never shared or inherited across policy key roots".</b> The four roots are:
    /// </para>
    /// <list type="table">
    /// <item><term>LAPS CSP</term>
    ///   <description><c>HKLM\Software\Microsoft\Policies\LAPS</c></description></item>
    /// <item><term>LAPS Group Policy</term>
    ///   <description><c>HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS</c></description></item>
    /// <item><term>LAPS Local Configuration</term>
    ///   <description><c>HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config</c></description></item>
    /// <item><term>Legacy Microsoft LAPS</term>
    ///   <description><c>HKLM\Software\Policies\Microsoft Services\AdmPwd</c></description></item>
    /// </list>
    /// <para>
    /// <b>This rule reads the Group Policy root and only that one.</b> It judges a
    /// <c>groupPolicyContainer</c> by parsing the <c>Registry.pol</c> in that policy's own SYSVOL
    /// folder, and that file is what Group Policy writes. The CSP root is delivered by device
    /// management rather than by a policy object, local configuration is a machine's own registry,
    /// and the legacy root is a different product whose settings SEC-091 covers.
    /// </para>
    /// <para>
    /// <b>This constant was wrong until 2026-09-04, and no test caught it.</b> It read
    /// <c>Policies\Microsoft\Windows\LAPS</c> - a path that appears in none of Microsoft's four
    /// roots and that no policy editor produces. The rule matched nothing, read that as "this
    /// policy configures no decryptor", and reported silence: a policy handing decryption to
    /// Domain Users would have been passed as clean. Twenty-five tests agreed with it because
    /// every fixture was built from the same invented constant, and seven mutations all fired
    /// against that closed loop. The first run against a real forest found it immediately, which
    /// is the whole reason a rule is not done until it has seen one.
    /// </para>
    /// <para>
    /// <b>Matched as a suffix rather than in full</b> because <c>Registry.pol</c> stores the key
    /// without the <c>HKLM\</c> prefix, and a reader should not depend on how the hive is spelled.
    /// The tail is specific enough that no unrelated product collides with it.
    /// </para>
    /// </remarks>
    private const string LapsKeySuffix = @"Microsoft\Windows\CurrentVersion\Policies\LAPS";

    /// <summary>
    /// The value naming who may decrypt, which is the whole of what this rule reads.
    /// </summary>
    private const string DecryptorValueName = "ADPasswordEncryptionPrincipal";

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        RuleId,
        "A broad principal can decrypt LAPS passwords",
        Severity.Critical,
        Version: RuleVersion,
        SubjectClasses: [JudgedClass],
        RequiredAttributes:
        [
            "objectClass",
            "displayName",
        ],
        RequiredDerivedFacts: [nameof(DerivedFactKind.PrincipalExpansion)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-093 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (!IsGroupPolicyContainer(subject))
            return RuleVerdict.Judged([]);

        if (subject.ObjectGuid is not { } objectGuid)
        {
            // Without the policy's own identifier there is no way to ask for its settings, and
            // reporting it as configuring no decryptor would be a silence about something unread.
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        if (context.GpoMachineRegistrySettings is not { } settingsOf
            || context.MembersOfPrincipal is not { } expand)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        var settings = settingsOf(objectGuid);

        if (DecryptorValueOf(settings.Settings) is not { } configured)
        {
            // NOTHING FOUND IS TWO DIFFERENT ANSWERS. Where the policy's files were read, it sets
            // no decryptor, Microsoft's documented default of Domain Admins applies, and there is
            // nothing to report. Where they were not, saying the same thing would report a policy
            // as harmless because nobody looked at it - which docs/decisions/0002 forbids and
            // which gate 4 caught in the first version of this rule.
            return settings.IsComplete
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotResolve([new UnresolvedInput(
                    DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        var domain = DnHelper.DnToFqdn(subject.DistinguishedName);
        var policyName = AttributeReading.Text(subject, "displayName");
        var form = FormOf(configured);

        // A qualified name or user principal name is not a security identifier, and this product
        // does not resolve names to identifiers - the capture reads objects, not the name-mapping a
        // domain controller does. So only the identifier form can be expanded, and the other two are
        // reported as what they are rather than guessed at.
        if (form is not LapsDecryptorForm.SecurityIdentifier)
            return RuleVerdict.Judged([Unresolved(subject, objectGuid, policyName, configured, form)]);

        var expansion = MembersOfDecryptor(expand, configured, domain);

        var decryptorName = NameFor(configured, context.PrincipalNames);

        // THE DECRYPTOR ITSELF FIRST, AND BEFORE THE EXPANSION IS EVEN ASKED. Whether a security
        // identifier is broad is a property of the identifier: a relative identifier of 513 is
        // Domain Users in whatever domain issued it, and S-1-1-0 is Everyone everywhere. That needs
        // no membership walk, no derivation and no captured object, so it must not be gated on any
        // of them.
        //
        // THIS WAS THE ORDER UNTIL 2026-09-04 AND IT WAS WRONG. The broadness test sat below the
        // PrincipalNotFound gate, so a policy naming Domain Users outright - the plainest form of
        // this finding, and the one the rule exists for - was reported as "this capture could not
        // resolve the value" whenever the expansion failed to find the group. The lab did exactly
        // that: the identifier was Domain Users, the group was in the bundle, and the rule threw
        // away an answer it already held and reported Critical exposure as unknown.
        if (BroadPrincipalCatalogue.IsBroad(configured))
        {
            return RuleVerdict.Judged(
            [
                Build(
                    subject,
                    objectGuid,
                    policyName,
                    configured,
                    form,
                    decryptorName,
                    configured,
                    [configured],

                    // The walk is beside the point here and is reported as it stands rather than
                    // claimed complete: nothing nested below matters when the decryptor is itself
                    // broad, but saying the membership was fully read when it was not would be a
                    // different untruth.
                    expansion.IsComplete,
                    context.PrincipalNames),
            ]);
        }

        // Only now does not finding the principal matter. Below this line the question is what is
        // *inside* the decryptor, and that cannot be answered without the walk.
        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalNotFound)
            return RuleVerdict.Judged([Unresolved(subject, objectGuid, policyName, configured, form)]);

        // NO SUCH DECRYPTOR EXISTS, SO THE POLICY DELEGATES DECRYPTION TO NOBODY. The identifier is
        // domain-relative, its domain was read in full, and nothing in that domain carries it -
        // most often a group deleted while the policy naming it was left behind. There is nothing
        // inside it, and unlike PrincipalNotFound that is a fact rather than an absence of one, so
        // the policy is judged and reported clean instead of refused.
        //
        // BELOW THE BROADNESS TEST ABOVE, AND THAT PLACEMENT IS DELIBERATE. Whether the configured
        // identifier is itself broad is a property of its shape and owes nothing to the walk, so
        // gating it on this outcome would repeat the 2026-09-04 defect in a new form: a coverage
        // join that wrongly said "read in full" would silently retire the finding this rule exists
        // for. Nothing well-known can reach here in any case, because a well-known identifier
        // carries no domain and so can never be judged non-existent.
        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalDoesNotExist)
            return RuleVerdict.Judged([]);

        // The shortest route to each broad principal, for the reason SEC-090 keeps the shortest: it
        // is the link an operator would cut.
        var reached = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var member in expansion.BroadMembers)
        {
            if (!reached.TryGetValue(member.Sid, out var held)
                || member.PathFromRoot.Count < held.Count)
            {
                reached[member.Sid] = member.PathFromRoot;
            }
        }

        if (reached.Count == 0)
        {
            // Nothing broad inside. Silent where the walk finished, and refused where it did not,
            // because an incomplete walk finding nothing is not the same as there being nothing.
            return expansion.IsComplete
                ? RuleVerdict.Judged([])
                : RuleVerdict.CouldNotResolve([new UnresolvedInput(
                    DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        return RuleVerdict.Judged(
        [
            .. reached
                .OrderBy(r => r.Value.Count)
                .ThenBy(r => r.Key, StringComparer.OrdinalIgnoreCase)
                .Select(r => Build(
                    subject,
                    objectGuid,
                    policyName,
                    configured,
                    form,
                    decryptorName,
                    r.Key,
                    r.Value,
                    expansion.IsComplete,
                    context.PrincipalNames)),
        ]);
    }

    /// <summary>
    /// Expands the configured decryptor, asking under each scope its identifier could be keyed
    /// under.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A principal is keyed under a domain only when its identifier repeats between
    /// domains.</b> <c>SidInterner</c> scopes a SID to its domain when it is a BUILTIN one -
    /// <c>S-1-5-32-544</c> means a different group in every domain - and stores everything else
    /// with no scope at all, because a domain-relative identifier such as
    /// <c>S-1-5-21-…-513</c> is already unique across the forest. Asking only under the policy's
    /// domain therefore finds the built-in principals and misses every ordinary group.
    /// </para>
    /// <para>
    /// <b>The lab found this, and it is the second rule to make the same mistake.</b> Every
    /// decryptor naming an ordinary group answered <c>PrincipalNotFound</c>, so the nested case -
    /// the one this rule was written for, and the one Microsoft's own wrapper-group guidance
    /// produces - could never have fired against a real forest. SEC-090 hit exactly this and
    /// records it at <c>MembersOfTrustee</c>; SEC-093 was written afterwards and did not carry the
    /// lesson across.
    /// </para>
    /// <para>
    /// <b>Asking more than once can only turn "not found" into an answer, never the reverse.</b> A
    /// domain-relative identifier is unique across the forest, so asking under a domain it does not
    /// belong to simply answers not found. This cannot manufacture a finding. What survives every
    /// scope is a principal this bundle genuinely does not hold, and that stays unresolved.
    /// </para>
    /// <para>
    /// <b><c>PrincipalDoesNotExist</c> does not end the walk either.</b> It reports that nothing in
    /// a fully-read domain carries the identifier <i>under the scope just asked</i>, and an ordinary
    /// group is keyed under the empty scope rather than under its domain. Returning it from the
    /// first scope would therefore declare a decryptor non-existent without ever looking where such
    /// a decryptor is actually stored - the same mistake in a new form, and the one that would
    /// silently retire this rule. Absence is concluded only after every scope has been asked.
    /// </para>
    /// </remarks>
    private static PrincipalExpansion MembersOfDecryptor(
        Func<string, string, PrincipalExpansion> expand, string sid, string? policyDomain)
    {
        // Most specific first, then the unscoped key that ordinary principals are stored under.
        var scopes = new List<string>();

        if (!string.IsNullOrEmpty(policyDomain))
            scopes.Add(policyDomain);

        scopes.Add(string.Empty);

        PrincipalExpansion last = null!;

        foreach (var scope in scopes)
        {
            last = expand(sid, scope);

            if (last.Outcome is not (PrincipalExpansionOutcome.PrincipalNotFound
                or PrincipalExpansionOutcome.PrincipalDoesNotExist))
            {
                return last;
            }
        }

        return last;
    }


    /// <summary>
    /// Whether this object is a Group Policy Object, read as its most derived class.
    /// </summary>
    /// <remarks>
    /// <b><c>groupPolicyContainer</c> derives from <c>container</c></b>, so the chain is
    /// <c>top, container, groupPolicyContainer</c> and the last value is the one that decides.
    /// </remarks>
    private static bool IsGroupPolicyContainer(ObjectAttributes subject) =>
        string.Equals(ClassOf(subject), JudgedClass, StringComparison.OrdinalIgnoreCase);

    private static string ClassOf(ObjectAttributes subject) =>
        AttributeReading.LastText(subject, "objectClass") ?? string.Empty;

    /// <summary>
    /// The decryptor this policy configures, or null where it configures none.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The last one wins.</b> A policy can set the same value more than once and a machine
    /// applies the last, so the settings are read in file order and the final match is taken.
    /// </para>
    /// <para>
    /// <b>A value that is present but blank counts as unset.</b> Microsoft's default applies when
    /// the setting "isn't specified", and an empty string specifies nothing.
    /// </para>
    /// </remarks>
    private static string? DecryptorValueOf(IReadOnlyList<RegistryPolicyEntry> settings)
    {
        string? found = null;

        foreach (var entry in settings)
        {
            if (!entry.KeyPath.EndsWith(LapsKeySuffix, StringComparison.OrdinalIgnoreCase))
                continue;

            if (!string.Equals(
                    entry.ValueName, DecryptorValueName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (entry.AsString() is { } text && !string.IsNullOrWhiteSpace(text))
                found = text.Trim();
        }

        return found;
    }

    /// <summary>
    /// Which of the three forms Microsoft accepts this value was written in.
    /// </summary>
    /// <remarks>
    /// Microsoft gives the accepted forms as an identifier in string form, <c>DOMAIN\name</c>, or
    /// <c>name@domain</c>. Event 10034 exists for a fourth shape - a bare name with no domain - and
    /// says it "must be corrected", so anything not matching the three is treated as a qualified
    /// name and reported as unresolvable rather than expanded.
    ///
    /// <para>
    /// <b>The identifier is recognised by parsing it, not by looking at its shape.</b>
    /// <see cref="Sid.ToBytes"/> returns null for anything it cannot parse, which is a stronger
    /// test than a prefix check: <c>S-1-5-21-oops</c> starts like an identifier and is not one.
    /// </para>
    /// </remarks>
    private static LapsDecryptorForm FormOf(string value) =>
        Sid.ToBytes(value) is not null ? LapsDecryptorForm.SecurityIdentifier
        : value.Contains('@') ? LapsDecryptorForm.UserPrincipalName
        : LapsDecryptorForm.QualifiedName;

    /// <summary>
    /// The finding for a decryptor this bundle cannot place, which is a different problem from a
    /// broad one.
    /// </summary>
    /// <remarks>
    /// <b>Reported rather than dropped.</b> Microsoft records that when an invalid principal is
    /// named "a policy processing failure occurs and the managed account's password isn't backed
    /// up", which the lab confirmed on 2026-09-03 - events 10035 then 10017, and no stored
    /// password. So an unresolvable decryptor may mean no password is protected at all, and staying
    /// silent about it would leave an operator believing LAPS is working.
    /// </remarks>
    private static Finding Unresolved(
        ObjectAttributes subject,
        Guid objectGuid,
        string? policyName,
        string configured,
        LapsDecryptorForm form)
    {
        var evidence = new LapsDecryptorEvidence(
            policyName,
            configured,
            form,
            DecryptorSid: null,
            DecryptorName: null,
            BroadPrincipalSid: null,
            BroadPrincipalName: null,
            MembershipPath: [],
            ExpansionWasComplete: false);

        return new Finding(
            RuleId,
            RuleVersion,
            Severity.Critical,
            new FindingSubject(FindingSubjectKind.Policy, SubjectKeyFor(policyName, objectGuid)),
            objectGuid,
            subject.DistinguishedName,
            DnHelper.DnToFqdn(subject.DistinguishedName),
            JudgedClass,
            UnresolvedDetail(policyName, evidence),

            // The object's own coverage, unchanged. EvidenceCompleteness states what the
            // connection could have withheld and says nothing about whether this rule reached an
            // answer - that is carried on the evidence, in ExpansionWasComplete, and said in the
            // wording. Overwriting it here would claim something about the read that is not true.
            subject.Completeness,
            evidence);
    }

    /// <summary>Builds a finding for one broad principal that can decrypt.</summary>
    private static Finding Build(
        ObjectAttributes subject,
        Guid objectGuid,
        string? policyName,
        string configured,
        LapsDecryptorForm form,
        string? decryptorName,
        string broadSid,
        IReadOnlyList<string> path,
        bool complete,
        Func<string, string?>? names)
    {
        // Resolved once, here, rather than when the finding is shown, for the reason SEC-090 gives
        // and P-128 measured: display-time resolution is one lookup per path entry per row per page.
        var route = path
            .Select(sid => new PathStep(sid, NameFor(sid, names)))
            .ToArray();

        var evidence = new LapsDecryptorEvidence(
            policyName,
            configured,
            form,
            configured,
            decryptorName,
            broadSid,
            NameFor(broadSid, names),
            route,
            complete);

        return new Finding(
            RuleId,
            RuleVersion,
            Severity.Critical,

            // THE SUBJECT IS THE POLICY, which is what this rule can speak about. A finding's
            // identity is its rule, its subject and its object, so keying on the broad principal
            // the way SEC-090 does would be wrong here: two broad principals inside one decryptor
            // are two routes to the same misconfiguration, not two separate things to accept.
            new FindingSubject(FindingSubjectKind.Policy, SubjectKeyFor(policyName, objectGuid)),
            objectGuid,
            subject.DistinguishedName,
            DnHelper.DnToFqdn(subject.DistinguishedName),
            JudgedClass,
            Detail(policyName, evidence),
            subject.Completeness,
            evidence);
    }

    /// <summary>
    /// How a policy is named as the subject of a finding: what an administrator calls it, with the
    /// identifier that keeps the key unique when two policies share a name.
    /// </summary>
    private static string SubjectKeyFor(string? policyName, Guid objectGuid) =>
        policyName is null ? objectGuid.ToString("D") : $"{policyName} ({objectGuid:D})";

    /// <summary>
    /// What a principal is called: the catalogue's word for one broad everywhere, then what this
    /// bundle captured, and the identifier where neither answers.
    /// </summary>
    private static string? NameFor(string sid, Func<string, string?>? names) =>
        BroadPrincipalCatalogue.NameOf(sid) ?? names?.Invoke(sid);

    /// <summary>What the operator is told about a broad decryptor.</summary>
    /// <remarks>
    /// <b>It always says that rotation is part of the fix.</b> Correcting the setting protects
    /// passwords written from then on and nothing already stored, because the decryptor cannot be
    /// changed after encryption - so an operator who edits the policy and stops has not finished.
    /// </remarks>
    private static string Detail(string? policyName, LapsDecryptorEvidence evidence)
    {
        var policy = policyName ?? "This policy";

        var route = evidence.NestingDepth == 0
            ? "which is named by the policy directly"
            : $"reached through {evidence.NestingDepth} nested group(s): {evidence.Route}";

        var name = evidence.BroadPrincipalName ?? evidence.BroadPrincipalSid;

        var completeness = evidence.ExpansionWasComplete
            ? string.Empty
            : " The membership walk did not finish, so there may be more inside it than is shown.";

        return $"{policy} authorizes {name} to decrypt the Windows LAPS passwords it protects, "
            + $"{route}. The policy sets ADPasswordEncryptionPrincipal to '{evidence.ConfiguredValue}'. "
            + "Windows LAPS encrypts each password against this one principal, so every member can "
            + "decrypt the local administrator password of every machine the policy covers, "
            + "whatever the directory permissions say. Correcting the setting protects only "
            + "passwords written afterwards: the authorized decryptor cannot be changed after a "
            + "password is encrypted, so the stored passwords must also be rotated."
            + completeness;
    }

    /// <summary>What the operator is told about a decryptor this bundle cannot place.</summary>
    private static string UnresolvedDetail(string? policyName, LapsDecryptorEvidence evidence)
    {
        var policy = policyName ?? "This policy";

        var why = evidence.Form is LapsDecryptorForm.SecurityIdentifier
            ? "No object in this capture carries that identifier, so it may belong to a domain "
                + "this run did not read, or to an object since deleted."
            : "SecureAD resolves principals by identifier and this policy names one by name, so "
                + "whether it resolves can only be settled on the machine.";

        return $"{policy} sets ADPasswordEncryptionPrincipal to '{evidence.ConfiguredValue}', which "
            + $"this capture could not resolve to a principal. {why} Whether that principal is "
            + "broad is therefore unknown. It also matters in its own right: Microsoft records that "
            + "when an invalid user or group is named, policy processing fails and the managed "
            + "account's password is not backed up at all - so if this name is wrong, these "
            + "machines have no stored password rather than a badly protected one.";
    }
}

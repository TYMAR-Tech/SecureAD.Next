using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-091 - a computer carrying neither LAPS expiration timestamp.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it finds.</b> A computer with no sign of either LAPS product - not Windows LAPS, not
/// legacy Microsoft LAPS - in a forest where LAPS management is possible and where this run could
/// see the answer. In plain terms: nothing is rotating the local administrator password on this
/// machine, so whatever that password is, it is probably the same password as on every other
/// machine imaged alongside it.
/// </para>
/// <para>
/// <b>The exposure is password reuse across machines, not the password itself.</b> When the local
/// administrator password is set once - by an image, a build script or a technician - every machine
/// built the same way shares it. One compromised machine yields a credential that works on all of
/// them, it works locally, so no domain authentication is involved and nothing is logged centrally.
/// That is the step that turns a single compromised workstation into every workstation, and it
/// requires no directory privilege at all.
/// </para>
/// <para>
/// <b>Microsoft's own words</b>, from <i>What is Windows LAPS?</i>: <i>"Windows Local
/// Administrator Password Solution (Windows LAPS) is a Windows feature that automatically manages
/// and backs up the password of a local administrator account on your Microsoft Entra-joined or
/// Windows Server Active Directory-joined devices."</i>
/// </para>
/// <para>
/// <b>Clients and servers are reported identically</b>, settled by the owner on 2026-09-03. LAPS
/// matters most on workstations - that is the population where one shared local password becomes
/// lateral movement across thousands of machines - so there is no client/server split and no
/// separate severity. One consequence follows immediately: on an estate of any size this rule's
/// finding count is the count of unmanaged machines, which during a rollout is most of them. That
/// volume is why the severity stays Medium rather than rising.
/// </para>
/// <para>
/// <b>A machine carrying only the legacy timestamp is not this rule.</b> That is
/// <see cref="WindowsLapsNotAppliedOnCapableComputer"/>. The first draft of the specification argued
/// such a machine should be silent because its password is being rotated; the legacy attribute is
/// never cleared, so it proves nothing, and the owner caught it. This rule fires only when there is
/// no timestamp of either kind, so legacy emulation mode - which still writes one - never reaches
/// it.
/// </para>
/// <para>
/// Specified in <c>docs/layers/judgement/rules/SEC-091-laps-missing-on-a-computer.md</c>.
/// </para>
/// </remarks>
public sealed class LapsMissingOnComputer : IRule
{
    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        "SEC-091",
        "LAPS missing on a computer",
        Severity.Medium,
        Version: 1,
        SubjectClasses: ["computer"],
        RequiredAttributes:
        [
            LapsAttributes.WindowsLapsExpiration,
            LapsAttributes.LegacyLapsExpiration,
            "objectClass",
            "operatingSystem",
            "operatingSystemVersion",
            "userAccountControl",
            "primaryGroupID",
        ],
        RequiredDerivedFacts: [nameof(DerivedFactKind.AttributeVisibility)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-091 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, DerivedFacts derived)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(derived);

        if (!LapsAttributes.IsComputer(subject))
            return RuleVerdict.Judged([]);

        // Excluded by the owner's decision of 2026-09-02, and through DomainControllerSignals
        // rather than by distinguished name. Worth recording that this is a scope choice and not a
        // technical impossibility: Windows LAPS does manage the DSRM account password on a domain
        // controller. What a domain controller has not got is an ordinary local administrator
        // account, which is why excluding it is right for this rule.
        if (DomainControllerSignals.Of(subject).IsDomainController)
            return RuleVerdict.Judged([]);

        // No live machine, so no local administrator password for anything to rotate. The forest
        // raised this: the first ad.lab run reported two disabled leftover accounts and told an
        // operator to deploy LAPS to machines that do not exist.
        if (LapsAttributes.IsDisabled(subject))
            return RuleVerdict.Judged([]);

        if (derived.AttributeVisibility is not { } visibility)
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.AttributeVisibility, UnresolvedReason.NotDerived)]);

        var modern = LapsAttributes.Judgeability(visibility, LapsAttributes.WindowsLapsExpiration);
        var legacy = LapsAttributes.Judgeability(visibility, LapsAttributes.LegacyLapsExpiration);

        // Withheld by this forest, or the schema was never read. Absence then says nothing about
        // the machine, and silence here would be a statement that it is managed. This is the branch
        // that protects a hardened estate, and no real forest reaches it - Microsoft ships both
        // expiration attributes non-confidential and ad.lab returned 0 for both on 2026-09-03.
        if (modern is LapsAttributes.Readability.Withheld)
            return RuleVerdict.CouldNotJudge([LapsAttributes.WindowsLapsExpiration]);

        if (legacy is LapsAttributes.Readability.Withheld)
            return RuleVerdict.CouldNotJudge([LapsAttributes.LegacyLapsExpiration]);

        // NEITHER EXTENSION IN THE SCHEMA IS A FACT ABOUT THE FOREST, NOT ABOUT A MACHINE. No
        // computer in such a forest can be managed by either product, so absence is not evidence
        // about any individual machine and reporting every computer would be reporting the estate
        // for the state of its schema. The honest statement is one finding about the forest, and
        // this product's rules judge one object at a time and cannot make one - so the rule reports
        // nothing and its About text says why.
        if (modern is LapsAttributes.Readability.NotInThisForest
            && legacy is LapsAttributes.Readability.NotInThisForest)
        {
            return RuleVerdict.Judged([]);
        }

        var modernValue = AttributeReading.Text(subject, LapsAttributes.WindowsLapsExpiration);
        var legacyValue = AttributeReading.Text(subject, LapsAttributes.LegacyLapsExpiration);

        // Either timestamp means something is rotating the password. Which product is doing it is a
        // migration question rather than a security one, and it is SEC-094's.
        //
        // ABSENCE IS THE ORDINARY CASE HERE AND IS NOT REPORTED AS AN UNREAD INPUT. Most computers
        // in a forest without LAPS carry neither attribute, and naming a missing attribute against
        // nearly every object would read as a broken capture. The distinction that matters was
        // settled above, from the schema: absent and readable is a finding, absent because withheld
        // is CouldNotJudge.
        if (!string.IsNullOrWhiteSpace(modernValue) || !string.IsNullOrWhiteSpace(legacyValue))
            return RuleVerdict.Judged([]);

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        // Decides nothing, and that is the point. Under a servers-only scope a machine with no
        // operatingSystem could not have been classified and would have had to be reported as
        // unjudgeable; because clients and servers are treated alike, the operating system is
        // carried into the evidence and shown to the operator, and the rule never branches on it.
        var capability = LapsCapability.Of(subject);
        var name = AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;
        var evidence = new LapsDeploymentEvidence(modernValue, legacyValue, capability);

        return RuleVerdict.Judged(
        [
            new Finding(
                Definition.Id,
                Definition.Version,
                Definition.Severity,
                new FindingSubject(FindingSubjectKind.Account, name),
                objectGuid,
                subject.DistinguishedName,
                DnHelper.DnToFqdn(subject.DistinguishedName),
                LapsAttributes.ClassOf(subject),
                Detail(name, evidence),
                subject.Completeness,
                evidence),
        ]);
    }

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It names what the rule cannot see.</b> A machine whose password is backed up to Microsoft
    /// Entra ID carries no Active Directory attribute at all, so this rule - reading a directory
    /// bundle - cannot tell it from an unmanaged one. That is the likeliest source of a false
    /// finding in a real estate, and the product cannot detect it while the operator can.
    /// </remarks>
    private static string Detail(string name, LapsDeploymentEvidence evidence)
    {
        var machine = evidence.Capability.Name is { } os
            ? $"{name} runs {os} and"
            : $"{name}";

        return $"{machine} carries neither LAPS expiration timestamp - not Windows LAPS's "
            + "msLAPS-PasswordExpirationTime and not legacy Microsoft LAPS's "
            + "ms-Mcs-AdmPwdExpirationTime - so nothing visible in this directory is rotating its "
            + "local administrator password. Where that password was set by an image, a build "
            + "script or a technician, every machine built the same way shares it, and one "
            + "compromised machine yields a credential that works on all of them. That access is "
            + "local, so no domain authentication is involved and nothing is logged centrally. "
            + "Deploy Windows LAPS to this machine and confirm it by looking for "
            + "msLAPS-PasswordExpirationTime appearing on this computer object, which is the check "
            + "Microsoft names. Note that this rule reads Active Directory only: a machine whose "
            + "password is backed up to Microsoft Entra ID instead carries no directory attribute "
            + "at all and cannot be told apart from an unmanaged one here.";
    }
}

using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Security;

namespace SecureAD.Audit.Sysvol;

/// <summary>
/// Reads the Group Policy files on SYSVOL into the bundle: inventory row B14.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the first read in the product that is allowed to fail.</b> Every capture before it is
/// fail-fast per <c>docs/decisions/0003</c>: a unit that could not be read returns before the seal,
/// so a bundle exists only when everything was read. <c>docs/decisions/0044</c> makes SYSVOL the
/// single stated exception, because SYSVOL is a file share, permission problems on it are ordinary
/// rather than exceptional, and a run that died because one policy folder out of four hundred was
/// locked would be unusable in the field.
/// </para>
/// <para>
/// So nothing in here returns early on a failure. Every failure is caught, attributed to the policy
/// it happened under, and carried into <see cref="SysvolCoverage"/> - which is what makes the
/// difference between a partial result and a quiet one. The rule this class is written to is that
/// <b>a file that could not be read never produces the same evidence as a file that held
/// nothing</b>.
/// </para>
/// <para>
/// <b>How deep it reads is settled by
/// <c>docs/decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md</c></b>: the
/// policy's own folder, every folder beneath it, every file whose contents are read, and every file
/// under <c>Machine\Scripts</c> and <c>User\Scripts</c>. Scripts are in scope because a logon script
/// that anybody can rewrite runs on every machine the policy reaches, and the predecessor's read
/// stopped at the root folder and could not see it.
/// </para>
/// </remarks>
public sealed class SysvolCapture
{
    /// <summary>
    /// The registry-backed settings, one file per half of a policy.
    /// </summary>
    private static readonly (string RelativePath, GpoSettingScope Scope)[] RegistryPolicyFiles =
    [
        (@"Machine\Registry.pol", GpoSettingScope.Machine),
        (@"User\Registry.pol", GpoSettingScope.User),
    ];

    /// <summary>
    /// The security template: the privileges a policy grants, the local groups it populates and the
    /// signing settings it can weaken. SEC-064, SEC-065 and SEC-066 all read this one file.
    /// </summary>
    private const string SecurityTemplateFile =
        @"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

    /// <summary>
    /// The two folders whose files are permission-read whether or not their contents are parsed,
    /// per <c>docs/decisions/0043</c>.
    /// </summary>
    private static readonly string[] ScriptFolders = [@"Machine\Scripts", @"User\Scripts"];

    /// <summary>The policy's own folder, which has no path beneath the policy root.</summary>
    private const string PolicyRoot = "";

    private readonly ISysvolFileReader _reader;
    private readonly BundleWriter _writer;
    private readonly IRunLog _log;
    private readonly TimeProvider _time;

    /// <summary>
    /// Creates a SYSVOL capture writing into <paramref name="writer"/>.
    /// </summary>
    /// <param name="reader">How the share is read.</param>
    /// <param name="writer">The bundle being written.</param>
    /// <param name="log">The run's operational log.</param>
    /// <param name="time">The diagnostic clock.</param>
    public SysvolCapture(ISysvolFileReader reader, BundleWriter writer, IRunLog log, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(log);
        ArgumentNullException.ThrowIfNull(time);

        _reader = reader;
        _writer = writer;
        _log = log;
        _time = time;
    }

    /// <summary>
    /// Reads every policy the directory declared, and reports what became of each.
    /// </summary>
    /// <param name="inventory">
    /// The policies the directory declared - the denominator. Both halves of it are used: the ones
    /// that can be read, and the ones the directory declared without saying where their files are.
    /// </param>
    /// <param name="cancellationToken">Cancellation for a capture an operator stopped.</param>
    /// <returns>
    /// What became of each policy. This is the only account of a SYSVOL failure that will ever
    /// reach an operator, because the run does not stop for one.
    /// </returns>
    /// <remarks>
    /// Cancellation is not a SYSVOL failure and is not swallowed. An operator who stopped the run
    /// has not discovered anything about his policies, and recording a cancelled read as an
    /// unreadable policy would put a finding in front of him that says more than he knows.
    /// </remarks>
    public async Task<SysvolCoverage> ReadAsync(
        GpoInventory inventory,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(inventory);

        var policies = new List<GpoCoverage>(inventory.UnlocatablePolicies);

        foreach (var target in inventory.Policies)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var started = _time.GetTimestamp();
            var total = inventory.Policies.Count + inventory.UnlocatablePolicies.Count;
            _log.Note("Capture", SysvolText.Get("PolicyStarted"), PolicyDetails(target, policies.Count, total, started, "Started"));
            var coverage = await ReadPolicyAsync(target, cancellationToken).ConfigureAwait(false);
            policies.Add(coverage);
            _log.Note("Capture", SysvolText.Get("PolicyFinished"), PolicyDetails(target, policies.Count, total, started, coverage.Outcome.ToString()));
        }

        return SysvolCoverage.Of(policies);
    }

    private IReadOnlyList<RunLogDetail> PolicyDetails(GpoTarget target, int completed, int total, long started, string outcome) =>
    [
        new("gpo", target.GpoGuid.ToString("D")), new("policy", target.DisplayName),
        new("uncPath", target.FileSysPath), new("outcome", outcome),
        new("policiesCompleted", completed.ToString(CultureInfo.InvariantCulture)),
        new("policiesTotal", total.ToString(CultureInfo.InvariantCulture)),
        new("elapsedSeconds", _time.GetElapsedTime(started).TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)),
    ];

    private sealed class PolicyAbandonedException : Exception { }

    /// <summary>
    /// Reads one policy's folder, recording what it holds and what could not be reached.
    /// </summary>
    private async Task<GpoCoverage> ReadPolicyAsync(GpoTarget target, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        var progress = new PolicyProgress(target, _writer);

        try
        {
            return await ReadPolicyContentsAsync(target, progress, cancellationToken).ConfigureAwait(false);
        }
        catch (PolicyAbandonedException)
        {
            return progress.Outcome();
        }
    }

    private async Task<GpoCoverage> ReadPolicyContentsAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        var root = await _reader
            .ReadSecurityDescriptorAsync(target, PolicyRoot, cancellationToken)
            .ConfigureAwait(false);

        if (!root.IsSuccess)
        {
            // The policy's own folder was refused. Nothing beneath it is worth attempting, and
            // reporting the whole policy as unread is the honest answer rather than a partial one.
            return GpoCoverage.Unreadable(
                target.GpoGuid, target.DisplayName, target.FileSysPath, root.Error.Description);
        }

        if (root.Value is null)
        {
            // The directory says this policy exists and the share does not hold its folder. That is
            // a fact about the customer's forest - an orphaned policy object - and not a failure of
            // this run, but it is still a policy nothing was read from.
            return GpoCoverage.Unreadable(
                target.GpoGuid,
                target.DisplayName,
                target.FileSysPath,
                "The policy's folder is not on the SYSVOL share. The directory holds the policy "
                + "object and its files are missing, so what it configures cannot be known.");
        }

        progress.WriteDescriptor(PolicyRoot, root.Value);

        await ReadFolderPermissionsAsync(target, progress, cancellationToken).ConfigureAwait(false);
        await ReadRegistryPoliciesAsync(target, progress, cancellationToken).ConfigureAwait(false);
        await ReadSecurityTemplateAsync(target, progress, cancellationToken).ConfigureAwait(false);
        await ReadPreferenceFilesAsync(target, progress, cancellationToken).ConfigureAwait(false);
        await ReadScriptPermissionsAsync(target, progress, cancellationToken).ConfigureAwait(false);

        return progress.Outcome();
    }

    /// <summary>
    /// Reads the permissions on every folder beneath the policy root, per
    /// <c>docs/decisions/0043</c>.
    /// </summary>
    private async Task ReadFolderPermissionsAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        progress.ThrowIfAbandoned();
        var folders = await _reader
            .EnumerateRelativeDirectoriesAsync(target, cancellationToken)
            .ConfigureAwait(false);

        if (!folders.IsSuccess)
        {
            progress.RecordFailure(folders.Error);
            return;
        }

        foreach (var folder in folders.Value)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ReadPermissionsAsync(target, progress, folder, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads the registry-backed settings out of both halves of the policy.</summary>
    private async Task ReadRegistryPoliciesAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        foreach (var (relativePath, scope) in RegistryPolicyFiles)
        {
            var file = await ReadFileAsync(target, progress, relativePath, FileExpectation.MayNotExist, cancellationToken)
                .ConfigureAwait(false);

            if (file is null)
            {
                continue;
            }

            var parsed = RegistryPolicyParser.ParsePolicyFile(file);

            progress.WriteFileErrors(relativePath, parsed.Errors);

            foreach (var entry in parsed.Entries)
            {
                progress.WriteRegistrySetting(scope, entry);
            }
        }
    }

    /// <summary>Reads the security template: privileges, restricted groups and signing settings.</summary>
    private async Task ReadSecurityTemplateAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        var file = await ReadFileAsync(target, progress, SecurityTemplateFile, FileExpectation.MayNotExist, cancellationToken)
            .ConfigureAwait(false);

        if (file is null)
        {
            return;
        }

        var parsed = SecurityTemplateParser.ParseTemplateFile(file);

        progress.WriteFileErrors(SecurityTemplateFile, parsed.Errors);

        foreach (var section in parsed.Sections)
        {
            foreach (var setting in section.Value)
            {
                progress.WriteSecuritySetting(section.Key, setting);
            }
        }

        foreach (var group in parsed.GetGroupMemberships())
        {
            progress.WriteRestrictedGroup(group);
        }
    }

    /// <summary>
    /// Scans the policy's preference files for a stored credential.
    /// </summary>
    /// <remarks>
    /// The files are found by listing the share rather than by trusting the policy's declared
    /// extension list, because what a workstation applies is what is on the share.
    /// </remarks>
    private async Task ReadPreferenceFilesAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        progress.ThrowIfAbandoned();
        var files = await _reader
            .EnumerateRelativeFilesAsync(target, "*.xml", cancellationToken)
            .ConfigureAwait(false);

        if (!files.IsSuccess)
        {
            progress.RecordFailure(files.Error);
            return;
        }

        foreach (var relativePath in files.Value)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var content = await ReadFileAsync(target, progress, relativePath, FileExpectation.WasListed, cancellationToken)
                .ConfigureAwait(false);

            if (content is null)
            {
                continue;
            }

            var parsed = GroupPolicyPreferenceParser.ParsePreferenceFile(content);

            progress.WriteFileErrors(relativePath, parsed.Errors);

            foreach (var finding in parsed.Findings)
            {
                progress.WriteStoredCredential(relativePath, finding);
            }
        }
    }

    /// <summary>
    /// Reads the permissions on the logon and startup scripts, which
    /// <c>docs/decisions/0043</c> puts in scope for SEC-082 even though their contents are not
    /// parsed.
    /// </summary>
    private async Task ReadScriptPermissionsAsync(
        GpoTarget target, PolicyProgress progress, CancellationToken cancellationToken)
    {
        progress.ThrowIfAbandoned();
        var files = await _reader
            .EnumerateRelativeFilesAsync(target, "*", cancellationToken)
            .ConfigureAwait(false);

        if (!files.IsSuccess)
        {
            progress.RecordFailure(files.Error);
            return;
        }

        foreach (var relativePath in files.Value.Where(IsUnderAScriptFolder))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ReadPermissionsAsync(target, progress, relativePath, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static bool IsUnderAScriptFolder(string relativePath) =>
        ScriptFolders.Any(folder =>
            relativePath.StartsWith(folder + "\\", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Whether a file this capture asks for is one the policy may simply not have.
    /// </summary>
    /// <remarks>
    /// <b>The same absent file means opposite things depending on who asked.</b> A policy with no
    /// <c>GptTmpl.inf</c> assigns no user rights, and that is an answer. A <c>Groups.xml</c> that
    /// enumeration has just listed and that will not open is a gap, because something established it
    /// was there. Reading both as "not there" is <c>CAP-003</c>, and it let a policy report complete
    /// coverage of a file it never captured.
    /// </remarks>
    private enum FileExpectation
    {
        /// <summary>
        /// A well-known path a policy is free not to have. Absent is an answer, not a gap.
        /// </summary>
        MayNotExist,

        /// <summary>
        /// A path enumeration returned, so the share said it was there. Absent is a gap.
        /// </summary>
        WasListed,
    }

    /// <summary>
    /// Reads one file's contents, recording a refusal against the policy and writing the
    /// permissions of every file it did open, per <c>docs/decisions/0043</c>.
    /// </summary>
    /// <param name="target">The policy being read.</param>
    /// <param name="progress">Where failures and permissions are recorded.</param>
    /// <param name="relativePath">The file inside the policy.</param>
    /// <param name="expectation">
    /// Whether this path is one the policy may not have, or one enumeration already listed. It
    /// decides what an absent file means, and nothing else here can tell the two apart.
    /// </param>
    /// <param name="cancellationToken">Stops the read.</param>
    /// <returns>The bytes, or null if the file is not there or could not be read.</returns>
    private async Task<byte[]?> ReadFileAsync(
        GpoTarget target,
        PolicyProgress progress,
        string relativePath,
        FileExpectation expectation,
        CancellationToken cancellationToken)
    {
        progress.ThrowIfAbandoned();
        var file = await _reader
            .ReadFileAsync(target, relativePath, cancellationToken)
            .ConfigureAwait(false);

        if (!file.IsSuccess)
        {
            progress.RecordFailure(file.Error);
            return null;
        }

        if (file.Value is null)
        {
            // Genuinely absent, and that is an answer rather than a gap. A policy with no
            // GptTmpl.inf assigns no user rights.
            //
            // UNLESS ENUMERATION JUST LISTED IT, in which case the share said the file was there
            // and then would not produce it - CAP-003. That is the same event RecordVanished
            // already covers for permissions, happening to a file's contents instead, and reading
            // it as "absent" let the policy keep reporting complete coverage.
            if (expectation == FileExpectation.WasListed)
            {
                progress.RecordVanishedContents(relativePath);
            }

            return null;
        }

        try
        {
            await ReadPermissionsAsync(target, progress, relativePath, cancellationToken).ConfigureAwait(false);
        }
        catch (PolicyAbandonedException)
        {
            // The content acquisition completed before the ACL timed out. Let its caller persist
            // the parsed content; the recorded gap remains and every subsequent acquisition stops.
        }

        return file.Value;
    }

    /// <summary>Reads and stores the permissions on one path inside the policy's folder.</summary>
    private async Task ReadPermissionsAsync(
        GpoTarget target,
        PolicyProgress progress,
        string relativePath,
        CancellationToken cancellationToken)
    {
        progress.ThrowIfAbandoned();
        var descriptor = await _reader
            .ReadSecurityDescriptorAsync(target, relativePath, cancellationToken)
            .ConfigureAwait(false);

        if (!descriptor.IsSuccess)
        {
            progress.RecordUnreadablePermissions(relativePath, descriptor.Error);
            return;
        }

        if (descriptor.Value is null)
        {
            // The path was there a moment ago and is not now. Nothing was denied and nothing is
            // known about it either, so it is recorded rather than dropped.
            progress.RecordVanished(relativePath);
            return;
        }

        progress.WriteDescriptor(relativePath, descriptor.Value);
    }

    /// <summary>
    /// What one policy's read has produced so far: the rows written, and the failures that have to
    /// be answered for at the end of it.
    /// </summary>
    /// <remarks>
    /// Held as a class rather than as loose variables because the ordinals, the failures and the
    /// final outcome are one bookkeeping problem. The previous product's SYSVOL writer kept its
    /// counter below the early return that ran on failure, so nothing recorded the failures at all.
    /// </remarks>
    private sealed class PolicyProgress(GpoTarget target, BundleWriter writer)
    {
        private readonly List<string> _failures = [];
        private bool _abandoned;

        public void ThrowIfAbandoned()
        {
            if (_abandoned)
                throw new PolicyAbandonedException();
        }

        /// <summary>
        /// Every path whose permissions this policy has already captured.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>Two scans reach the same file, and the bundle will not have it twice.</b> The
        /// preference scan enumerates <c>*.xml</c> across the whole policy folder and captures the
        /// descriptor of every file it opens; <c>ReadScriptPermissionsAsync</c> then enumerates
        /// everything under the script folders and captures them again. An ordinary
        /// <c>Machine\Scripts\settings.xml</c> is therefore reached twice, and
        /// <c>sysvol_path_security_descriptor</c> is keyed <c>(gpo_guid, relative_path)</c> - so the
        /// second insert violated the key and the exception unwound the entire run, after every
        /// domain had been read and before anything was sealed. <c>CAP-001</c>, and <c>P-172</c>.
        /// </para>
        /// <para>
        /// <b>Case-insensitive, because a share is.</b> <c>Machine\Scripts</c> and
        /// <c>MACHINE\SCRIPTS</c> are one path to Windows, and a case-sensitive set would let the
        /// same defect back in through a policy whose folders are cased differently from the
        /// pattern.
        /// </para>
        /// <para>
        /// <b>The second acquisition is skipped, not overwritten.</b> Overwriting would conceal a
        /// second observation that genuinely differed from the first, and this record exists to say
        /// what the run saw.
        /// </para>
        /// </remarks>
        private readonly HashSet<string> _descriptorsCaptured =
            new(StringComparer.OrdinalIgnoreCase);
        private int _registryOrdinal;
        private int _securityOrdinal;
        private int _restrictedGroupOrdinal;
        private int _credentialOrdinal;
        private int _errorOrdinal;
        private bool _anythingRead;

        public void WriteDescriptor(string relativePath, byte[] descriptorBytes)
        {
            // Already captured by the other scan. See _descriptorsCaptured: the bundle keys this
            // table on (gpo_guid, relative_path), so a second insert is not a duplicate row but a
            // failed capture.
            if (!_descriptorsCaptured.Add(relativePath))
            {
                return;
            }

            var parsed = SecurityDescriptorParser.Parse(descriptorBytes);
            var normalized = AceNormalizer.Normalize(Guid.Empty, parsed);

            writer.WriteSysvolSecurityDescriptor(
                target.GpoGuid, relativePath, descriptorBytes, normalized);

            _anythingRead = true;
        }

        public void WriteRegistrySetting(GpoSettingScope scope, RegistryPolicyEntry entry)
        {
            writer.WriteGpoRegistrySetting(
                target.GpoGuid,
                _registryOrdinal++,
                scope,
                entry.KeyPath,
                entry.ValueName,
                entry.RegistryType,
                entry.Data);

            _anythingRead = true;
        }

        public void WriteSecuritySetting(string section, SecurityTemplateSetting setting)
        {
            writer.WriteGpoSecuritySetting(
                target.GpoGuid, _securityOrdinal++, section, setting.Name, setting.Value);

            _anythingRead = true;
        }

        public void WriteRestrictedGroup(RestrictedGroup group)
        {
            foreach (var member in group.Members)
            {
                writer.WriteGpoRestrictedGroup(
                    target.GpoGuid,
                    _restrictedGroupOrdinal++,
                    group.GroupName,
                    RestrictedGroupRelationship.Member,
                    member);
            }

            foreach (var container in group.MemberOf)
            {
                writer.WriteGpoRestrictedGroup(
                    target.GpoGuid,
                    _restrictedGroupOrdinal++,
                    group.GroupName,
                    RestrictedGroupRelationship.MemberOf,
                    container);
            }

            _anythingRead = true;
        }

        public void WriteStoredCredential(string relativePath, GppPasswordFinding finding)
        {
            writer.WriteGpoStoredCredential(
                target.GpoGuid,
                _credentialOrdinal++,
                relativePath,
                finding.ElementType,
                finding.AccountName,
                finding.SourceAttribute);

            _anythingRead = true;
        }

        /// <summary>
        /// Records what a parser could not make sense of: a row per diagnostic, and a mark against
        /// the policy's coverage.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <b>The coverage mark was missing until 2026-09-13, and its absence was a false clean
        /// answer.</b> This wrote the diagnostic rows and returned, so a policy whose
        /// <c>Machine\Registry.pol</c> was truncated or malformed yielded no settings and was still
        /// reported as <c>Read</c> and complete. <c>SEC-093</c> then treated an absent LAPS decryptor
        /// setting as an assessed, finding-free policy rather than as evidence it never got - which
        /// is the product telling an administrator his directory is clean when it failed to read it.
        /// Recorded as <c>CAP-002</c> of the capture review.
        /// </para>
        /// <para>
        /// <b>What the file did yield is kept.</b> A half-parsed file is facts plus a gap, not a
        /// write-off: the caller writes every recovered setting and this marks the gap beside them.
        /// Coverage becomes <see cref="GpoCoverage.PartiallyRead"/> rather than
        /// <see cref="GpoCoverage.Unreadable"/>, because reaching a parser at all means the bytes
        /// were read and the file's own permissions were captured.
        /// </para>
        /// <para>
        /// <b>The reason names the file.</b> The obvious alternative was a generic sentence, because
        /// <see cref="Summarize"/> shows three distinct reasons and counts the rest - so per-file
        /// reasons can crowd a different kind of failure out of the summary. That was the wrong
        /// trade: <c>gpo_file_error</c> is written, merged, and never read back by anything, so a
        /// generic reason would leave an operator told his policy was incomplete with no way to find
        /// out which file did it. Owner's call, 2026-09-13.
        /// </para>
        /// </remarks>
        /// <param name="relativePath">The file inside the policy, as the parser was given it.</param>
        /// <param name="errors">What the parser could not make sense of. Empty is the ordinary case.</param>
        public void WriteFileErrors(string relativePath, IReadOnlyList<string> errors)
        {
            foreach (var error in errors)
            {
                writer.WriteGpoFileError(target.GpoGuid, _errorOrdinal++, relativePath, error);
            }

            if (errors.Count > 0)
            {
                _failures.Add(
                    $"{relativePath} was read but could not be understood. Whatever it configures "
                    + "is missing from the evidence, so this policy has not been read in full.");
            }
        }

        /// <summary>
        /// Records that a path's permissions could not be read: a row in the bundle, and a mark
        /// against the policy's coverage.
        /// </summary>
        public void RecordUnreadablePermissions(string relativePath, AuditError error)
        {
            // The refusal is recorded once per path, for the reason WriteDescriptor is:
            // unreadable_sysvol_descriptor is keyed (gpo_guid, relative_path) too, and both scans
            // reach a denied file under a scripts folder. The coverage failure is still recorded
            // every time, because Summarize distincts them and a policy's coverage should not
            // depend on which scan happened to reach a path first.
            if (_descriptorsCaptured.Add(relativePath))
            {
                writer.WriteUnreadableSysvolDescriptor(
                    target.GpoGuid, relativePath, error.Description);
            }

            RecordFailure(error);
        }

        /// <summary>
        /// Records a path that was listed and then was not there. Rare, and recorded rather than
        /// ignored, because a policy being rewritten while it is audited is worth knowing about.
        /// </summary>
        public void RecordVanished(string relativePath)
        {
            const string reason =
                "This path was listed and then was gone before its permissions could be read. "
                + "Something changed the policy's folder while the audit was reading it.";

            // Once per path, as above: this writes to the same keyed table.
            if (_descriptorsCaptured.Add(relativePath))
            {
                writer.WriteUnreadableSysvolDescriptor(target.GpoGuid, relativePath, reason);
            }

            _failures.Add(reason);
        }

        /// <summary>
        /// Records a file that was listed and then would not open when its contents were read.
        /// </summary>
        /// <remarks>
        /// <b>The same event as <see cref="RecordVanished"/>, happening to a file's contents rather
        /// than to its permissions</b>, and worded almost identically on purpose: an operator who
        /// meets both should recognise them as one kind of problem. Until 2026-09-13 this case
        /// returned quietly and the policy went on reporting complete coverage of a file it never
        /// captured - <c>CAP-003</c> of the capture review.
        ///
        /// <para>
        /// No <c>unreadable_sysvol_descriptor</c> row is written here. That table is about
        /// permissions, and the permissions of a file that would not open were never attempted; a
        /// row there would claim an attempt that did not happen.
        /// </para>
        /// </remarks>
        /// <param name="relativePath">The file that was listed and then would not open.</param>
        public void RecordVanishedContents(string relativePath)
        {
            _failures.Add(
                $"{relativePath} was listed and then could not be opened when its contents were "
                + "read. Something changed the policy's folder while the audit was reading it.");
        }

        public void RecordFailure(AuditError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            if (error.Code == "Capture.SysvolOperationTimedOut")
            {
                // The reason remaining operations were not attempted must survive the coverage
                // summary's existing cap even if earlier files had already recorded parse errors.
                _failures.Insert(0, error.Description);
                _abandoned = true;
                throw new PolicyAbandonedException();
            }
            _failures.Add(error.Description);
        }

        /// <summary>
        /// What to report for this policy.
        /// </summary>
        /// <remarks>
        /// The three answers are kept apart deliberately. <c>Read</c> means nothing was refused;
        /// <c>PartiallyRead</c> means some of the policy is in the evidence and some is not, which
        /// is the state a report has to caveat; <c>Unreadable</c> means the policy is in the
        /// evidence in name only. Collapsing the middle one into either neighbour is how a customer
        /// ends up reading a partial answer as a complete one.
        /// </remarks>
        public GpoCoverage Outcome()
        {
            if (_failures.Count == 0)
            {
                return GpoCoverage.Read(target.GpoGuid, target.DisplayName, target.FileSysPath);
            }

            var reason = Summarize();

            return _anythingRead
                ? GpoCoverage.PartiallyRead(
                    target.GpoGuid, target.DisplayName, target.FileSysPath, reason)
                : GpoCoverage.Unreadable(
                    target.GpoGuid, target.DisplayName, target.FileSysPath, reason);
        }

        /// <summary>
        /// Turns the failures into one sentence an operator can act on.
        /// </summary>
        /// <remarks>
        /// Distinct reasons only, and at most three of them. A locked-down policy folder produces
        /// the same refusal on every path beneath it, and a reason repeated forty times is a reason
        /// nobody reads. The count of the rest is stated rather than dropped, so the summary never
        /// claims to be shorter than the truth.
        /// </remarks>
        private string Summarize()
        {
            var distinct = _failures.Distinct(StringComparer.Ordinal).ToArray();
            var shown = distinct.Take(3).ToArray();
            var summary = string.Join(" ", shown);

            return distinct.Length > shown.Length
                ? summary + $" ({distinct.Length - shown.Length} further failures of other kinds "
                    + "were recorded against this policy.)"
                : summary;
        }
    }
}

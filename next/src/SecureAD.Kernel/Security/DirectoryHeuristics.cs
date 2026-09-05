namespace SecureAD.Kernel.Security;

/// <summary>
/// Whether a heuristic character was read, and if not, why not.
/// </summary>
/// <remarks>
/// <b>Absent and unread are different facts and must not render alike.</b> MS-ADTS states that an
/// absent character defaults to <c>"0"</c>, so a forest with no <c>dSHeuristics</c> value has a
/// documented answer rather than a missing one. A forest whose configuration object was never read
/// has no answer at all. Collapsing the two would let a bundle that could not look report the
/// default, which is the shape of failure <c>docs/decisions/0002</c> exists to prevent.
/// </remarks>
public enum HeuristicReadOutcome
{
    /// <summary>The character was present in the string and carried a value.</summary>
    Stated,

    /// <summary>
    /// The string was read and this position was past its end, so the documented default applies.
    /// </summary>
    /// <remarks>
    /// Truncation is the only way to omit a character - the order is fixed - so a short string is a
    /// normal string and not a malformed one.
    /// </remarks>
    DefaultedByAbsence,

    /// <summary>
    /// Nothing was read: no configuration object, or a bundle captured before the attribute was
    /// requested.
    /// </summary>
    NotRead,

    /// <summary>The forest stated a character outside the values the specification defines.</summary>
    Malformed,
}

/// <summary>
/// One character of <c>dSHeuristics</c>, read at a stated position.
/// </summary>
/// <param name="Position">The one-based character position, as MS-ADTS numbers them.</param>
/// <param name="Value">
/// The character read, or the documented default where the string ended before this position. Null
/// only when nothing was read at all.
/// </param>
/// <param name="Outcome">Whether the value was stated, defaulted, or never read.</param>
public sealed record HeuristicCharacter(int Position, char? Value, HeuristicReadOutcome Outcome)
{
    /// <summary>Whether this answer rests on a value the forest actually stated.</summary>
    /// <remarks>
    /// Named for gate 4: a caller holding a character needs to know whether it is reading the
    /// forest or reading a default, and a bare <c>char</c> cannot say.
    /// </remarks>
    public bool IsComplete => Outcome is HeuristicReadOutcome.Stated
        or HeuristicReadOutcome.DefaultedByAbsence;
}

/// <summary>
/// A group AdminSDHolder can be told to stop protecting, and the bit that says so.
/// </summary>
/// <remarks>
/// <b>Four groups, and only these four.</b> The mask is four bits wide, and
/// <see href="https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980">Microsoft's
/// own article</see> assigns each bit to one operator group. No other protected group can be
/// excluded this way, which is why a mask cannot explain a Domain Admins object that is unprotected.
/// </remarks>
public enum AdminSdExcludableGroup
{
    /// <summary>Account Operators, <c>S-1-5-32-548</c>. Bit 0.</summary>
    AccountOperators = 548,

    /// <summary>Server Operators, <c>S-1-5-32-549</c>. Bit 1.</summary>
    ServerOperators = 549,

    /// <summary>Print Operators, <c>S-1-5-32-550</c>. Bit 2.</summary>
    PrintOperators = 550,

    /// <summary>Backup Operators, <c>S-1-5-32-551</c>. Bit 3.</summary>
    BackupOperators = 551,
}

/// <summary>
/// Which operator groups a forest has removed from AdminSDHolder's protection.
/// </summary>
/// <param name="Excluded">
/// The groups the mask names. Empty when the forest excludes none, which is different from not
/// knowing - <see cref="IsComplete"/> carries that.
/// </param>
/// <param name="Outcome">Whether the mask character was stated, defaulted or never read.</param>
/// <param name="Character">
/// The character the mask was resolved from, kept so an operator can check this product against
/// what the directory holds. Null only where nothing was read.
/// </param>
public sealed record AdminSdExclusionMask(
    IReadOnlyList<AdminSdExcludableGroup> Excluded,
    HeuristicReadOutcome Outcome,
    char? Character)
{
    /// <summary>Whether the forest was asked and answered.</summary>
    /// <remarks>
    /// <b>An empty exclusion list means two things without this.</b> Either the forest excludes
    /// nothing, or nobody looked - and the second reported as the first tells an operator that four
    /// operator groups are protected when nothing established it.
    /// </remarks>
    public bool IsComplete => Outcome is HeuristicReadOutcome.Stated
        or HeuristicReadOutcome.DefaultedByAbsence;
}

/// <summary>
/// Whether a forest has switched off the rights an object's owner gets without being granted them.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for.</b> An owner normally holds <c>READ_CONTROL</c> and <c>WRITE_DAC</c> over
/// what they own without any entry in the permission list saying so, which is why owning an object
/// is a form of control that no permission review shows. A forest can turn that off, and a rule
/// telling a customer that an owner can rewrite an object's permissions has to know whether this
/// forest did.
/// </para>
/// <para>
/// <b>It is deliberately not the answer on its own, and this is the whole reason the type exists
/// rather than a bare <c>bool</c>.</b> The heuristic is one of three conditions, and the other two
/// depend on the object and the owner rather than on the forest -
/// <see cref="DirectoryHeuristics.BlocksImplicitOwnerRights"/> puts all three together. Handing
/// back "owner rights are blocked" from the forest setting alone would be true of a computer object
/// and false of the organizational unit beside it.
/// </para>
/// </remarks>
/// <param name="Value">
/// The heuristic's numeric value, after the specification's own fallbacks. Null only where nothing
/// was read.
/// </param>
/// <param name="Outcome">Whether the character was stated, defaulted or never read.</param>
/// <param name="Character">
/// The character the value was resolved from, kept so an operator can check this product against
/// what the directory holds. Null only where nothing was read.
/// </param>
public sealed record OwnerImplicitRightsSetting(
    int? Value,
    HeuristicReadOutcome Outcome,
    char? Character)
{
    /// <summary>Whether the forest was asked and answered.</summary>
    public bool IsComplete => Outcome is HeuristicReadOutcome.Stated
        or HeuristicReadOutcome.DefaultedByAbsence;

    /// <summary>
    /// Whether this setting blocks an owner's implicit rights, taking the forest's part of the
    /// question alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Only the value 1 blocks, and 2 and 3 do not.</b> MS-ADTS 6.1.3.4 names the blocking
    /// condition as the heuristic being set to 1. The higher values are settings of the same
    /// heuristic that do not block, so reading this as "anything above zero is hardened" would be
    /// wrong in the direction that hides a real capability.
    /// </para>
    /// <para>
    /// <b>The specification also blocks on 0 for Windows 11 version 26H1, and this deliberately
    /// does not.</b> Nothing captured says which build serves the forest, and 0 is the documented
    /// default of every forest that has never set the attribute. Treating 0 as blocking would
    /// silence the owner question across essentially every directory this product will ever be
    /// pointed at, on the strength of a build that is not a domain controller operating system.
    /// The limit is real and is recorded rather than hidden: on a 26H1 server this answers
    /// <c>false</c> where the platform would block.
    /// </para>
    /// </remarks>
    public bool BlocksWhereItApplies => Value == 1;
}

/// <summary>
/// Reads the forest-wide settings held one per character position in <c>dSHeuristics</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Each position is a separate setting, and the string is not a number.</b> The attribute is a
/// Unicode string on the forest's one <c>nTDSService</c> object, and
/// <see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5">MS-ADTS
/// 6.1.1.2.4.1.2</see> gives each character its own meaning. Position 16 decides which groups
/// AdminSDHolder protects; position 12 decides whether descriptors are standardised; position 29
/// decides whether an owner's implicit rights are blocked. They share nothing but a string.
/// </para>
/// <para>
/// <b>Positions are one-based, because Microsoft numbers them that way.</b> Converting to a
/// zero-based index at the boundary and keeping Microsoft's numbering in the API means a reader
/// comparing this against the specification is comparing like with like. The alternative - exposing
/// index 15 for character 16 - is an off-by-one waiting to be written down as correct.
/// </para>
/// <para>
/// <b>It resolves two settings, not all thirty-one.</b> <c>dwAdminSDExMask</c> and
/// <c>BlockOwnerImplicitRights</c> have consumers; the rest are reachable through
/// <see cref="CharacterAt"/> when something needs them, and building an accessor for each now
/// would shape thirty types against no caller.
/// </para>
/// </remarks>
public static class DirectoryHeuristics
{
    /// <summary>
    /// The value every character takes when the string ends before it, per MS-ADTS: "unless
    /// otherwise specified, the default value of each character in the dSHeuristics string is 0".
    /// </summary>
    /// <remarks>
    /// <b>Two characters document a different default and neither is read here.</b>
    /// <c>fLDAPBlockAnonOps</c> at position 7 defaults by DC functional level, and
    /// <c>fUserPwdSupport</c> at position 9 differs between AD DS and AD LDS. A caller reaching for
    /// either through <see cref="CharacterAt"/> must apply its own rule; this constant is the
    /// general case and is not a claim about those two.
    /// </remarks>
    public const char DocumentedDefault = '0';

    /// <summary>The position of <c>dwAdminSDExMask</c>, which decides the protected set.</summary>
    public const int AdminSdExMaskPosition = 16;

    /// <summary>
    /// The position of <c>BlockOwnerImplicitRights</c>, which decides whether an owner keeps the
    /// rights nobody granted them.
    /// </summary>
    public const int BlockOwnerImplicitRightsPosition = 29;

    /// <summary>
    /// Reads one character by its MS-ADTS position.
    /// </summary>
    /// <param name="dsHeuristics">
    /// The attribute's value, or null where it was never read. An empty string is a read that found
    /// nothing, which is different from null and is treated as the specification treats it: every
    /// character defaults.
    /// </param>
    /// <param name="position">The one-based character position.</param>
    /// <returns>The character, and whether it was stated, defaulted or never read.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The position is not one-based and positive.</exception>
    public static HeuristicCharacter CharacterAt(string? dsHeuristics, int position)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(position, 1);

        if (dsHeuristics is null)
            return new HeuristicCharacter(position, null, HeuristicReadOutcome.NotRead);

        // Past the end of the string is a normal state, not an error: the order of the characters
        // is fixed and truncation is the only way to omit one, so every string is a prefix of a
        // longer one that was never written.
        if (position > dsHeuristics.Length)
        {
            return new HeuristicCharacter(
                position, DocumentedDefault, HeuristicReadOutcome.DefaultedByAbsence);
        }

        return new HeuristicCharacter(
            position, dsHeuristics[position - 1], HeuristicReadOutcome.Stated);
    }

    /// <summary>
    /// Resolves <c>dwAdminSDExMask</c> into the operator groups the forest has stopped protecting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The character is a hex digit, not a number.</b> MS-ADTS: "The valid values for this
    /// character are from the set 0-9 and a-f. The dwAdminSDExMask heuristic equals the character
    /// interpreted as a hex digit and converted into a 4-bit value." So <c>'c'</c> is twelve and
    /// excludes two groups, where reading it as a decimal digit would fail and reading it as a
    /// character code would exclude nothing.
    /// </para>
    /// <para>
    /// <b>A character outside that set excludes nothing, and says so.</b> The specification defines
    /// no behaviour for one, and this product's error is asymmetric: reporting a group as
    /// unprotected when it is protected is a false alarm an operator can check, but reporting one
    /// as protected when it is not is a hole nobody is told about. Refusing to resolve a character
    /// nobody documented keeps the protected set at its published size, which is the direction that
    /// cannot hide a group.
    /// </para>
    /// </remarks>
    /// <param name="dsHeuristics">
    /// The attribute's value, or null where it was never read.
    /// </param>
    /// <returns>The excluded groups, and whether the forest was asked and answered.</returns>
    public static AdminSdExclusionMask AdminSdExclusions(string? dsHeuristics)
    {
        var character = CharacterAt(dsHeuristics, AdminSdExMaskPosition);

        if (character.Outcome == HeuristicReadOutcome.NotRead)
            return new AdminSdExclusionMask([], HeuristicReadOutcome.NotRead, Character: null);

        var digit = character.Value!.Value;

        // Uri.FromHex would throw on an undocumented character, and throwing is the wrong answer:
        // a forest is allowed to hold a value nobody planned for, and this product's job is to
        // report what it found rather than to fail on it.
        var mask = HexValueOf(digit);

        if (mask is null)
        {
            return new AdminSdExclusionMask(
                [], HeuristicReadOutcome.Malformed, digit);
        }

        var excluded = new List<AdminSdExcludableGroup>();

        if ((mask & 0x1) != 0) excluded.Add(AdminSdExcludableGroup.AccountOperators);
        if ((mask & 0x2) != 0) excluded.Add(AdminSdExcludableGroup.ServerOperators);
        if ((mask & 0x4) != 0) excluded.Add(AdminSdExcludableGroup.PrintOperators);
        if ((mask & 0x8) != 0) excluded.Add(AdminSdExcludableGroup.BackupOperators);

        return new AdminSdExclusionMask(excluded, character.Outcome, digit);
    }

    /// <summary>
    /// Resolves <c>BlockOwnerImplicitRights</c> into the forest's setting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The specification states its own fallbacks, and they are not the ones used elsewhere in
    /// this file.</b> MS-ADTS 6.1.1.2.4.1.2: <i>"If this character is '0', '1', '2', or '3' the
    /// BlockOwnerImplicitRights heuristic is set to the equivalent numeric value. If this character
    /// is not set, the heuristic defaults to 0. If this character has any other value, the heuristic
    /// defaults to 1."</i> So an unreadable character is not a refusal here the way it is for
    /// <see cref="AdminSdExclusions"/> - Microsoft documents what the server does with it, and what
    /// the server does is block. The outcome is still reported as
    /// <see cref="HeuristicReadOutcome.Malformed"/> so a caller can see that the forest wrote
    /// something nobody planned for, but the value follows the platform rather than this product's
    /// preference.
    /// </para>
    /// <para>
    /// <b>Defaulting a junk character to 1 lands on the safe side by luck rather than by design,
    /// and it is worth saying which.</b> 1 is the blocking value, so a malformed character makes
    /// this product quieter, not louder. That is the direction that hides a capability rather than
    /// inventing one - normally the worse direction - but it is what the platform does, and a rule
    /// that departed from the platform would be describing a forest that does not exist.
    /// </para>
    /// </remarks>
    /// <param name="dsHeuristics">The attribute's value, or null where it was never read.</param>
    /// <returns>The setting, and whether the forest was asked and answered.</returns>
    public static OwnerImplicitRightsSetting OwnerImplicitRights(string? dsHeuristics)
    {
        var character = CharacterAt(dsHeuristics, BlockOwnerImplicitRightsPosition);

        if (character.Outcome == HeuristicReadOutcome.NotRead)
            return new OwnerImplicitRightsSetting(Value: null, HeuristicReadOutcome.NotRead, null);

        var stated = character.Value!.Value;

        return stated switch
        {
            >= '0' and <= '3' => new OwnerImplicitRightsSetting(
                stated - '0', character.Outcome, stated),

            // Documented, not invented: any other character defaults the heuristic to 1.
            _ => new OwnerImplicitRightsSetting(1, HeuristicReadOutcome.Malformed, stated),
        };
    }

    /// <summary>
    /// Whether an owner's implicit <c>READ_CONTROL</c> and <c>WRITE_DAC</c> are blocked for one
    /// object and one owner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Three conditions, and all three must hold.</b> MS-ADTS 6.1.3.4 lists them together: the
    /// heuristic blocks, the owner is in neither Domain Admins nor Enterprise Admins, and the
    /// object's class is <c>computer</c> or derives from it. A forest that sets the heuristic has
    /// not switched owner rights off across the directory - it has switched them off for computer
    /// objects owned by people who are not forest or domain administrators.
    /// </para>
    /// <para>
    /// <b>Why this is a method and not three checks at each call site.</b> Two rules need this
    /// answer and each would otherwise carry its own copy of a condition that is easy to state
    /// incompletely - and stating it incompletely is exactly the defect this exists to fix.
    /// Treating the heuristic alone as the answer would make a rule silent about every
    /// organizational unit, group and user in a hardened forest, hiding real latent authority
    /// behind a setting that never applied to them.
    /// </para>
    /// </remarks>
    /// <param name="setting">The forest's setting, from <see cref="OwnerImplicitRights"/>.</param>
    /// <param name="objectIsComputerClass">
    /// Whether the object's class is <c>computer</c> or derived from it. The caller decides this,
    /// because resolving a class hierarchy needs the forest's schema and this type holds no schema.
    /// </param>
    /// <param name="ownerIsDomainOrEnterpriseAdmin">
    /// Whether the owner is a member of Domain Admins or Enterprise Admins - those two groups
    /// specifically, and not administrative standing in the wider sense, because those two are what
    /// the specification names.
    /// </param>
    public static bool BlocksImplicitOwnerRights(
        OwnerImplicitRightsSetting setting,
        bool objectIsComputerClass,
        bool ownerIsDomainOrEnterpriseAdmin)
    {
        ArgumentNullException.ThrowIfNull(setting);

        return setting.BlocksWhereItApplies
            && objectIsComputerClass
            && !ownerIsDomainOrEnterpriseAdmin;
    }

    /// <summary>
    /// The four-bit value of one hex digit, or null where the character is not one.
    /// </summary>
    /// <remarks>
    /// Upper case is accepted although MS-ADTS names only <c>a</c>-<c>f</c>: the string is written
    /// by administrators through <c>ldp.exe</c> and the directory stores what it is given, so a
    /// forest holding <c>F</c> is a forest this product should read rather than refuse.
    /// </remarks>
    private static int? HexValueOf(char digit) => digit switch
    {
        >= '0' and <= '9' => digit - '0',
        >= 'a' and <= 'f' => digit - 'a' + 10,
        >= 'A' and <= 'F' => digit - 'A' + 10,
        _ => null,
    };
}

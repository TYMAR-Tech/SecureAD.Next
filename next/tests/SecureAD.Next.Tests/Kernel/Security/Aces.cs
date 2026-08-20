using SecureAD.Kernel.Security;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Constructors for already-parsed ACEs, so the normalisation tests can state the case they are
/// about without assembling bytes for it. Parsing is tested separately, by
/// <see cref="SecurityDescriptorParserTests"/>.
/// </summary>
internal static class Aces
{
    /// <summary>An explicit or inherited ACCESS_ALLOWED ACE for a trustee.</summary>
    public static ParsedAce Allow(string sid, int mask, bool inherited = false) =>
        new(AceType.AccessAllowed, InheritedFlag(inherited), mask, sid,
            null, null, inherited, 0, 0, Ordinal: 0, ObjectFlags: 0, ApplicationData: []);

    /// <summary>An explicit or inherited ACCESS_DENIED ACE for a trustee.</summary>
    public static ParsedAce Deny(string sid, int mask, bool inherited = false) =>
        new(AceType.AccessDenied, InheritedFlag(inherited), mask, sid,
            null, null, inherited, 0, 0, Ordinal: 0, ObjectFlags: 0, ApplicationData: []);

    /// <summary>A descriptor with a present DACL holding the given ACEs and no parse errors.</summary>
    /// <remarks>
    /// The declared count is the number of entries given, because a fixture built by hand has read
    /// everything it declared. Canonical order is judged from the entries rather than asserted, so
    /// a fixture written deliberately out of order carries <c>false</c> without the author having
    /// to remember - which is what a test for non-canonical handling needs.
    ///
    /// <para>
    /// Ordinals are stamped here rather than asked of the caller, for the same reason: the order
    /// the entries are written in <i>is</i> the order the directory stored them, so a fixture
    /// cannot claim a stored position it does not occupy.
    /// </para>
    /// </remarks>
    public static ParsedSecurityDescriptor Sd(params ParsedAce[] aces)
    {
        var stored = aces.Select((ace, index) => ace with { Ordinal = index }).ToArray();

        return new(
            "S-1-5-18", "S-1-5-32-544", DaclState.Present, false, stored, 0x8004, [],
            DaclCompleteness: DaclCompleteness.Complete,
            DaclWasCanonical: AceCanonicalization.IsCanonicalOrder(stored));
    }

    private static byte InheritedFlag(bool inherited) => inherited ? (byte)0x10 : (byte)0x00;
}

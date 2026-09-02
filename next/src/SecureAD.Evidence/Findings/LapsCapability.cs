using System.Globalization;

namespace SecureAD.Evidence.Findings;

/// <summary>
/// Which Local Administrator Password Solution a machine is capable of running.
/// </summary>
public enum LapsCapabilityKind
{
    /// <summary>
    /// Nothing in the evidence says what this machine is, so nothing can be expected of it.
    /// </summary>
    Unknown,

    /// <summary>
    /// Too old for Windows LAPS. Legacy Microsoft LAPS is the only option Microsoft ever shipped
    /// for it, so the absence of a modern timestamp says nothing about the machine.
    /// </summary>
    LegacyLapsOnly,

    /// <summary>
    /// Capable of running Windows LAPS, so Microsoft's own success signal - the appearance of
    /// <c>msLAPS-PasswordExpirationTime</c> - is a thing that can reasonably be expected.
    /// </summary>
    WindowsLapsCapable,
}

/// <summary>
/// How the capability was decided, which travels in the finding so a reader can weigh it.
/// </summary>
public enum LapsCapabilityBasis
{
    /// <summary>Neither the operating system name nor its version was present.</summary>
    NothingToReadFrom,

    /// <summary>
    /// The operating system name only. A bundle sealed before the build number was captured -
    /// catalogue version 5 or earlier - can be judged no other way.
    /// </summary>
    OperatingSystemName,

    /// <summary>
    /// The build number, with the name supplying only the family. The reliable answer.
    /// </summary>
    OperatingSystemVersion,
}

/// <summary>
/// What LAPS product a computer could run, and what that answer rests on.
/// </summary>
/// <remarks>
/// <para>
/// <b>The basis travels with the answer, rather than the answer travelling alone.</b> Gate 4 refuses
/// a bare value from a type that cannot say whether it looked, and this is the same principle for a
/// classification: <see cref="LapsCapabilityKind.WindowsLapsCapable"/> decided from a build number
/// and the same value guessed from a name string are not equally good, and a finding that reports
/// only the conclusion lets a reader believe they are.
/// </para>
/// <para>
/// <b>That is <c>docs/decisions/0086</c> applied to a classification</b> - say what you know, with
/// its uncertainty. A bundle stamped at catalogue version 5 still yields findings; they simply
/// record that the capability came from a name.
/// </para>
/// <para>
/// <b>Unknown is a real answer and is never quietly turned into a capability.</b> SEC-091 reports an
/// unknown machine carrying no timestamps, because *no LAPS at all* is worth reporting whatever the
/// machine is. SEC-094 stays silent about one, because its whole claim is that this machine could be
/// running Windows LAPS - which cannot be said about a machine nobody can identify.
/// </para>
/// </remarks>
/// <param name="Kind">What the machine can run.</param>
/// <param name="Basis">What that rests on.</param>
/// <param name="Name">The operating system name as read, or null.</param>
/// <param name="Version">The operating system version as read, or null.</param>
public sealed record LapsCapability(
    LapsCapabilityKind Kind,
    LapsCapabilityBasis Basis,
    string? Name,
    string? Version)
{
    /// <summary>
    /// Whether the machine is a Windows Server, by the only signal the directory offers.
    /// </summary>
    /// <remarks>
    /// Null where there is no name to read. See <see cref="LapsPlatformCatalog.ServerNameMarker"/>
    /// for why a name is the only available answer.
    /// </remarks>
    public bool? IsServer =>
        string.IsNullOrWhiteSpace(Name)
            ? null
            : Name.Contains(LapsPlatformCatalog.ServerNameMarker, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads the capability from a captured computer object.
    /// </summary>
    /// <param name="subject">The object to classify.</param>
    public static LapsCapability Of(ObjectAttributes subject)
    {
        ArgumentNullException.ThrowIfNull(subject);

        var name = AttributeReading.Text(subject, "operatingSystem");
        var version = AttributeReading.Text(subject, "operatingSystemVersion");

        var isServer = string.IsNullOrWhiteSpace(name)
            ? (bool?) null
            : name.Contains(LapsPlatformCatalog.ServerNameMarker, StringComparison.OrdinalIgnoreCase);

        // The build number is the reliable answer, but it cannot tell a client from a server on its
        // own - Windows 10 1607 and Server 2016 are both 14393 - so it is only used where the name
        // has supplied the family.
        if (isServer is { } server && TryReadVersion(version, out var major, out var build))
        {
            var kind = server
                ? build >= LapsPlatformCatalog.FirstWindowsLapsServerBuild
                    ? LapsCapabilityKind.WindowsLapsCapable
                    : LapsCapabilityKind.LegacyLapsOnly
                : major >= LapsPlatformCatalog.FirstWindowsLapsClientMajorVersion
                    ? LapsCapabilityKind.WindowsLapsCapable
                    : LapsCapabilityKind.LegacyLapsOnly;

            return new LapsCapability(
                kind, LapsCapabilityBasis.OperatingSystemVersion, name, version);
        }

        if (!string.IsNullOrWhiteSpace(name))
        {
            return new LapsCapability(
                FromName(name), LapsCapabilityBasis.OperatingSystemName, name, version);
        }

        return new LapsCapability(
            LapsCapabilityKind.Unknown, LapsCapabilityBasis.NothingToReadFrom, name, version);
    }

    /// <summary>
    /// The fallback for a bundle sealed before the build number was captured.
    /// </summary>
    /// <remarks>
    /// <b>Deliberately coarse, and it answers Unknown rather than guessing.</b> This is the
    /// predecessor's technique and it is kept only because a bundle stamped at catalogue version 5
    /// offers nothing else. Its faults are why the build number is captured: it cannot read a
    /// localised name, and it cannot classify a release nobody added a string for. Where it cannot
    /// tell, it says so, and the caller decides - which is what the predecessor did not do.
    /// </remarks>
    private static LapsCapabilityKind FromName(string name)
    {
        // Windows LAPS: Server 2019 and later, and Windows 10 and 11 clients.
        if (Mentions(name, "2019") || Mentions(name, "2022") || Mentions(name, "2025")
            || Mentions(name, "Windows 11") || Mentions(name, "Windows 10"))
        {
            return LapsCapabilityKind.WindowsLapsCapable;
        }

        // Legacy Microsoft LAPS runs on these; Windows LAPS was never shipped for them. The
        // predecessor classed 2012 and earlier as "not applicable", which reported nothing about a
        // large slice of a real estate where LAPS applies perfectly well.
        if (Mentions(name, "2016") || Mentions(name, "2012") || Mentions(name, "2008")
            || Mentions(name, "2003") || Mentions(name, "Windows 7") || Mentions(name, "Windows 8"))
        {
            return LapsCapabilityKind.LegacyLapsOnly;
        }

        return LapsCapabilityKind.Unknown;
    }

    private static bool Mentions(string name, string fragment) =>
        name.Contains(fragment, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads <c>10.0 (20348)</c>, the shape Active Directory stores.
    /// </summary>
    /// <remarks>
    /// The build is in parentheses and is what decides a server; the leading major version is what
    /// decides a client, because every Windows LAPS-capable client is major version 10 and every
    /// older one is not. A value carrying no build - some machines report only <c>10.0</c> - still
    /// yields a major version, so a client is classifiable from it and a server is not.
    /// </remarks>
    private static bool TryReadVersion(string? value, out int major, out int build)
    {
        major = 0;
        build = 0;

        if (string.IsNullOrWhiteSpace(value)) return false;

        var open = value.IndexOf('(', StringComparison.Ordinal);
        var close = value.IndexOf(')', StringComparison.Ordinal);

        if (open >= 0 && close > open)
        {
            _ = int.TryParse(
                value.AsSpan(open + 1, close - open - 1).Trim(),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out build);
        }

        var head = open >= 0 ? value.AsSpan(0, open) : value.AsSpan();
        var dot = head.IndexOf('.');
        var majorText = dot >= 0 ? head[..dot] : head;

        return int.TryParse(
            majorText.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out major);
    }
}

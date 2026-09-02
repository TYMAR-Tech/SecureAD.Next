namespace SecureAD.Evidence.Findings;

/// <summary>
/// The operating system build numbers that decide which Local Administrator Password Solution a
/// machine can run.
/// </summary>
/// <remarks>
/// <para>
/// <b>Its own type, so the exemption is granted to the table and not to the rules.</b> Gate 4's
/// exemption is per type, and folding these constants into <see cref="LapsCapability"/> would exempt
/// the classifying as well as the table. <c>PrivilegedSidCatalogue</c> is separate from
/// <c>PrivilegedSidHistory</c> for the same reason.
/// </para>
/// <para>
/// <b>Every value here is Microsoft's, and a test checks them against Microsoft rather than against
/// another copy of this file.</b> A rule with no predecessor card has no internal anchor, and
/// <c>F-S44-2</c> records what a set of internally consistent checks is worth: SEC-027's positive
/// tests all passed while the rule and its tests shared one mistake.
/// </para>
/// <para>
/// <b>Why a build number and not the operating system name.</b> The predecessor classified by
/// matching the name - <c>LIKE '%2019%'</c>, <c>LIKE '%2016%'</c> - which its own backlog flagged as
/// brittle under <c>[IMP-OS-CLASSIFIER]</c>. It broke on localised names, on any release nobody had
/// added a string for, and it under-reported twice: Windows 10 was classed as *not applicable* when
/// Microsoft supports Windows LAPS on it, and Server 2012 was classed the same when legacy LAPS runs
/// on it. A build number has none of those faults.
/// </para>
/// <para>
/// <b>Why the name is still needed.</b> Windows 10 1607 and Windows Server 2016 are <b>both build
/// 14393</b>. The build cannot tell a client from a server, so the family comes from the name and
/// the generation from the build. Either alone gives a wrong answer, which is why capture takes
/// both.
/// </para>
/// </remarks>
public static class LapsPlatformCatalog
{
    /// <summary>
    /// Windows Server 2019, the first Windows Server release Windows LAPS was shipped for.
    /// </summary>
    /// <remarks>
    /// Microsoft lists the supported platforms as Windows Server 2025 and later, Windows Server
    /// Annual Channel 23H2 and later, and "other versions of Windows Server that have received the
    /// April 11, 2023 Update or later, including Windows Server 2022 and Windows Server 2019".
    /// Server 2016 is absent from that list and Windows LAPS was never backported to it.
    /// </remarks>
    public const int FirstWindowsLapsServerBuild = 17763;

    /// <summary>
    /// Windows 10, the first Windows client generation Windows LAPS was shipped for.
    /// </summary>
    /// <remarks>
    /// Microsoft lists Windows 11 23H2 and later, and "other versions of Windows client that have
    /// received the April 11, 2023 Update or later, including Windows 11 22H2, Windows 11 21H2 and
    /// Windows 10". Every one of those carries a major version of 10, and every Windows client older
    /// than Windows 10 carries a lower one.
    /// </remarks>
    public const int FirstWindowsLapsClientMajorVersion = 10;

    /// <summary>
    /// Windows Server 2016, and Windows 10 1607. One build number, two operating systems.
    /// </summary>
    /// <remarks>
    /// Held as a constant because it is the reason this product captures the operating system name
    /// as well as its version, and because a test asserts the collision rather than leaving it as a
    /// remark somebody could delete.
    /// </remarks>
    public const int SharedServer2016AndWindows10Build = 14393;

    /// <summary>
    /// The word that distinguishes a Windows Server operating system name from a client one.
    /// </summary>
    /// <remarks>
    /// <b>The weakest thing here, and it is used only for the family.</b> Microsoft publishes no
    /// directory attribute stating whether a machine is a client or a server:
    /// <c>userAccountControl</c> marks a laptop and a member server alike with
    /// <c>WORKSTATION_TRUST_ACCOUNT</c>, and only a domain controller differs. So the name is the
    /// only available answer, and it decides the family and nothing else - the generation always
    /// comes from the build number where one is present.
    /// </remarks>
    public const string ServerNameMarker = "Server";
}

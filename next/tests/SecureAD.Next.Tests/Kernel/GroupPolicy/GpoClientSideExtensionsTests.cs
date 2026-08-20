using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public class GpoClientSideExtensionsTests
{
    // Real-world gPCMachineExtensionNames groups. The first GUID in each [..] group is the CSE;
    // the second is the snap-in/tool GUID (ignored for filtering).
    private const string RegistryGroup = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
    private const string SecurityGroup = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]";
    // Folder Redirection CSE — not analyzed by SecureAD.
    private const string FolderRedirectionGroup = "[{25537BA6-77A8-11D2-9B6C-0000F8080861}{88E729D6-BDC1-11D1-BD2A-00C04FB9603F}]";

    // --- ParseCseGuids ---

    [Fact]
    public void WhenNull_ThenNoGuids()
    {
        Assert.Empty(GpoClientSideExtensions.ParseCseGuids(null).Cses);
    }

    [Fact]
    public void WhenEmpty_ThenNoGuids()
    {
        Assert.Empty(GpoClientSideExtensions.ParseCseGuids("").Cses);
    }

    [Fact]
    public void WhenSingleRegistryGroup_ThenReturnsRegistryCse()
    {
        var cses = GpoClientSideExtensions.ParseCseGuids(RegistryGroup).Cses;

        var cse = Assert.Single(cses);
        Assert.Equal(GpoClientSideExtensionCatalog.RegistryCse, cse);
    }

    [Fact]
    public void WhenMultipleGroups_ThenReturnsFirstGuidOfEach()
    {
        var value = RegistryGroup + SecurityGroup;

        var cses = GpoClientSideExtensions.ParseCseGuids(value).Cses;

        Assert.Equal(2, cses.Count);
        Assert.Contains(GpoClientSideExtensionCatalog.RegistryCse, cses);
        Assert.Contains(GpoClientSideExtensionCatalog.SecurityCse, cses);
    }

    [Fact]
    public void WhenGroupHasMultipleGuids_ThenOnlyFirstIsTreatedAsCse()
    {
        // The second GUID in the group is a tool GUID and must not be returned as a CSE.
        var cses = GpoClientSideExtensions.ParseCseGuids(RegistryGroup).Cses;

        Assert.DoesNotContain(new Guid("D02B1F72-3407-48AE-BA88-E8213C6761F1"), cses);
    }

    [Fact]
    public void WhenDuplicateCseGroups_ThenDeduplicated()
    {
        var value = RegistryGroup + RegistryGroup;

        var cses = GpoClientSideExtensions.ParseCseGuids(value).Cses;

        Assert.Single(cses);
    }

    [Fact]
    public void WhenMalformedTokens_ThenSkippedWithoutThrowing()
    {
        var value = "[{not-a-guid}{also-bad}]" + RegistryGroup;

        var cses = GpoClientSideExtensions.ParseCseGuids(value).Cses;

        Assert.Single(cses);
        Assert.Equal(GpoClientSideExtensionCatalog.RegistryCse, cses[0]);
    }

    [Fact]
    public void WhenMalformedTokens_ThenTheyAreRecordedRatherThanSkippedSilently()
    {
        var value = "[{not-a-guid}{also-bad}]" + RegistryGroup;

        var parsed = GpoClientSideExtensions.ParseCseGuids(value);

        var error = Assert.Single(parsed.Errors);
        Assert.Contains("not-a-guid", error, StringComparison.Ordinal);
    }

    [Fact]
    public void WhenEverythingParsed_ThenNoErrorsAreReported()
    {
        var parsed = GpoClientSideExtensions.ParseCseGuids(RegistryGroup + SecurityGroup);

        Assert.Empty(parsed.Errors);
    }

    [Fact]
    public void WhenAttributeIsAbsent_ThenNoErrorsAreReported()
    {
        // Declaring nothing is a fact about the GPO, not a failure to read it. If this reported an
        // error the permissive fetch below would become unconditional and the smart filter dead.
        Assert.Empty(GpoClientSideExtensions.ParseCseGuids(null).Errors);
    }

    [Fact]
    public void WhenCaseInsensitiveGuid_ThenParsed()
    {
        var lower = RegistryGroup.ToLowerInvariant();

        var cses = GpoClientSideExtensions.ParseCseGuids(lower).Cses;

        Assert.Contains(GpoClientSideExtensionCatalog.RegistryCse, cses);
    }

    // --- HasAnalyzableSettings (permissive fallback) ---

    [Fact]
    public void WhenNull_ThenAnalyzable_PermissiveFallback()
    {
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(null));
    }

    [Fact]
    public void WhenEmpty_ThenAnalyzable_PermissiveFallback()
    {
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(""));
    }

    [Fact]
    public void WhenWhitespace_ThenAnalyzable_PermissiveFallback()
    {
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings("   "));
    }

    [Fact]
    public void WhenRegistryCse_ThenAnalyzable()
    {
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(RegistryGroup));
    }

    [Fact]
    public void WhenSecurityCse_ThenAnalyzable()
    {
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(SecurityGroup));
    }

    [Fact]
    public void WhenAnalyzableMixedWithOther_ThenAnalyzable()
    {
        var value = FolderRedirectionGroup + SecurityGroup;

        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(value));
    }

    [Fact]
    public void WhenOnlyNonAnalyzableCse_ThenNotAnalyzable()
    {
        Assert.False(GpoClientSideExtensions.HasAnalyzableSettings(FolderRedirectionGroup));
    }

    [Fact]
    public void WhenMalformedOnly_ThenAnalyzable_PermissiveFallback()
    {
        // Nothing parses, so we cannot tell what the GPO contains — fetch it.
        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings("[{garbage}]"));
    }

    [Fact]
    public void WhenOneCseIsUnreadableBesideANonAnalyzableOne_ThenStillAnalyzable()
    {
        // The case the permissive fallback used to miss. One group parses to a CSE this product
        // does not analyse, so the list is not empty and the "nothing parsed" path never ran; the
        // other group is unreadable and could have been Registry or Security. Skipping the GPO on
        // that evidence would leave SEC-064, SEC-065, SEC-066 and SEC-093 silent about it, looking
        // exactly like a GPO that had been assessed and found clean.
        var value = FolderRedirectionGroup + "[{not-a-guid}{also-bad}]";

        Assert.True(GpoClientSideExtensions.HasAnalyzableSettings(value));
    }

    [Fact]
    public void WhenEveryCseIsReadableAndNoneAnalyzable_ThenStillNotAnalyzable()
    {
        // The other direction, so the fix above cannot pass by making the filter unconditional:
        // a fully readable attribute naming only extensions we do not parse still skips the GPO.
        Assert.False(GpoClientSideExtensions.HasAnalyzableSettings(FolderRedirectionGroup));
    }

    // --- Constants ---

    [Fact]
    public void WhenAnalyzableCses_ThenContainsRegistryAndSecurity()
    {
        Assert.Contains(GpoClientSideExtensionCatalog.RegistryCse, GpoClientSideExtensionCatalog.AnalyzableCses);
        Assert.Contains(GpoClientSideExtensionCatalog.SecurityCse, GpoClientSideExtensionCatalog.AnalyzableCses);
        Assert.Equal(2, GpoClientSideExtensionCatalog.AnalyzableCses.Count);
    }
}

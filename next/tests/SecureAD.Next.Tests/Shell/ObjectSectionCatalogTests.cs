using SecureAD.Kernel.Capture;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The gate on the object view: an attribute this product captures is either shown to an operator
/// or declared, in writing, as deliberately not shown.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the direction the catalogue's own documentation records as missing.</b>
/// <c>CapturedAttributeCatalogDocumentationTests</c> proves every captured attribute names a
/// consumer in prose, and its remarks say outright that nothing checks the opposite - whether
/// something that needs an attribute finds it - and calls that the direction with the one-way door
/// in it (<c>F-S7-24</c>, <c>F-S44-2</c>). A prose cell reading <i>Read by: SEC-091</i> is true the
/// day it is written and stays true after SEC-091 is abandoned.
/// </para>
/// <para>
/// <b>The state this exists to make impossible.</b> On 2026-08-13, <c>operatingSystem</c> and the
/// two LAPS expiry timestamps were added to capture for SEC-091 and SEC-092. Neither rule has been
/// written. So every bundle since carries three values for every computer in the forest that no
/// human being can see, and nothing in the build says so. Nobody finds that by reading; they find
/// it a year later and wonder whether capture is broken.
/// </para>
/// </remarks>
public sealed class ObjectSectionCatalogTests
{
    /// <summary>
    /// The classes an operator can open and this catalogue answers for. Read from the capture
    /// catalogue rather than listed, so a class added there cannot be forgotten here.
    /// </summary>
    public static TheoryData<string> OpenableClasses()
    {
        var classes = new TheoryData<string>();

        foreach (var name in CapturedAttributeCatalog.ObjectClasses)
            classes.Add(name);

        return classes;
    }

    [Theory]
    [MemberData(nameof(OpenableClasses))]
    public void EveryAttributeAClassJustifiesIsShownOrDeclaredNotShown(string objectClass)
    {
        var shown = ObjectSectionCatalog.AttributesShownFor(objectClass);

        var unaccounted = CapturedAttributeCatalog.AttributesJustifiedBy(objectClass)
            .Select(a => a.LdapDisplayName)
            .Where(name => !shown.Contains(name))
            .Where(name => !ObjectSectionCatalog.NotShown.ContainsKey(name))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unaccounted.Count == 0,
            $"'{objectClass}' justifies capturing attributes that no section of the object view "
            + "shows and that nothing declares as deliberately not shown. An attribute nobody can "
            + "see is bytes in every bundle forever that nobody will dare remove. Either give it a "
            + "section, or name it in ObjectSectionCatalog.NotShown with the reason:"
            + Environment.NewLine + string.Join(Environment.NewLine, unaccounted.Select(n => "  " + n)));
    }

    /// <summary>
    /// A declaration with no reason is an omission wearing a declaration's clothes.
    /// </summary>
    [Fact]
    public void EveryAttributeDeclaredNotShownGivesAReason()
    {
        var silent = ObjectSectionCatalog.NotShown
            .Where(entry => string.IsNullOrWhiteSpace(entry.Value))
            .Select(entry => "  " + entry.Key)
            .ToList();

        Assert.True(
            silent.Count == 0,
            "Attributes declared not shown without saying why:"
            + Environment.NewLine + string.Join(Environment.NewLine, silent));
    }

    /// <summary>
    /// The other direction, so the declaration list cannot outlive what it was about. An entry for
    /// an attribute capture no longer requests reads as a decision somebody made, and is not one.
    /// </summary>
    [Fact]
    public void NothingIsDeclaredNotShownThatIsNoLongerCaptured()
    {
        var captured = CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var stale = ObjectSectionCatalog.NotShown.Keys
            .Where(name => !captured.Contains(name))
            .Select(name => "  " + name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            stale.Count == 0,
            "Attributes declared not shown that capture no longer requests:"
            + Environment.NewLine + string.Join(Environment.NewLine, stale));
    }

    /// <summary>
    /// A class nothing anticipates still gets somewhere to be read, and its permissions - which are
    /// the thing this product assesses - are always among them.
    /// </summary>
    [Fact]
    public void AClassTheCatalogueDoesNotKnowStillGetsTheSectionsEveryObjectHas()
    {
        var sections = ObjectSectionCatalog.For("msExchDynamicDistributionList");

        Assert.Contains(sections, s => s.Key == ObjectSectionCatalog.Overview);
        Assert.Contains(sections, s => s.Key == ObjectSectionCatalog.Permissions);
    }

    /// <summary>
    /// An object whose class did not arrive is not a reason to show nothing.
    /// </summary>
    [Fact]
    public void AnObjectWithNoClassStillGetsSections()
    {
        Assert.NotEmpty(ObjectSectionCatalog.For(null));
    }

    /// <summary>
    /// Every class has a findings section, including ones the catalogue does not know.
    /// </summary>
    /// <remarks>
    /// <b>Not hidden when there are none, unlike LAPS on a user.</b> Hiding LAPS says something
    /// this product can defend - a user is not a thing LAPS applies to. <i>No findings</i> says
    /// nothing about what a class is: an object nothing was found about, an object nobody judged,
    /// and an object whose rules could not read what they needed are three different facts, and an
    /// absent section renders all three as silence. That is <c>docs/decisions/0002</c>.
    /// </remarks>
    [Theory]
    [InlineData("user")]
    [InlineData("computer")]
    [InlineData("group")]
    [InlineData("organizationalUnit")]
    [InlineData("groupPolicyContainer")]
    [InlineData("domainDNS")]
    [InlineData("msExchDynamicDistributionList")]
    [InlineData(null)]
    public void EveryClassHasAFindingsSection(string? objectClass)
    {
        Assert.Contains(
            ObjectSectionCatalog.For(objectClass),
            s => s.Key == ObjectSectionCatalog.Findings);
    }

    /// <summary>
    /// The findings section claims no attribute, so it cannot take one from another section.
    /// </summary>
    /// <remarks>
    /// A finding is not a value the directory gave. It is what a rule made of several, and it lives
    /// in another file entirely - so a findings section that claimed an attribute would be saying
    /// the attribute is shown there when it is not shown at all.
    /// </remarks>
    [Fact]
    public void TheFindingsSectionClaimsNoAttribute()
    {
        var findings = ObjectSectionCatalog.For("user")
            .Single(s => s.Key == ObjectSectionCatalog.Findings);

        Assert.Empty(findings.Attributes);
    }

    /// <summary>
    /// Curation may not hide a captured value. Because capture requests every attribute of every
    /// object whatever its class, an object can carry a value its class does not justify, and
    /// without somewhere for it to land a class-driven section list would silently drop it.
    /// </summary>
    [Fact]
    public void EveryClassHasSomewhereForValuesItsSectionsDoNotClaim()
    {
        foreach (var objectClass in CapturedAttributeCatalog.ObjectClasses)
        {
            Assert.Contains(
                ObjectSectionCatalog.For(objectClass),
                s => s.Key == ObjectSectionCatalog.OtherValues);
        }
    }

    /// <summary>
    /// How this run came by the object is the same question whatever the object is, so no class may
    /// be without it.
    /// </summary>
    [Fact]
    public void EveryClassCanBeAskedHowThisRunCameByTheObject()
    {
        foreach (var objectClass in CapturedAttributeCatalog.ObjectClasses)
        {
            Assert.Contains(
                ObjectSectionCatalog.For(objectClass),
                s => s.Key == ObjectSectionCatalog.Evidence);
        }
    }

    /// <summary>
    /// A credential is never captured, so no section may claim to show one. The guard on capture is
    /// <c>CredentialAttributeGuardTests</c>; this is the same rule stated where a screen could
    /// otherwise promise what the bundle does not hold.
    /// </summary>
    [Theory]
    [InlineData("ms-Mcs-AdmPwd")]
    [InlineData("msLAPS-Password")]
    [InlineData("msLAPS-EncryptedPassword")]
    [InlineData("unicodePwd")]
    public void NoSectionShowsACredential(string credential)
    {
        foreach (var objectClass in CapturedAttributeCatalog.ObjectClasses)
        {
            Assert.DoesNotContain(
                credential,
                ObjectSectionCatalog.AttributesShownFor(objectClass),
                StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// A section may only claim an attribute capture actually requests.
    /// </summary>
    /// <remarks>
    /// <b>The gate in the other direction, and the one that fails silently.</b> The existing gate
    /// proves every captured attribute reaches a section. This proves the reverse: a section
    /// claiming an attribute the catalogue does not request shows a row reading <i>not in this
    /// bundle</i> on every object in every forest forever, which is indistinguishable on screen
    /// from an attribute the run was refused. Nobody would find it by looking.
    /// </remarks>
    [Fact]
    public void NoSectionClaimsAnAttributeCaptureDoesNotRequest()
    {
        var requested = CapturedAttributeCatalog.All
            .Select(a => a.LdapDisplayName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var unrequested = CapturedAttributeCatalog.ObjectClasses
            .SelectMany(ObjectSectionCatalog.AttributesShownFor)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(a => !requested.Contains(a))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(
            unrequested.Count == 0,
            "Sections claim attributes capture never asks for, so their rows would read as an "
            + "absence in every bundle ever written: " + string.Join(", ", unrequested));
    }

    /// <summary>
    /// Every attribute a section claims has a label written for it.
    /// </summary>
    /// <remarks>
    /// <c>LabelFor</c> falls back to the attribute's own name so that a row is never blank, and
    /// that fallback is a safety net rather than a way of supplying labels: an unlabelled
    /// <c>gPCFileSysPath</c> on screen is this product asking an operator to know the schema. The
    /// gate turns the fallback into something that has to be chosen rather than reached by
    /// forgetting.
    /// </remarks>
    [Fact]
    public void EveryAttributeASectionShowsHasALabel()
    {
        var unlabelled = CapturedAttributeCatalog.ObjectClasses
            .SelectMany(ObjectSectionCatalog.AttributesShownFor)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(a => !ObjectSectionCatalog.Labels.ContainsKey(a))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(
            unlabelled.Count == 0,
            "Attributes shown with no label written for them, so they would appear under the "
            + "directory's own spelling: " + string.Join(", ", unlabelled));
    }

    /// <summary>
    /// A label for an attribute no section shows is a label for something nobody sees, and the
    /// first sign that a section was removed without its labels.
    /// </summary>
    [Fact]
    public void NoLabelIsWrittenForAnAttributeNoSectionShows()
    {
        var shown = CapturedAttributeCatalog.ObjectClasses
            .SelectMany(ObjectSectionCatalog.AttributesShownFor)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var orphaned = ObjectSectionCatalog.Labels.Keys
            .Where(a => !shown.Contains(a))
            .OrderBy(a => a, StringComparer.OrdinalIgnoreCase)
            .ToList();

        Assert.True(
            orphaned.Count == 0,
            "Labels written for attributes no section shows: " + string.Join(", ", orphaned));
    }
}

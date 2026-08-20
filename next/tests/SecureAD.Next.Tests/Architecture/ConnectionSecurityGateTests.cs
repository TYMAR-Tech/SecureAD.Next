using System.Text.RegularExpressions;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Inventory row A2's boundary: one place opens a connection, one place decides how well protected it
/// is, and nothing anywhere binds in a way that puts a credential on the wire in clear text.
///
/// <para>
/// <b>What this catches.</b> The connection is the only moment in the whole product at which a
/// customer's credentials and a customer's evidence cross a network. Everything downstream reads a
/// file. So a second place that opens a connection is not a duplication - it is a second answer to
/// "how protected was this", made by somebody who was solving a different problem, and there is
/// nothing later in the run that could notice. The referral policy has a guard of this shape for
/// the identical reason, and both are gate 1's shape rather than gate 1 itself: a correct
/// mechanism, with a boundary obliging its use.
/// </para>
/// <para>
/// <b>Why a source scan rather than reflection.</b> The subject is a syntax form that must not
/// exist. Reflection can only inspect what compiled, and it cannot say where a constructor was
/// called - the same choice, for the same reason, as <see cref="DirectorySearchGateTests"/>.
/// </para>
/// <para>
/// <b>What it cannot do.</b> It cannot prove a connection is ever opened, or that the one opened
/// climbed the ladder correctly at run time against a real controller. The first is gate 5b, which
/// needs an entry point and still has none. The second needs a domain controller, which no build
/// agent has, and is the lab obligation inventory row B20 carries. Both halves are recorded rather
/// than implied, because a guard that quietly suggested it had proved the whole thing is how gate
/// 5's original wording came to pass against a tree in which nothing was reachable at all.
/// </para>
/// </summary>
public sealed class ConnectionSecurityGateTests
{
    /// <summary>The one file allowed to open a connection or set a transport-security option.</summary>
    private const string Factory = "LdapDirectoryChannelFactory.cs";

    /// <summary>Opening a connection to a domain controller.</summary>
    private static readonly Regex ConnectionConstruction =
        new(@"\bnew\s+LdapConnection\b", RegexOptions.Compiled);

    /// <summary>
    /// Assigning any of the three things that decide how protected a channel is. Written as an
    /// assignment rather than a bare mention so that reading the level back - which the channel
    /// does, and must - is not an offence.
    /// </summary>
    private static readonly Regex TransportSecurityAssignment =
        new(@"\b(SecureSocketLayer|Signing|Sealing)\s*=[^=]", RegexOptions.Compiled);

    /// <summary>
    /// Any authentication type that is not Negotiate. None may appear anywhere in production,
    /// including inside the factory: there is one authentication mode and there is no rung of the
    /// ladder on which a credential crosses the wire in clear text.
    /// </summary>
    private static readonly Regex NonNegotiateAuthType =
        new(@"\bAuthType\.(?!Negotiate\b)\w+", RegexOptions.Compiled);

    [Fact]
    public void OnlyTheFactoryOpensAConnection()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), ConnectionConstruction)
            .Where(o => !IsFactory(o.File))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "A connection to a domain controller is opened outside " + Factory + ". Every "
            + "connection walks the ladder recorded at docs/decisions/0018, and the rung it lands "
            + "on decides whether a customer's evidence could have been altered in transit. A "
            + "second place that opens one is a second ladder, and nothing later in a run could "
            + "notice they disagreed:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    [Fact]
    public void OnlyTheFactoryDecidesHowProtectedAChannelIs()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), TransportSecurityAssignment)
            .Where(o => !IsFactory(o.File))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Transport security assigned outside " + Factory + ". The level a connection reached "
            + "is reported and recorded, never adjusted:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    [Fact]
    public void NothingEverBindsWithAnythingButNegotiate()
    {
        var offenders = RebuildTree
            .ScanPattern(RebuildTree.ProductionFiles(), NonNegotiateAuthType)
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "An authentication type other than Negotiate appears in production code. Microsoft's "
            + "account of a simple bind on port 389 is that \"There's no security for these "
            + "sessions. This is because credentials are transmitted in clear text\". A tool that "
            + "reads permissions on credential material cannot arrive at a customer's domain "
            + "controller carrying their administrative password in the open:"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// The ladder is a list, and the list is the whole of it. A rung added to the enumeration and
    /// not to the list, or the reverse, would leave the product climbing one ladder and reporting
    /// another - and the reporting half is what a customer reads.
    /// </summary>
    [Fact]
    public void EveryNamedLevelIsARungAndEveryRungIsANamedLevel()
    {
        var named = Enum.GetValues<ConnectionSecurityLevel>();
        var rungs = ConnectionSecurityLadder.Rungs.Select(r => r.Level).ToList();

        Assert.Equal(named.Length, rungs.Count);
        Assert.Equal(named, rungs);
    }

    /// <summary>
    /// The scanner self-test. Without it all three checks above pass by scanning an empty set of
    /// files and finding no offenders - the failure this repository has committed three times.
    ///
    /// <para>
    /// It asserts quantities rather than that something was read, which is the lesson F-S7-43
    /// records: a scanner keyed to a syntax form is keyed to a decision somebody is free to change,
    /// and only a floor on what it finds catches the day they do.
    /// </para>
    /// </summary>
    [Fact]
    public void TheScannerReadsTheFactoryAndItsPatternsMatch()
    {
        var production = RebuildTree.ProductionFiles().ToList();
        Assert.True(production.Count > 20, $"Scanned only {production.Count} production files.");

        var factories = production.Where(IsFactory).ToList();
        Assert.True(
            factories.Count == 1,
            $"Expected exactly one {Factory} in the rebuild, found {factories.Count}. Two of the "
            + "checks here exempt that file by name, so a rename would leave them policing a tree "
            + "with no mechanism in it and reporting it clean.");

        // The factory must actually contain the constructs the first two checks permit only in it.
        // Four transport assignments, because the ladder sets all three options plus the protocol
        // version on every attempt; a factory containing fewer has stopped setting one of them.
        Assert.Single(RebuildTree.ScanPattern(factories, ConnectionConstruction));
        Assert.Equal(3, RebuildTree.ScanPattern(factories, TransportSecurityAssignment).Count);

        Assert.Matches(ConnectionConstruction, "using var c = new LdapConnection(id);");
        Assert.DoesNotMatch(ConnectionConstruction, "private readonly LdapConnection _connection;");

        Assert.Matches(TransportSecurityAssignment, "options.Signing = true;");
        Assert.Matches(TransportSecurityAssignment, "options.SecureSocketLayer = rung.UseTls;");
        Assert.Matches(TransportSecurityAssignment, "o.Sealing = false;");
        Assert.DoesNotMatch(TransportSecurityAssignment, "if (options.Signing == true) { }");
        Assert.DoesNotMatch(TransportSecurityAssignment, "return _connection.SessionOptions.Signing;");

        Assert.Matches(NonNegotiateAuthType, "connection.AuthType = AuthType.Basic;");
        Assert.Matches(NonNegotiateAuthType, "x = AuthType.Anonymous;");
        Assert.DoesNotMatch(NonNegotiateAuthType, "connection.AuthType = AuthType.Negotiate;");

        // And the ladder itself is there to be policed, rather than the level enumeration having
        // quietly become the only statement of it.
        Assert.Equal(4, ConnectionSecurityLadder.Rungs.Count);
    }

    private static bool IsFactory(string file) =>
        Path.GetFileName(file).Equals(Factory, StringComparison.Ordinal);
}

using System.DirectoryServices.Protocols;
using System.Reflection;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// P-214: exercise the real factory and ladder with only the external LDAP calls replaced.
/// The platform's response fixtures are synthetic; none of these tests binds or sends over LDAP.
/// </summary>
public sealed class LdapDirectoryChannelFactoryTests
{
    private const string Controller = "dc01.example.invalid";
    private const string Diagnostic = "Synthetic controller diagnostic.";

    [Theory]
    [InlineData(ResultCode.Busy)]
    [InlineData(ResultCode.Unavailable)]
    [InlineData(ResultCode.InsufficientAccessRights)]
    [InlineData(ResultCode.StrongAuthRequired)]
    [InlineData(ResultCode.ConfidentialityRequired)]
    public void AServerErrorAfterBindingIsARootDseFailure(ResultCode code)
    {
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(code, Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.RootDseReadFailed", outcome.Error?.Code);
    }

    [Theory]
    [InlineData(81)]
    [InlineData(85)]
    [InlineData(49)]
    public void AClientErrorAfterBindingDoesNotRewriteTheSuccessfulBind(int code)
    {
        var ldap = new OfflineLdap { ReadFailure = new LdapException(code, Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.RootDseReadFailed", outcome.Error?.Code);
    }

    [Fact]
    public void AResponseLessErrorAfterBindingStillNamesTheFailedRead()
    {
        var ldap = new OfflineLdap { ReadFailure = new DirectoryOperationException(Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.RootDseReadFailed", outcome.Error?.Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AFailedReadNeverTriggersWeakerProtection(bool allowUnprotected)
    {
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };

        ldap.Factory(allowUnprotected: allowUnprotected).Connect(Controller);

        Assert.Equal(["bind", "RootDSE"], ldap.Operations);
    }

    [Fact]
    public void EarlierConnectionFailureDoesNotEraseTheRungThatAuthenticated()
    {
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };
        ldap.InitialBindFailures.Enqueue(new LdapException(91, "Synthetic connect failure."));

        var outcome = ldap.Factory().Connect(Controller);

        Assert.StartsWith($"Connected to {Controller} using SignedAndSealed,", outcome.Error?.Description);
    }

    [Fact]
    public void TheLogRetainsTheSamePostBindFailureReturnedToTheCaller()
    {
        var log = new ConnectionSecurityLog();
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };

        var outcome = ldap.Factory(log).Connect(Controller);

        Assert.Equal([outcome.Error], log.Errors);
    }

    [Fact]
    public void AFailedReadIsNotRecordedAsAUsableCaptureConnection()
    {
        var log = new ConnectionSecurityLog();
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };

        ldap.Factory(log).Connect(Controller);

        Assert.Empty(log.Controllers);
    }

    [Fact]
    public void AFailedReadDisposesItsConnection()
    {
        var ldap = new OfflineLdap { ReadFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };

        ldap.Factory().Connect(Controller);

        Assert.Throws<ObjectDisposedException>(() => ldap.Connections[0].SessionOptions.ProtocolVersion);
    }

    [Fact]
    public void TheBusyMessagePreservesTheResultAndServerDiagnostic()
    {
        var response = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic).Response;
        var ldap = new OfflineLdap { ReadFailure = new DirectoryOperationException(response, "Request failed.") };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal(
            $"Connected to {Controller} using Ldaps, but could not read its directory capabilities (RootDSE). "
            + "This connection cannot be used for capture. LDAP result: Busy (51). Request failed. "
            + Diagnostic,
            outcome.Error?.Description);
    }

    [Fact]
    public void AnEmptySuccessfulResponseIsAFailedReadRatherThanAnAcceptedChannel()
    {
        var ldap = new OfflineLdap
        {
            Reply = (SearchResponse)ServerResultFailure.AnsweredWith(ResultCode.Success, "").Response,
        };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.RootDseReadFailed", outcome.Error?.Code);
    }

    [Fact]
    public void AReturnedErrorResponseIsAFailedReadEvenWhenItHasAnEntry()
    {
        var ldap = new OfflineLdap { Reply = RootDseReply(ResultCode.Busy) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.RootDseReadFailed", outcome.Error?.Code);
    }

    [Theory]
    [InlineData(ResultCode.StrongAuthRequired)]
    [InlineData(ResultCode.ConfidentialityRequired)]
    public void AProtectionSpecificBindResponseStillReportsRefusedProtection(ResultCode code)
    {
        var ldap = new OfflineLdap { BindFailure = ServerResultFailure.AnsweredWith(code, Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.DomainControllerAcceptedNoProtectedConnection", outcome.Error?.Code);
    }

    [Fact]
    public void ARejectedCredentialResponseStillReportsCredentials()
    {
        var ldap = new OfflineLdap { BindFailure = ServerResultFailure.AnsweredWith((ResultCode)49, Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.CredentialsWereRejected", outcome.Error?.Code);
    }

    [Fact]
    public void ABusyBindResponseIsNotPromotedToAProtectionRefusalByOtherRungs()
    {
        var ldap = new OfflineLdap { BindFailure = ServerResultFailure.AnsweredWith(ResultCode.Busy, Diagnostic) };
        ldap.InitialBindFailures.Enqueue(new LdapException(8, "Synthetic protection refusal."));

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.DirectoryOperationFailed", outcome.Error?.Code);
    }

    [Fact]
    public void AResponseLessBindFailureRetainsTheConservativeUnknownOutcome()
    {
        var ldap = new OfflineLdap { BindFailure = new DirectoryOperationException(Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.DomainControllerDidNotAnswer", outcome.Error?.Code);
    }

    [Fact]
    public void AnUnknownBindResponseRetainsTheConservativeUnknownOutcome()
    {
        var ldap = new OfflineLdap { BindFailure = ServerResultFailure.AnsweredWith((ResultCode)999, Diagnostic) };

        var outcome = ldap.Factory().Connect(Controller);

        Assert.Equal("Capture.DomainControllerDidNotAnswer", outcome.Error?.Code);
    }

    [Fact]
    public void ASuccessfulRootDseReadReturnsTheAdvertisedCapabilitiesOnAnOpenChannel()
    {
        var ldap = new OfflineLdap();

        var outcome = ldap.Factory().Connect(Controller);
        using var channel = outcome.Value;

        Assert.Equal(
            (Controller, ConnectionSecurityLevel.Ldaps, ReferralChasingOptions.None,
                "1.2.840.113556.1.4.1339", "DC=example,DC=invalid"),
            (channel.DomainController, channel.SecurityLevel, channel.ReferralChasing,
                string.Join(",", channel.SupportedControls), string.Join(",", channel.NamingContextsServed)));
    }

    private static SearchResponse RootDseReply(ResultCode code)
    {
        // These constructors and collection writers belong to Microsoft's wire-response types,
        // not product internals. The actual result and entry must be independent: an empty entry
        // list must not hide a missing result-code check in the returned-error regression.
        var response = (SearchResponse)ServerResultFailure.AnsweredWith(code, Diagnostic).Response;
        var attributes = Assert.IsType<SearchResultAttributeCollection>(Activator.CreateInstance(
            typeof(SearchResultAttributeCollection), nonPublic: true));
        var addAttribute = typeof(SearchResultAttributeCollection).GetMethod(
            "Add", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(addAttribute);
        addAttribute.Invoke(attributes, ["supportedControl", new DirectoryAttribute("supportedControl", "1.2.840.113556.1.4.1339")]);
        addAttribute.Invoke(attributes, ["namingContexts", new DirectoryAttribute("namingContexts", "DC=example,DC=invalid")]);
        var entry = Assert.IsType<SearchResultEntry>(Activator.CreateInstance(typeof(SearchResultEntry),
            BindingFlags.NonPublic | BindingFlags.Instance, binder: null, ["", attributes], culture: null));
        var addEntry = typeof(SearchResultEntryCollection).GetMethod(
            "Add", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(addEntry);
        addEntry.Invoke(response.Entries, [entry]);
        return response;
    }

    private sealed class OfflineLdap
    {
        public DirectoryException? BindFailure { get; init; }
        public DirectoryException? ReadFailure { get; init; }
        public SearchResponse Reply { get; init; } = RootDseReply(ResultCode.Success);
        public Queue<DirectoryException> InitialBindFailures { get; } = new();
        public List<string> Operations { get; } = [];
        public List<LdapConnection> Connections { get; } = [];

        public LdapDirectoryChannelFactory Factory(ConnectionSecurityLog? log = null, bool allowUnprotected = false) =>
            new(DirectoryConnectionSettings.Default with
            {
                Allowance = allowUnprotected
                    ? UnprotectedConnectionAllowance.DeclaredFor("Synthetic offline test.")
                    : UnprotectedConnectionAllowance.Refused,
            }, log ?? new ConnectionSecurityLog(), Bind, SendRequest);

        private void Bind(LdapConnection connection)
        {
            Connections.Add(connection);
            Operations.Add("bind");
            if (InitialBindFailures.TryDequeue(out var failure))
                throw failure;
            if (BindFailure is not null)
                throw BindFailure;
        }

        private SearchResponse SendRequest(LdapConnection connection, SearchRequest request)
        {
            Operations.Add("RootDSE");
            if (ReadFailure is not null)
                throw ReadFailure;
            return Reply;
        }
    }
}

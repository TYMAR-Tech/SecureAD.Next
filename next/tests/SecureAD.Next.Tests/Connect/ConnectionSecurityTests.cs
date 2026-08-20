using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Kernel;
using SecureAD.Evidence;
using Xunit;

namespace SecureAD.Next.Tests.Connect;

/// <summary>
/// The connection-security ladder of
/// <c>docs/decisions/0018-connection-security-is-an-ordered-ladder.md</c>: its shape, its order,
/// and the one rung that is never reached without a declaration.
/// </summary>
public sealed class ConnectionSecurityLadderTests
{
    [Fact]
    public void TheLadderIsWalkedFromTheMostProtectedRungDownwards()
    {
        Assert.Equal(
            [
                ConnectionSecurityLevel.Ldaps,
                ConnectionSecurityLevel.SignedAndSealed,
                ConnectionSecurityLevel.Signed,
                ConnectionSecurityLevel.Unprotected,
            ],
            ConnectionSecurityLadder.Rungs.Select(r => r.Level));
    }

    [Fact]
    public void LdapsIsTheOnlyRungOnPort636()
    {
        Assert.Equal(
            [ConnectionSecurityLevel.Ldaps],
            ConnectionSecurityLadder.Rungs
                .Where(r => r.Port == ConnectionSecurityLadder.LdapsPort)
                .Select(r => r.Level));
    }

    /// <summary>
    /// Signing and sealing are asked for over Negotiate, never alongside TLS. Both mechanisms
    /// protect the same channel, and the platform's client rejects a connection that asks for both.
    /// </summary>
    [Fact]
    public void NoRungAsksForBothTlsAndSaslProtection()
    {
        Assert.Empty(ConnectionSecurityLadder.Rungs.Where(r => r.UseTls && (r.Sign || r.Seal)));
    }

    [Fact]
    public void SealingIsNeverAskedForWithoutSigning()
    {
        Assert.Empty(ConnectionSecurityLadder.Rungs.Where(r => r.Seal && !r.Sign));
    }

    /// <summary>
    /// Exactly one rung needs a declaration, and it is the bottom one. Two would mean a run could
    /// decline the whole lower half with one statement; zero would mean the ladder descends to an
    /// unprotected connection on its own, which is the thing the decision forbids.
    /// </summary>
    [Fact]
    public void ExactlyTheBottomRungNeedsADeclaredAllowance()
    {
        var declared = ConnectionSecurityLadder.Rungs.Where(r => r.RequiresDeclaredAllowance).ToList();

        Assert.Single(declared);
        Assert.Equal(ConnectionSecurityLevel.Unprotected, declared[0].Level);
        Assert.Same(ConnectionSecurityLadder.Rungs[^1], declared[0]);
    }

    [Fact]
    public void ARunThatDeclaredNothingIsOfferedNoUnprotectedRung()
    {
        var permitted = ConnectionSecurityLadder
            .PermittedBy(UnprotectedConnectionAllowance.Refused)
            .ToList();

        Assert.Equal(3, permitted.Count);
        Assert.DoesNotContain(permitted, r => r.Level == ConnectionSecurityLevel.Unprotected);
    }

    [Fact]
    public void ARunThatDeclaredOneIsOfferedEveryRung()
    {
        var permitted = ConnectionSecurityLadder
            .PermittedBy(UnprotectedConnectionAllowance.DeclaredFor("Isolated lab, no CA."))
            .ToList();

        Assert.Equal(ConnectionSecurityLadder.Rungs.Count, permitted.Count);
        Assert.Contains(permitted, r => r.Level == ConnectionSecurityLevel.Unprotected);
    }

    /// <summary>
    /// A declaration with no stated reason is the persisted setting this decision exists to avoid,
    /// reached by another route: nothing in the run says why, so nothing in the report can either.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnAllowanceWithoutAReasonIsRefused(string reason) =>
        Assert.Throws<ArgumentException>(() => UnprotectedConnectionAllowance.DeclaredFor(reason));

    [Fact]
    public void RefusingIsTheStandingAnswerAndSaysSo()
    {
        Assert.False(UnprotectedConnectionAllowance.Refused.IsDeclared);
        Assert.NotEmpty(UnprotectedConnectionAllowance.Refused.Reason);
    }
}

/// <summary>
/// The descent: which rungs are tried, in what order, and what is left when none answers.
/// </summary>
public sealed class ConnectionLadderWalkTests
{
    private const string Controller = "dc01.example.com";

    [Fact]
    public void TheFirstRungThatAnswersIsTheOneUsedAndNothingBelowItIsTried()
    {
        var tried = new List<ConnectionSecurityLevel>();
        var log = new ConnectionSecurityLog();

        var outcome = ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.Refused,
            log,
            rung =>
            {
                tried.Add(rung.Level);
                return rung.Level == ConnectionSecurityLevel.SignedAndSealed
                    ? Result<IDirectoryChannel>.Success(new StubChannel())
                    : Refusal();
            });

        Assert.True(outcome.IsSuccess);
        Assert.Equal(
            [ConnectionSecurityLevel.Ldaps, ConnectionSecurityLevel.SignedAndSealed],
            tried);
    }

    /// <summary>
    /// The level is recorded by name against the controller, with how many better rungs it turned
    /// down. A boolean here would have nowhere to put the third and fourth answers.
    /// </summary>
    [Fact]
    public void TheRungThatAnsweredIsRecordedAgainstTheController()
    {
        var log = new ConnectionSecurityLog();

        ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.Refused,
            log,
            rung => rung.Level == ConnectionSecurityLevel.Signed
                ? Result<IDirectoryChannel>.Success(new StubChannel())
                : Refusal());

        var recorded = Assert.Single(log.Controllers);
        Assert.Equal(Controller, recorded.DomainController);
        Assert.Equal(ConnectionSecurityLevel.Signed, recorded.Level);
        Assert.Equal(2, recorded.RungsRefused);
    }

    /// <summary>
    /// The rung the decision exists to keep out of reach. A run that declared nothing must never
    /// see it offered, even where every protected rung has already failed.
    /// </summary>
    [Fact]
    public void AnUndeclaredRunNeverAttemptsTheUnprotectedRung()
    {
        var tried = new List<ConnectionSecurityLevel>();

        var outcome = ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.Refused,
            new ConnectionSecurityLog(),
            rung =>
            {
                tried.Add(rung.Level);
                return Refusal();
            });

        Assert.DoesNotContain(ConnectionSecurityLevel.Unprotected, tried);
        Assert.False(outcome.IsSuccess);
        Assert.Equal(
            "Capture.DomainControllerAcceptedNoProtectedConnection", outcome.Error!.Code);
    }

    [Fact]
    public void ADeclaredRunReachesTheUnprotectedRungLast()
    {
        var tried = new List<ConnectionSecurityLevel>();
        var log = new ConnectionSecurityLog();

        var outcome = ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.DeclaredFor("Isolated lab, no CA."),
            log,
            rung =>
            {
                tried.Add(rung.Level);
                return rung.Level == ConnectionSecurityLevel.Unprotected
                    ? Result<IDirectoryChannel>.Success(new StubChannel())
                    : Refusal();
            });

        Assert.True(outcome.IsSuccess);
        Assert.Equal(ConnectionSecurityLevel.Unprotected, tried[^1]);
        Assert.Equal(4, tried.Count);
        Assert.Equal(3, Assert.Single(log.Controllers).RungsRefused);
    }

    /// <summary>
    /// A controller that declines every rung a declared run may use is a different failure from one
    /// that declined only the protected rungs, and the two say different things to an operator.
    /// </summary>
    [Fact]
    public void ADeclaredRunThatStillFailsSaysTheUnprotectedRungWasTriedToo()
    {
        var outcome = ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.DeclaredFor("Isolated lab, no CA."),
            new ConnectionSecurityLog(),
            _ => Refusal());

        Assert.False(outcome.IsSuccess);
        Assert.Equal("Capture.DomainControllerAcceptedNoConnection", outcome.Error!.Code);
    }

    /// <summary>
    /// Nothing is recorded for a controller that was never read. A log entry saying which rung
    /// answered, for a controller on which none did, would make an unread partition look read.
    /// </summary>
    [Fact]
    public void AControllerThatAnsweredOnNoRungIsNotRecordedAsHavingOne()
    {
        var log = new ConnectionSecurityLog();

        ConnectionLadderWalk.Descend(
            Controller, UnprotectedConnectionAllowance.Refused, log, _ => Refusal());

        Assert.Empty(log.Controllers);
    }

    /// <summary>
    /// And it is recorded as a failure rather than vanishing. An empty list of unprotected
    /// controllers means "none was unprotected" only where the run knows it reached them all.
    /// </summary>
    [Fact]
    public void AControllerThatAnsweredOnNoRungIsRecordedAsAFailure()
    {
        var log = new ConnectionSecurityLog();

        ConnectionLadderWalk.Descend(
            Controller, UnprotectedConnectionAllowance.Refused, log, _ => Refusal());

        var error = Assert.Single(log.Errors);
        Assert.Equal("Capture.DomainControllerAcceptedNoProtectedConnection", error.Code);
        Assert.Equal(Controller, error.Context);
    }

    /// <summary>
    /// A controller that answered and would not have the connection at that rung.
    /// </summary>
    /// <remarks>
    /// It carries <c>ProtectionWasRefused</c> because that is what these cases are about: a machine
    /// that was reached and said no. The ladder now tells that apart from a machine that never
    /// answered, and only the first of them may be described as accepting nothing protected.
    /// </remarks>
    private static Result<IDirectoryChannel> Refusal() =>
        AuditError.Create(
            ErrorCategory.Capture,
            "ProtectionWasRefused",
            ErrorSeverity.Failed,
            "declined",
            context: null);

    /// <summary>A machine that nothing came back from, at any rung.</summary>
    private static Result<IDirectoryChannel> NoAnswer() =>
        AuditError.Create(
            ErrorCategory.Capture,
            "ControllerDidNotAnswer",
            ErrorSeverity.Failed,
            "nothing answered",
            context: null);

    /// <summary>A machine that answered and would not have this account.</summary>
    private static Result<IDirectoryChannel> BadCredentials() =>
        AuditError.Create(
            ErrorCategory.Capture,
            "CredentialsWereRejected",
            ErrorSeverity.Failed,
            "invalid credentials",
            context: null);

    /// <summary>
    /// A controller nothing answered from is not described as refusing protection.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is <c>F-S35-1</c> at the ladder rather than at preflight. A walk that was answered by
    /// nothing has observed nothing, and the sentence it used to produce - <i>a controller
    /// accepting nothing signed leaves its LDAP traffic open to alteration in transit</i> - is a
    /// security claim about a customer's forest on the strength of a name that did not resolve.
    /// </para>
    /// <para>
    /// Make the walk describe an unanswered controller as refusing protection and this fails.
    /// </para>
    /// </remarks>
    [Fact]
    public void AControllerThatNeverAnsweredIsNotDescribedAsRefusingProtection()
    {
        var outcome = ConnectionLadderWalk.Descend(
            Controller, UnprotectedConnectionAllowance.Refused, new ConnectionSecurityLog(),
            _ => NoAnswer());

        Assert.Equal("Capture.DomainControllerDidNotAnswer", outcome.Error!.Code);
        Assert.DoesNotContain("open to alteration", outcome.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// Rejected credentials are reported as credentials, not as a forest that refuses protection.
    /// </summary>
    /// <remarks>
    /// The controller answered on the first rung and declined to authenticate. Every rung below it
    /// then failed the same way, and the run used to conclude that the machine accepted nothing
    /// signed - accusing a customer's forest of a weakness on the strength of a stale password. An
    /// expired account is among the likeliest reasons a run fails at all, so this is the ordinary
    /// case and not a corner of one.
    /// </remarks>
    [Fact]
    public void RejectedCredentialsAreReportedAsCredentialsAndNotAsAWeakness()
    {
        var outcome = ConnectionLadderWalk.Descend(
            Controller, UnprotectedConnectionAllowance.Refused, new ConnectionSecurityLog(),
            _ => BadCredentials());

        Assert.Equal("Capture.CredentialsWereRejected", outcome.Error!.Code);
        Assert.DoesNotContain("open to alteration", outcome.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// A walk that was answered and refused still says so, which is the case the checks above must
    /// not have removed.
    /// </summary>
    [Fact]
    public void AControllerThatAnsweredAndRefusedProtectionIsStillAFindingAboutTheForest()
    {
        var outcome = ConnectionLadderWalk.Descend(
            Controller, UnprotectedConnectionAllowance.Refused, new ConnectionSecurityLog(),
            _ => Refusal());

        Assert.Equal("Capture.DomainControllerAcceptedNoProtectedConnection", outcome.Error!.Code);
        Assert.Contains("open to alteration", outcome.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// An unrecognised failure claims nothing about the controller.
    /// </summary>
    /// <remarks>
    /// The conservative direction, and the one that keeps the classification honest as the protocol
    /// grows: a code nobody has classified must not be promoted into a security finding, because a
    /// finding resting on it would be one the product did not measure.
    /// </remarks>
    [Fact]
    public void AFailureNobodyClassifiedIsNotPromotedIntoAFinding()
    {
        var outcome = ConnectionLadderWalk.Descend(
            Controller,
            UnprotectedConnectionAllowance.Refused,
            new ConnectionSecurityLog(),
            _ => AuditError.Create(
                ErrorCategory.Capture, "SomethingNew", ErrorSeverity.Failed, "?", context: null));

        Assert.Equal("Capture.DomainControllerDidNotAnswer", outcome.Error!.Code);
    }

    /// <summary>
    /// A channel that is nothing but a successful outcome. The walk decides which rungs are tried;
    /// what is on the other end of a successful one is not its business.
    /// </summary>
    private sealed class StubChannel : IDirectoryChannel
    {
        public string DomainController => Controller;

        public ConnectionSecurityLevel SecurityLevel => ConnectionSecurityLevel.SignedAndSealed;

        public ReferralChasingOptions ReferralChasing => ReferralChasingOptions.None;

        public IReadOnlyList<string> SupportedControls => ["1.2.840.113556.1.4.1339"];

        public bool IsComplete => true;

        public IReadOnlyList<string> NamingContextsServed => [];

        public Task<DirectoryPage> SendAsync(
            SearchRequest request, CancellationToken cancellationToken) =>
            throw new NotSupportedException("The walk never sends anything.");

        public void Dispose()
        {
        }
    }
}

/// <summary>
/// What a run's connection log says afterwards, which is what a report has to disclose and what a
/// finding is made from.
/// </summary>
public sealed class ConnectionSecurityLogTests
{
    [Fact]
    public void ARunOnWhichEveryControllerWasProtectedHasNothingToDisclose()
    {
        var log = new ConnectionSecurityLog();
        log.Record("dc01", ConnectionSecurityLevel.Ldaps, rungsRefused: 0);
        log.Record("dc02", ConnectionSecurityLevel.SignedAndSealed, rungsRefused: 1);
        log.Record("dc03", ConnectionSecurityLevel.Signed, rungsRefused: 2);

        Assert.False(log.AnyUnprotected);
        Assert.Empty(log.RefusedIntegrity);
        Assert.Empty(log.Errors);
    }

    /// <summary>
    /// The difference an empty list cannot express on its own: a run in which nothing was
    /// unprotected and a run in which nothing was reached both leave <c>RefusedIntegrity</c> empty,
    /// and only the errors beside it tell them apart.
    /// </summary>
    [Fact]
    public void ARunThatReachedNoControllerIsNotARunThatFoundNothingWrong()
    {
        var log = new ConnectionSecurityLog();
        log.RecordFailure(AuditError.Create(
            ErrorCategory.Capture, "Refused", ErrorSeverity.Failed, "declined", "dc01"));

        Assert.Empty(log.RefusedIntegrity);
        Assert.NotEmpty(log.Errors);
    }

    [Fact]
    public void ASingleUnprotectedControllerMakesTheWholeRunDisclosable()
    {
        var log = new ConnectionSecurityLog();
        log.Record("dc01", ConnectionSecurityLevel.Ldaps, rungsRefused: 0);
        log.Record("dc02", ConnectionSecurityLevel.Unprotected, rungsRefused: 3);

        Assert.True(log.AnyUnprotected);
        Assert.Equal("dc02", Assert.Single(log.RefusedIntegrity).DomainController);
    }

    /// <summary>
    /// Signing is the line the finding is drawn at, not encryption. A controller that accepted
    /// signing but not sealing is protected against alteration in transit, which is what
    /// Microsoft's hardening guidance and the Windows Server 2025 default are both about.
    /// </summary>
    [Fact]
    public void AControllerThatAcceptedSigningWithoutSealingIsNotAFinding()
    {
        var log = new ConnectionSecurityLog();
        log.Record("dc01", ConnectionSecurityLevel.Signed, rungsRefused: 2);

        Assert.Empty(log.RefusedIntegrity);
    }

    /// <summary>
    /// The question the log answers is what the run actually used, so the first answer stands. A
    /// later, better answer for the same controller would describe a connection the evidence did
    /// not cross.
    /// </summary>
    [Fact]
    public void AControllerIsRecordedOnceAndTheFirstAnswerStands()
    {
        var log = new ConnectionSecurityLog();
        log.Record("dc01", ConnectionSecurityLevel.Unprotected, rungsRefused: 3);
        log.Record("DC01", ConnectionSecurityLevel.Ldaps, rungsRefused: 0);

        var only = Assert.Single(log.Controllers);
        Assert.Equal(ConnectionSecurityLevel.Unprotected, only.Level);
    }
}

/// <summary>
/// What happens to a customer's credentials - inventory row A1's half of this session.
/// </summary>
public sealed class DirectoryCredentialTests
{
    private const string Password = "correct-horse-battery-staple";

    /// <summary>
    /// The way a password normally escapes is that something prints the object holding it. It
    /// cannot here, and this type is deliberately not a record for that reason: a record's
    /// compiler-generated <c>ToString</c> prints every member it has.
    /// </summary>
    [Fact]
    public void PrintingACredentialDisclosesNeitherThePasswordNorTheAccount()
    {
        var credential = DirectoryCredential.For("svc-audit", "EXAMPLE", Password);

        var printed = credential.ToString();

        Assert.DoesNotContain(Password, printed, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("svc-audit", printed, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(printed);
    }

    /// <summary>
    /// And nothing outside this project can ask for it either. A member returning the secret would
    /// make every caller a place it could be logged from, which is how the disclosure surface of a
    /// product grows without anyone deciding to grow it.
    /// </summary>
    [Fact]
    public void NoPublicMemberHandsBackTheSecret()
    {
        var members = typeof(DirectoryCredential)
            .GetMembers(System.Reflection.BindingFlags.Public
                        | System.Reflection.BindingFlags.Instance
                        | System.Reflection.BindingFlags.Static)
            .Select(m => m.Name)
            .ToList();

        Assert.DoesNotContain("Password", members);
        Assert.DoesNotContain("NetworkCredential", members);
        Assert.DoesNotContain("ForBind", members);

        // The scanner half: the reflection above proves nothing if it read no members at all.
        Assert.Contains("DescribedAs", members);
        Assert.Contains("IsLoggedOnUser", members);
    }

    [Fact]
    public void TheOrdinaryCaseCarriesNoSecretAtAll()
    {
        Assert.True(DirectoryCredential.LoggedOnUser.IsLoggedOnUser);
        Assert.False(DirectoryCredential.For("svc", "EXAMPLE", Password).IsLoggedOnUser);
    }

    [Theory]
    [InlineData("", "EXAMPLE", "pw")]
    [InlineData("svc", "", "pw")]
    [InlineData("svc", "EXAMPLE", "")]
    public void AnIncompleteCredentialIsRefusedRatherThanBoundWith(
        string user, string domain, string password) =>
        Assert.Throws<ArgumentException>(() => DirectoryCredential.For(user, domain, password));

    /// <summary>
    /// A run that says nothing about unprotected connections has refused them. The default is the
    /// safe answer, not the convenient one.
    /// </summary>
    [Fact]
    public void TheDefaultRunBindsAsTheLoggedOnUserAndPermitsNothingUnprotected()
    {
        Assert.True(DirectoryConnectionSettings.Default.Credential.IsLoggedOnUser);
        Assert.False(DirectoryConnectionSettings.Default.Allowance.IsDeclared);
        Assert.Equal(
            DirectoryConnectionSettings.DefaultConnectTimeout,
            DirectoryConnectionSettings.Default.ConnectTimeout);
    }
}

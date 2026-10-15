using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F6 - reading a run's state from its bundle directory, by the procedure decision <c>0028</c>
/// lays out and using the run-outcome file and liveness test decided in <c>0029</c>.
///
/// <para>
/// The predecessor caught every exception and returned one sentinel, so a corrupt database and a
/// directory that was never a run read identically, and the operator was told <i>required run
/// metadata is missing</i> for both. Each state here is reached from something observed.
/// </para>
/// </summary>
public sealed class RunStateReaderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-runstate-" + Guid.NewGuid().ToString("n"));

    public RunStateReaderTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A test that held a lock may still be releasing it. Leaving a temp directory behind
            // is not worth failing a run over.
        }
    }

    [Fact]
    public void AnEvidenceFileWithAnIntactSealIsSealed()
    {
        WriteEvidenceAndSeal();

        Assert.Equal(RunState.Sealed, Observe().State);
    }

    /// <summary>
    /// <b>Evidence that no longer matches its seal is observed as sealed, and that is deliberate.</b>
    /// Answering otherwise means hashing the whole evidence file, and this is asked of every run
    /// each time the Home list is drawn - 1,266 ms per 1.73 GB, measured, on nine occasions
    /// including every navigation back to Home.
    /// <c>docs/decisions/0020-the-seal-detects-corruption-not-tampering.md</c> puts the one
    /// verification at the moment a bundle is opened and requires that it not be repeated per
    /// screen. <see cref="ACorruptedBundleIsStillRefusedWhenItIsOpened"/> is what makes that safe.
    /// </summary>
    [Fact]
    public void AnEvidenceFileWhoseSealDoesNotMatchIsStillSealed()
    {
        WriteEvidenceAndSeal();
        File.AppendAllText(BundleLayout.EvidencePath(_directory), "corrupted");

        Assert.Equal(RunState.Sealed, Observe().State);
    }

    /// <summary>
    /// The other half of the one above. Nothing is read off corrupted evidence, however it was
    /// listed - so moving the check to opening loses no protection against a bad file.
    /// </summary>
    [Fact]
    public void ACorruptedBundleIsStillRefusedWhenItIsOpened()
    {
        WriteEvidenceAndSeal();
        File.AppendAllText(BundleLayout.EvidencePath(_directory), "corrupted");

        Assert.False(BundleReader.Open(_directory).IsSuccess);
    }

    /// <summary>
    /// <b>Observing a run must not hash its evidence.</b> This is the check that keeps the Home
    /// screen free, and it measures the thing rather than trusting the comment above: a bundle far
    /// larger than anything hashed in a test suite is observed, and the time is held well under
    /// what reading it once would take. Written after the listing was found to hash every bundle
    /// twice on nine separate triggers, which made the product unusable with a real run in the
    /// library.
    /// </summary>
    [Fact]
    public void ObservingARunDoesNotReadTheWholeEvidenceFile()
    {
        WriteEvidenceAndSeal();

        var evidence = BundleLayout.EvidencePath(_directory);
        var padded = new byte[64 * 1024 * 1024];
        using (var stream = new FileStream(evidence, FileMode.Append, FileAccess.Write))
            stream.Write(padded, 0, padded.Length);

        // Appending broke the seal, which is the point: a check that hashed would have to read all
        // 64 MB to discover that, and this must not.
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var state = Observe().State;
        clock.Stop();

        Assert.Equal(RunState.Sealed, state);
        Assert.True(
            clock.ElapsedMilliseconds < 250,
            $"Observing took {clock.ElapsedMilliseconds} ms, which is long enough to have hashed "
            + "the evidence. Drawing a list must not read the whole file.");
    }

    [Fact]
    public void ObservingASealedBundleCreatesNoSqliteSidecars()
    {
        using (var writer = BundleWriter.Create(_directory, DateTimeOffset.UtcNow))
        {
            writer.Complete(
                RunCoverage.Of(
                    CoverageId.ForDomains("contoso.com", ["contoso.com"]),
                    [DomainCoverage.Read("contoso.com")],
                    [
                        ForestPartitionCoverage.Read(
                            "CN=Configuration,DC=contoso,DC=com",
                            NamingContextKind.Configuration),
                        ForestPartitionCoverage.Read(
                            "CN=Schema,CN=Configuration,DC=contoso,DC=com",
                            NamingContextKind.Schema),
                    ],
                    SysvolCoverage.Of([])),
                DateTimeOffset.UtcNow);
        }

        Observe();

        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory) + "-wal"));
        Assert.False(File.Exists(BundleLayout.EvidencePath(_directory) + "-shm"));
    }

    [Fact]
    public void AnEvidenceFileWithNoSealIsDamaged()
    {
        WriteEvidenceAndSeal();
        File.Delete(BundleLayout.SealPath(_directory));

        Assert.Equal(RunState.Damaged, Observe().State);
    }

    /// <summary>
    /// A malformed seal must not degrade to "nobody sealed this", per <c>0019</c>. Either way it
    /// is damaged here, but the detail must say which, or the operator cannot tell a corrupt seal
    /// from an absent one.
    /// </summary>
    [Fact]
    public void ADamagedRunSaysWhatWasWrongWithIt()
    {
        WriteEvidenceAndSeal();
        File.WriteAllText(BundleLayout.SealPath(_directory), "{ not json");

        var observed = Observe();

        Assert.Equal(RunState.Damaged, observed.State);
        Assert.False(string.IsNullOrWhiteSpace(observed.Detail));
    }

    [Fact]
    public void AnOutcomeFileRecordingAFailureIsFailed()
    {
        WritePartial();
        RunOutcomeFile.Write(_directory, RunOutcome.Failed, "The forest root would not answer.");

        var observed = Observe();

        Assert.Equal(RunState.Failed, observed.State);
        Assert.Equal("The forest root would not answer.", observed.Detail);
    }

    [Fact]
    public void AnOutcomeFileRecordingACancellationIsCancelled()
    {
        WritePartial();
        RunOutcomeFile.Write(_directory, RunOutcome.Cancelled, "Stopped by the operator.");

        Assert.Equal(RunState.Cancelled, Observe().State);
    }

    /// <summary>
    /// Something still holds the partial file, so a run is writing it. This is what stops the run
    /// library offering a delete button beside a capture that is still going.
    /// </summary>
    [Fact]
    public void APartialFileSomethingIsHoldingIsInProgress()
    {
        WritePartial();

        using var held = new FileStream(
            BundleLayout.PartialPath(_directory),
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None);

        Assert.Equal(RunState.InProgress, Observe().State);
    }

    /// <summary>
    /// Nothing holds the partial file and no outcome was recorded, so the run stopped without
    /// being able to say why. The operating system released the handle when the process died,
    /// which is what makes this observable rather than inferred from a timestamp.
    /// </summary>
    [Fact]
    public void APartialFileNothingIsHoldingIsInterrupted()
    {
        WritePartial();

        Assert.Equal(RunState.Interrupted, Observe().State);
    }

    /// <summary>
    /// The outcome file is consulted before the lock, because a run that recorded why it stopped
    /// has said something more useful than the file system can.
    /// </summary>
    [Fact]
    public void ARecordedOutcomeIsPreferredToTheLivenessTest()
    {
        WritePartial();
        RunOutcomeFile.Write(_directory, RunOutcome.Cancelled, "Stopped by the operator.");

        using var held = new FileStream(
            BundleLayout.PartialPath(_directory),
            FileMode.Open,
            FileAccess.ReadWrite,
            FileShare.None);

        Assert.Equal(RunState.Cancelled, Observe().State);
    }

    /// <summary>
    /// A finished bundle outranks everything else. A stale outcome file beside a sealed evidence
    /// file must not make a good run look like a failed one.
    /// </summary>
    [Fact]
    public void AFinishedBundleOutranksAStaleOutcomeFile()
    {
        WriteEvidenceAndSeal();
        RunOutcomeFile.Write(_directory, RunOutcome.Failed, "Stale.");

        Assert.Equal(RunState.Sealed, Observe().State);
    }

    /// <summary>
    /// A directory holding none of the four bundle files is not a run at all. The predecessor
    /// reported this as a run with missing metadata, which is a claim about a run that does not
    /// exist.
    /// </summary>
    [Fact]
    public void ADirectoryThatIsNotARunIsRefusedRatherThanGivenAState()
    {
        var read = RunStateReader.Observe(_directory);

        Assert.False(
            read.IsSuccess,
            "An empty directory is not a run in any state. Giving it one would put a row in the "
            + "library for something that was never a run.");
    }

    [Fact]
    public void ADirectoryThatDoesNotExistIsRefused()
    {
        Assert.False(RunStateReader.Observe(Path.Combine(_directory, "absent")).IsSuccess);
    }

    /// <summary>
    /// An outcome file that cannot be parsed must not be read as a successful run, nor as an
    /// absent one. It is damaged, and it says so.
    /// </summary>
    [Fact]
    public void AnUnreadableOutcomeFileIsDamaged()
    {
        WritePartial();
        File.WriteAllText(BundleLayout.OutcomePath(_directory), "{ not json");

        Assert.Equal(RunState.Damaged, Observe().State);
    }

    /// <summary>
    /// The scanner self-test: proves the helpers actually create what the assertions above assume,
    /// so none of them can pass by observing an empty directory.
    /// </summary>
    [Fact]
    public void TheHelpersProduceTheFilesTheTestsAssumeExist()
    {
        WriteEvidenceAndSeal();
        Assert.True(File.Exists(BundleLayout.EvidencePath(_directory)));
        Assert.True(File.Exists(BundleLayout.SealPath(_directory)));

        File.Delete(BundleLayout.EvidencePath(_directory));
        File.Delete(BundleLayout.SealPath(_directory));

        WritePartial();
        Assert.True(File.Exists(BundleLayout.PartialPath(_directory)));

        RunOutcomeFile.Write(_directory, RunOutcome.Failed, "why");
        Assert.True(File.Exists(BundleLayout.OutcomePath(_directory)));
    }

    private RunStateObservation Observe()
    {
        var read = RunStateReader.Observe(_directory);
        Assert.True(read.IsSuccess, read.IsSuccess ? "" : read.Error.Description);
        return read.Value;
    }

    private void WritePartial() =>
        File.WriteAllText(BundleLayout.PartialPath(_directory), "not really a database");

    private void WriteEvidenceAndSeal()
    {
        using var writer = BundleWriter.Create(_directory, DateTimeOffset.UnixEpoch);
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
            SysvolCoverage.Of([])), DateTimeOffset.UnixEpoch.AddMinutes(1));
    }
}

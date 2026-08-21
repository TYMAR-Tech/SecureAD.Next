using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// What an operator writes about a run, which is kept beside the evidence and is not evidence.
/// </summary>
/// <remarks>
/// The distinction these tests hold is that annotation is editable and evidence is not. Every
/// assertion here is about a file outside the seal; if one of them ever required the seal to be
/// rewritten, the feature would have become a way to alter a sealed run.
/// </remarks>
public sealed class RunAnnotationsTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-annotation-" + Guid.NewGuid().ToString("n"));

    public RunAnnotationsTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A held lock is not worth failing a run over.
        }
    }

    [Fact]
    public void ARunNobodyHasAnnotatedHasNoName()
    {
        Assert.Null(RunAnnotations.Read(_directory).Name);
    }

    [Fact]
    public void ARunNobodyHasAnnotatedHasNoNotes()
    {
        Assert.Null(RunAnnotations.Read(_directory).Notes);
    }

    [Fact]
    public void TheNameAnOperatorSavesIsReadBack()
    {
        Save(new RunAnnotation("Quarterly review", null));

        Assert.Equal("Quarterly review", RunAnnotations.Read(_directory).Name);
    }

    [Fact]
    public void TheNotesAnOperatorSavesAreReadBack()
    {
        Save(new RunAnnotation(null, "Ran after the DC rebuild."));

        Assert.Equal("Ran after the DC rebuild.", RunAnnotations.Read(_directory).Notes);
    }

    /// <summary>
    /// Saving again corrects the run rather than adding a second answer to one question.
    /// </summary>
    [Fact]
    public void SavingAgainReplacesWhatWasThere()
    {
        Save(new RunAnnotation("First name", null));
        Save(new RunAnnotation("Second name", null));

        Assert.Equal("Second name", RunAnnotations.Read(_directory).Name);
    }

    /// <summary>
    /// Clearing the box leaves the run unnamed rather than named with a space, so that
    /// <c>IsNamed</c> on the screen means what it says.
    /// </summary>
    [Fact]
    public void ANameOfNothingButSpacesIsNoName()
    {
        Save(new RunAnnotation("   ", null));

        Assert.Null(RunAnnotations.Read(_directory).Name);
    }

    [Fact]
    public void SurroundingSpaceIsNotKept()
    {
        Save(new RunAnnotation("  Quarterly review  ", null));

        Assert.Equal("Quarterly review", RunAnnotations.Read(_directory).Name);
    }

    /// <summary>
    /// The point of the sidecar. An annotation must never require the sealed evidence to change,
    /// because that would make annotating a run destroy the proof that the run is unmodified.
    /// </summary>
    [Fact]
    public void AnnotatingLeavesTheSealedEvidenceUntouched()
    {
        File.WriteAllText(BundleLayout.EvidencePath(_directory), "sealed evidence");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        Save(new RunAnnotation("Named after sealing", "And annotated."));

        Assert.True(BundleSealing.Verify(_directory).MayBeOpened);
    }

    /// <summary>
    /// The scanner self-test. Proves the seal check above can fail, so that
    /// <see cref="AnnotatingLeavesTheSealedEvidenceUntouched"/> is not passing because nothing
    /// would ever break it.
    /// </summary>
    [Fact]
    public void TheSealCheckUsedAboveCanFail()
    {
        File.WriteAllText(BundleLayout.EvidencePath(_directory), "sealed evidence");
        BundleSealing.Seal(
            BundleLayout.EvidencePath(_directory), BundleLayout.SealPath(_directory));

        File.AppendAllText(BundleLayout.EvidencePath(_directory), "tampered");

        Assert.False(BundleSealing.Verify(_directory).MayBeOpened);
    }

    private void Save(RunAnnotation annotation)
    {
        var saved = RunAnnotations.Save(_directory, annotation);
        Assert.True(saved.IsSuccess, saved.IsSuccess ? "" : saved.Error.Description);
    }
}

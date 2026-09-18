using System.Windows.Threading;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class SavedTier0PathSectionTests
{
    [Fact]
    public async Task P246LoadingDoesNotClaimQuestionsAreAbsent()
    {
        var section = Read(Saved());
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, _ => pending.Task);
        section.Read();
        Assert.Equal(("Loading and validating saved results...", "Saved results have not been read.",
            "Saved results have not been read.", 0, ""),
            (section.Result, section.AutomaticChecks, section.SavedQuestions, section.Steps.Count, section.Provenance));
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await section.ReadCompletion;
    }

    [Fact]
    public async Task P246AsyncCompletionDisplaysTheSameProof()
    {
        var saved = Saved();
        var expected = Read(saved);
        var section = Section();
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, _ => pending.Task);
        section.Read();
        pending.SetResult(Result<SavedTier0Path?>.Success(saved));
        await section.ReadCompletion;
        Assert.Equal((expected.Result, expected.Provenance, expected.AutomaticChecks, expected.SavedQuestions,
            expected.Distance, expected.Destination), (section.Result, section.Provenance, section.AutomaticChecks,
            section.SavedQuestions, section.Distance, section.Destination));
        Assert.Equal(expected.Steps, section.Steps);
        Assert.Equal(expected.Limitations, section.Limitations);
    }

    [Fact]
    public async Task P246CancellationRejectsLateSuccessEvenWhenSourceIgnoresToken()
    {
        var section = Section();
        var pending = PendingPath();
        CancellationToken observed = default;
        section.ConfigureAsync(UserDn, token => { observed = token; return pending.Task; });
        section.Read();
        var completion = section.ReadCompletion;
        section.CancelRead();
        Assert.True(observed.IsCancellationRequested);
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await completion;
        Assert.Equal(("Saved results have not been read.", 0, ""), (section.Result, section.Steps.Count, section.Provenance));
    }

    [Fact]
    public async Task P246RebindingDoesNotPublishThePreviousGeneration()
    {
        var section = Section();
        var pending = PendingPath();
        section.ConfigureAsync(UserDn, _ => pending.Task);
        section.Read();
        var first = section.ReadCompletion;
        var replacement = Saved();
        section.ConfigureAsync(UserDn, _ => Task.FromResult(Result<SavedTier0Path?>.Success(replacement)));
        section.Read();
        await section.ReadCompletion;
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await first;
        Assert.Equal(Read(replacement).Provenance, section.Provenance);
    }

    [Fact]
    public async Task P246SectionNavigationCancelsAndReselectionReadsFresh()
    {
        var screen = OpenScreen(Source());
        var section = (SavedTier0PathSectionViewModel)screen.Opened!.Section(ObjectSectionCatalog.SavedTier0Path)!;
        var first = PendingPath();
        var second = PendingPath();
        var calls = 0;
        CancellationToken original = default;
        section.ConfigureAsync(UserDn, token => { if (++calls == 1) { original = token; return first.Task; } return second.Task; });
        screen.Opened.Show(ObjectSectionCatalog.SavedTier0Path);
        var originalCompletion = section.ReadCompletion;
        screen.Opened.Show(ObjectSectionCatalog.Overview);
        Assert.True(original.IsCancellationRequested);
        screen.Opened.Show(ObjectSectionCatalog.SavedTier0Path);
        Assert.Equal(2, calls);
        var replacement = Saved();
        second.SetResult(Result<SavedTier0Path?>.Success(replacement));
        await section.ReadCompletion;
        first.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await originalCompletion;
        Assert.Equal(Read(replacement).Provenance, section.Provenance);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task P246ChangingObjectOrRunCancelsThePreviousRead(bool changeRun)
    {
        var screen = OpenScreen(Source());
        var section = (SavedTier0PathSectionViewModel)screen.Opened!.Section(ObjectSectionCatalog.SavedTier0Path)!;
        var pending = PendingPath();
        CancellationToken original = default;
        section.ConfigureAsync(UserDn, token => { original = token; return pending.Task; });
        screen.Opened.Show(ObjectSectionCatalog.SavedTier0Path);
        var completion = section.ReadCompletion;
        if (changeRun) screen.Show(@"C:\synthetic-runs\other", false);
        else screen.OpenObject(new(new(UserDn, "User", Guid.NewGuid(), "user", "DC=contoso,DC=com")));
        Assert.True(original.IsCancellationRequested);
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await completion;
        Assert.Equal("Saved results have not been read.", section.Result);
    }

    [Fact]
    public async Task P246LeavingTheAssetsPaneCancelsAndReturningReadsFresh()
    {
        var screen = OpenScreen(Source());
        var section = (SavedTier0PathSectionViewModel)screen.Opened!.Section(ObjectSectionCatalog.SavedTier0Path)!;
        var pending = PendingPath();
        var calls = 0;
        CancellationToken original = default;
        section.ConfigureAsync(UserDn, token => { calls++; original = token; return pending.Task; });
        screen.Opened.Show(ObjectSectionCatalog.SavedTier0Path);
        var completion = section.ReadCompletion;
        screen.Pane = AssetsPane.Findings;
        Assert.True(original.IsCancellationRequested);
        pending.SetResult(Result<SavedTier0Path?>.Success(Saved()));
        await completion;
        screen.Pane = AssetsPane.Objects;
        await section.ReadCompletion;
        Assert.Equal(2, calls);
        Assert.Equal("Supported route recorded", section.Result);
    }

    [Fact]
    public async Task P246AsyncFailureIsUnavailableNotAnEmptySecurityAnswer()
    {
        var section = Section();
        section.ConfigureAsync(UserDn, _ => Task.FromException<Result<SavedTier0Path?>>(new IOException("synthetic failure")));
        section.Read();
        await section.ReadCompletion;
        Assert.Equal("Saved result unavailable", section.Result);
        Assert.Contains("synthetic failure", section.Detail);
        Assert.Empty(section.Steps);
    }

    [Fact]
    public void P246AsyncPublicationReturnsToTheDispatcher() => OnPathSta(() =>
    {
        var section = Section();
        var pending = PendingPath();
        var thread = Environment.CurrentManagedThreadId;
        var notifications = new List<int>();
        section.PropertyChanged += (_, _) => notifications.Add(Environment.CurrentManagedThreadId);
        section.ConfigureAsync(UserDn, _ => pending.Task);
        section.Read();
        var frame = new DispatcherFrame();
        var dispatcher = Dispatcher.CurrentDispatcher;
        _ = section.ReadCompletion.ContinueWith(_ => dispatcher.BeginInvoke(new Action(() => frame.Continue = false)), TaskScheduler.Default);
        _ = Task.Run(() => pending.SetResult(Result<SavedTier0Path?>.Success(Saved())));
        Dispatcher.PushFrame(frame);
        section.ReadCompletion.GetAwaiter().GetResult();
        Assert.Equal("Supported route recorded", section.Result);
        Assert.NotEmpty(notifications);
        Assert.All(notifications, id => Assert.Equal(thread, id));
    });

    private static TaskCompletionSource<Result<SavedTier0Path?>> PendingPath() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

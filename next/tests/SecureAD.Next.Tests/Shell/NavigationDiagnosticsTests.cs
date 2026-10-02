using SecureAD.Evidence;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class NavigationDiagnosticsTests
{
    [Fact]
    public void NavigationLogCarriesActionBuildWorkIdentityAndAppliedOutcome()
    {
        var directory = Path.Combine(Path.GetTempPath(), "securead-navigation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            using (var navigation = NavigationDiagnostics.Begin(directory, "read selected object"))
            {
                NavigationDiagnostics.Identity("judgementGeneration", Guid.Empty.ToString("D"));
                NavigationDiagnostics.Mark("query", TimeSpan.FromMilliseconds(12));
                navigation.Complete("success", null);
            }

            var log = File.ReadAllText(BundleLayout.RunLogPath(directory));
            Assert.Contains("action=\"read selected object\"", log, StringComparison.Ordinal);
            Assert.Contains("processSha256=", log, StringComparison.Ordinal);
            Assert.Contains("shellMvid=", log, StringComparison.Ordinal);
            Assert.Contains("work=query", log, StringComparison.Ordinal);
            Assert.Contains("judgementGeneration=00000000-0000-0000-0000-000000000000", log, StringComparison.Ordinal);
            Assert.Contains("outcome=success", log, StringComparison.Ordinal);
            Assert.Contains("appliedMs=", log, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}

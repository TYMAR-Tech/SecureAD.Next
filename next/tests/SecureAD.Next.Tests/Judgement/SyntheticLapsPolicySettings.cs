using System.Text;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.GroupPolicy;

namespace SecureAD.Next.Tests.Judgement;

internal static class SyntheticLapsPolicySettings
{
    internal static LapsPolicySettingsEvidence Complete(string value)
    {
        const string key = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
        const string name = "ADPasswordEncryptionPrincipal";
        return new(new(0, key, name, new(key, name, (uint)RegistryValueType.String,
            Encoding.Unicode.GetBytes(value + "\0"))), GpoSettingsOutcome.Read, null, [], []);
    }
}

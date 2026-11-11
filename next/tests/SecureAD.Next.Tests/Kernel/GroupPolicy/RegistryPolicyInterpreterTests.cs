using System.Text;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public sealed class RegistryPolicyInterpreterTests
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    private const string Name = "ADPasswordEncryptionPrincipal";

    [Theory]
    [InlineData("**Del.ADPasswordEncryptionPrincipal", " ")]
    [InlineData("**DeleteValues", "Other;ADPasswordEncryptionPrincipal")]
    [InlineData("**DelVals.", " ")]
    [InlineData("**dEL.adpasswordencryptionprincipal", " ")]
    public void RegistryInterpretDocumentedValueDeletesRemoveEarlierValues(string operation, string data)
    {
        var first = Entry(Key, Name, "earlier");
        var result = RegistryPolicyInterpreter.Evaluate([first, Entry(Key, operation, data)]);
        Assert.Null(result.Find(Key, Name));
        Assert.Empty(result.Issues);
        Assert.Equal("earlier", first.AsString());
    }

    [Fact]
    public void RegistryInterpretParentKeyDeletionRemovesTheSubtreeButNotSimilarNames()
    {
        var parent = @"Software\Microsoft\Windows\CurrentVersion\Policies";
        var result = RegistryPolicyInterpreter.Evaluate(
            [Entry(Key, Name, "old"), Entry(Key + @"\Child", Name, "child"),
                Entry(Key + "Other", Name, "unrelated"), Entry(parent, "**DeleteKeys", "LAPS")]);
        Assert.Null(result.Find(Key, Name));
        Assert.Null(result.Find(Key + @"\Child", Name));
        Assert.Equal("unrelated", result.Find(Key + "Other", Name)!.Source.AsString());
        Assert.Empty(result.Issues);
    }

    [Fact]
    public void RegistryInterpretOrderingAndCaseInsensitivityRetainTheLastOriginalOccurrence()
    {
        var last = Entry(Key.ToUpperInvariant(), Name.ToUpperInvariant(), "replacement");
        var result = RegistryPolicyInterpreter.Evaluate(
            [Entry(Key, Name, "first"), Entry(Key, "**DelVals.", " "), last]);
        var value = result.Find(Key, Name)!;
        Assert.Equal(2, value.EntryIndex);
        Assert.Same(last, value.Source);
        Assert.Equal("replacement", value.Source.AsString());
        Assert.Empty(result.Issues);
    }

    [Theory]
    [InlineData("**DelVals", " ")]
    [InlineData("**DelVals.", "")]
    [InlineData("**Del.ADPasswordEncryptionPrincipal", "wrong")]
    [InlineData("**DeleteKeys", @"LAPS\Child")]
    [InlineData("**DeleteValues", "value;")]
    public void RegistryInterpretUnqualifiedOperationsRetainOriginalsAndExplicitLimits(string name, string data)
    {
        var operation = Entry(Key, name, data);
        var result = RegistryPolicyInterpreter.Evaluate([Entry(Key, Name, "observed"), operation]);
        Assert.NotEmpty(result.IssuesFor(Key));
        var issue = Assert.Single(result.Issues);
        Assert.Equal((1, Key, name), (issue.EntryIndex, issue.KeyPath, issue.ValueName));
        Assert.Equal("observed", result.Find(Key, Name)!.Source.AsString());
        Assert.Equal(data, operation.AsString());
        Assert.Empty(result.IssuesFor(@"Software\Unrelated"));
    }

    [Fact]
    public void RegistryInterpretSoftWritesRequireClientStateUnlessEarlierInstructionsSetOrDeleteTheValue()
    {
        var soft = Entry(Key, "**soft." + Name, "conditional");
        var initial = RegistryPolicyInterpreter.Evaluate([soft]);
        Assert.Single(initial.Issues);
        Assert.Same(soft, initial.Find(Key, Name)!.Source);
        var afterDelete = RegistryPolicyInterpreter.Evaluate([Entry(Key, "**Del." + Name, " "), soft]);
        Assert.Empty(afterDelete.Issues);
        Assert.Equal("conditional", afterDelete.Find(Key, Name)!.Source.AsString());
        var afterSet = RegistryPolicyInterpreter.Evaluate([Entry(Key, Name, "fixed"), soft]);
        Assert.Empty(afterSet.Issues);
        Assert.Equal("fixed", afterSet.Find(Key, Name)!.Source.AsString());
    }

    [Theory]
    [InlineData("values")]
    [InlineData("key")]
    public void RegistryInterpretSoftCreationAfterAnExplicitClearHasNoUncapturedClientDependency(string kind)
    {
        var operation = kind == "values" ? Entry(Key, "**DelVals.", " ")
            : Entry(@"Software\Microsoft\Windows\CurrentVersion\Policies", "**DeleteKeys", "LAPS");
        var result = RegistryPolicyInterpreter.Evaluate([operation, Entry(Key, "**soft." + Name, "new")]);
        Assert.Empty(result.Issues);
        Assert.Equal("new", result.Find(Key, Name)!.Source.AsString());
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(17u)]
    public void RegistryInterpretKeySecurityOperationsDoNotReplaceConfiguredValues(uint flags)
    {
        var source = Entry(Key, Name, "retained");
        var result = RegistryPolicyInterpreter.Evaluate([source,
            new(Key, "**SecureKey", (uint)RegistryValueType.Dword, BitConverter.GetBytes(flags))]);
        Assert.Empty(result.Issues);
        Assert.Same(source, result.Find(Key, Name)!.Source);
    }

    [Theory]
    [InlineData("wrong-type")]
    [InlineData("unterminated")]
    [InlineData("odd-bytes")]
    [InlineData("embedded-null")]
    [InlineData("invalid-utf16")]
    public void RegistryInterpretUnqualifiedStringsAreNotSilentlyDecoded(string kind)
    {
        var entry = kind switch
        {
            "wrong-type" => new RegistryPolicyEntry(Key, Name, (uint)RegistryValueType.ExpandString, Encoding.Unicode.GetBytes("value\0")),
            "unterminated" => new(Key, Name, 1, Encoding.Unicode.GetBytes("value")),
            "odd-bytes" => new(Key, Name, 1, [1, 0, 0]),
            "embedded-null" => Entry(Key, Name, "one\0two"),
            "invalid-utf16" => new(Key, Name, 1, [0, 0xD8, 0, 0]),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var original = entry.Data.ToArray();
        Assert.False(RegistryPolicyInterpreter.TryReadString(entry, out _));
        Assert.Equal(original, entry.Data);
    }

    internal static RegistryPolicyEntry Entry(string key, string name, string text) =>
        new(key, name, (uint)RegistryValueType.String, Encoding.Unicode.GetBytes(text + "\0"));
}

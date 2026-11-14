using System.Runtime.InteropServices;
using System.Text;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

public sealed class GptIniVersionParserTests
{
    [Theory]
    [InlineData("0", 0u)]
    [InlineData("1", 1u)]
    [InlineData("65537", 65537u)]
    [InlineData("2147483648", 2147483648u)]
    [InlineData("4294967295", uint.MaxValue)]
    [InlineData(" 00042\t", 42u)]
    public void GptIniRequiredVersionRetainsOriginalAndFullUnsignedRange(string original, uint expected)
    {
        var result = GptIniVersionParser.Parse(Encoding.ASCII.GetBytes("[General]\r\nVersion=" + original + "\r\n"));
        Assert.Empty(result.Errors);
        Assert.Equal(expected, result.Version);
        Assert.Equal(original, result.OriginalValue);
    }

    [Theory]
    [InlineData("")]
    [InlineData("[Other]\r\nVersion=1\r\n")]
    [InlineData("[General]\r\nOther=1\r\n")]
    [InlineData("[General\r\nVersion=1\r\n")]
    [InlineData("Version=1\r\n[General]\r\n")]
    [InlineData("[General]\r\nVersion=-1\r\n")]
    [InlineData("[General]\r\nVersion=4294967296\r\n")]
    [InlineData("[General]\r\nVersion=1.0\r\n")]
    [InlineData("[General]\r\nVersion=0x10\r\n")]
    [InlineData("[General]\r\nVersion=\r\n")]
    [InlineData("[General]\r\nVersion=1\r\nversion=2\r\n")]
    [InlineData("[General]\r\nVersion=1\r\n[general]\r\nOther=2\r\n")]
    [InlineData("[General]\r\nVersion=1\r\n[Other]\r\nKey=1\r\nkey=2\r\n")]
    [InlineData("[General]\r\nVersion=1\r\nunframed\r\n")]
    public void GptIniUnusableOrAmbiguousInputIsNotAZeroOrPartialSuccess(string text)
    {
        var result = GptIniVersionParser.Parse(Encoding.ASCII.GetBytes(text));
        Assert.Null(result.Version);
        Assert.Null(result.OriginalValue);
        Assert.NotEmpty(result.Errors);
    }

    [Theory]
    [InlineData("utf16")]
    [InlineData("utf8-bom")]
    [InlineData("embedded-null")]
    public void GptIniNonAnsiOrNullTerminatedInputCannotHideTrailingData(string encoding)
    {
        const string text = "[General]\r\nVersion=1\r\n";
        byte[] bytes = encoding switch
        {
            "utf16" => [.. Encoding.Unicode.GetPreamble(), .. Encoding.Unicode.GetBytes(text)],
            "utf8-bom" => [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(text)],
            "embedded-null" => [.. Encoding.ASCII.GetBytes(text + "Other=prefix"), 0, .. Encoding.ASCII.GetBytes("suffix\r\n")],
            _ => throw new ArgumentOutOfRangeException(nameof(encoding)),
        };
        var result = GptIniVersionParser.Parse(bytes);
        Assert.Null(result.Version);
        Assert.NotEmpty(result.Errors);
    }

    [Fact]
    public void GptIniIdentifiersAreCaseInsensitiveAndUnrelatedAnsiValuesStayOpaque()
    {
        var bytes = Encoding.Latin1.GetBytes("; note\r\n[general]\r\nvErSiOn=65537\r\nDisplayName=Privil\u00e8ges\r\n[Other]\r\nVersion=7\r\n");
        var result = GptIniVersionParser.Parse(bytes);
        Assert.Empty(result.Errors);
        Assert.Equal(65537u, result.Version);
        Assert.Equal("65537", result.OriginalValue);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(65537u)]
    [InlineData(2147483648u)]
    [InlineData(uint.MaxValue)]
    public void GptIniQualifiedValuesMatchTheOfflineMicrosoftIniApi(uint value)
    {
        var directory = TempDirectories.Create("gpt-native-anchor");
        var path = Path.Combine(directory, "GPT.ini");
        var bytes = Encoding.ASCII.GetBytes("[General]\r\nVersion=" + value.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\r\n");
        File.WriteAllBytes(path, bytes);
        Assert.Equal(value, GetPrivateProfileInt("General", "Version", 12345, path));
        Assert.Equal(GetPrivateProfileInt("General", "Version", 12345, path), GptIniVersionParser.Parse(bytes).Version);
    }

    [DllImport("kernel32.dll", EntryPoint = "GetPrivateProfileIntW", CharSet = CharSet.Unicode)]
    private static extern uint GetPrivateProfileInt(string section, string key, int fallback, string file);
}

using System.Text;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

public sealed class EnterpriseCaCaptureTests
{
    [Theory]
    [InlineData("DC=example,DC=com", NamingContextKind.Domain)]
    [InlineData("CN=Configuration,DC=example,DC=com", NamingContextKind.Configuration)]
    public void FutureCaptureRequestsTheRecordedHostField(string context, NamingContextKind kind)
    {
        var request = CaptureSearchRequestFactory.ForUnit(new(context, kind, "dc01.example.com"), []);

        Assert.Contains("dNSHostName", request.Attributes.Cast<string>());
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("pKIEnrollmentService")]
    public void TheMicrosoftHostFieldIsSingleValuedText(string objectClass)
    {
        Assert.Contains(CapturedAttributeCatalog.AttributesJustifiedBy(objectClass), attribute =>
            attribute.LdapDisplayName == "dNSHostName" && attribute.Cardinality == AttributeCardinality.SingleValued
            && attribute.Storage == AttributeStorage.Text);
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("pKIEnrollmentService")]
    public async Task CaptureRetainsTheReturnedHostValueAsync(string objectClass)
    {
        var model = new ControllerModel();
        model.AddObject("CN=Recorded,DC=example,DC=com", ("objectClass", ["top", objectClass]),
            ("dNSHostName", ["CAHOST.example.com"]));
        var sink = new RecordingSink();
        var capture = new PartitionCapture(model.Connections(), sink, new ImmediateTimeProvider(), new RecordingRunLog());

        await capture.ReadAsync(new("DC=example,DC=com", NamingContextKind.Domain, "dc01.example.com"), CancellationToken.None);

        Assert.Contains(Assert.Single(sink.Received).Attributes, attribute => attribute.LdapDisplayName == "dNSHostName"
            && attribute.Completeness == AttributeCompleteness.Complete
            && attribute.Values.Count == 1 && attribute.Values[0] is byte[] bytes
            && bytes.SequenceEqual(Encoding.UTF8.GetBytes("CAHOST.example.com")));
    }
}

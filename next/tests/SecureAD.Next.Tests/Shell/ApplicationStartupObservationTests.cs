using SecureAD.Next.Tests.Measurements;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ApplicationStartupObservationTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void ARequiredStartupBoundaryCannotBeUnobserved(int index)
    {
        var missing = Enum.GetValues<AppStartupPoint>()[index];
        var marks = Enum.GetValues<AppStartupPoint>().Where(point => point != missing)
            .Select(point => new ApplicationStartupMeasurement.StartupMark(point, 1)).ToArray();
        Assert.Throws<InvalidDataException>(() => ApplicationStartupMeasurement.RequireCompleteMarks(marks));
    }

    [Fact]
    public void AllRealStartupBoundariesHaveAPositiveControl()
    {
        var marks = Enum.GetValues<AppStartupPoint>()
            .Select(point => new ApplicationStartupMeasurement.StartupMark(point, 1)).ToArray();
        ApplicationStartupMeasurement.RequireCompleteMarks(marks);
    }

    [Fact]
    public void DuplicateStartupMarksAreNotACompleteTrace()
    {
        var marks = Enum.GetValues<AppStartupPoint>()
            .Select(point => new ApplicationStartupMeasurement.StartupMark(point, 1))
            .Append(new(AppStartupPoint.WindowShown, 2)).ToArray();
        Assert.Throws<InvalidDataException>(() => ApplicationStartupMeasurement.RequireCompleteMarks(marks));
    }
}

using System;
using System.Diagnostics;
using SecureAD.Next.Tests.Measurements;

namespace SecureAD.Measure.Shell;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args) => ApplicationStartupMeasurement.Run(args, Stopwatch.GetTimestamp());
}

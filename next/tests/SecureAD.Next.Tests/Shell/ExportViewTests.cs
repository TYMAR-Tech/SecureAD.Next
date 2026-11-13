using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using SecureAD.Shell.Services.Export;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ExportViewTests
{
    [Theory]
    [InlineData(900, 650, false)]
    [InlineData(1300, 850, false)]
    [InlineData(900, 650, true)]
    public void RealPreviewBindsSourceCountsQualitiesAndReachableActions(int width, int height, bool light) =>
        AuditProgressViewTests.OnSta(() =>
        {
            using var fixture = new CsvExportTests.Fixture();
            var dataset = ExportViewModelTests.Dataset(fixture);
            var preview = fixture.Preview(3) with
            {
                Columns = LapsExportDataset.Columns,
                SampleHeaders = ["Computer", "Windows expiry (UTC)", "Legacy expiry (UTC)", "Account state"],
                Sample =
                [
                    new("PC-01", "No value captured", "No value captured", "Unknown"),
                    new("PC-02", "Zero (no usable date)", "Unusable value", "Disabled"),
                    new("PC-03", "2026-11-13T09:30:00.1234567Z", "No value captured", "Enabled"),
                ],
                CoverageSummary = "Some captured computer evidence is incomplete; the missing count is unknown.",
            };
            dataset.Prepare = (_, _) => Task.FromResult(preview);
            using var model = new ExportViewModel(dataset, new ExportViewModelTests.Exporter(),
                new ExportViewModelTests.Picker(null));
            model.OpenCommand.ExecuteAsync(null).GetAwaiter().GetResult();
            var window = Assert.IsAssignableFrom<Window>(FindingsViewTests.View(model, "ExportWindow.xaml"));
            window.Width = width;
            window.Height = height;
            window.WindowStyle = WindowStyle.None;
            window.ShowInTaskbar = false;
            window.Left = -10000;
            window.Top = -10000;
            new WpfThemeApplier(window.Resources).Apply(light ? ThemeVariant.Light : ThemeVariant.Dark);
            window.Show();
            try
            {
                window.UpdateLayout();
                Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ContextIdle);
                var grid = Assert.Single(Descendants<DataGrid>(window));
                Assert.Equal(3, grid.Items.Count);
                var headerText = Descendants<DataGridColumnHeader>(grid)
                    .SelectMany(Descendants<TextBlock>).Select(text => text.Text).ToArray();
                Assert.All(preview.SampleHeaders, header => Assert.Contains(header, headerText));
                Assert.Contains(Descendants<TextBlock>(window), text => text.Text == model.CountText);
                Assert.Contains(Descendants<TextBlock>(window), text => text.Text == model.SourceRun);
                Assert.Contains(Descendants<TextBlock>(window), text => text.Text == preview.CoverageSummary);
                Assert.Contains(Descendants<TextBlock>(grid), text => text.Text == "Zero (no usable date)");
                Assert.Contains(Descendants<TextBlock>(grid), text => text.Text == "Unusable value");
                var save = Assert.Single(Descendants<Button>(window),
                    button => ReferenceEquals(button.Command, model.SaveCommand));
                var cancel = Assert.Single(Descendants<Button>(window),
                    button => ReferenceEquals(button.Command, model.CancelCommand));
                Assert.True(save.IsEnabled);
                Assert.True(cancel.IsEnabled);
                var content = Assert.IsAssignableFrom<FrameworkElement>(window.Content);
                var savePoint = save.TransformToAncestor(content).Transform(new Point(0, save.ActualHeight));
                Assert.True(savePoint.Y <= content.ActualHeight + 1);
                Assert.True(save.ActualWidth > 100);
                Assert.Contains(Descendants<RadioButton>(window), radio => radio.IsChecked == true
                    && BindingOperations.GetBinding(radio, ToggleButton.IsCheckedProperty)?.Path.Path == "Matching");
            }
            finally { window.Close(); }
        });

    private static IEnumerable<T> Descendants<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T typed) yield return typed;
            foreach (var nested in Descendants<T>(child)) yield return nested;
        }
    }
}

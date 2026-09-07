using System.Windows;

namespace SecureAD.Gallery;

/// <summary>The harness application, separate from the product and its data sources.</summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Contains("--r6-preview"))
        {
            var preview = new RequesterSizingPreview();
            MainWindow = preview;
            preview.Show();
        }
        else if (e.Args.Length == 2 && e.Args[0] == "--r6-check")
        {
            try
            {
                RequesterSizingPreview.Check(e.Args[1]);
                Shutdown(0);
            }
            catch (Exception error)
            {
                System.IO.File.WriteAllText(e.Args[1], error.ToString());
                Shutdown(1);
            }
            return;
        }
        else
        {
            MainWindow = new GalleryWindow();
            MainWindow.Show();
        }
        base.OnStartup(e);
    }
}

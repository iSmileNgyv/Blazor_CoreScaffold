using MudBlazor;

namespace Blazor_CoreScaffold.Components.Layout;

public partial class MainLayout
{
    private MudThemeProvider? _mudThemeProvider;
    private bool _isDarkMode = true;
    private bool _drawerOpen = true;

    private readonly MudTheme _dashboardTheme = new()
    {
        PaletteDark = new PaletteDark
        {
            Primary = "#137fec",
            Background = "#101922",
            Surface = "#1A242E",
            DrawerBackground = "#1A242E",
            AppbarBackground = "#101922",
            TextPrimary = "#f9fafb",
            TextSecondary = "#9ca3af",
            Divider = "#324d67",
            LinesDefault = "#324d67"
        },
        Palette = new Palette
        {
            Primary = "#137fec",
            Background = "#f6f7f8",
            Surface = "#ffffff",
            DrawerBackground = "#ffffff",
            AppbarBackground = "#f6f7f8",
            TextPrimary = "#1f2937",
            TextSecondary = "#6b7280",
            Divider = "#e5e7eb",
            LinesDefault = "#e5e7eb"
        },
        LayoutProperties = new LayoutProperties
        {
            DefaultBorderRadius = "12px"
        },
        Typography = new Typography
        {
            Default = new Default
            {
                FontFamily = new[] { "Inter", "sans-serif" }
            }
        }
    };
}

using System;
using System.Collections.Generic;
using MudBlazor;

namespace Blazor_CoreScaffold.Components.Layout;

public static class DashboardHeaderAppearance
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        "success",
        "warning",
        "error"
    };

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "success";
        }

        var trimmed = value.Trim();
        return Allowed.Contains(trimmed) ? trimmed.ToLowerInvariant() : "success";
    }

    public static string GetIcon(string normalizedAppearance)
    {
        return normalizedAppearance switch
        {
            "warning" => Icons.Material.Outlined.ErrorOutline,
            "error" => Icons.Material.Outlined.ReportProblem,
            _ => Icons.Material.Outlined.Verified
        };
    }
}

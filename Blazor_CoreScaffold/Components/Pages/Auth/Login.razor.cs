using System;
using Blazor_CoreScaffold.Services.Auth;
using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Blazor_CoreScaffold.Components.Pages.Auth;

public partial class Login
{
    private MudForm? form;
    private bool success;

    private string Username { get; set; } = string.Empty;
    private string Password { get; set; } = string.Empty;
    private bool RememberMe { get; set; } = false;

    private bool isShowPassword;
    private InputType PasswordInput { get; set; } = InputType.Password;
    private bool isSubmitting;

    private string PasswordVisibilityIcon => isShowPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;

    [Inject]
    private IClientAuthService AuthService { get; set; } = default!;

    [Inject]
    private ILogger<Login> Logger { get; set; } = default!;

    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    private void TogglePasswordVisibility()
    {
        isShowPassword = !isShowPassword;
        PasswordInput = isShowPassword ? InputType.Text : InputType.Password;
    }
    
    private async Task SubmitLogin()
    {
        await form!.Validate();
        if (!success)
        {
            return;
        }

        if (isSubmitting)
        {
            return;
        }

        isSubmitting = true;
        try
        {
            Logger.LogInformation("Sending login request for {Username}", Username);

            var response = await AuthService.LoginAsync(Username, Password);

            Logger.LogInformation(
                "Login response received. Success: {Success}, Message: {Message}, OtpRequired: {OtpRequired}",
                response.Success,
                response.Message,
                response.OtpRequired);

            if (response.Success)
            {
                if (response.OtpRequired)
                {
                    Snackbar.Add("OTP doğrulaması gerekiyor. Lütfen kodu girin.", Severity.Info);
                    isSubmitting = false;
                    await InvokeAsync(async () =>
                    {
                        if (NavigationManager.Uri != NavigationManager.ToAbsoluteUri("/otp").ToString())
                            NavigationManager.NavigateTo("/otp");
                    });
                    return;
                }
                Snackbar.Add("Başarıyla giriş yapıldı.", Severity.Success);
                isSubmitting = false;
                await InvokeAsync(async () =>
                {
                    var ticket = await AuthService.ConsumeLoginTicketAsync();
                    if (!string.IsNullOrWhiteSpace(ticket))
                    {
                        var target = $"/auth/callback?ticket={Uri.EscapeDataString(ticket)}";
                        NavigationManager.NavigateTo(target, forceLoad: true);
                    }
                    else
                    {
                        NavigationManager.NavigateTo("/", forceLoad: true);
                    }
                });
                return;
            }
            Snackbar.Add(response.Message ?? "Login failed.", Severity.Error);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Login request failed for {Username}", Username);
            Snackbar.Add("An unexpected error occurred while processing the login request.", Severity.Error);
        }
        
        isSubmitting = false;
        await InvokeAsync(StateHasChanged);
    }
}

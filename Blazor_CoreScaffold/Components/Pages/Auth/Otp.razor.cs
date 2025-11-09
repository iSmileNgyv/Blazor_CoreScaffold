using System;
using Blazor_CoreScaffold.Services.Auth;
using Microsoft.AspNetCore.Components;
using MudBlazor;

namespace Blazor_CoreScaffold.Components.Pages.Auth;

public partial class Otp
{
    private MudForm? form;
    private bool success;
    private bool isSubmitting;

    private string OtpCode { get; set; } = string.Empty;
    protected string? PendingUsername { get; private set; }

    [Inject]
    private IClientAuthService ClientAuthService { get; set; } = default!;

    [Inject]
    private NavigationManager NavigationManager { get; set; } = default!;

    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;

    [Inject]
    private ILogger<Otp> Logger { get; set; } = default!;

    protected override async Task OnInitializedAsync()
    {
        PendingUsername = await ClientAuthService.GetPendingOtpUsernameAsync();
        if (string.IsNullOrWhiteSpace(PendingUsername))
        {
            NavigationManager.NavigateTo("/login");
        }
    }

    private async Task SubmitOtp()
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
            var response = await ClientAuthService.VerifyOtpAsync(OtpCode);

            if (response.Success && !response.OtpRequired)
            {
                Snackbar.Add("OTP doğrulandı. Hoş geldiniz!", Severity.Success);
                var ticket = await ClientAuthService.ConsumeLoginTicketAsync();
                if (!string.IsNullOrWhiteSpace(ticket))
                {
                    var target = $"/auth/callback?ticket={Uri.EscapeDataString(ticket)}";
                    NavigationManager.NavigateTo(target, forceLoad: true);
                }
                else
                {
                    NavigationManager.NavigateTo("/", forceLoad: true);
                }
                return;
            }

            Snackbar.Add(response.Message ?? "OTP doğrulaması başarısız.", Severity.Error);
        }
        catch (InvalidOperationException ex)
        {
            Logger.LogWarning(ex, "OTP doğrulama isteği reddedildi. Geçerli bir OTP oturumu bulunamadı.");
            Snackbar.Add("OTP doğrulaması için geçerli bir giriş isteği bulunamadı.", Severity.Warning);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "OTP doğrulama isteği başarısız oldu.");
            Snackbar.Add("OTP doğrulaması yapılırken beklenmedik bir hata oluştu.", Severity.Error);
        }
        finally
        {
            isSubmitting = false;
            await InvokeAsync(StateHasChanged);
        }
    }

    private void NavigateBack()
    {
        NavigationManager.NavigateTo("/login");
    }
}

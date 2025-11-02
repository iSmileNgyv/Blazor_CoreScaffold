using System;
using System.Threading;
using System.Threading.Tasks;
using Blazor_CoreScaffold.Models;
using Blazor_CoreScaffold.Services;
using API_CoreScaffold.Services.Authentication;
using Grpc.Core;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using MudBlazor;

namespace Blazor_CoreScaffold.Components.Pages.Auth;

public partial class Login
{
    private MudForm? form;
    private bool success;

    private string Email { get; set; } = string.Empty;
    private string Password { get; set; } = string.Empty;
    private bool RememberMe { get; set; } = false;

    private bool isShowPassword;
    private InputType PasswordInput { get; set; } = InputType.Password;
    private bool isSubmitting;
    private string? errorMessage;

    [Inject]
    private IAuthenticationClient AuthenticationClient { get; set; } = default!;

    [Inject]
    private AuthState AuthState { get; set; } = default!;

    [Inject]
    private NavigationManager Navigation { get; set; } = default!;

    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;

    [Inject]
    private ILogger<Login> Logger { get; set; } = default!;

    private string PasswordVisibilityIcon => isShowPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;

    protected override void OnInitialized()
    {
        base.OnInitialized();
        CaptureReturnUrlFromQuery();
    }

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

        isSubmitting = true;
        errorMessage = null;

        try
        {
            var response = await AuthenticationClient.LoginAsync(Email, Password, CancellationToken.None);

            if (response.OtpRequired)
            {
                errorMessage = string.IsNullOrWhiteSpace(response.Message)
                    ? "Two-factor authentication is required to proceed."
                    : response.Message;
                Snackbar.Add(errorMessage, Severity.Info);
                return;
            }

            if (!response.Success)
            {
                errorMessage = string.IsNullOrWhiteSpace(response.Message)
                    ? "Login failed. Please verify your credentials."
                    : response.Message;
                Snackbar.Add(errorMessage, Severity.Error);
                return;
            }

            var session = AuthSession.FromResponse(response);
            AuthState.SetSession(session);

            Snackbar.Add("Successfully signed in.", Severity.Success);

            var targetUrl = AuthState.ReturnUrl;
            AuthState.ClearReturnUrl();

            if (string.IsNullOrWhiteSpace(targetUrl))
            {
                targetUrl = Navigation.BaseUri;
            }

            Navigation.NavigateTo(targetUrl!, forceLoad: false);
        }
        catch (RpcException rpcException)
        {
            errorMessage = "Unable to contact the authentication service.";
            Logger.LogError(rpcException, "gRPC login call failed");
            Snackbar.Add(errorMessage, Severity.Error);
        }
        catch (Exception exception)
        {
            errorMessage = "An unexpected error occurred during sign-in.";
            Logger.LogError(exception, "Unexpected error while processing login");
            Snackbar.Add(errorMessage, Severity.Error);
        }
        finally
        {
            isSubmitting = false;
        }
    }

    private void CaptureReturnUrlFromQuery()
    {
        var uri = Navigation.ToAbsoluteUri(Navigation.Uri);
        var query = QueryHelpers.ParseQuery(uri.Query);

        if (query.TryGetValue("state", out var stateValue) && !string.IsNullOrWhiteSpace(stateValue))
        {
            AuthState.SetReturnUrl(Uri.UnescapeDataString(stateValue!));
        }
        else if (query.TryGetValue("returnUrl", out var returnUrl) && !string.IsNullOrWhiteSpace(returnUrl))
        {
            AuthState.SetReturnUrl(Uri.UnescapeDataString(returnUrl!));
        }
    }
}

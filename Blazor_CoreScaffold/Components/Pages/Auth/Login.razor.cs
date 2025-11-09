using System.Threading.Tasks;
using API_CoreScaffold.Contracts;
using Microsoft.AspNetCore.Components;
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

    private string PasswordVisibilityIcon => isShowPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;

    [Inject]
    private IAuthService AuthService { get; set; } = default!;

    [Inject]
    private ILogger<Login> Logger { get; set; } = default!;

    [Inject]
    private ISnackbar Snackbar { get; set; } = default!;

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
            Logger.LogInformation("Sending login request for {Email}", Email);

            var response = await AuthService.LoginAsync(Email, Password);

            Logger.LogInformation(
                "Login response received. Success: {Success}, Message: {Message}, OtpRequired: {OtpRequired}",
                response.Success,
                response.Message,
                response.OtpRequired);

            if (response.Success)
            {
                Snackbar.Add("Login request succeeded.", Severity.Success);
            }
            else
            {
                Snackbar.Add(response.Message ?? "Login failed.", Severity.Error);
            }
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Login request failed for {Email}", Email);
            Snackbar.Add("An unexpected error occurred while processing the login request.", Severity.Error);
        }
        finally
        {
            isSubmitting = false;
            await InvokeAsync(StateHasChanged);
        }
    }
}

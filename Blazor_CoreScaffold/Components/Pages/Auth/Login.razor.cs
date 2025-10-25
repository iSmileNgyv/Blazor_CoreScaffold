using System.Threading.Tasks;
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

    private string PasswordVisibilityIcon => isShowPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;

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

        // TODO: Replace with authentication service call.
        await Task.CompletedTask;
    }
}

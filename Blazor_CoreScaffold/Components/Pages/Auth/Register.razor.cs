using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using MudBlazor;

namespace Blazor_CoreScaffold.Components.Pages.Auth;

public partial class Register
{
    private MudForm? form;
    private bool success;
    private readonly RegisterModel model = new();

    private bool isShowPassword;
    private bool isShowConfirmPassword;

    private InputType PasswordInput { get; set; } = InputType.Password;
    private InputType ConfirmPasswordInput { get; set; } = InputType.Password;

    private string PasswordVisibilityIcon => isShowPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;
    private string ConfirmPasswordVisibilityIcon => isShowConfirmPassword ? Icons.Material.Filled.VisibilityOff : Icons.Material.Filled.Visibility;

    private void TogglePasswordVisibility()
    {
        isShowPassword = !isShowPassword;
        PasswordInput = isShowPassword ? InputType.Text : InputType.Password;
    }

    private void ToggleConfirmPasswordVisibility()
    {
        isShowConfirmPassword = !isShowConfirmPassword;
        ConfirmPasswordInput = isShowConfirmPassword ? InputType.Text : InputType.Password;
    }

    private IEnumerable<string> PasswordMatch(string confirmPassword)
    {
        if (model.Password != confirmPassword)
        {
            yield return "Passwords do not match.";
        }
    }

    private double GetPasswordStrengthValue()
    {
        if (string.IsNullOrWhiteSpace(model.Password))
        {
            return 0;
        }

        int score = CalculatePasswordScore(model.Password);
        return Math.Clamp(score / 4.0 * 100.0, 0, 100);
    }

    private Color GetPasswordStrengthColor()
    {
        if (string.IsNullOrWhiteSpace(model.Password))
        {
            return Color.Default;
        }

        int score = CalculatePasswordScore(model.Password);
        return score switch
        {
            <= 1 => Color.Error,
            2 => Color.Warning,
            3 => Color.Info,
            _ => Color.Success
        };
    }

    private string GetPasswordStrengthLabel()
    {
        if (string.IsNullOrWhiteSpace(model.Password))
        {
            return string.Empty;
        }

        int score = CalculatePasswordScore(model.Password);
        return score switch
        {
            <= 1 => "Weak",
            2 => "Medium",
            3 => "Strong",
            _ => "Very Strong"
        };
    }

    private int CalculatePasswordScore(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return 0;
        }

        int score = 0;

        if (password.Length >= 8)
        {
            score++;
        }

        if (Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]"))
        {
            score++;
        }

        if (Regex.IsMatch(password, "[0-9]"))
        {
            score++;
        }

        if (Regex.IsMatch(password, "[^a-zA-Z0-9]"))
        {
            score++;
        }

        if (password.Length < 6)
        {
            score = Math.Min(score, 1);
        }

        return score;
    }

    private async Task SubmitRegistration()
    {
        await form!.Validate();
        if (!success)
        {
            return;
        }

        // TODO: Replace with registration service call.
        await Task.CompletedTask;
    }

    private sealed class RegisterModel
    {
        [Required]
        public string FullName { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string UserName { get; set; } = string.Empty;

        [Required]
        [MinLength(6, ErrorMessage = "Password must be at least 6 characters long.")]
        public string Password { get; set; } = string.Empty;

        [Required]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}

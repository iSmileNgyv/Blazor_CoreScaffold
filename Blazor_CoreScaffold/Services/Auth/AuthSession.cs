using System.Collections.Generic;
using System.Linq;
using Auth;

namespace Blazor_CoreScaffold.Services.Auth;

public sealed class AuthSession
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public AuthenticatedUser? User { get; set; }

    public static AuthSession? FromAuthResponse(AuthResponse response)
    {
        if (!response.Success)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(response.Token))
        {
            return null;
        }

        var userInfo = response.User;
        if (userInfo is null)
        {
            return null;
        }

        var user = new AuthenticatedUser
        {
            Id = userInfo.Id,
            Username = userInfo.Username,
            Name = userInfo.Name,
            Surname = userInfo.Surname,
            PhoneNumber = userInfo.PhoneNumber,
            Roles = userInfo.Roles?.ToList() ?? new List<string>()
        };

        return new AuthSession
        {
            Token = response.Token,
            RefreshToken = response.RefreshToken ?? string.Empty,
            User = user
        };
    }
}

public sealed class AuthenticatedUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string? Surname { get; set; }
    public string? PhoneNumber { get; set; }
    public List<string> Roles { get; set; } = new();
}

public sealed class PendingOtpChallenge
{
    public string Username { get; set; } = string.Empty;
}

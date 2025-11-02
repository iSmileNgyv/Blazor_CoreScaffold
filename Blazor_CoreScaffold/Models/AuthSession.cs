using System.Collections.Generic;
using Auth;

namespace Blazor_CoreScaffold.Models;

public sealed record AuthSession(
    string Token,
    string RefreshToken,
    UserProfile? User)
{
    public static AuthSession FromResponse(AuthResponse response)
    {
        var user = response.User is null
            ? null
            : new UserProfile(
                response.User.Id,
                response.User.Username,
                response.User.Name,
                response.User.Surname,
                response.User.PhoneNumber,
                response.User.Roles);

        return new AuthSession(response.Token, response.RefreshToken, user);
    }
}

public sealed record UserProfile(
    int Id,
    string Username,
    string Name,
    string Surname,
    string PhoneNumber,
    IEnumerable<string> Roles);

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.Extensions.Logging;

namespace Blazor_CoreScaffold.Services.Auth;

public class ServerAuthenticationStateProvider(
    ProtectedSessionStorage sessionStorage,
    ILogger<ServerAuthenticationStateProvider> logger)
    : AuthenticationStateProvider
{
    private const string SessionStorageKey = "auth.session";
    private const string PendingOtpStorageKey = "auth.pendingOtp";

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var session = await GetCurrentSessionInternalAsync();
        if (session is null)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var principal = CreatePrincipal(session);
        return new AuthenticationState(principal);
    }

    public async Task<AuthSession?> GetCurrentSessionAsync() => await GetCurrentSessionInternalAsync();

    public async Task SetSessionAsync(AuthSession session)
    {
        await sessionStorage.SetAsync(SessionStorageKey, session);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(CreatePrincipal(session))));
    }

    public async Task ClearSessionAsync()
    {
        await sessionStorage.DeleteAsync(SessionStorageKey);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
    }

    public async Task SetPendingOtpAsync(PendingOtpChallenge challenge)
    {
        await sessionStorage.SetAsync(PendingOtpStorageKey, challenge);
    }

    public async Task<PendingOtpChallenge?> GetPendingOtpAsync()
    {
        var pending = await sessionStorage.GetAsync<PendingOtpChallenge>(PendingOtpStorageKey);
        if (pending.Success)
        {
            return pending.Value;
        }

        return null;
    }

    public async Task ClearPendingOtpAsync()
    {
        await sessionStorage.DeleteAsync(PendingOtpStorageKey);
    }

    private static ClaimsPrincipal CreatePrincipal(AuthSession session)
    {
        if (session.User is null)
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, session.User.Id.ToString()),
            new(ClaimTypes.Name, session.User.Username)
        };

        if (!string.IsNullOrWhiteSpace(session.User.Name))
        {
            claims.Add(new Claim(ClaimTypes.GivenName, session.User.Name));
        }

        if (!string.IsNullOrWhiteSpace(session.User.Surname))
        {
            claims.Add(new Claim(ClaimTypes.Surname, session.User.Surname));
        }

        if (!string.IsNullOrWhiteSpace(session.User.PhoneNumber))
        {
            claims.Add(new Claim(ClaimTypes.MobilePhone, session.User.PhoneNumber));
        }

        foreach (var role in session.User.Roles)
        {
            if (!string.IsNullOrWhiteSpace(role))
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
        }

        var identity = new ClaimsIdentity(claims, nameof(ServerAuthenticationStateProvider));
        return new ClaimsPrincipal(identity);
    }

    private async Task<AuthSession?> GetCurrentSessionInternalAsync()
    {
        try
        {
            var storedSession = await sessionStorage.GetAsync<AuthSession>(SessionStorageKey);
            if (storedSession.Success)
            {
                return storedSession.Value;
            }
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to restore authentication session from storage.");
        }

        return null;
    }
}

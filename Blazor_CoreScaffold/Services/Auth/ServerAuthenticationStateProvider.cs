using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.JSInterop;

namespace Blazor_CoreScaffold.Services.Auth;

public class ServerAuthenticationStateProvider(
    ProtectedSessionStorage sessionStorage,
    ILogger<ServerAuthenticationStateProvider> logger,
    IHttpContextAccessor httpContextAccessor)
    : AuthenticationStateProvider
{
    private const string SessionStorageKey = "auth.session";
    private PendingOtpChallenge? pendingOtpCache;
    private AuthSession? currentSessionCache;

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext?.User?.Identity?.IsAuthenticated is true)
        {
            return new AuthenticationState(httpContext.User);
        }

        var session = await GetCurrentSessionInternalAsync();
        if (session is null)
        {
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var principal = CreatePrincipal(session);
        await SignInHttpContextAsync(principal);
        return new AuthenticationState(principal);
    }

    public async Task<AuthSession?> GetCurrentSessionAsync() => await GetCurrentSessionInternalAsync();

    public async Task SetSessionAsync(AuthSession session)
    {
        currentSessionCache = session;

        try
        {
            await sessionStorage.SetAsync(SessionStorageKey, session);
        }
        catch (JSDisconnectedException ex)
        {
            logger.LogWarning(ex, "Unable to persist authentication session because the JS runtime is no longer available.");
        }
        var principal = CreatePrincipal(session);
        await SignInHttpContextAsync(principal);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
    }

    public async Task ClearSessionAsync()
    {
        currentSessionCache = null;

        try
        {
            await sessionStorage.DeleteAsync(SessionStorageKey);
        }
        catch (JSDisconnectedException ex)
        {
            logger.LogWarning(ex, "Unable to clear authentication session from storage because the JS runtime is no longer available.");
        }
        await SignOutHttpContextAsync();
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
    }

    public Task SetPendingOtpAsync(PendingOtpChallenge challenge)
    {
        pendingOtpCache = challenge;
        return Task.CompletedTask;
    }

    public Task<PendingOtpChallenge?> GetPendingOtpAsync()
    {
        return Task.FromResult(pendingOtpCache);
    }

    public Task ClearPendingOtpAsync()
    {
        pendingOtpCache = null;
        return Task.CompletedTask;
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
        if (currentSessionCache is not null)
        {
            return currentSessionCache;
        }

        try
        {
            var storedSession = await sessionStorage.GetAsync<AuthSession>(SessionStorageKey);
            if (storedSession.Success)
            {
                currentSessionCache = storedSession.Value;
                return currentSessionCache;
            }
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to restore authentication session from storage.");
        }

        return null;
    }

    private async Task SignInHttpContextAsync(ClaimsPrincipal principal)
    {
        var context = httpContextAccessor.HttpContext;
        if (context is null)
        {
            return;
        }

        try
        {
            await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
            context.User = principal;
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to sign in HTTP context principal.");
        }
    }

    private async Task SignOutHttpContextAsync()
    {
        var context = httpContextAccessor.HttpContext;
        if (context is null)
        {
            return;
        }

        try
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            context.User = new ClaimsPrincipal(new ClaimsIdentity());
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to sign out HTTP context principal.");
        }
    }
}

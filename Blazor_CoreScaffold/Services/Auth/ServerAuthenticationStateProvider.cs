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
    private const string PendingOtpStorageKey = "auth.pendingOtp";
    private PendingOtpChallenge? pendingOtpCache;

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
        await sessionStorage.SetAsync(SessionStorageKey, session);
        var principal = CreatePrincipal(session);
        await SignInHttpContextAsync(principal);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
    }

    public async Task ClearSessionAsync()
    {
        await sessionStorage.DeleteAsync(SessionStorageKey);
        await SignOutHttpContextAsync();
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()))));
    }

    public async Task SetPendingOtpAsync(PendingOtpChallenge challenge)
    {
        pendingOtpCache = challenge;

        try
        {
            await sessionStorage.SetAsync(PendingOtpStorageKey, challenge);
        }
        catch (JSDisconnectedException ex)
        {
            logger.LogWarning(ex, "Circuit disconnected while persisting the pending OTP challenge to session storage.");
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to persist the pending OTP challenge to session storage.");
        }
    }

    public async Task<PendingOtpChallenge?> GetPendingOtpAsync()
    {
        if (pendingOtpCache is not null)
        {
            return pendingOtpCache;
        }

        try
        {
            var pending = await sessionStorage.GetAsync<PendingOtpChallenge>(PendingOtpStorageKey);
            if (pending.Success)
            {
                pendingOtpCache = pending.Value;
                return pending.Value;
            }
        }
        catch (JSDisconnectedException ex)
        {
            logger.LogWarning(ex, "Circuit disconnected while attempting to read the pending OTP challenge from session storage.");
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to read the pending OTP challenge from session storage.");
        }

        return pendingOtpCache;
    }

    public async Task ClearPendingOtpAsync()
    {
        pendingOtpCache = null;

        try
        {
            await sessionStorage.DeleteAsync(PendingOtpStorageKey);
        }
        catch (JSDisconnectedException ex)
        {
            logger.LogWarning(ex, "Circuit disconnected while attempting to clear the pending OTP challenge from session storage.");
        }
        catch (System.Exception ex)
        {
            logger.LogError(ex, "Failed to clear the pending OTP challenge from session storage.");
        }
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

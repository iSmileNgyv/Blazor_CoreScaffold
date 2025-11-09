using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Blazor_CoreScaffold.Services.Auth;

public class ServerAuthenticationStateProvider(
    ILogger<ServerAuthenticationStateProvider> logger,
    IHttpContextAccessor httpContextAccessor)
    : AuthenticationStateProvider
{
    private const string TokenClaimType = "auth:token";
    private const string RefreshTokenClaimType = "auth:refresh-token";
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

    public Task<AuthSession?> GetCurrentSessionAsync() => GetCurrentSessionInternalAsync();

    public async Task SetSessionAsync(AuthSession session)
    {
        currentSessionCache = session;

        var principal = CreatePrincipal(session);
        await SignInHttpContextAsync(principal);
        NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(principal)));
    }

    public async Task ClearSessionAsync()
    {
        currentSessionCache = null;

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

        if (!string.IsNullOrWhiteSpace(session.Token))
        {
            claims.Add(new Claim(TokenClaimType, session.Token));
        }

        if (!string.IsNullOrWhiteSpace(session.RefreshToken))
        {
            claims.Add(new Claim(RefreshTokenClaimType, session.RefreshToken));
        }

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

    private Task<AuthSession?> GetCurrentSessionInternalAsync()
    {
        if (currentSessionCache is not null)
        {
            return Task.FromResult<AuthSession?>(currentSessionCache);
        }

        var principal = httpContextAccessor.HttpContext?.User;
        var session = CreateSessionFromPrincipal(principal);
        if (session is null)
        {
            return Task.FromResult<AuthSession?>(null);
        }

        currentSessionCache = session;
        return Task.FromResult<AuthSession?>(currentSessionCache);
    }

    private static AuthSession? CreateSessionFromPrincipal(ClaimsPrincipal? principal)
    {
        if (principal?.Identity?.IsAuthenticated is not true)
        {
            return null;
        }

        var username = principal.FindFirstValue(ClaimTypes.Name);
        if (string.IsNullOrWhiteSpace(username))
        {
            return null;
        }

        var idClaim = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!int.TryParse(idClaim, out var id))
        {
            return null;
        }

        var user = new AuthenticatedUser
        {
            Id = id,
            Username = username,
            Name = principal.FindFirstValue(ClaimTypes.GivenName),
            Surname = principal.FindFirstValue(ClaimTypes.Surname),
            PhoneNumber = principal.FindFirstValue(ClaimTypes.MobilePhone),
            Roles = principal.FindAll(ClaimTypes.Role)
                .Where(r => !string.IsNullOrWhiteSpace(r.Value))
                .Select(r => r.Value)
                .ToList()
        };

        var token = principal.FindFirstValue(TokenClaimType) ?? string.Empty;
        var refreshToken = principal.FindFirstValue(RefreshTokenClaimType) ?? string.Empty;

        return new AuthSession
        {
            Token = token,
            RefreshToken = refreshToken,
            User = user
        };
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

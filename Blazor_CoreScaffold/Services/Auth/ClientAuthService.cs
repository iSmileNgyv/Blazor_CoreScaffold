using System;
using System.Threading.Tasks;
using API_CoreScaffold.Contracts;
using Auth;
using Microsoft.Extensions.Logging;

namespace Blazor_CoreScaffold.Services.Auth;

public interface IClientAuthService
{
    Task<AuthResponse> LoginAsync(string username, string password);
    Task<AuthResponse> VerifyOtpAsync(string otpCode);
    Task LogoutAsync();
    Task<AuthSession?> GetCurrentSessionAsync();
    Task<string?> GetPendingOtpUsernameAsync();
    Task<string?> ConsumeLoginTicketAsync();
}

public class ClientAuthService(
    IAuthService authService,
    ServerAuthenticationStateProvider authenticationStateProvider,
    ILogger<ClientAuthService> logger) : IClientAuthService
{
    private string? pendingLoginTicket;

    public async Task<AuthResponse> LoginAsync(string username, string password)
    {
        pendingLoginTicket = null;
        var response = await authService.LoginAsync(username, password);

        if (!response.Success)
        {
            await authenticationStateProvider.ClearPendingOtpAsync();
            return response;
        }

        if (response.OtpRequired)
        {
            await authenticationStateProvider.SetPendingOtpAsync(new PendingOtpChallenge
            {
                Username = username
            });
            return response;
        }

        await PersistAuthenticatedSessionAsync(response);
        return response;
    }

    public async Task<AuthResponse> VerifyOtpAsync(string otpCode)
    {
        pendingLoginTicket = null;
        var pendingChallenge = await authenticationStateProvider.GetPendingOtpAsync();
        if (pendingChallenge is null || string.IsNullOrWhiteSpace(pendingChallenge.Username))
        {
            throw new InvalidOperationException("No pending OTP challenge is available.");
        }

        var response = await authService.VerifyOtpAndLoginAsync(pendingChallenge.Username, otpCode);

        if (!response.Success)
        {
            return response;
        }

        if (response.OtpRequired)
        {
            // Backend indicates OTP is still required; keep the challenge stored
            return response;
        }

        await authenticationStateProvider.ClearPendingOtpAsync();
        await PersistAuthenticatedSessionAsync(response);

        return response;
    }

    public async Task LogoutAsync()
    {
        await authenticationStateProvider.ClearPendingOtpAsync();
        await authenticationStateProvider.ClearSessionAsync();
        pendingLoginTicket = null;
    }

    public Task<AuthSession?> GetCurrentSessionAsync() => authenticationStateProvider.GetCurrentSessionAsync();

    public async Task<string?> GetPendingOtpUsernameAsync()
    {
        var pending = await authenticationStateProvider.GetPendingOtpAsync();
        return pending?.Username;
    }

    public Task<string?> ConsumeLoginTicketAsync()
    {
        var ticket = pendingLoginTicket;
        pendingLoginTicket = null;
        return Task.FromResult(ticket);
    }

    private async Task PersistAuthenticatedSessionAsync(AuthResponse response)
    {
        var session = AuthSession.FromAuthResponse(response);
        if (session is null)
        {
            logger.LogWarning("AuthResponse did not contain the expected session information.");
            await authenticationStateProvider.ClearSessionAsync();
            return;
        }

        await authenticationStateProvider.ClearPendingOtpAsync();
        var cookieIssued = await authenticationStateProvider.SetSessionAsync(session);
        pendingLoginTicket = cookieIssued
            ? null
            : await authenticationStateProvider.CreateLoginTicketAsync(session);
    }
}

using System;
using System.Threading;
using System.Threading.Tasks;
using Auth;
using Grpc.Core;
using Microsoft.Extensions.Logging;

namespace Blazor_CoreScaffold.Services.Authentication;

public class AuthenticationClient : IAuthenticationClient
{
    private readonly AuthService.AuthServiceClient _client;
    private readonly ILogger<AuthenticationClient> _logger;

    public AuthenticationClient(AuthService.AuthServiceClient client, ILogger<AuthenticationClient> logger)
    {
        _client = client;
        _logger = logger;
    }

    public async Task<AuthResponse> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _client.LoginAsync(new LoginRequest
            {
                Username = username,
                Password = password,
            }, cancellationToken: cancellationToken);

            return response;
        }
        catch (RpcException rpcException)
        {
            _logger.LogError(rpcException, "gRPC login request failed with status {Status}", rpcException.Status);
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Unexpected error while calling login gRPC endpoint");
            throw;
        }
    }
}

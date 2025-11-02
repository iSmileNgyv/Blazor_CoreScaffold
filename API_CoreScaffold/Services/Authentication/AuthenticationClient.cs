using System.Threading;
using System.Threading.Tasks;
using API_CoreScaffold.Abstractions;
using Auth;
using Microsoft.Extensions.Logging;

namespace API_CoreScaffold.Services.Authentication;

public class AuthenticationClient : GrpcClientBase<AuthService.AuthServiceClient>, IAuthenticationClient
{
    public AuthenticationClient(AuthService.AuthServiceClient client, ILogger<AuthenticationClient> logger)
        : base(client, logger)
    {
    }

    public Task<AuthResponse> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        return ExecuteAsync((grpcClient, token) =>
            grpcClient.LoginAsync(new LoginRequest
            {
                Username = username,
                Password = password,
            }, cancellationToken: token),
            nameof(LoginAsync),
            cancellationToken);
    }
}

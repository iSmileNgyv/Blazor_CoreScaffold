using API_CoreScaffold.Contracts;
using Auth;
using Grpc.Core;
using Microsoft.Extensions.Logging;

namespace API_CoreScaffold.Services;

public class AuthClientService(
    ILogger<AuthClientService> logger,
    AuthService.AuthServiceClient grpcClient
    ) : IAuthService
{
    public async Task<AuthResponse> LoginAsync(string username, string password)
    {
        try
        {
            // Create the request message as defined in auth.proto
            var request = new LoginRequest
            {
                Username = username,
                Password = password
            };

            logger.LogInformation("Attempting gRPC login for user: {Username}", username);

            // Call the gRPC service
            var response = await grpcClient.LoginAsync(request);

            return response;
        }
        catch (RpcException rpcEx)
        {
            // Log gRPC-specific errors
            logger.LogError(rpcEx, "gRPC error during login for {Username}. Status: {Status}, Detail: {Detail}",
                username, rpcEx.StatusCode, rpcEx.Status.Detail);
            
            // Return a failure response
            return new AuthResponse
            {
                Success = false,
                Message = $"Error connecting to service: {rpcEx.Status.Detail ?? rpcEx.Message}"
            };
        }
        catch (Exception ex)
        {
            // Log any other unexpected errors
            logger.LogError(ex, "Unexpected error during login for {Username}", username);

            // Return a generic failure response
            return new AuthResponse
            {
                Success = false,
                Message = "An unexpected error occurred."
            };
        }
    }
}
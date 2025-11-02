using System;
using System.Threading;
using System.Threading.Tasks;
using Grpc.Core;
using Microsoft.Extensions.Logging;

namespace API_CoreScaffold.Abstractions;

public abstract class GrpcClientBase<TClient>
{
    private readonly ILogger _logger;

    protected GrpcClientBase(TClient client, ILogger logger)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected TClient Client { get; }

    protected Task<TResult> ExecuteAsync<TResult>(Func<TClient, CancellationToken, Task<TResult>> operation, string operationName, CancellationToken cancellationToken)
    {
        if (operation is null)
        {
            throw new ArgumentNullException(nameof(operation));
        }

        if (string.IsNullOrWhiteSpace(operationName))
        {
            throw new ArgumentException("Operation name must be provided.", nameof(operationName));
        }

        return ExecuteCoreAsync(operation, operationName, cancellationToken);
    }

    private async Task<TResult> ExecuteCoreAsync<TResult>(Func<TClient, CancellationToken, Task<TResult>> operation, string operationName, CancellationToken cancellationToken)
    {
        try
        {
            return await operation(Client, cancellationToken).ConfigureAwait(false);
        }
        catch (RpcException rpcException)
        {
            _logger.LogError(rpcException, "gRPC {Operation} request failed with status {Status}", operationName, rpcException.Status);
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Unexpected error while executing gRPC {Operation} request", operationName);
            throw;
        }
    }
}

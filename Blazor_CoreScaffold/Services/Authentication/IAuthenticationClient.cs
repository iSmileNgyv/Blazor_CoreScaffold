using System.Threading;
using System.Threading.Tasks;
using Auth;

namespace Blazor_CoreScaffold.Services.Authentication;

public interface IAuthenticationClient
{
    Task<AuthResponse> LoginAsync(string username, string password, CancellationToken cancellationToken = default);
}

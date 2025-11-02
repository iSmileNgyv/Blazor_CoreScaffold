using System;
using Blazor_CoreScaffold.Models;

namespace Blazor_CoreScaffold.Services;

public class AuthState
{
    private AuthSession? _session;
    private string? _returnUrl;

    public event Action? StateChanged;

    public AuthSession? Session => _session;

    public string? ReturnUrl => _returnUrl;

    public void SetSession(AuthSession session)
    {
        _session = session;
        NotifyStateChanged();
    }

    public void ClearSession()
    {
        _session = null;
        NotifyStateChanged();
    }

    public void SetReturnUrl(string? url)
    {
        if (!string.IsNullOrWhiteSpace(url))
        {
            _returnUrl = url;
        }
    }

    public void ClearReturnUrl()
    {
        _returnUrl = null;
    }

    private void NotifyStateChanged()
    {
        StateChanged?.Invoke();
    }
}

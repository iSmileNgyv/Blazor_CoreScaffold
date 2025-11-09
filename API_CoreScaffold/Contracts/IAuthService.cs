namespace API_CoreScaffold.Contracts;

using Auth; 
public interface IAuthService
{
    Task<AuthResponse> LoginAsync(string username, string password);
    Task<AuthResponse> VerifyOtpAndLoginAsync(string username, string otpCode);
}
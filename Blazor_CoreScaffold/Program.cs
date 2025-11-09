using API_CoreScaffold.Contracts;
using API_CoreScaffold.Services;
using Auth;
using Blazor_CoreScaffold.Components;
using Blazor_CoreScaffold.Services.Auth;
using MudBlazor.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.Services.AddAuthorizationCore();
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.LogoutPath = "/logout";
        options.SlidingExpiration = true;
    });
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<ServerAuthenticationStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(sp =>
    sp.GetRequiredService<ServerAuthenticationStateProvider>());
builder.Services.AddScoped<IClientAuthService, ClientAuthService>();
builder.Services.AddScoped<IAuthService, AuthClientService>();

// Register the gRPC client generated from auth.proto
builder.Services.AddGrpcClient<AuthService.AuthServiceClient>(options =>
    {
        options.Address = new Uri("http://localhost:5051"); 
    })
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler
        {
            // Allow insecure HTTP/2 connections
            ServerCertificateCustomValidationCallback = 
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        return handler;
    });
// *** END ADDED/MODIFIED SECTION ***
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/auth/callback", async (HttpContext context, string? ticket, ServerAuthenticationStateProvider authenticationStateProvider, ILoggerFactory loggerFactory) =>
    {
        var logger = loggerFactory.CreateLogger("AuthCallback");

        if (string.IsNullOrWhiteSpace(ticket))
        {
            logger.LogWarning("Auth callback invoked without a ticket.");
            return Results.Redirect("/login?authTicket=missing");
        }

        var redeemed = await authenticationStateProvider.TryRedeemLoginTicketAsync(ticket);
        if (!redeemed)
        {
            logger.LogWarning("Auth callback ticket {Ticket} was invalid or expired.", ticket);
            return Results.Redirect("/login?authTicket=invalid");
        }

        return Results.Redirect("/");
    })
    .AllowAnonymous();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
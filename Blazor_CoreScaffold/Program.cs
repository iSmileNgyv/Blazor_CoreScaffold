using Blazor_CoreScaffold.Components;
using Blazor_CoreScaffold.Services;
using Blazor_CoreScaffold.Services.Authentication;
using MudBlazor.Services;

AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddMudServices();
builder.Services.AddScoped<AuthState>();
builder.Services.AddGrpcClient<Auth.AuthService.AuthServiceClient>(options =>
{
    var address = builder.Configuration["Grpc:AuthUrl"] ?? "http://localhost:9090";
    options.Address = new Uri(address);
});
builder.Services.AddScoped<IAuthenticationClient, AuthenticationClient>();
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
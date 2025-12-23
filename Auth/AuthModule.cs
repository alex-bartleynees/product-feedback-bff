using ProductFeedback.BFF.Auth.Antiforgery;
using ProductFeedback.BFF.Auth.DataProtection;
using ProductFeedback.BFF.Auth.OIDC;
using ProductFeedback.BFF.Auth.TokenManagement;

namespace ProductFeedback.BFF.Auth;

internal static class AuthModule
{
    internal static IServiceCollection AddAuth(this WebApplicationBuilder builder)
    {
        builder.AddRedisDataProtection();
        builder.AddOidcAuthentication();
        builder.Services.AddAuthorizationPolicies();

        // Configure anti-forgery services
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.Name = "__CSRF";
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

        // Register token management service
        builder.Services.AddScoped<ITokenService, TokenService>();

        // Register HttpClientFactory for token refresh
        builder.Services.AddHttpClient();

        return builder.Services;
    }

    internal static IApplicationBuilder UseAuth(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();

        // Add anti-forgery protection middleware (must be after UseAuthentication)
        app.UseAntiforgeryProtection();

        // Map BFF management endpoints
        app.MapBffEndpoints();

        return app;
    }
}
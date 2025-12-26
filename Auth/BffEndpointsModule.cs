using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using OpenIdConnectOptions = ProductFeedback.BFF.Auth.OIDC.OpenIdConnectOptions;

namespace ProductFeedback.BFF.Auth;

internal static class BffEndpointsModule
{
    internal static IApplicationBuilder MapBffEndpoints(this WebApplication app)
    {
        var bffGroup = app.MapGroup("/bff");

        // GET /bff/user - Returns current user claims
        bffGroup.MapGet("/user", (HttpContext context) =>
        {
            if (context.User.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            var claims = context.User.Claims.Select(c => new
            {
                type = c.Type,
                value = c.Value
            });

            return Results.Ok(new
            {
                isAuthenticated = true,
                claims = claims
            });
        });

        // GET /bff/login - Initiates OIDC login flow
        bffGroup.MapGet("/login", (HttpContext context, IOptions<OpenIdConnectOptions> oidcOptions) =>
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = oidcOptions.Value.RedirectUri
            };

            return Results.Challenge(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
        });

        // POST /bff/logout - Initiates logout
        bffGroup.MapPost("/logout", async (HttpContext context, IAntiforgery antiforgery, IOptions<OpenIdConnectOptions> oidcOptions) =>
        {
            // Validate anti-forgery token
            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest(new
                {
                    error = "Invalid anti-forgery token",
                    details = "Include X-CSRF-TOKEN header with valid token"
                });
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = oidcOptions.Value.RedirectUri
            };

            // Sign out from both cookie and OIDC
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.SignOut(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
        })
        .RequireAuthorization();

        // GET /bff/antiforgery - Returns anti-forgery token for SPA clients
        bffGroup.MapGet("/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);

            return Results.Ok(new
            {
                requestToken = tokens.RequestToken,
                headerName = "X-CSRF-TOKEN"
            });
        });

        return app;
    }
}

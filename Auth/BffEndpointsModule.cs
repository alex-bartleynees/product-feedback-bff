using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

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
        })
        .RequireAuthorization();

        // GET /bff/login - Initiates OIDC login flow
        bffGroup.MapGet("/login", (HttpContext context, string? returnUrl) =>
        {
            // Validate returnUrl to prevent open redirect
            if (!string.IsNullOrEmpty(returnUrl) && !IsLocalUrl(returnUrl, context))
            {
                returnUrl = "/";
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? "/"
            };

            return Results.Challenge(properties, [OpenIdConnectDefaults.AuthenticationScheme]);
        });

        // POST /bff/logout - Initiates logout
        bffGroup.MapPost("/logout", async (HttpContext context, IAntiforgery antiforgery, string? returnUrl) =>
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

            // Validate returnUrl to prevent open redirect
            if (!string.IsNullOrEmpty(returnUrl) && !IsLocalUrl(returnUrl, context))
            {
                returnUrl = "/";
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = returnUrl ?? "/"
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

    private static bool IsLocalUrl(string url, HttpContext context)
    {
        // Check if URL is relative
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Reject URLs that start with // or /\ (protocol-relative)
        if (url.StartsWith("//") || url.StartsWith("/\\"))
        {
            return false;
        }

        // Reject URLs with @ (could be user info in absolute URL)
        if (url.Contains('@'))
        {
            return false;
        }

        // URL must start with / and not be protocol-relative
        if (url.StartsWith('/'))
        {
            return !url.StartsWith("//") && !url.StartsWith("/\\");
        }

        // Reject any absolute URLs
        if (Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            return false;
        }

        return true;
    }
}

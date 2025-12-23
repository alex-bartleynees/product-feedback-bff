using Microsoft.AspNetCore.Antiforgery;

namespace ProductFeedback.BFF.Auth.Antiforgery;

/// <summary>
/// Middleware to validate anti-forgery tokens for state-changing requests
/// </summary>
public class AntiforgeryMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IAntiforgery _antiforgery;
    private readonly ILogger<AntiforgeryMiddleware> _logger;

    public AntiforgeryMiddleware(
        RequestDelegate next,
        IAntiforgery antiforgery,
        ILogger<AntiforgeryMiddleware> logger)
    {
        _next = next;
        _antiforgery = antiforgery;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only validate for authenticated users making state-changing requests
        if (context.User.Identity?.IsAuthenticated == true &&
            IsStateChangingRequest(context.Request))
        {
            // Check if this is a BFF API endpoint (starts with /api/)
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                try
                {
                    // Validate anti-forgery token from header
                    var token = context.Request.Headers["X-CSRF-TOKEN"].FirstOrDefault();

                    if (string.IsNullOrEmpty(token))
                    {
                        _logger.LogWarning("Anti-forgery token missing for {Method} {Path}",
                            context.Request.Method, context.Request.Path);

                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new
                        {
                            error = "Anti-forgery token is required",
                            details = "Include X-CSRF-TOKEN header with valid token"
                        });
                        return;
                    }

                    // Validate the token
                    await _antiforgery.ValidateRequestAsync(context);
                }
                catch (AntiforgeryValidationException ex)
                {
                    _logger.LogWarning(ex, "Anti-forgery validation failed for {Method} {Path}",
                        context.Request.Method, context.Request.Path);

                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Invalid anti-forgery token",
                        details = ex.Message
                    });
                    return;
                }
            }
        }

        await _next(context);
    }

    private static bool IsStateChangingRequest(HttpRequest request)
    {
        var method = request.Method.ToUpperInvariant();
        return method != "GET" &&
               method != "HEAD" &&
               method != "OPTIONS" &&
               method != "TRACE";
    }
}

public static class AntiforgeryMiddlewareExtensions
{
    public static IApplicationBuilder UseAntiforgeryProtection(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AntiforgeryMiddleware>();
    }
}

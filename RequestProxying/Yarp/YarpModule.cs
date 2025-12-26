using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using ProductFeedback.BFF.Auth.TokenManagement;
using Yarp.ReverseProxy.Transforms;

namespace ProductFeedback.BFF.RequestProxying.Yarp;

internal static class YarpModule
{
    internal static IServiceCollection AddYarp(this IServiceCollection services, ConfigurationManager configuration)
    {
        var reverseProxyConfig =
            configuration.GetSection("ReverseProxy") ?? throw new ArgumentException("ReverseProxy section is missing!");

        services.AddReverseProxy()
            .LoadFromConfig(reverseProxyConfig)
            .AddTransforms(builderContext =>
            {
                // Add authentication token to proxied requests
                builderContext.AddRequestTransform(async transformContext =>
                {
                    // Only add token for authenticated users
                    if (transformContext.HttpContext.User.Identity?.IsAuthenticated == true)
                    {
                        var tokenService = transformContext.HttpContext.RequestServices
                            .GetRequiredService<ITokenService>();

                        var tokenResult = await tokenService.GetUserAccessTokenAsync(transformContext.HttpContext);

                        if (tokenResult.IsSuccess && !string.IsNullOrEmpty(tokenResult.AccessToken))
                        {
                            transformContext.ProxyRequest.Headers.Authorization =
                                new AuthenticationHeaderValue(JwtBearerDefaults.AuthenticationScheme, tokenResult.AccessToken);
                        }
                        else
                        {
                            // Log warning but continue - backend will handle unauthorized
                            var logger = transformContext.HttpContext.RequestServices
                                .GetRequiredService<ILoggerFactory>()
                                .CreateLogger("ProductFeedback.BFF.RequestProxying.Yarp");
                            logger.LogWarning("Failed to retrieve access token: {Error}", tokenResult.Error);
                        }
                    }
                });
            });

        return services;
    }

    internal static WebApplication UseYarp(this WebApplication app)
    {
        app.MapReverseProxy();
        return app;
    }
}
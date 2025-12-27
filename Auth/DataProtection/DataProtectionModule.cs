using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

namespace ProductFeedback.BFF.Auth.DataProtection;

internal static class DataProtectionModule
{
    internal static IServiceCollection AddRedisDataProtection(this WebApplicationBuilder builder)
    {
        var redisHost = builder.Configuration["Redis:Host"] ?? "localhost:6379";

        var redisConfig = ConfigurationOptions.Parse(redisHost);

        // Set password from configuration
        var redisPassword = builder.Configuration["Redis:Password"];
        if (!string.IsNullOrEmpty(redisPassword))
        {
            redisConfig.Password = redisPassword;
        }

        // Configure TLS if enabled
        if (builder.Configuration.GetValue<bool>("Redis:UseTls"))
        {
            redisConfig.Ssl = true;

            // Extract host without port for SslHost
            var hostWithoutPort = redisHost.Split(':')[0];
            redisConfig.SslHost = hostWithoutPort;

            // Allow self-signed certificates (common in Kubernetes internal Redis)
            redisConfig.CertificateValidation += (sender, cert, chain, errors) => true;
        }

        // Retry configuration
        redisConfig.AbortOnConnectFail = false;
        redisConfig.ConnectRetry = 3;

        var redis = ConnectionMultiplexer.Connect(redisConfig);

        // Register Redis connection as singleton for use by other services
        builder.Services.AddSingleton<IConnectionMultiplexer>(redis);

        // Register the Redis ticket store for cookie authentication
        builder.Services.AddSingleton<ITicketStore, RedisTicketStore>();

        builder.Services.AddDataProtection()
            .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
            .SetApplicationName("product-feedback-bff");

        return builder.Services;
    }
}

using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace ProductFeedback.BFF.Auth.TokenManagement;

public interface ITokenService
{
    Task<TokenResult> GetUserAccessTokenAsync(HttpContext httpContext);
}

public class TokenService(
    ILogger<TokenService> logger,
    TimeProvider timeProvider,
    IHttpClientFactory httpClientFactory)
    : ITokenService
{
    public async Task<TokenResult> GetUserAccessTokenAsync(HttpContext httpContext)
    {
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            logger.LogWarning("User is not authenticated, cannot retrieve access token");
            return TokenResult.FromError("User is not authenticated");
        }

        var accessToken = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "access_token");

        if (string.IsNullOrEmpty(accessToken))
        {
            logger.LogWarning("Access token not found in authentication properties");
            return TokenResult.FromError("Access token not found");
        }

        if (await IsTokenExpired(httpContext))
        {
            logger.LogInformation("Access token is expired, attempting refresh");
            var refreshResult = await RefreshTokenAsync(httpContext);
        
            if (!refreshResult.IsSuccess)
            {
                return refreshResult;
            }

            accessToken = refreshResult.AccessToken;
        }
            
        return TokenResult.Success(accessToken!);
    }

    private async Task<bool> IsTokenExpired(HttpContext httpContext)
    {
        var expiresAt = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "expires_at");
        return !string.IsNullOrEmpty(expiresAt)
               && DateTimeOffset.TryParse(expiresAt, out var expiration)
               && expiration <= timeProvider.GetUtcNow();
    }

    private async Task<TokenResult> RefreshTokenAsync(HttpContext httpContext)
    {
        var refreshToken = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "refresh_token");

        if (string.IsNullOrEmpty(refreshToken))
        {
            logger.LogWarning("Refresh token not found, cannot refresh access token");
            return TokenResult.FromError("Refresh token not found");
        }

        // Get OIDC configuration
        var oidcOptions = httpContext.RequestServices
            .GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        if (string.IsNullOrEmpty(oidcOptions.Authority))
        {
            logger.LogError("OIDC Authority is not configured");
            return TokenResult.FromError("OIDC Authority is not configured");
        }

        // Construct token endpoint (Keycloak standard path)
        var tokenEndpoint = $"{oidcOptions.Authority}/protocol/openid-connect/token";

        var requestBody = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = oidcOptions.ClientId ?? string.Empty,
            ["client_secret"] = oidcOptions.ClientSecret ?? string.Empty
        });

        try
        {
            using var httpClient = httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(tokenEndpoint, requestBody);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                logger.LogWarning("Token refresh failed with status {StatusCode}: {Error}",
                    response.StatusCode, errorContent);
                return TokenResult.FromError($"Token refresh failed: {response.StatusCode}");
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                logger.LogWarning("Invalid token response - missing access_token");
                return TokenResult.FromError("Invalid token response");
            }

            // Update tokens in authentication properties
            var authResult = await httpContext.AuthenticateAsync(
                CookieAuthenticationDefaults.AuthenticationScheme);

            if (authResult?.Properties != null && authResult.Principal != null)
            {
                authResult.Properties.UpdateTokenValue("access_token", tokenResponse.AccessToken);

                if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                {
                    authResult.Properties.UpdateTokenValue("refresh_token", tokenResponse.RefreshToken);
                }

                if (tokenResponse.ExpiresIn > 0)
                {
                    var expiresAt = timeProvider.GetUtcNow().AddSeconds(tokenResponse.ExpiresIn);
                    authResult.Properties.UpdateTokenValue("expires_at", expiresAt.ToString("o"));
                }

                // Re-issue the cookie with updated tokens
                await httpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    authResult.Principal,
                    authResult.Properties);

                logger.LogInformation("Successfully refreshed access token");
                return TokenResult.Success(tokenResponse.AccessToken);
            }

            logger.LogError("Failed to retrieve authentication properties for token update");
            return TokenResult.FromError("Failed to update authentication properties");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Exception during token refresh");
            return TokenResult.FromError($"Token refresh exception: {ex.Message}");
        }
    }
}

public class TokenResult
{
    public bool IsSuccess { get; init; }
    public string? AccessToken { get; init; }
    public string? Error { get; init; }

    public static TokenResult Success(string accessToken) => new()
    {
        IsSuccess = true,
        AccessToken = accessToken
    };

    public static TokenResult FromError(string error) => new()
    {
        IsSuccess = false,
        Error = error
    };
}

internal class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string? AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace ProductFeedback.BFF.Auth.TokenManagement;

public interface ITokenService
{
    Task<TokenResult> GetUserAccessTokenAsync(HttpContext httpContext);
}

public class TokenService : ITokenService
{
    private readonly ILogger<TokenService> _logger;
    private readonly TimeProvider _timeProvider;
    private readonly IHttpClientFactory _httpClientFactory;

    public TokenService(
        ILogger<TokenService> logger,
        TimeProvider timeProvider,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _timeProvider = timeProvider;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<TokenResult> GetUserAccessTokenAsync(HttpContext httpContext)
    {
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            _logger.LogWarning("User is not authenticated, cannot retrieve access token");
            return TokenResult.FromError("User is not authenticated");
        }

        // OIDC with SaveTokens=true stores tokens in the authentication properties
        var accessToken = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "access_token");

        if (string.IsNullOrEmpty(accessToken))
        {
            _logger.LogWarning("Access token not found in authentication properties");
            return TokenResult.FromError("Access token not found");
        }

        // Check if token is expired
        var expiresAt = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "expires_at");

        if (!string.IsNullOrEmpty(expiresAt))
        {
            if (DateTimeOffset.TryParse(expiresAt, out var expiration))
            {
                if (expiration <= _timeProvider.GetUtcNow())
                {
                    _logger.LogInformation("Access token is expired, attempting refresh");

                    // Attempt to refresh the token
                    var refreshResult = await RefreshTokenAsync(httpContext);
                    if (!refreshResult.IsSuccess)
                    {
                        return refreshResult;
                    }

                    accessToken = refreshResult.AccessToken;
                }
            }
        }

        return TokenResult.Success(accessToken!);
    }

    private async Task<TokenResult> RefreshTokenAsync(HttpContext httpContext)
    {
        var refreshToken = await httpContext.GetTokenAsync(
            OpenIdConnectDefaults.AuthenticationScheme,
            "refresh_token");

        if (string.IsNullOrEmpty(refreshToken))
        {
            _logger.LogWarning("Refresh token not found, cannot refresh access token");
            return TokenResult.FromError("Refresh token not found");
        }

        // Get OIDC configuration
        var oidcOptions = httpContext.RequestServices
            .GetRequiredService<IOptionsSnapshot<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);

        if (string.IsNullOrEmpty(oidcOptions.Authority))
        {
            _logger.LogError("OIDC Authority is not configured");
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
            using var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.PostAsync(tokenEndpoint, requestBody);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogWarning("Token refresh failed with status {StatusCode}: {Error}",
                    response.StatusCode, errorContent);
                return TokenResult.FromError($"Token refresh failed: {response.StatusCode}");
            }

            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.AccessToken))
            {
                _logger.LogWarning("Invalid token response - missing access_token");
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
                    var expiresAt = _timeProvider.GetUtcNow().AddSeconds(tokenResponse.ExpiresIn);
                    authResult.Properties.UpdateTokenValue("expires_at", expiresAt.ToString("o"));
                }

                // Re-issue the cookie with updated tokens
                await httpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    authResult.Principal,
                    authResult.Properties);

                _logger.LogInformation("Successfully refreshed access token");
                return TokenResult.Success(tokenResponse.AccessToken);
            }

            _logger.LogError("Failed to retrieve authentication properties for token update");
            return TokenResult.FromError("Failed to update authentication properties");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exception during token refresh");
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
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public int ExpiresIn { get; set; }
}

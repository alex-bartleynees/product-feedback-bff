namespace ProductFeedback.BFF.Auth.OIDC;

internal sealed class OpenIdConnectOptions
{
    public const string Key = "OpenIdConnectOptions";
    public string ServerUrl => Environment.GetEnvironmentVariable("KEYCLOAK_SERVER_URL") 
                               ?? "http://localhost:7002";
    
    public string CookieName { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public string ResponseType { get; init; } = string.Empty;
    public string ResponseMode { get; init; } = string.Empty;
    public bool GetClaimsFromUserInfoEndpoint { get; init; }
    public bool MapInboundClaims { get; init; }
    public bool SaveTokens { get; init; }
    public string Scope { get; init; } = string.Empty; 
    public string AuthorityPath { get; init; } = string.Empty; 
    public string Authority => $"{ServerUrl}/{AuthorityPath}";
}
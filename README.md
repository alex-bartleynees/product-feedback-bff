# Product Feedback BFF

A Backend-for-Frontend (BFF) service for the Product Feedback application, built with ASP.NET Core 10.0. This service handles authentication, session management, and proxies API requests to backend services.

## Features

- **OpenID Connect Authentication**: Cookie-based session management with Keycloak integration
- **Token Management**: Automatic access token refresh and secure token storage
- **Reverse Proxy**: YARP-based request proxying with automatic Bearer token injection
- **CSRF Protection**: Anti-forgery token validation for state-changing operations
- **Distributed Sessions**: Redis-backed data protection for multi-instance deployments
- **Reverse Proxy Support**: Handles X-Forwarded headers for deployment behind load balancers

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────────┐
│   Browser   │─────▶│     BFF     │─────▶│  Backend API    │
│    (SPA)    │      │  (Cookies)  │      │  (JWT Bearer)   │
└─────────────┘      └─────────────┘      └─────────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │  Keycloak   │
                     │   (OIDC)    │
                     └─────────────┘
```

The BFF pattern keeps access tokens server-side, exposing only HTTP-only cookies to the browser. This improves security by preventing token theft via XSS attacks.

## Prerequisites

- .NET 10.0 SDK
- Redis (for distributed data protection)
- Keycloak or compatible OIDC provider

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Keycloak server URL
KEYCLOAK_SERVER_URL=http://localhost:7002

# OIDC client secret (overrides appsettings.json)
OpenIdConnectOptions__ClientSecret=your-client-secret-here
```

### Application Settings

Key configuration in `appsettings.json`:

| Section | Setting | Description |
|---------|---------|-------------|
| `Redis` | `Host` | Redis connection string |
| `OpenIdConnectOptions` | `ClientId` | OIDC client identifier |
| `OpenIdConnectOptions` | `AuthorityPath` | Keycloak realm path |
| `OpenIdConnectOptions` | `Scope` | Requested OIDC scopes |
| `ReverseProxy` | `Routes` | YARP route configuration |
| `ReverseProxy` | `Clusters` | Backend service addresses |

## API Endpoints

### BFF Management Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/bff/user` | Get current user claims |
| `GET` | `/bff/login` | Initiate OIDC login flow |
| `POST` | `/bff/logout` | Logout (requires CSRF token) |
| `GET` | `/bff/antiforgery` | Get CSRF token for SPA |

### Proxied Endpoints

All requests to `/api/**` are proxied to the configured backend API with the user's access token automatically injected as a Bearer token.

## Development

### Running Locally

```bash
# Restore dependencies
dotnet restore

# Run the application
dotnet run
```

The service runs on `http://localhost:5224` by default.

### Using Nix

This project includes a Nix flake for reproducible development environments:

```bash
# Enter development shell
nix develop

# Or with direnv
direnv allow
```

## Deployment

### Docker

```bash
# Build the image
docker build -t product-feedback-bff .

# Run the container
docker run -p 5224:5224 \
  -e KEYCLOAK_SERVER_URL=https://keycloak.example.com \
  -e OpenIdConnectOptions__ClientSecret=your-secret \
  product-feedback-bff
```

### Kubernetes

Helm charts are available in the `deployment/helm-charts` directory:

```bash
helm install product-feedback-bff ./deployment/helm-charts/product-feedback-bff \
  --set keycloak.serverUrl=https://keycloak.example.com \
  --set oidc.clientSecret=your-secret
```

## Security Considerations

- Access tokens are stored server-side in encrypted cookies
- CSRF protection is enabled for all state-changing operations
- Cookies are configured with `HttpOnly`, `Secure`, and `SameSite=Strict`
- Token refresh is handled automatically before expiration
- Redis data protection keys enable secure session sharing across instances

## Project Structure

```
├── Auth/
│   ├── Antiforgery/       # CSRF protection middleware
│   ├── DataProtection/    # Redis key storage
│   ├── OIDC/              # OpenID Connect configuration
│   └── TokenManagement/   # Token refresh service
├── Common/
│   └── Clocks/            # TimeProvider abstraction
├── RequestProxying/
│   └── Yarp/              # Reverse proxy configuration
└── deployment/
    └── helm-charts/       # Kubernetes deployment
```

## License

This project is private.

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace ProductFeedback.BFF.Auth.OIDC;

internal static class OpenIdConnectModule
{
   public static IServiceCollection AddOidcAuthentication(this WebApplicationBuilder builder)
   {
      var openIdConnectOptions = builder.Configuration.GetSection(OpenIdConnectOptions.Key)
                                    .Get<OpenIdConnectOptions>()
                                 ?? throw new ArgumentException("OpenId Connect config is missing!");

      builder.Services.AddAuthentication(options =>
      {
         options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
         options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
         options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
      })
      .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
      {
         options.Cookie.Name = openIdConnectOptions.CookieName;
         options.ExpireTimeSpan = TimeSpan.FromHours(8);
         options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
         options.Cookie.SameSite = SameSiteMode.Strict;
         options.Cookie.HttpOnly = true;

         // Return 401 for API requests instead of redirecting to login
         options.Events.OnRedirectToLogin = context =>
         {
            if (IsApiRequest(context.Request))
            {
               context.Response.StatusCode = StatusCodes.Status401Unauthorized;
               return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
         };

         // Return 403 for API requests instead of redirecting to access denied
         options.Events.OnRedirectToAccessDenied = context =>
         {
            if (IsApiRequest(context.Request))
            {
               context.Response.StatusCode = StatusCodes.Status403Forbidden;
               return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
         };
      })
      .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
      {
         options.Authority = openIdConnectOptions.Authority;
         options.ClientId = openIdConnectOptions.ClientId;
         options.ClientSecret = openIdConnectOptions.ClientSecret;
         options.ResponseType = openIdConnectOptions.ResponseType;
         options.ResponseMode = openIdConnectOptions.ResponseMode;
         options.GetClaimsFromUserInfoEndpoint = openIdConnectOptions.GetClaimsFromUserInfoEndpoint;
         options.MapInboundClaims = openIdConnectOptions.MapInboundClaims;
         options.SaveTokens = openIdConnectOptions.SaveTokens;
         options.RequireHttpsMetadata = false;

         // Callback paths
         options.CallbackPath = "/signin-oidc";
         options.SignedOutCallbackPath = "/signout-callback-oidc";

         var scopes = openIdConnectOptions.Scope
            .Split(" ")
            .ToList();

         options.Scope.Clear();
         scopes.ForEach(scope => options.Scope.Add(scope));

         // Return 401 for API requests instead of redirecting to identity provider
         options.Events.OnRedirectToIdentityProvider = context =>
         {
            if (IsApiRequest(context.Request))
            {
               context.Response.StatusCode = StatusCodes.Status401Unauthorized;
               context.HandleResponse();
            }
            return Task.CompletedTask;
         };
      });

      // Configure Redis ticket store for session persistence across pod restarts
      builder.Services.AddSingleton<IPostConfigureOptions<CookieAuthenticationOptions>, ConfigureCookieTicketStore>();

      return builder.Services;
   }

   private static bool IsApiRequest(HttpRequest request)
   {
      return request.Path.StartsWithSegments("/api");
   }
}

internal sealed class ConfigureCookieTicketStore : IPostConfigureOptions<CookieAuthenticationOptions>
{
   private readonly ITicketStore _ticketStore;

   public ConfigureCookieTicketStore(ITicketStore ticketStore)
   {
      _ticketStore = ticketStore;
   }

   public void PostConfigure(string? name, CookieAuthenticationOptions options)
   {
      options.SessionStore = _ticketStore;
   }
}
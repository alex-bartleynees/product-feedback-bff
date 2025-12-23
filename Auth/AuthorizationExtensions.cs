using Microsoft.AspNetCore.Authorization;

namespace ProductFeedback.BFF.Auth;

internal static class AuthorizationExtensions
{
    internal static void AddAuthorizationPolicies(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
           // options.FallbackPolicy = new AuthorizationPolicyBuilder()
           //     .RequireAuthenticatedUser()
            //    .Build();
            options.AddPolicy("RequireAuthenticatedUserPolicy",b =>
            {
                b.RequireAuthenticatedUser()
                    .Build();
            });
        });
    }
}
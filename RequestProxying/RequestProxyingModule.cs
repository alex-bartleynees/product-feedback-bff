using ProductFeedback.BFF.RequestProxying.Yarp;

namespace ProductFeedback.BFF.RequestProxying;

internal static class RequestProxyingModule
{
    internal static IServiceCollection AddProxy(this IServiceCollection services, ConfigurationManager configuration)
    {
        services.AddYarp(configuration);
        return services;
    }  
    
    internal static WebApplication UseProxy(this WebApplication app)
    {
        app.UseYarp();
        return app;
    }   
}
using OpenTelemetry;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace AuthGateway.BFF.Telemetry;

internal static class ObservabilityExtensions
{
    private const string ServiceName = "authgateway-bff";
    private const string ServiceNamespace = "shared-platform";

    internal static WebApplicationBuilder AddObservability(this WebApplicationBuilder builder)
    {
        var serviceVersion = builder.Configuration["OTEL_SERVICE_VERSION"]
            ?? typeof(ObservabilityExtensions).Assembly.GetName().Version?.ToString();
        var instanceId = Environment.GetEnvironmentVariable("HOSTNAME") ?? Environment.MachineName;

        void ConfigureResource(ResourceBuilder resource)
        {
            resource.AddService(
                serviceName: ServiceName,
                serviceNamespace: ServiceNamespace,
                serviceVersion: serviceVersion,
                serviceInstanceId: instanceId)
            .AddAttributes([
                new("deployment.environment.name", builder.Environment.EnvironmentName),
            ]);
        }

        builder.Logging.AddOpenTelemetry(logging =>
        {
            var resource = ResourceBuilder.CreateDefault();
            ConfigureResource(resource);
            logging.SetResourceBuilder(resource);
            logging.IncludeScopes = true;
            logging.IncludeFormattedMessage = true;
        });

        var telemetry = builder.Services.AddOpenTelemetry()
            .ConfigureResource(ConfigureResource)
            .WithTracing(tracing => tracing
                .AddSource("Yarp.ReverseProxy")
                .AddAspNetCoreInstrumentation(options =>
                    options.Filter = context => !context.Request.Path.StartsWithSegments("/health"))
                .AddHttpClientInstrumentation())
            .WithMetrics(metrics => metrics
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation());

        if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        {
            telemetry.UseOtlpExporter();
        }

        return builder;
    }
}

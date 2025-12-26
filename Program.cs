using Microsoft.AspNetCore.HttpOverrides;
using ProductFeedback.BFF.Auth;
using ProductFeedback.BFF.Common.Clocks;
using ProductFeedback.BFF.RequestProxying;
using IPNetwork = System.Net.IPNetwork;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProxy(builder.Configuration);
builder.AddAuth();
builder.Services.AddClock();
builder.Services.AddControllers();

var app = builder.Build();

app.UseRouting();

// Configure forwarded headers for reverse proxy support (must be before UseAuth)
var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};

if (app.Environment.IsDevelopment())
{
    // In development, trust all proxies for easier local setup
    forwardedHeadersOptions.KnownIPNetworks.Clear();
    forwardedHeadersOptions.KnownProxies.Clear();
}
else
{
    // Trust only the Kubernetes pod network
    var trustedNetwork = builder.Configuration["TrustedProxyNetwork"];
    if (!string.IsNullOrEmpty(trustedNetwork) && IPNetwork.TryParse(trustedNetwork, out var network))
    {
        forwardedHeadersOptions.KnownIPNetworks.Add(network);
    }
}

app.UseForwardedHeaders(forwardedHeadersOptions);

app.UseAuth();
app.UseProxy();
app.MapControllers();
app.Run();

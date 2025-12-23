using ProductFeedback.BFF.Auth;
using ProductFeedback.BFF.Common.Clocks;
using ProductFeedback.BFF.RequestProxying;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProxy(builder.Configuration);
builder.AddAuth();
builder.Services.AddClock();
builder.Services.AddControllers();

var app = builder.Build();

app.UseRouting();
app.UseAuth();
app.UseProxy();
app.MapControllers();
app.Run();

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using StackExchange.Redis;

namespace ProductFeedback.BFF.Auth.DataProtection;

internal sealed class RedisTicketStore : ITicketStore
{
    private const string KeyPrefix = "AuthTicket:";
    private readonly IConnectionMultiplexer _redis;
    private readonly TicketSerializer _ticketSerializer = TicketSerializer.Default;

    public RedisTicketStore(IConnectionMultiplexer redis)
    {
        _redis = redis;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Guid.NewGuid().ToString();
        await RenewAsync(key, ticket);
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var db = _redis.GetDatabase();
        var serialized = _ticketSerializer.Serialize(ticket);

        var expiresUtc = ticket.Properties.ExpiresUtc;
        TimeSpan? expiry = expiresUtc.HasValue
            ? expiresUtc.Value - DateTimeOffset.UtcNow
            : null;

        await db.StringSetAsync(KeyPrefix + key, serialized, expiry);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var db = _redis.GetDatabase();
        var bytes = await db.StringGetAsync(KeyPrefix + key);

        if (bytes.IsNullOrEmpty)
        {
            return null;
        }

        return _ticketSerializer.Deserialize((byte[])bytes!);
    }

    public async Task RemoveAsync(string key)
    {
        var db = _redis.GetDatabase();
        await db.KeyDeleteAsync(KeyPrefix + key);
    }
}

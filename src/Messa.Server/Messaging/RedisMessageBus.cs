using System;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using StackExchange.Redis;
using Messa.Core.Models;

namespace Messa.Server.Messaging
{
    public class RedisMessageBus : IMessageBus
    {
        private readonly string _connectionString;
        private readonly string _prefix;
        private IConnectionMultiplexer? _redis;
        private ISubscriber? _subscriber;
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<Guid, Func<ProtocolPacket, Task>>> _handlers = new();

        public RedisMessageBus(string connectionString, string prefix = "messa")
        {
            _connectionString = connectionString;
            _prefix = prefix;
        }

        public async Task StartAsync(CancellationToken ct = default)
        {
            _redis = await ConnectionMultiplexer.ConnectAsync(_connectionString);
            _subscriber = _redis.GetSubscriber();
        }

        public async Task StopAsync(CancellationToken ct = default)
        {
            if (_redis != null)
            {
                await _redis.CloseAsync();
            }
        }

        public async ValueTask PublishAsync(string channel, ProtocolPacket packet, CancellationToken ct = default)
        {
            if (_subscriber == null) return;
            var redisChannel = new RedisChannel($"{_prefix}:{channel}", RedisChannel.PatternMode.Literal);
            var json = JsonSerializer.Serialize(packet);
            await _subscriber.PublishAsync(redisChannel, json);
        }

        public IDisposable Subscribe(string channel, Func<ProtocolPacket, Task> handler)
        {
            var subs = _handlers.GetOrAdd(channel, _ => new ConcurrentDictionary<Guid, Func<ProtocolPacket, Task>>());
            var subId = Guid.NewGuid();
            subs[subId] = handler;

            if (_subscriber != null && subs.Count == 1)
            {
                var redisChannel = new RedisChannel($"{_prefix}:{channel}", RedisChannel.PatternMode.Literal);
                _subscriber.Subscribe(redisChannel, (rc, value) =>
                {
                    if (value.IsNullOrEmpty) return;
                    try
                    {
                        var packet = JsonSerializer.Deserialize<ProtocolPacket>(value.ToString());
                        if (packet != null && _handlers.TryGetValue(channel, out var channelSubs))
                        {
                            foreach (var h in channelSubs.Values)
                            {
                                _ = Task.Run(async () =>
                                {
                                    try { await h(packet); } catch { }
                                });
                            }
                        }
                    }
                    catch { }
                });
            }

            return new SubscriptionToken(() =>
            {
                subs.TryRemove(subId, out _);
                if (subs.IsEmpty && _subscriber != null)
                {
                    var redisChannel = new RedisChannel($"{_prefix}:{channel}", RedisChannel.PatternMode.Literal);
                    _subscriber.Unsubscribe(redisChannel);
                }
            });
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _redis?.Dispose();
        }

        private sealed class SubscriptionToken : IDisposable
        {
            private Action? _unsubscribe;

            public SubscriptionToken(Action unsubscribe)
            {
                _unsubscribe = unsubscribe;
            }

            public void Dispose()
            {
                Interlocked.Exchange(ref _unsubscribe, null)?.Invoke();
            }
        }
    }
}

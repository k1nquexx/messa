using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Messa.Core.Models;

namespace Messa.Server.Messaging
{
    public class ChannelMessageBus : IMessageBus
    {
        private readonly Channel<BusEnvelope> _channel;
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<Guid, Func<ProtocolPacket, Task>>> _subscribers = new();
        private CancellationTokenSource? _cts;
        private Task? _processingTask;

        private record BusEnvelope(string Channel, ProtocolPacket Packet);

        public ChannelMessageBus()
        {
            _channel = Channel.CreateUnbounded<BusEnvelope>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false
            });
        }

        public Task StartAsync(CancellationToken ct = default)
        {
            _cts = new CancellationTokenSource();
            _processingTask = Task.Run(ProcessQueueAsync);
            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken ct = default)
        {
            _channel.Writer.TryComplete();
            if (_cts != null)
            {
                _cts.Cancel();
            }

            if (_processingTask != null)
            {
                try
                {
                    await _processingTask.WaitAsync(TimeSpan.FromSeconds(3), ct);
                }
                catch { }
            }
        }

        public ValueTask PublishAsync(string channel, ProtocolPacket packet, CancellationToken ct = default)
        {
            _channel.Writer.TryWrite(new BusEnvelope(channel, packet));
            return ValueTask.CompletedTask;
        }

        public IDisposable Subscribe(string channel, Func<ProtocolPacket, Task> handler)
        {
            var subs = _subscribers.GetOrAdd(channel, _ => new ConcurrentDictionary<Guid, Func<ProtocolPacket, Task>>());
            var subId = Guid.NewGuid();
            subs[subId] = handler;

            return new SubscriptionToken(() =>
            {
                subs.TryRemove(subId, out _);
            });
        }

        private async Task ProcessQueueAsync()
        {
            var reader = _channel.Reader;
            var token = _cts?.Token ?? CancellationToken.None;

            try
            {
                while (await reader.WaitToReadAsync(token))
                {
                    while (reader.TryRead(out var envelope))
                    {
                        if (_subscribers.TryGetValue(envelope.Channel, out var subs))
                        {
                            foreach (var handler in subs.Values)
                            {
                                _ = SafeInvokeAsync(handler, envelope.Packet);
                            }
                        }

                        // Wildcard subscribers (e.g. "*")
                        if (_subscribers.TryGetValue("*", out var wildSubs))
                        {
                            foreach (var handler in wildSubs.Values)
                            {
                                _ = SafeInvokeAsync(handler, envelope.Packet);
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch { }
        }

        private static async Task SafeInvokeAsync(Func<ProtocolPacket, Task> handler, ProtocolPacket packet)
        {
            try
            {
                await handler(packet);
            }
            catch { }
        }

        public async ValueTask DisposeAsync()
        {
            await StopAsync();
            _cts?.Dispose();
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

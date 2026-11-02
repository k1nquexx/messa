using System;
using System.Threading;
using System.Threading.Tasks;
using Messa.Core.Models;

namespace Messa.Server.Messaging
{
    public interface IMessageBus : IAsyncDisposable
    {
        Task StartAsync(CancellationToken ct = default);
        Task StopAsync(CancellationToken ct = default);
        ValueTask PublishAsync(string channel, ProtocolPacket packet, CancellationToken ct = default);
        IDisposable Subscribe(string channel, Func<ProtocolPacket, Task> handler);
    }
}

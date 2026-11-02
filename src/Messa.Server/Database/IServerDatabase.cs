using System.Collections.Generic;
using System.Threading.Tasks;
using Messa.Core.Models;
using Messa.Core.Crypto;

namespace Messa.Server.Database
{
    public interface IServerDatabase
    {
        Task InitializeAsync();
        Task SaveUserAsync(UserProfile profile);
        Task<UserProfile?> GetUserAsync(string query);
        Task<List<UserProfile>> SearchUsersAsync(string query, int limit = 20);
        Task SavePreKeyBundleAsync(PreKeyBundle bundle);
        Task<PreKeyBundle?> GetPreKeyBundleAsync(string query);
        Task<(CloudMessage recipientMsg, CloudMessage senderMsg)> StoreAndSequenceMessageAsync(
            string senderFp,
            string recipientFp,
            string ciphertext,
            string tag,
            string iv,
            string signature,
            string plainText,
            string? messageId = null);
        Task UpdateMessageStatusAsync(string messageId, string accountFp, MessageDeliveryStatus status);
        Task<(List<CloudMessage> messages, long currentPts)> GetDifferenceAsync(string accountFp, long fromPts, int limit = 100);
        Task<long> GetCurrentPtsAsync(string accountFp);
    }
}

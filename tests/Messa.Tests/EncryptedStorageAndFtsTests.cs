using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Messa.Core.Storage;
using Xunit;

namespace Messa.Tests
{
    public class EncryptedStorageAndFtsTests
    {
        [Fact]
        public void EncryptedDb_EncryptsMessagesAtRestAndSupportsFts()
        {
            var tempDb = Path.Combine(Path.GetTempPath(), $"messa_test_db_{Guid.NewGuid():N}.db");
            var masterKey = new byte[32];
            RandomNumberGenerator.Fill(masterKey);

            try
            {
                using (var db = new EncryptedLocalDatabase(tempDb, masterKey))
                {
                    // Insert test messages
                    db.SaveMessage(new LocalMessageRecord
                    {
                        Id = "msg_001",
                        ChatId = "bob_fp",
                        SenderId = "alice_fp",
                        IsOutgoing = true,
                        Pts = 1,
                        Timestamp = 1000,
                        PlainText = "Top secret sovereign mission code 9921",
                        Signature = "sig1"
                    });

                    db.SaveMessage(new LocalMessageRecord
                    {
                        Id = "msg_002",
                        ChatId = "bob_fp",
                        SenderId = "bob_fp",
                        IsOutgoing = false,
                        Pts = 2,
                        Timestamp = 2000,
                        PlainText = "Acknowledged secret order, commencing flight",
                        Signature = "sig2"
                    });

                    db.SaveMessage(new LocalMessageRecord
                    {
                        Id = "msg_003",
                        ChatId = "charlie_fp",
                        SenderId = "charlie_fp",
                        IsOutgoing = false,
                        Pts = 3,
                        Timestamp = 3000,
                        PlainText = "Hello Alice, unrelated message about pizza",
                        Signature = "sig3"
                    });

                    // 1. Verify retrieval for chat
                    var bobMessages = db.GetMessagesForChat("bob_fp");
                    Assert.Equal(2, bobMessages.Count);
                    Assert.Equal("Top secret sovereign mission code 9921", bobMessages[0].PlainText);
                    Assert.Equal("Acknowledged secret order, commencing flight", bobMessages[1].PlainText);

                    // 2. Full-Text Search (FTS5): search "secret"
                    var searchSecret = db.SearchMessages("secret");
                    Assert.Equal(2, searchSecret.Count);

                    // 3. FTS5 with Chat Filter: search "pizza" in bob_fp -> 0 results, in charlie_fp -> 1 result
                    var pizzaInBob = db.SearchMessages("pizza", chatIdFilter: "bob_fp");
                    Assert.Empty(pizzaInBob);

                    var pizzaInCharlie = db.SearchMessages("pizza", chatIdFilter: "charlie_fp");
                    Assert.Single(pizzaInCharlie);
                    Assert.Equal("Hello Alice, unrelated message about pizza", pizzaInCharlie[0].PlainText);

                    // 4. Date range filter
                    var dateRangeSearch = db.SearchMessages("secret", fromTimestamp: 1500, toTimestamp: 2500);
                    Assert.Single(dateRangeSearch);
                    Assert.Equal("msg_002", dateRangeSearch[0].Id);
                }

                // 5. Verify database encryption at rest: raw file bytes should NOT contain plain text "9921"
                var dbFileBytes = File.ReadAllBytes(tempDb);
                var rawString = Encoding.UTF8.GetString(dbFileBytes);
                // The encrypted_text column contains ciphertext, not the secret text
                Assert.DoesNotContain("mission code 9921", rawString);
            }
            finally
            {
                if (File.Exists(tempDb)) File.Delete(tempDb);
            }
        }

        [Fact]
        public void MediaCacheManager_PurgesExpiredFilesAndEnforcesQuota()
        {
            var tempCacheDir = Path.Combine(Path.GetTempPath(), $"messa_cache_test_{Guid.NewGuid():N}");

            try
            {
                var cache = new MediaCacheManager(tempCacheDir);

                // Save 3 files
                var dummy1 = new byte[1024]; // 1 KB
                var dummy2 = new byte[2048]; // 2 KB
                var dummy3 = new byte[4096]; // 4 KB

                var path1 = cache.SaveMedia(dummy1, "jpg", "photo1");
                var path2 = cache.SaveMedia(dummy2, "png", "photo2");
                var path3 = cache.SaveMedia(dummy3, "wav", "voice1");

                Assert.True(File.Exists(path1));
                Assert.True(File.Exists(path2));
                Assert.True(File.Exists(path3));

                // Read photo1 back
                var readBytes = cache.GetMedia("photo1.jpg");
                Assert.NotNull(readBytes);
                Assert.Equal(1024, readBytes.Length);

                // Set photo1 access time to 10 days ago
                File.SetLastAccessTimeUtc(path1, DateTime.UtcNow.AddDays(-10));

                // Purge with Days7 retention policy
                var (purgedCount, freedBytes) = cache.PurgeExpiredMedia(CacheRetentionPolicy.Days7, maxQuotaBytes: 100 * 1024);
                Assert.Equal(1, purgedCount);
                Assert.Equal(1024, freedBytes);
                Assert.False(File.Exists(path1)); // Photo1 expired!
                Assert.True(File.Exists(path2));  // Photo2 retained
                Assert.True(File.Exists(path3));  // Voice1 retained

                // Test LRU Quota enforcement: set maxQuota to 3 KB (Photo2 is 2KB, Voice1 is 4KB -> total 6KB > 3KB)
                File.SetLastAccessTimeUtc(path2, DateTime.UtcNow.AddHours(-2)); // older
                File.SetLastAccessTimeUtc(path3, DateTime.UtcNow.AddHours(-1)); // newer

                var (lruPurged, lruFreed) = cache.PurgeExpiredMedia(CacheRetentionPolicy.Forever, maxQuotaBytes: 3000);
                Assert.True(lruPurged >= 1);
                Assert.False(File.Exists(path2)); // Oldest file (photo2) evicted first
            }
            finally
            {
                if (Directory.Exists(tempCacheDir)) Directory.Delete(tempCacheDir, true);
            }
        }
    }
}

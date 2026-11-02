using System;
using System.IO;
using Messa.Core.Storage;
using Xunit;

namespace Messa.Tests
{
    public class MultiDevicePtsSyncTests
    {
        [Fact]
        public void PtsStore_AssignsMonotonicSequenceNumbers()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "messa_pts_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                var store = new PtsMessageStore(tempDir);
                var aliceFp = "alice_fingerprint_001";
                var bobFp = "bob_fingerprint_002";

                // Msg 1
                var (bMsg1, aMsg1) = store.StoreAndSequenceMessage(aliceFp, bobFp, "cipher1", "tag1", "iv1", "sig1", "Hello 1");
                Assert.Equal(1, bMsg1.Pts);
                Assert.Equal(1, aMsg1.Pts);
                Assert.False(bMsg1.IsOutgoing);
                Assert.True(aMsg1.IsOutgoing);

                // Msg 2
                var (bMsg2, aMsg2) = store.StoreAndSequenceMessage(aliceFp, bobFp, "cipher2", "tag2", "iv2", "sig2", "Hello 2");
                Assert.Equal(2, bMsg2.Pts);
                Assert.Equal(2, aMsg2.Pts);

                // Msg 3 (Bob replies to Alice)
                var (aMsg3, bMsg3) = store.StoreAndSequenceMessage(bobFp, aliceFp, "cipher3", "tag3", "iv3", "sig3", "Reply 1");
                Assert.Equal(3, aMsg3.Pts); // Alice receives -> pts 3
                Assert.Equal(3, bMsg3.Pts); // Bob outgoing -> pts 3
            }
            finally
            {
                Directory.Delete(tempDir, true);
            }
        }

        [Fact]
        public void PtsStore_GetDifference_ReplaysMissedMessagesInExactOrder()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "messa_pts_diff_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);

            try
            {
                var store = new PtsMessageStore(tempDir);
                var aliceFp = "alice_001";
                var bobFp = "bob_002";

                // 3 messages sent to Bob while his PC was offline
                store.StoreAndSequenceMessage(aliceFp, bobFp, "c1", "t1", "i1", "s1", "Message 1");
                store.StoreAndSequenceMessage(aliceFp, bobFp, "c2", "t2", "i2", "s2", "Message 2");
                store.StoreAndSequenceMessage(aliceFp, bobFp, "c3", "t3", "i3", "s3", "Message 3");

                // Bob's PC connects with fromPts = 0
                var (diff, currentPts) = store.GetDifference(bobFp, fromPts: 0);
                Assert.Equal(3, currentPts);
                Assert.Equal(3, diff.Count);
                Assert.Equal(1, diff[0].Pts);
                Assert.Equal(2, diff[1].Pts);
                Assert.Equal(3, diff[2].Pts);
                Assert.Equal("Message 1", diff[0].Text);
                Assert.Equal("Message 2", diff[1].Text);
                Assert.Equal("Message 3", diff[2].Text);

                // Bob's PC later checks fromPts = 3 (no new updates)
                var (noDiff, _) = store.GetDifference(bobFp, fromPts: 3);
                Assert.Empty(noDiff);

                // Alice sends Message 4
                store.StoreAndSequenceMessage(aliceFp, bobFp, "c4", "t4", "i4", "s4", "Message 4");

                // Bob's PC asks updates fromPts = 3 -> gets exactly Message 4
                var (newDiff, updatedPts) = store.GetDifference(bobFp, fromPts: 3);
                Assert.Equal(4, updatedPts);
                Assert.Single(newDiff);
                Assert.Equal(4, newDiff[0].Pts);
                Assert.Equal("Message 4", newDiff[0].Text);
            }
            finally
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}

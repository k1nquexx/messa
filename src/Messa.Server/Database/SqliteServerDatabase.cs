using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Messa.Core.Models;
using Messa.Core.Crypto;

namespace Messa.Server.Database
{
    public class SqliteServerDatabase : IServerDatabase
    {
        private readonly string _connectionString;
        private readonly object _lock = new();

        public SqliteServerDatabase(string dbPath)
        {
            var csb = new SqliteConnectionStringBuilder
            {
                DataSource = dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Shared
            };
            _connectionString = csb.ToString();
        }

        public Task InitializeAsync()
        {
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;
                    PRAGMA busy_timeout = 5000;

                    CREATE TABLE IF NOT EXISTS users (
                        fingerprint TEXT PRIMARY KEY,
                        username TEXT UNIQUE,
                        display_name TEXT,
                        status_text TEXT,
                        bio TEXT,
                        avatar_base64 TEXT,
                        has_2fa INTEGER DEFAULT 0,
                        two_factor_salt TEXT,
                        two_factor_verifier TEXT,
                        updated_at INTEGER
                    );

                    CREATE TABLE IF NOT EXISTS prekey_bundles (
                        fingerprint TEXT PRIMARY KEY,
                        username TEXT,
                        bundle_json TEXT NOT NULL,
                        updated_at INTEGER
                    );

                    CREATE TABLE IF NOT EXISTS pts_sequences (
                        account_fp TEXT PRIMARY KEY,
                        current_pts INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS messages (
                        id TEXT NOT NULL,
                        owner_fp TEXT NOT NULL,
                        peer_fp TEXT NOT NULL,
                        sender_fp TEXT NOT NULL,
                        pts INTEGER NOT NULL,
                        is_outgoing INTEGER NOT NULL,
                        status INTEGER NOT NULL,
                        text TEXT,
                        ciphertext TEXT,
                        tag TEXT,
                        iv TEXT,
                        signature TEXT,
                        timestamp INTEGER NOT NULL,
                        delivered_at INTEGER,
                        read_at INTEGER,
                        PRIMARY KEY(owner_fp, id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_messages_owner_pts ON messages(owner_fp, pts);
                    CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(owner_fp, peer_fp);
                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                ";
                cmd.ExecuteNonQuery();
            }
            return Task.CompletedTask;
        }

        public Task SaveUserAsync(UserProfile profile)
        {
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO users (fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, two_factor_salt, two_factor_verifier, updated_at)
                    VALUES (@fp, @u, @name, @status, @bio, @avatar, @has2fa, @salt, @verifier, @updated);
                ";
                cmd.Parameters.AddWithValue("@fp", profile.Fingerprint);
                cmd.Parameters.AddWithValue("@u", profile.Username ?? "");
                cmd.Parameters.AddWithValue("@name", profile.DisplayName ?? "");
                cmd.Parameters.AddWithValue("@status", profile.StatusText ?? "Online");
                cmd.Parameters.AddWithValue("@bio", profile.Bio ?? "");
                cmd.Parameters.AddWithValue("@avatar", profile.AvatarBase64 ?? "");
                cmd.Parameters.AddWithValue("@has2fa", profile.Has2FA ? 1 : 0);
                cmd.Parameters.AddWithValue("@salt", profile.TwoFactorSaltBase64 ?? (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@verifier", profile.TwoFactorVerifierBase64 ?? (object)DBNull.Value);
                cmd.Parameters.AddWithValue("@updated", profile.UpdatedAt);
                cmd.ExecuteNonQuery();
            }
            return Task.CompletedTask;
        }

        public Task<UserProfile?> GetUserAsync(string query)
        {
            var q = query.Trim().TrimStart('@');
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, two_factor_salt, two_factor_verifier, updated_at
                    FROM users
                    WHERE fingerprint = @q OR username = @q COLLATE NOCASE
                    LIMIT 1;
                ";
                cmd.Parameters.AddWithValue("@q", q);

                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    return Task.FromResult<UserProfile?>(new UserProfile
                    {
                        Fingerprint = reader.GetString(0),
                        Username = reader.GetString(1),
                        DisplayName = reader.GetString(2),
                        StatusText = reader.GetString(3),
                        Bio = reader.GetString(4),
                        AvatarBase64 = reader.GetString(5),
                        Has2FA = reader.GetInt32(6) == 1,
                        TwoFactorSaltBase64 = reader.IsDBNull(7) ? null : reader.GetString(7),
                        TwoFactorVerifierBase64 = reader.IsDBNull(8) ? null : reader.GetString(8),
                        UpdatedAt = reader.GetInt64(9)
                    });
                }
            }
            return Task.FromResult<UserProfile?>(null);
        }

        public Task<List<UserProfile>> SearchUsersAsync(string query, int limit = 20)
        {
            var q = query.Trim().TrimStart('@');
            var results = new List<UserProfile>();
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, updated_at
                    FROM users
                    WHERE username LIKE @like OR display_name LIKE @like OR fingerprint = @q
                    LIMIT @limit;
                ";
                cmd.Parameters.AddWithValue("@like", $"%{q}%");
                cmd.Parameters.AddWithValue("@q", q);
                cmd.Parameters.AddWithValue("@limit", limit);

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    results.Add(new UserProfile
                    {
                        Fingerprint = reader.GetString(0),
                        Username = reader.GetString(1),
                        DisplayName = reader.GetString(2),
                        StatusText = reader.GetString(3),
                        Bio = reader.GetString(4),
                        AvatarBase64 = reader.GetString(5),
                        Has2FA = reader.GetInt32(6) == 1,
                        UpdatedAt = reader.GetInt64(7)
                    });
                }
            }
            return Task.FromResult(results);
        }

        public Task SavePreKeyBundleAsync(PreKeyBundle bundle)
        {
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT OR REPLACE INTO prekey_bundles (fingerprint, username, bundle_json, updated_at)
                    VALUES (@fp, @u, @json, @ts);
                ";
                cmd.Parameters.AddWithValue("@fp", bundle.Fingerprint);
                cmd.Parameters.AddWithValue("@u", bundle.Username ?? "");
                cmd.Parameters.AddWithValue("@json", JsonSerializer.Serialize(bundle));
                cmd.Parameters.AddWithValue("@ts", bundle.Timestamp);
                cmd.ExecuteNonQuery();
            }
            return Task.CompletedTask;
        }

        public Task<PreKeyBundle?> GetPreKeyBundleAsync(string query)
        {
            var q = query.Trim().TrimStart('@');
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT bundle_json FROM prekey_bundles
                    WHERE fingerprint = @q OR username = @q COLLATE NOCASE
                    LIMIT 1;
                ";
                cmd.Parameters.AddWithValue("@q", q);

                var json = cmd.ExecuteScalar() as string;
                if (!string.IsNullOrEmpty(json))
                {
                    return Task.FromResult(JsonSerializer.Deserialize<PreKeyBundle>(json));
                }
            }
            return Task.FromResult<PreKeyBundle?>(null);
        }

        public Task<(CloudMessage recipientMsg, CloudMessage senderMsg)> StoreAndSequenceMessageAsync(
            string senderFp,
            string recipientFp,
            string ciphertext,
            string tag,
            string iv,
            string signature,
            string plainText,
            string? messageId = null)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var sharedMsgId = string.IsNullOrEmpty(messageId) ? Guid.NewGuid().ToString("N") : messageId;

            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();
                using var trans = conn.BeginTransaction();

                try
                {
                    // 1. Next PTS for recipient
                    var recipientPts = IncrementPtsInternal(conn, trans, recipientFp);
                    var recipientMsg = new CloudMessage
                    {
                        Id = sharedMsgId,
                        OwnerFingerprint = recipientFp,
                        PeerFingerprint = senderFp,
                        SenderFingerprint = senderFp,
                        Pts = recipientPts,
                        IsOutgoing = false,
                        Status = MessageDeliveryStatus.Sent,
                        Text = plainText,
                        CiphertextBase64 = ciphertext,
                        TagBase64 = tag,
                        IvBase64 = iv,
                        SignatureBase64 = signature,
                        Timestamp = now
                    };
                    InsertMessageInternal(conn, trans, recipientMsg);

                    // 2. Next PTS for sender (outgoing sync)
                    var senderPts = IncrementPtsInternal(conn, trans, senderFp);
                    var senderMsg = new CloudMessage
                    {
                        Id = sharedMsgId,
                        OwnerFingerprint = senderFp,
                        PeerFingerprint = recipientFp,
                        SenderFingerprint = senderFp,
                        Pts = senderPts,
                        IsOutgoing = true,
                        Status = MessageDeliveryStatus.Sent,
                        Text = plainText,
                        CiphertextBase64 = ciphertext,
                        TagBase64 = tag,
                        IvBase64 = iv,
                        SignatureBase64 = signature,
                        Timestamp = now
                    };
                    InsertMessageInternal(conn, trans, senderMsg);

                    trans.Commit();
                    return Task.FromResult((recipientMsg, senderMsg));
                }
                catch
                {
                    trans.Rollback();
                    throw;
                }
            }
        }

        public Task UpdateMessageStatusAsync(string messageId, string accountFp, MessageDeliveryStatus status)
        {
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                using var cmd = conn.CreateCommand();

                if (status == MessageDeliveryStatus.Delivered)
                {
                    cmd.CommandText = @"
                        UPDATE messages
                        SET status = @status, delivered_at = @now
                        WHERE id = @id AND (owner_fp = @fp OR peer_fp = @fp) AND status < @status;
                    ";
                }
                else if (status == MessageDeliveryStatus.Read)
                {
                    cmd.CommandText = @"
                        UPDATE messages
                        SET status = @status, read_at = @now
                        WHERE id = @id AND (owner_fp = @fp OR peer_fp = @fp);
                    ";
                }
                else
                {
                    cmd.CommandText = @"
                        UPDATE messages
                        SET status = @status
                        WHERE id = @id AND (owner_fp = @fp OR peer_fp = @fp);
                    ";
                }

                cmd.Parameters.AddWithValue("@id", messageId);
                cmd.Parameters.AddWithValue("@fp", accountFp);
                cmd.Parameters.AddWithValue("@status", (int)status);
                cmd.Parameters.AddWithValue("@now", now);
                cmd.ExecuteNonQuery();
            }
            return Task.CompletedTask;
        }

        public Task<(List<CloudMessage> messages, long currentPts)> GetDifferenceAsync(string accountFp, long fromPts, int limit = 100)
        {
            var messages = new List<CloudMessage>();
            long currentPts = 0;

            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                // Get current pts
                using (var ptsCmd = conn.CreateCommand())
                {
                    ptsCmd.CommandText = "SELECT current_pts FROM pts_sequences WHERE account_fp = @fp;";
                    ptsCmd.Parameters.AddWithValue("@fp", accountFp);
                    var val = ptsCmd.ExecuteScalar();
                    if (val != null && val != DBNull.Value) currentPts = Convert.ToInt64(val);
                }

                // Get messages since fromPts
                using (var msgCmd = conn.CreateCommand())
                {
                    msgCmd.CommandText = @"
                        SELECT id, owner_fp, peer_fp, sender_fp, pts, is_outgoing, status, text, ciphertext, tag, iv, signature, timestamp, delivered_at, read_at
                        FROM messages
                        WHERE owner_fp = @fp AND pts > @fromPts
                        ORDER BY pts ASC
                        LIMIT @limit;
                    ";
                    msgCmd.Parameters.AddWithValue("@fp", accountFp);
                    msgCmd.Parameters.AddWithValue("@fromPts", fromPts);
                    msgCmd.Parameters.AddWithValue("@limit", limit);

                    using var reader = msgCmd.ExecuteReader();
                    while (reader.Read())
                    {
                        messages.Add(new CloudMessage
                        {
                            Id = reader.GetString(0),
                            OwnerFingerprint = reader.GetString(1),
                            PeerFingerprint = reader.GetString(2),
                            SenderFingerprint = reader.GetString(3),
                            Pts = reader.GetInt64(4),
                            IsOutgoing = reader.GetInt32(5) == 1,
                            Status = (MessageDeliveryStatus)reader.GetInt32(6),
                            Text = reader.IsDBNull(7) ? "" : reader.GetString(7),
                            CiphertextBase64 = reader.IsDBNull(8) ? "" : reader.GetString(8),
                            TagBase64 = reader.IsDBNull(9) ? "" : reader.GetString(9),
                            IvBase64 = reader.IsDBNull(10) ? "" : reader.GetString(10),
                            SignatureBase64 = reader.IsDBNull(11) ? "" : reader.GetString(11),
                            Timestamp = reader.GetInt64(12),
                            DeliveredAt = reader.IsDBNull(13) ? null : reader.GetInt64(13),
                            ReadAt = reader.IsDBNull(14) ? null : reader.GetInt64(14)
                        });
                    }
                }
            }

            return Task.FromResult((messages, currentPts));
        }

        public Task<long> GetCurrentPtsAsync(string accountFp)
        {
            lock (_lock)
            {
                using var conn = new SqliteConnection(_connectionString);
                conn.Open();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT current_pts FROM pts_sequences WHERE account_fp = @fp;";
                cmd.Parameters.AddWithValue("@fp", accountFp);
                var val = cmd.ExecuteScalar();
                if (val != null && val != DBNull.Value) return Task.FromResult(Convert.ToInt64(val));
            }
            return Task.FromResult(0L);
        }

        private static long IncrementPtsInternal(SqliteConnection conn, SqliteTransaction trans, string accountFp)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT INTO pts_sequences (account_fp, current_pts)
                VALUES (@fp, 1)
                ON CONFLICT(account_fp) DO UPDATE SET current_pts = current_pts + 1
                RETURNING current_pts;
            ";
            cmd.Parameters.AddWithValue("@fp", accountFp);
            return Convert.ToInt64(cmd.ExecuteScalar());
        }

        private static void InsertMessageInternal(SqliteConnection conn, SqliteTransaction trans, CloudMessage msg)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT OR REPLACE INTO messages (id, owner_fp, peer_fp, sender_fp, pts, is_outgoing, status, text, ciphertext, tag, iv, signature, timestamp, delivered_at, read_at)
                VALUES (@id, @owner, @peer, @sender, @pts, @is_out, @status, @text, @cipher, @tag, @iv, @sig, @ts, @deliv, @read);
            ";
            cmd.Parameters.AddWithValue("@id", msg.Id);
            cmd.Parameters.AddWithValue("@owner", msg.OwnerFingerprint);
            cmd.Parameters.AddWithValue("@peer", msg.PeerFingerprint);
            cmd.Parameters.AddWithValue("@sender", msg.SenderFingerprint);
            cmd.Parameters.AddWithValue("@pts", msg.Pts);
            cmd.Parameters.AddWithValue("@is_out", msg.IsOutgoing ? 1 : 0);
            cmd.Parameters.AddWithValue("@status", (int)msg.Status);
            cmd.Parameters.AddWithValue("@text", msg.Text ?? "");
            cmd.Parameters.AddWithValue("@cipher", msg.CiphertextBase64 ?? "");
            cmd.Parameters.AddWithValue("@tag", msg.TagBase64 ?? "");
            cmd.Parameters.AddWithValue("@iv", msg.IvBase64 ?? "");
            cmd.Parameters.AddWithValue("@sig", msg.SignatureBase64 ?? "");
            cmd.Parameters.AddWithValue("@ts", msg.Timestamp);
            cmd.Parameters.AddWithValue("@deliv", msg.DeliveredAt ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@read", msg.ReadAt ?? (object)DBNull.Value);
            cmd.ExecuteNonQuery();
        }
    }
}

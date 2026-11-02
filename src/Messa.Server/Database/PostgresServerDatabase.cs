using System;
using System.Collections.Generic;
using System.Data;
using System.Text.Json;
using System.Threading.Tasks;
using Npgsql;
using Messa.Core.Models;
using Messa.Core.Crypto;

namespace Messa.Server.Database
{
    public class PostgresServerDatabase : IServerDatabase
    {
        private readonly string _connectionString;

        public PostgresServerDatabase(string connectionString)
        {
            _connectionString = connectionString;
        }

        public async Task InitializeAsync()
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS users (
                    fingerprint VARCHAR(128) PRIMARY KEY,
                    username VARCHAR(64) UNIQUE,
                    display_name TEXT,
                    status_text TEXT,
                    bio TEXT,
                    avatar_base64 TEXT,
                    has_2fa BOOLEAN DEFAULT FALSE,
                    two_factor_salt TEXT,
                    two_factor_verifier TEXT,
                    updated_at BIGINT
                );

                CREATE TABLE IF NOT EXISTS prekey_bundles (
                    fingerprint VARCHAR(128) PRIMARY KEY,
                    username VARCHAR(64),
                    bundle_json TEXT NOT NULL,
                    updated_at BIGINT
                );

                CREATE TABLE IF NOT EXISTS pts_sequences (
                    account_fp VARCHAR(128) PRIMARY KEY,
                    current_pts BIGINT DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id VARCHAR(64) NOT NULL,
                    owner_fp VARCHAR(128) NOT NULL,
                    peer_fp VARCHAR(128) NOT NULL,
                    sender_fp VARCHAR(128) NOT NULL,
                    pts BIGINT NOT NULL,
                    is_outgoing BOOLEAN NOT NULL,
                    status INT NOT NULL,
                    text TEXT,
                    ciphertext TEXT,
                    tag TEXT,
                    iv TEXT,
                    signature TEXT,
                    timestamp BIGINT NOT NULL,
                    delivered_at BIGINT,
                    read_at BIGINT,
                    PRIMARY KEY(owner_fp, id)
                );

                CREATE INDEX IF NOT EXISTS idx_pg_messages_owner_pts ON messages(owner_fp, pts);
                CREATE INDEX IF NOT EXISTS idx_pg_messages_peer ON messages(owner_fp, peer_fp);
                CREATE INDEX IF NOT EXISTS idx_pg_users_username ON users(username);
            ";
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task SaveUserAsync(UserProfile profile)
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO users (fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, two_factor_salt, two_factor_verifier, updated_at)
                VALUES (@fp, @u, @name, @status, @bio, @avatar, @has2fa, @salt, @verifier, @updated)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    username = EXCLUDED.username,
                    display_name = EXCLUDED.display_name,
                    status_text = EXCLUDED.status_text,
                    bio = EXCLUDED.bio,
                    avatar_base64 = EXCLUDED.avatar_base64,
                    has_2fa = EXCLUDED.has_2fa,
                    two_factor_salt = EXCLUDED.two_factor_salt,
                    two_factor_verifier = EXCLUDED.two_factor_verifier,
                    updated_at = EXCLUDED.updated_at;
            ";
            cmd.Parameters.AddWithValue("@fp", profile.Fingerprint);
            cmd.Parameters.AddWithValue("@u", profile.Username ?? "");
            cmd.Parameters.AddWithValue("@name", profile.DisplayName ?? "");
            cmd.Parameters.AddWithValue("@status", profile.StatusText ?? "Online");
            cmd.Parameters.AddWithValue("@bio", profile.Bio ?? "");
            cmd.Parameters.AddWithValue("@avatar", profile.AvatarBase64 ?? "");
            cmd.Parameters.AddWithValue("@has2fa", profile.Has2FA);
            cmd.Parameters.AddWithValue("@salt", profile.TwoFactorSaltBase64 ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@verifier", profile.TwoFactorVerifierBase64 ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@updated", profile.UpdatedAt);
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<UserProfile?> GetUserAsync(string query)
        {
            var q = query.Trim().TrimStart('@');
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, two_factor_salt, two_factor_verifier, updated_at
                FROM users
                WHERE fingerprint = @q OR username ILIKE @q
                LIMIT 1;
            ";
            cmd.Parameters.AddWithValue("@q", q);

            await using var reader = await cmd.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                return new UserProfile
                {
                    Fingerprint = reader.GetString(0),
                    Username = reader.GetString(1),
                    DisplayName = reader.GetString(2),
                    StatusText = reader.GetString(3),
                    Bio = reader.GetString(4),
                    AvatarBase64 = reader.GetString(5),
                    Has2FA = reader.GetBoolean(6),
                    TwoFactorSaltBase64 = reader.IsDBNull(7) ? null : reader.GetString(7),
                    TwoFactorVerifierBase64 = reader.IsDBNull(8) ? null : reader.GetString(8),
                    UpdatedAt = reader.GetInt64(9)
                };
            }
            return null;
        }

        public async Task<List<UserProfile>> SearchUsersAsync(string query, int limit = 20)
        {
            var q = query.Trim().TrimStart('@');
            var results = new List<UserProfile>();
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT fingerprint, username, display_name, status_text, bio, avatar_base64, has_2fa, updated_at
                FROM users
                WHERE username ILIKE @like OR display_name ILIKE @like OR fingerprint = @q
                LIMIT @limit;
            ";
            cmd.Parameters.AddWithValue("@like", $"%{q}%");
            cmd.Parameters.AddWithValue("@q", q);
            cmd.Parameters.AddWithValue("@limit", limit);

            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                results.Add(new UserProfile
                {
                    Fingerprint = reader.GetString(0),
                    Username = reader.GetString(1),
                    DisplayName = reader.GetString(2),
                    StatusText = reader.GetString(3),
                    Bio = reader.GetString(4),
                    AvatarBase64 = reader.GetString(5),
                    Has2FA = reader.GetBoolean(6),
                    UpdatedAt = reader.GetInt64(7)
                });
            }
            return results;
        }

        public async Task SavePreKeyBundleAsync(PreKeyBundle bundle)
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                INSERT INTO prekey_bundles (fingerprint, username, bundle_json, updated_at)
                VALUES (@fp, @u, @json, @ts)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    username = EXCLUDED.username,
                    bundle_json = EXCLUDED.bundle_json,
                    updated_at = EXCLUDED.updated_at;
            ";
            cmd.Parameters.AddWithValue("@fp", bundle.Fingerprint);
            cmd.Parameters.AddWithValue("@u", bundle.Username ?? "");
            cmd.Parameters.AddWithValue("@json", JsonSerializer.Serialize(bundle));
            cmd.Parameters.AddWithValue("@ts", bundle.Timestamp);
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<PreKeyBundle?> GetPreKeyBundleAsync(string query)
        {
            var q = query.Trim().TrimStart('@');
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT bundle_json FROM prekey_bundles
                WHERE fingerprint = @q OR username ILIKE @q
                LIMIT 1;
            ";
            cmd.Parameters.AddWithValue("@q", q);

            var json = await cmd.ExecuteScalarAsync() as string;
            if (!string.IsNullOrEmpty(json))
            {
                return JsonSerializer.Deserialize<PreKeyBundle>(json);
            }
            return null;
        }

        public async Task<(CloudMessage recipientMsg, CloudMessage senderMsg)> StoreAndSequenceMessageAsync(
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

            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();
            await using var trans = await conn.BeginTransactionAsync();

            try
            {
                // 1. Next PTS for recipient
                var recipientPts = await IncrementPtsInternalAsync(conn, trans, recipientFp);
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
                await InsertMessageInternalAsync(conn, trans, recipientMsg);

                // 2. Next PTS for sender
                var senderPts = await IncrementPtsInternalAsync(conn, trans, senderFp);
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
                await InsertMessageInternalAsync(conn, trans, senderMsg);

                await trans.CommitAsync();
                return (recipientMsg, senderMsg);
            }
            catch
            {
                await trans.RollbackAsync();
                throw;
            }
        }

        public async Task UpdateMessageStatusAsync(string messageId, string accountFp, MessageDeliveryStatus status)
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            await using var cmd = conn.CreateCommand();

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
            await cmd.ExecuteNonQueryAsync();
        }

        public async Task<(List<CloudMessage> messages, long currentPts)> GetDifferenceAsync(string accountFp, long fromPts, int limit = 100)
        {
            var messages = new List<CloudMessage>();
            long currentPts = 0;

            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using (var ptsCmd = conn.CreateCommand())
            {
                ptsCmd.CommandText = "SELECT current_pts FROM pts_sequences WHERE account_fp = @fp;";
                ptsCmd.Parameters.AddWithValue("@fp", accountFp);
                var val = await ptsCmd.ExecuteScalarAsync();
                if (val != null && val != DBNull.Value) currentPts = Convert.ToInt64(val);
            }

            await using (var msgCmd = conn.CreateCommand())
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

                await using var reader = await msgCmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    messages.Add(new CloudMessage
                    {
                        Id = reader.GetString(0),
                        OwnerFingerprint = reader.GetString(1),
                        PeerFingerprint = reader.GetString(2),
                        SenderFingerprint = reader.GetString(3),
                        Pts = reader.GetInt64(4),
                        IsOutgoing = reader.GetBoolean(5),
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

            return (messages, currentPts);
        }

        public async Task<long> GetCurrentPtsAsync(string accountFp)
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync();

            await using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT current_pts FROM pts_sequences WHERE account_fp = @fp;";
            cmd.Parameters.AddWithValue("@fp", accountFp);
            var val = await cmd.ExecuteScalarAsync();
            if (val != null && val != DBNull.Value) return Convert.ToInt64(val);
            return 0L;
        }

        private static async Task<long> IncrementPtsInternalAsync(NpgsqlConnection conn, NpgsqlTransaction trans, string accountFp)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT INTO pts_sequences (account_fp, current_pts)
                VALUES (@fp, 1)
                ON CONFLICT(account_fp) DO UPDATE SET current_pts = pts_sequences.current_pts + 1
                RETURNING current_pts;
            ";
            cmd.Parameters.AddWithValue("@fp", accountFp);
            var res = await cmd.ExecuteScalarAsync();
            return Convert.ToInt64(res);
        }

        private static async Task InsertMessageInternalAsync(NpgsqlConnection conn, NpgsqlTransaction trans, CloudMessage msg)
        {
            await using var cmd = conn.CreateCommand();
            cmd.Transaction = trans;
            cmd.CommandText = @"
                INSERT INTO messages (id, owner_fp, peer_fp, sender_fp, pts, is_outgoing, status, text, ciphertext, tag, iv, signature, timestamp, delivered_at, read_at)
                VALUES (@id, @owner, @peer, @sender, @pts, @is_out, @status, @text, @cipher, @tag, @iv, @sig, @ts, @deliv, @read)
                ON CONFLICT (owner_fp, id) DO UPDATE SET
                    status = EXCLUDED.status,
                    delivered_at = EXCLUDED.delivered_at,
                    read_at = EXCLUDED.read_at;
            ";
            cmd.Parameters.AddWithValue("@id", msg.Id);
            cmd.Parameters.AddWithValue("@owner", msg.OwnerFingerprint);
            cmd.Parameters.AddWithValue("@peer", msg.PeerFingerprint);
            cmd.Parameters.AddWithValue("@sender", msg.SenderFingerprint);
            cmd.Parameters.AddWithValue("@pts", msg.Pts);
            cmd.Parameters.AddWithValue("@is_out", msg.IsOutgoing);
            cmd.Parameters.AddWithValue("@status", (int)msg.Status);
            cmd.Parameters.AddWithValue("@text", msg.Text ?? "");
            cmd.Parameters.AddWithValue("@cipher", msg.CiphertextBase64 ?? "");
            cmd.Parameters.AddWithValue("@tag", msg.TagBase64 ?? "");
            cmd.Parameters.AddWithValue("@iv", msg.IvBase64 ?? "");
            cmd.Parameters.AddWithValue("@sig", msg.SignatureBase64 ?? "");
            cmd.Parameters.AddWithValue("@ts", msg.Timestamp);
            cmd.Parameters.AddWithValue("@deliv", msg.DeliveredAt ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("@read", msg.ReadAt ?? (object)DBNull.Value);
            await cmd.ExecuteNonQueryAsync();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Messa.Core.Models;

namespace Messa.Core.Storage
{
    public class LocalMessageRecord
    {
        public string Id { get; set; } = string.Empty;
        public string ChatId { get; set; } = string.Empty;
        public string SenderId { get; set; } = string.Empty;
        public bool IsOutgoing { get; set; }
        public long Pts { get; set; }
        public long Timestamp { get; set; }
        public string PlainText { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
        public MessageDeliveryStatus Status { get; set; } = MessageDeliveryStatus.Sent;
    }

    public class EncryptedLocalDatabase : IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly byte[] _dbKey;
        private readonly object _dbLock = new();

        static EncryptedLocalDatabase()
        {
            try
            {
                SQLitePCL.Batteries_V2.Init();
            }
            catch { }
        }

        public EncryptedLocalDatabase(string dbPath, byte[] masterKeyMaterial)
        {
            // Derive 256-bit storage key from user's master key
            _dbKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                masterKeyMaterial,
                32,
                null,
                Encoding.UTF8.GetBytes("MESSA_LOCAL_DB_STORAGE_ENCRYPTION_KEY"));

            var csb = new SqliteConnectionStringBuilder
            {
                DataSource = dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Password = Convert.ToHexString(_dbKey) // SQLCipher 256-bit page-level database encryption
            };

            _connection = new SqliteConnection(csb.ToString());
            _connection.Open();

            InitializeSchema();
        }

        private void InitializeSchema()
        {
            lock (_dbLock)
            {
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    PRAGMA journal_mode = WAL;
                    PRAGMA synchronous = NORMAL;

                    CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        chat_id TEXT NOT NULL,
                        sender_id TEXT NOT NULL,
                        is_outgoing INTEGER NOT NULL,
                        pts INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        plain_text TEXT NOT NULL,
                        signature TEXT,
                        status INTEGER DEFAULT 1
                    );

                    CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages(chat_id, timestamp);
                    CREATE INDEX IF NOT EXISTS idx_messages_pts ON messages(pts);

                    -- FTS5 Full-Text Search Table
                    CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                        message_id UNINDEXED,
                        chat_id,
                        sender_id,
                        text_content,
                        tokenize = 'unicode61'
                    );
                ";
                cmd.ExecuteNonQuery();

                // Safe migration in case table was created previously without status
                try
                {
                    using var alterCmd = _connection.CreateCommand();
                    alterCmd.CommandText = "ALTER TABLE messages ADD COLUMN status INTEGER DEFAULT 1;";
                    alterCmd.ExecuteNonQuery();
                }
                catch { }
            }
        }

        public void SaveMessage(LocalMessageRecord record)
        {
            lock (_dbLock)
            {
                using var trans = _connection.BeginTransaction();
                try
                {
                    // 1. Insert into messages table
                    using (var cmd = _connection.CreateCommand())
                    {
                        cmd.Transaction = trans;
                        cmd.CommandText = @"
                            INSERT OR REPLACE INTO messages (id, chat_id, sender_id, is_outgoing, pts, timestamp, plain_text, signature, status)
                            VALUES (@id, @chat_id, @sender_id, @is_outgoing, @pts, @timestamp, @plain_text, @signature, @status);
                        ";
                        cmd.Parameters.AddWithValue("@id", record.Id);
                        cmd.Parameters.AddWithValue("@chat_id", record.ChatId);
                        cmd.Parameters.AddWithValue("@sender_id", record.SenderId);
                        cmd.Parameters.AddWithValue("@is_outgoing", record.IsOutgoing ? 1 : 0);
                        cmd.Parameters.AddWithValue("@pts", record.Pts);
                        cmd.Parameters.AddWithValue("@timestamp", record.Timestamp);
                        cmd.Parameters.AddWithValue("@plain_text", record.PlainText);
                        cmd.Parameters.AddWithValue("@signature", record.Signature ?? "");
                        cmd.Parameters.AddWithValue("@status", (int)record.Status);
                        cmd.ExecuteNonQuery();
                    }

                    // 2. Insert into FTS5 index
                    using (var ftsCmd = _connection.CreateCommand())
                    {
                        ftsCmd.Transaction = trans;
                        ftsCmd.CommandText = @"
                            INSERT OR REPLACE INTO messages_fts (message_id, chat_id, sender_id, text_content)
                            VALUES (@message_id, @chat_id, @sender_id, @text_content);
                        ";
                        ftsCmd.Parameters.AddWithValue("@message_id", record.Id);
                        ftsCmd.Parameters.AddWithValue("@chat_id", record.ChatId);
                        ftsCmd.Parameters.AddWithValue("@sender_id", record.SenderId);
                        ftsCmd.Parameters.AddWithValue("@text_content", record.PlainText);
                        ftsCmd.ExecuteNonQuery();
                    }

                    trans.Commit();
                }
                catch
                {
                    trans.Rollback();
                    throw;
                }
            }
        }

        public void UpdateMessageStatus(string messageId, MessageDeliveryStatus status)
        {
            lock (_dbLock)
            {
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    UPDATE messages
                    SET status = @status
                    WHERE id = @id;
                ";
                cmd.Parameters.AddWithValue("@id", messageId);
                cmd.Parameters.AddWithValue("@status", (int)status);
                cmd.ExecuteNonQuery();
            }
        }

        public List<LocalMessageRecord> GetMessagesForChat(string chatId, int limit = 100)
        {
            var results = new List<LocalMessageRecord>();
            lock (_dbLock)
            {
                using var cmd = _connection.CreateCommand();
                cmd.CommandText = @"
                    SELECT id, chat_id, sender_id, is_outgoing, pts, timestamp, plain_text, signature, status
                    FROM messages
                    WHERE chat_id = @chat_id
                    ORDER BY timestamp ASC
                    LIMIT @limit;
                ";
                cmd.Parameters.AddWithValue("@chat_id", chatId);
                cmd.Parameters.AddWithValue("@limit", limit);

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    results.Add(new LocalMessageRecord
                    {
                        Id = reader.GetString(0),
                        ChatId = reader.GetString(1),
                        SenderId = reader.GetString(2),
                        IsOutgoing = reader.GetInt32(3) == 1,
                        Pts = reader.GetInt64(4),
                        Timestamp = reader.GetInt64(5),
                        PlainText = reader.GetString(6),
                        Signature = reader.IsDBNull(7) ? "" : reader.GetString(7),
                        Status = (MessageDeliveryStatus)reader.GetInt32(8)
                    });
                }
            }
            return results;
        }

        public List<LocalMessageRecord> SearchMessages(
            string searchQuery,
            string? chatIdFilter = null,
            long? fromTimestamp = null,
            long? toTimestamp = null,
            int limit = 50)
        {
            var results = new List<LocalMessageRecord>();
            lock (_dbLock)
            {
                using var cmd = _connection.CreateCommand();

                var sql = @"
                    SELECT m.id, m.chat_id, m.sender_id, m.is_outgoing, m.pts, m.timestamp, m.plain_text, m.signature, m.status
                    FROM messages_fts fts
                    JOIN messages m ON fts.message_id = m.id
                    WHERE messages_fts MATCH @query
                ";

                if (!string.IsNullOrEmpty(chatIdFilter))
                {
                    sql += " AND m.chat_id = @chat_id";
                    cmd.Parameters.AddWithValue("@chat_id", chatIdFilter);
                }

                if (fromTimestamp.HasValue)
                {
                    sql += " AND m.timestamp >= @from_ts";
                    cmd.Parameters.AddWithValue("@from_ts", fromTimestamp.Value);
                }

                if (toTimestamp.HasValue)
                {
                    sql += " AND m.timestamp <= @to_ts";
                    cmd.Parameters.AddWithValue("@to_ts", toTimestamp.Value);
                }

                sql += " ORDER BY m.timestamp DESC LIMIT @limit;";

                var sanitizedQuery = searchQuery.Trim().Replace("'", "''");
                if (!sanitizedQuery.EndsWith("*")) sanitizedQuery += "*";

                cmd.CommandText = sql;
                cmd.Parameters.AddWithValue("@query", sanitizedQuery);
                cmd.Parameters.AddWithValue("@limit", limit);

                using var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    results.Add(new LocalMessageRecord
                    {
                        Id = reader.GetString(0),
                        ChatId = reader.GetString(1),
                        SenderId = reader.GetString(2),
                        IsOutgoing = reader.GetInt32(3) == 1,
                        Pts = reader.GetInt64(4),
                        Timestamp = reader.GetInt64(5),
                        PlainText = reader.GetString(6),
                        Signature = reader.IsDBNull(7) ? "" : reader.GetString(7),
                        Status = (MessageDeliveryStatus)reader.GetInt32(8)
                    });
                }
            }
            return results;
        }

        public void Dispose()
        {
            _connection.Close();
            _connection.Dispose();
            SqliteConnection.ClearAllPools();
            CryptographicOperations.ZeroMemory(_dbKey);
        }
    }
}

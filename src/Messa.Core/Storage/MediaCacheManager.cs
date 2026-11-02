using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Messa.Core.Storage
{
    public enum CacheRetentionPolicy
    {
        Days3,
        Days7,
        Days30,
        Forever
    }

    public class MediaCacheManager
    {
        private readonly string _cacheDir;
        private readonly object _lock = new();

        public MediaCacheManager(string cacheDir)
        {
            _cacheDir = cacheDir;
            Directory.CreateDirectory(_cacheDir);
        }

        public string SaveMedia(byte[] data, string extension, string? optionalId = null)
        {
            var ext = extension.TrimStart('.').ToLowerInvariant();
            var fileName = !string.IsNullOrEmpty(optionalId) ? $"{optionalId}.{ext}" : $"{Guid.NewGuid():N}.{ext}";
            var filePath = Path.Combine(_cacheDir, fileName);

            lock (_lock)
            {
                File.WriteAllBytes(filePath, data);
                File.SetLastAccessTimeUtc(filePath, DateTime.UtcNow);
            }

            return filePath;
        }

        public byte[]? GetMedia(string fileNameOrPath)
        {
            var filePath = Path.IsPathRooted(fileNameOrPath) ? fileNameOrPath : Path.Combine(_cacheDir, fileNameOrPath);
            if (!File.Exists(filePath)) return null;

            lock (_lock)
            {
                try
                {
                    File.SetLastAccessTimeUtc(filePath, DateTime.UtcNow);
                    return File.ReadAllBytes(filePath);
                }
                catch
                {
                    return null;
                }
            }
        }

        public (int deletedFiles, long freedBytes) PurgeExpiredMedia(CacheRetentionPolicy policy, long maxQuotaBytes = 500 * 1024 * 1024)
        {
            int deletedCount = 0;
            long freedBytes = 0;

            lock (_lock)
            {
                if (!Directory.Exists(_cacheDir)) return (0, 0);

                var di = new DirectoryInfo(_cacheDir);
                var files = di.GetFiles().ToList();

                // 1. Time-based expiration (Telegram style: 3 days, 1 week, 1 month)
                if (policy != CacheRetentionPolicy.Forever)
                {
                    var days = policy switch
                    {
                        CacheRetentionPolicy.Days3 => 3,
                        CacheRetentionPolicy.Days7 => 7,
                        CacheRetentionPolicy.Days30 => 30,
                        _ => 30
                    };

                    var cutoff = DateTime.UtcNow.AddDays(-days);

                    foreach (var file in files.ToList())
                    {
                        if (file.LastAccessTimeUtc < cutoff)
                        {
                            try
                            {
                                freedBytes += file.Length;
                                file.Delete();
                                files.Remove(file);
                                deletedCount++;
                            }
                            catch { }
                        }
                    }
                }

                // 2. LRU Size-quota expiration (Least Recently Used)
                long currentTotalSize = files.Sum(f => f.Length);
                if (currentTotalSize > maxQuotaBytes)
                {
                    var sortedByAge = files.OrderBy(f => f.LastAccessTimeUtc).ToList();
                    foreach (var file in sortedByAge)
                    {
                        if (currentTotalSize <= maxQuotaBytes) break;

                        try
                        {
                            var len = file.Length;
                            file.Delete();
                            currentTotalSize -= len;
                            freedBytes += len;
                            deletedCount++;
                        }
                        catch { }
                    }
                }
            }

            return (deletedCount, freedBytes);
        }

        public long GetCurrentCacheSize()
        {
            lock (_lock)
            {
                if (!Directory.Exists(_cacheDir)) return 0;
                return new DirectoryInfo(_cacheDir).GetFiles().Sum(f => f.Length);
            }
        }
    }
}

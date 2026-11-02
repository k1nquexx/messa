using System;
using System.Text.Json.Serialization;

namespace Messa.Core.Models
{
    public class UserProfile
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;

        [JsonPropertyName("statusText")]
        public string StatusText { get; set; } = "Available";

        [JsonPropertyName("bio")]
        public string Bio { get; set; } = string.Empty;

        [JsonPropertyName("avatarBase64")]
        public string AvatarBase64 { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        [JsonPropertyName("has2FA")]
        public bool Has2FA { get; set; } = false;

        [JsonPropertyName("updatedAt")]
        public long UpdatedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // 2FA SRP-6a / PBKDF2 Verifier (stored on server, secret password never leaves client)
        [JsonPropertyName("twoFactorSalt")]
        public string? TwoFactorSaltBase64 { get; set; }

        [JsonPropertyName("twoFactorVerifier")]
        public string? TwoFactorVerifierBase64 { get; set; }
    }

    public class ContactCard
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("displayName")]
        public string DisplayName { get; set; } = string.Empty;

        [JsonPropertyName("fingerprint")]
        public string Fingerprint { get; set; } = string.Empty;

        [JsonPropertyName("bio")]
        public string Bio { get; set; } = string.Empty;

        [JsonPropertyName("avatarBase64")]
        public string AvatarBase64 { get; set; } = string.Empty;

        [JsonPropertyName("lastMessagePreview")]
        public string LastMessagePreview { get; set; } = string.Empty;

        [JsonPropertyName("lastMessageTime")]
        public string LastMessageTime { get; set; } = string.Empty;

        [JsonPropertyName("unreadCount")]
        public int UnreadCount { get; set; } = 0;

        [JsonPropertyName("addedAt")]
        public long AddedAt { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public string ToInviteLink() => $"messa://contact?u={Username}&fp={Fingerprint}&name={Uri.EscapeDataString(DisplayName)}";

        public static ContactCard? FromInviteLink(string link)
        {
            try
            {
                if (!link.StartsWith("messa://contact?", StringComparison.OrdinalIgnoreCase)) return null;
                var uri = new Uri(link);
                var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
                var u = query["u"] ?? "";
                var fp = query["fp"] ?? "";
                var name = query["name"] ?? u;

                if (string.IsNullOrEmpty(fp)) return null;

                return new ContactCard
                {
                    Username = u,
                    DisplayName = name,
                    Fingerprint = fp
                };
            }
            catch
            {
                return null;
            }
        }
    }
}

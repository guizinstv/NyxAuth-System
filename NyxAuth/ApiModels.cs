namespace NyxAuth;

public sealed class NyxAuthSettings
{
    public string ListenUrl { get; set; } = "http://127.0.0.1:5050";
    public string AdminApiKey { get; set; } = "";
    public string DatabaseFile { get; set; } = "nyxauth.db";
    public int SessionHours { get; set; } = 24;
    public int AuthRequestsPerMinute { get; set; } = 10;

    public bool IsAdminKeyUsable() =>
        !string.IsNullOrWhiteSpace(AdminApiKey)
        && AdminApiKey.Length >= 32
        && !AdminApiKey.StartsWith("CHANGE_ME", StringComparison.OrdinalIgnoreCase);
}

public enum LicenseStatus
{
    Active,
    Expired,
    Banned,
    Redeemed
}

public enum AccountStatus
{
    Active,
    Expired,
    Banned
}

public sealed class License
{
    public string Key { get; set; } = "";
    public string AppId { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public int? DurationDays { get; set; }
    public bool IsLifetime { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public bool IsBanned { get; set; }
    public long? UserId { get; set; }
    public string? Username { get; set; }
    public DateTime? RedeemedUtc { get; set; }
    public string? DeviceId { get; set; }
    public DateTime? ActivatedUtc { get; set; }

    public LicenseStatus GetStatus(DateTime nowUtc)
    {
        if (IsBanned) return LicenseStatus.Banned;
        if (RedeemedUtc.HasValue) return LicenseStatus.Redeemed;
        if (!IsLifetime && (!ExpiresUtc.HasValue || ExpiresUtc.Value <= nowUtc)) return LicenseStatus.Expired;
        return LicenseStatus.Active;
    }

    public AdminLicenseInfo ToAdminInfo(DateTime nowUtc) =>
        new(Key, AppId, GetStatus(nowUtc).ToString().ToLowerInvariant(), CreatedUtc, ExpiresUtc, IsLifetime,
            Username, RedeemedUtc, DeviceId, ActivatedUtc);

    public PublicLicenseInfo ToPublicInfo(DateTime nowUtc)
    {
        int? remaining = null;
        if (!IsLifetime && ExpiresUtc.HasValue)
        {
            remaining = (int)Math.Max(0, Math.Ceiling((ExpiresUtc.Value - nowUtc).TotalDays));
        }

        return new PublicLicenseInfo(AppId, GetStatus(nowUtc).ToString().ToLowerInvariant(), ExpiresUtc, IsLifetime,
            remaining, DeviceId is not null);
    }
}

public sealed class UserAccount
{
    public long Id { get; set; }
    public string Username { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool IsBanned { get; set; }
    public bool IsLifetime { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public DateTime CreatedUtc { get; set; }
    public DateTime? LastLoginUtc { get; set; }

    public AccountStatus GetStatus(DateTime nowUtc)
    {
        if (IsBanned) return AccountStatus.Banned;
        if (IsLifetime) return AccountStatus.Active;
        return ExpiresUtc.HasValue && ExpiresUtc.Value > nowUtc ? AccountStatus.Active : AccountStatus.Expired;
    }

    public UserInfo ToInfo(DateTime nowUtc) =>
        new(Username, GetStatus(nowUtc).ToString().ToLowerInvariant(), ExpiresUtc, IsLifetime, CreatedUtc, LastLoginUtc);
}

public sealed record ApiResponse(bool Success, string Code, string Message, object? Data = null);

public sealed record PublicLicenseInfo(
    string AppId,
    string Status,
    DateTime? ExpiresUtc,
    bool IsLifetime,
    int? DaysRemaining,
    bool Activated);

public sealed record AdminLicenseInfo(
    string LicenseKey,
    string AppId,
    string Status,
    DateTime CreatedUtc,
    DateTime? ExpiresUtc,
    bool IsLifetime,
    string? Username,
    DateTime? RedeemedUtc,
    string? DeviceId,
    DateTime? ActivatedUtc);

public sealed record UserInfo(
    string Username,
    string Status,
    DateTime? ExpiresUtc,
    bool IsLifetime,
    DateTime CreatedUtc,
    DateTime? LastLoginUtc);

public sealed record LicenseRequest(string? LicenseKey, string? AppId, string? DeviceId);

public sealed record RedeemRequest(string? Username, string? Password, string? LicenseKey, string? AppId);

public sealed record LoginRequest(string? Username, string? Password);

public sealed record TokenRequest(string? Token);

public sealed record GenerateLicensesRequest(string? AppId, int Count, int? DurationDays, bool Lifetime, string? Username);

public sealed record LicenseKeyRequest(string? LicenseKey);

public sealed record ExtendLicenseRequest(string? LicenseKey, int Days);

public sealed record CreateUserRequest(string? Username, string? Password, int? DurationDays, bool Lifetime);

public sealed record UsernameRequest(string? Username);

using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace NyxAuth;

public sealed record LicenseCheck(string Code, License? License);

public sealed class LicenseService
{
    public static readonly int[] AllowedDurations = { 1, 7, 30, 90, 365 };

    private const string KeyAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private const string SelectSql =
        "SELECT l.license_key, l.app_id, l.created_utc, l.duration_days, l.is_lifetime, l.expires_utc, " +
        "l.is_banned, l.user_id, u.username, l.redeemed_utc, l.device_id, l.activated_utc " +
        "FROM licenses l LEFT JOIN users u ON u.id = l.user_id ";

    private static readonly Regex AppIdRegex = new(@"^[A-Za-z0-9_.-]{1,64}\z", RegexOptions.Compiled);

    private readonly DatabaseService _db;

    public LicenseService(DatabaseService db)
    {
        _db = db;
    }

    public static bool IsValidAppId(string? value) => value is not null && AppIdRegex.IsMatch(value);

    public static string NormalizeKey(string? key) => (key ?? "").Trim().ToUpperInvariant();

    public static string GenerateKey()
    {
        var chars = new char[20];
        for (var i = 0; i < chars.Length; i++)
        {
            chars[i] = KeyAlphabet[RandomNumberGenerator.GetInt32(KeyAlphabet.Length)];
        }

        var s = new string(chars);
        return $"NYX-{s[..5]}-{s[5..10]}-{s[10..15]}-{s[15..]}";
    }

    public List<License> Generate(string appId, int count, int? durationDays, string? username)
    {
        var now = DateTime.UtcNow;
        using var connection = _db.Open();
        using var tx = connection.BeginTransaction();

        long? userId = null;
        string? resolvedUsername = null;
        if (!string.IsNullOrWhiteSpace(username))
        {
            using var find = connection.Make("SELECT id, username FROM users WHERE username = @u", tx)
                .With("@u", username.Trim());
            using var reader = find.ExecuteReader();
            if (!reader.Read())
            {
                throw new InvalidOperationException("User not found.");
            }

            userId = reader.GetInt64(0);
            resolvedUsername = reader.GetString(1);
        }

        using (var app = connection.Make("INSERT OR IGNORE INTO applications(app_id, created_utc) VALUES(@a, @c)", tx)
                   .With("@a", appId)
                   .With("@c", DatabaseService.ToDb(now)))
        {
            app.ExecuteNonQuery();
        }

        var created = new List<License>();
        while (created.Count < count)
        {
            var key = GenerateKey();
            var license = new License
            {
                Key = key,
                AppId = appId,
                CreatedUtc = now,
                DurationDays = durationDays,
                IsLifetime = durationDays is null,
                ExpiresUtc = durationDays is null ? null : now.AddDays(durationDays.Value),
                UserId = userId,
                Username = resolvedUsername
            };

            using var insert = connection.Make(
                    "INSERT OR IGNORE INTO licenses(license_key, app_id, created_utc, duration_days, is_lifetime, expires_utc, user_id) " +
                    "VALUES(@k, @a, @c, @d, @l, @e, @u)", tx)
                .With("@k", key)
                .With("@a", appId)
                .With("@c", DatabaseService.ToDb(now))
                .With("@d", durationDays)
                .With("@l", license.IsLifetime)
                .With("@e", license.ExpiresUtc.HasValue ? DatabaseService.ToDb(license.ExpiresUtc.Value) : null)
                .With("@u", userId);

            if (insert.ExecuteNonQuery() == 1)
            {
                created.Add(license);
            }
        }

        tx.Commit();
        return created;
    }

    public License? Get(string rawKey)
    {
        var key = NormalizeKey(rawKey);
        using var connection = _db.Open();
        using var command = connection.Make(SelectSql + "WHERE l.license_key = @k").With("@k", key);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadLicense(reader) : null;
    }

    public List<License> List(string? search)
    {
        var all = new List<License>();
        using (var connection = _db.Open())
        using (var command = connection.Make(SelectSql + "ORDER BY l.created_utc DESC, l.license_key"))
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                all.Add(ReadLicense(reader));
            }
        }

        if (string.IsNullOrWhiteSpace(search))
        {
            return all;
        }

        var q = search.Trim();
        var now = DateTime.UtcNow;
        return all.Where(l =>
                l.Key.Contains(q, StringComparison.OrdinalIgnoreCase)
                || l.AppId.Contains(q, StringComparison.OrdinalIgnoreCase)
                || (l.Username?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)
                || l.GetStatus(now).ToString().Equals(q, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public bool SetBanned(string rawKey, bool banned)
    {
        using var connection = _db.Open();
        using var command = connection.Make("UPDATE licenses SET is_banned = @b WHERE license_key = @k")
            .With("@b", banned)
            .With("@k", NormalizeKey(rawKey));
        return command.ExecuteNonQuery() > 0;
    }

    public bool Delete(string rawKey)
    {
        using var connection = _db.Open();
        using var command = connection.Make("DELETE FROM licenses WHERE license_key = @k")
            .With("@k", NormalizeKey(rawKey));
        return command.ExecuteNonQuery() > 0;
    }

    public bool ResetDevice(string rawKey)
    {
        using var connection = _db.Open();
        using var command = connection.Make("UPDATE licenses SET device_id = NULL, activated_utc = NULL WHERE license_key = @k")
            .With("@k", NormalizeKey(rawKey));
        return command.ExecuteNonQuery() > 0;
    }

    public (string Code, DateTime? NewExpiry) Extend(string rawKey, int days)
    {
        if (days < 1 || days > 3650)
        {
            return ("invalid_days", null);
        }

        var license = Get(rawKey);
        if (license is null)
        {
            return ("not_found", null);
        }

        if (license.IsLifetime)
        {
            return ("lifetime", null);
        }

        var now = DateTime.UtcNow;
        var baseTime = license.ExpiresUtc.HasValue && license.ExpiresUtc.Value > now ? license.ExpiresUtc.Value : now;
        var newExpiry = baseTime.AddDays(days);

        using var connection = _db.Open();
        using var command = connection.Make("UPDATE licenses SET expires_utc = @e WHERE license_key = @k")
            .With("@e", DatabaseService.ToDb(newExpiry))
            .With("@k", license.Key);
        command.ExecuteNonQuery();
        return ("ok", newExpiry);
    }

    public LicenseCheck Check(string? rawKey, string? appId, string? deviceId)
    {
        var license = Get(NormalizeKey(rawKey));
        if (license is null || !string.Equals(license.AppId, appId, StringComparison.Ordinal))
        {
            return new LicenseCheck("license_not_found", null);
        }

        var now = DateTime.UtcNow;
        switch (license.GetStatus(now))
        {
            case LicenseStatus.Banned:
                return new LicenseCheck("license_banned", license);
            case LicenseStatus.Redeemed:
                return new LicenseCheck("license_redeemed", license);
            case LicenseStatus.Expired:
                return new LicenseCheck("license_expired", license);
        }

        if (license.DeviceId is not null && !string.Equals(license.DeviceId, deviceId, StringComparison.Ordinal))
        {
            return new LicenseCheck("device_mismatch", license);
        }

        return new LicenseCheck("ok", license);
    }

    public LicenseCheck Activate(string? rawKey, string appId, string deviceId)
    {
        var check = Check(rawKey, appId, deviceId);
        if (check.Code != "ok" || check.License is null)
        {
            return check;
        }

        var license = check.License;
        if (license.DeviceId is not null)
        {
            return new LicenseCheck("already_activated", license);
        }

        var now = DateTime.UtcNow;
        int changed;
        using (var connection = _db.Open())
        using (var command = connection.Make(
                       "UPDATE licenses SET device_id = @d, activated_utc = @t WHERE license_key = @k AND device_id IS NULL")
                   .With("@d", deviceId)
                   .With("@t", DatabaseService.ToDb(now))
                   .With("@k", license.Key))
        {
            changed = command.ExecuteNonQuery();
        }

        if (changed == 0)
        {
            var again = Check(rawKey, appId, deviceId);
            return again.Code == "ok" ? new LicenseCheck("already_activated", again.License) : again;
        }

        license.DeviceId = deviceId;
        license.ActivatedUtc = now;
        return new LicenseCheck("activated", license);
    }

    public string Redeem(UserAccount user, string? rawKey, string appId)
    {
        var key = NormalizeKey(rawKey);
        var now = DateTime.UtcNow;

        using (var connection = _db.Open())
        using (var tx = connection.BeginTransaction())
        {
            using var claim = connection.Make(
                    "UPDATE licenses SET user_id = @u, redeemed_utc = @now " +
                    "WHERE license_key = @k AND app_id = @a AND redeemed_utc IS NULL AND is_banned = 0 " +
                    "AND (is_lifetime = 1 OR expires_utc > @now) AND (user_id IS NULL OR user_id = @u)", tx)
                .With("@u", user.Id)
                .With("@now", DatabaseService.ToDb(now))
                .With("@k", key)
                .With("@a", appId);

            if (claim.ExecuteNonQuery() == 1)
            {
                int? days;
                bool licenseLifetime;
                using (var select = connection.Make(
                               "SELECT duration_days, is_lifetime FROM licenses WHERE license_key = @k", tx)
                           .With("@k", key))
                using (var reader = select.ExecuteReader())
                {
                    reader.Read();
                    days = reader.IsDBNull(0) ? null : reader.GetInt32(0);
                    licenseLifetime = reader.GetInt64(1) != 0;
                }

                bool userLifetime;
                DateTime? userExpiry;
                using (var select = connection.Make("SELECT is_lifetime, expires_utc FROM users WHERE id = @u", tx)
                           .With("@u", user.Id))
                using (var reader = select.ExecuteReader())
                {
                    reader.Read();
                    userLifetime = reader.GetInt64(0) != 0;
                    userExpiry = reader.IsDBNull(1) ? null : DatabaseService.FromDb(reader.GetString(1));
                }

                if (licenseLifetime)
                {
                    using var update = connection.Make(
                            "UPDATE users SET is_lifetime = 1, expires_utc = NULL WHERE id = @u", tx)
                        .With("@u", user.Id);
                    update.ExecuteNonQuery();
                }
                else if (!userLifetime)
                {
                    var baseTime = userExpiry.HasValue && userExpiry.Value > now ? userExpiry.Value : now;
                    var newExpiry = baseTime.AddDays(days ?? 0);
                    using var update = connection.Make("UPDATE users SET expires_utc = @e WHERE id = @u", tx)
                        .With("@e", DatabaseService.ToDb(newExpiry))
                        .With("@u", user.Id);
                    update.ExecuteNonQuery();
                }

                tx.Commit();
                return "ok";
            }

            tx.Rollback();
        }

        return Diagnose(key, appId, user.Id);
    }

    private string Diagnose(string key, string appId, long userId)
    {
        var license = Get(key);
        if (license is null || !string.Equals(license.AppId, appId, StringComparison.Ordinal))
        {
            return "license_not_found";
        }

        switch (license.GetStatus(DateTime.UtcNow))
        {
            case LicenseStatus.Banned:
                return "license_banned";
            case LicenseStatus.Redeemed:
                return "license_redeemed";
            case LicenseStatus.Expired:
                return "license_expired";
        }

        if (license.UserId.HasValue && license.UserId.Value != userId)
        {
            return "license_reserved";
        }

        return "license_unavailable";
    }

    private static License ReadLicense(Microsoft.Data.Sqlite.SqliteDataReader r) => new()
    {
        Key = r.GetString(0),
        AppId = r.GetString(1),
        CreatedUtc = DatabaseService.FromDb(r.GetString(2)),
        DurationDays = r.IsDBNull(3) ? null : r.GetInt32(3),
        IsLifetime = r.GetInt64(4) != 0,
        ExpiresUtc = r.IsDBNull(5) ? null : DatabaseService.FromDb(r.GetString(5)),
        IsBanned = r.GetInt64(6) != 0,
        UserId = r.IsDBNull(7) ? null : r.GetInt64(7),
        Username = r.IsDBNull(8) ? null : r.GetString(8),
        RedeemedUtc = r.IsDBNull(9) ? null : DatabaseService.FromDb(r.GetString(9)),
        DeviceId = r.IsDBNull(10) ? null : r.GetString(10),
        ActivatedUtc = r.IsDBNull(11) ? null : DatabaseService.FromDb(r.GetString(11))
    };
}

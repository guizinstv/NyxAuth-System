using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using BCryptNet = BCrypt.Net.BCrypt;

namespace NyxAuth;

public sealed class UserService
{
    private const int BcryptWorkFactor = 12;

    private const string SelectSql =
        "SELECT id, username, password_hash, is_banned, is_lifetime, expires_utc, created_utc, last_login_utc FROM users ";

    private static readonly Regex UsernameRegex = new(@"^[A-Za-z0-9_.-]{3,32}\z", RegexOptions.Compiled);

    private static readonly string DummyHash = BCryptNet.HashPassword("nyxauth-timing-dummy", BcryptWorkFactor);

    private readonly DatabaseService _db;
    private readonly int _sessionHours;

    public UserService(DatabaseService db, int sessionHours)
    {
        _db = db;
        _sessionHours = sessionHours;
    }

    public (string Code, string Message, UserAccount? User) Create(string? username, string? password, bool lifetime, int? durationDays)
    {
        username = username?.Trim();
        if (username is null || !UsernameRegex.IsMatch(username))
        {
            return ("invalid_username", "Username must be 3-32 characters: letters, numbers, '_', '.' or '-'.", null);
        }

        if (!IsValidPassword(password))
        {
            return ("invalid_password", "Password must be 8-72 bytes long.", null);
        }

        var now = DateTime.UtcNow;
        DateTime? expires = lifetime || durationDays is null ? null : now.AddDays(durationDays.Value);
        var hash = BCryptNet.HashPassword(password!, BcryptWorkFactor);

        try
        {
            using var connection = _db.Open();
            using var command = connection.Make(
                    "INSERT INTO users(username, password_hash, is_lifetime, expires_utc, created_utc) VALUES(@u, @h, @l, @e, @c)")
                .With("@u", username)
                .With("@h", hash)
                .With("@l", lifetime)
                .With("@e", expires.HasValue ? DatabaseService.ToDb(expires.Value) : null)
                .With("@c", DatabaseService.ToDb(now));
            command.ExecuteNonQuery();
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return ("username_taken", "Username already exists.", null);
        }

        return ("ok", "User created.", GetByUsername(username));
    }

    public UserAccount? GetByUsername(string username)
    {
        using var connection = _db.Open();
        using var command = connection.Make(SelectSql + "WHERE username = @u").With("@u", username.Trim());
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public UserAccount? GetById(long id)
    {
        using var connection = _db.Open();
        using var command = connection.Make(SelectSql + "WHERE id = @i").With("@i", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public List<UserAccount> List(string? search)
    {
        var all = new List<UserAccount>();
        using (var connection = _db.Open())
        using (var command = connection.Make(SelectSql + "ORDER BY username"))
        using (var reader = command.ExecuteReader())
        {
            while (reader.Read())
            {
                all.Add(ReadUser(reader));
            }
        }

        if (string.IsNullOrWhiteSpace(search))
        {
            return all;
        }

        var q = search.Trim();
        var now = DateTime.UtcNow;
        return all.Where(u =>
                u.Username.Contains(q, StringComparison.OrdinalIgnoreCase)
                || u.GetStatus(now).ToString().Equals(q, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    public bool SetBanned(string username, bool banned)
    {
        using var connection = _db.Open();
        bool changed;
        using (var update = connection.Make("UPDATE users SET is_banned = @b WHERE username = @u")
                   .With("@b", banned)
                   .With("@u", username.Trim()))
        {
            changed = update.ExecuteNonQuery() > 0;
        }

        if (changed && banned)
        {
            using var cleanup = connection.Make(
                    "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = @u)")
                .With("@u", username.Trim());
            cleanup.ExecuteNonQuery();
        }

        return changed;
    }

    public (string Code, UserAccount? User) Authenticate(string? username, string? password)
    {
        var user = string.IsNullOrWhiteSpace(username) ? null : GetByUsername(username);
        var candidate = password ?? "";
        if (Encoding.UTF8.GetByteCount(candidate) > 72)
        {
            candidate = "";
        }

        var passwordMatches = BCryptNet.Verify(candidate, user?.PasswordHash ?? DummyHash);
        if (user is null || !passwordMatches)
        {
            return ("invalid_credentials", null);
        }

        if (user.IsBanned)
        {
            return ("account_banned", null);
        }

        return ("ok", user);
    }

    public (string Token, DateTime ExpiresUtc) CreateSession(UserAccount user)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddHours(_sessionHours);
        if (!user.IsLifetime && user.ExpiresUtc.HasValue && user.ExpiresUtc.Value < expires)
        {
            expires = user.ExpiresUtc.Value;
        }

        var token = NewToken();

        using var connection = _db.Open();
        using var tx = connection.BeginTransaction();

        using (var cleanup = connection.Make("DELETE FROM sessions WHERE expires_utc <= @now", tx)
                   .With("@now", DatabaseService.ToDb(now)))
        {
            cleanup.ExecuteNonQuery();
        }

        using (var insert = connection.Make(
                       "INSERT INTO sessions(token_hash, user_id, created_utc, expires_utc) VALUES(@h, @u, @c, @e)", tx)
                   .With("@h", HashToken(token))
                   .With("@u", user.Id)
                   .With("@c", DatabaseService.ToDb(now))
                   .With("@e", DatabaseService.ToDb(expires)))
        {
            insert.ExecuteNonQuery();
        }

        using (var touch = connection.Make("UPDATE users SET last_login_utc = @now WHERE id = @u", tx)
                   .With("@now", DatabaseService.ToDb(now))
                   .With("@u", user.Id))
        {
            touch.ExecuteNonQuery();
        }

        tx.Commit();
        return (token, expires);
    }

    public (string Code, UserAccount? User, DateTime? ExpiresUtc) ValidateSession(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 200)
        {
            return ("invalid_token", null, null);
        }

        long userId;
        DateTime expires;
        using (var connection = _db.Open())
        using (var command = connection.Make("SELECT user_id, expires_utc FROM sessions WHERE token_hash = @h")
                   .With("@h", HashToken(token)))
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read())
            {
                return ("invalid_token", null, null);
            }

            userId = reader.GetInt64(0);
            expires = DatabaseService.FromDb(reader.GetString(1));
        }

        var now = DateTime.UtcNow;
        if (expires <= now)
        {
            return ("invalid_token", null, null);
        }

        var user = GetById(userId);
        if (user is null)
        {
            return ("invalid_token", null, null);
        }

        if (user.IsBanned)
        {
            return ("account_banned", null, null);
        }

        if (user.GetStatus(now) == AccountStatus.Expired)
        {
            return ("account_expired", null, null);
        }

        return ("ok", user, expires);
    }

    private static bool IsValidPassword(string? password) =>
        !string.IsNullOrEmpty(password) && password.Length >= 8 && Encoding.UTF8.GetByteCount(password) <= 72;

    private static string NewToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private static UserAccount ReadUser(SqliteDataReader r) => new()
    {
        Id = r.GetInt64(0),
        Username = r.GetString(1),
        PasswordHash = r.GetString(2),
        IsBanned = r.GetInt64(3) != 0,
        IsLifetime = r.GetInt64(4) != 0,
        ExpiresUtc = r.IsDBNull(5) ? null : DatabaseService.FromDb(r.GetString(5)),
        CreatedUtc = DatabaseService.FromDb(r.GetString(6)),
        LastLoginUtc = r.IsDBNull(7) ? null : DatabaseService.FromDb(r.GetString(7))
    };
}

using System.Globalization;
using Microsoft.Data.Sqlite;

namespace NyxAuth;

public sealed class DatabaseService
{
    private readonly string _connectionString;

    public string FilePath { get; }

    public DatabaseService(string filePath)
    {
        FilePath = filePath;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = filePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true
        }.ToString();
    }

    public SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        var directory = Path.GetDirectoryName(FilePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            PRAGMA journal_mode=WAL;

            CREATE TABLE IF NOT EXISTS applications (
                app_id TEXT PRIMARY KEY,
                created_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_banned INTEGER NOT NULL DEFAULT 0,
                is_lifetime INTEGER NOT NULL DEFAULT 0,
                expires_utc TEXT NULL,
                created_utc TEXT NOT NULL,
                last_login_utc TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT NOT NULL UNIQUE,
                app_id TEXT NOT NULL REFERENCES applications(app_id),
                created_utc TEXT NOT NULL,
                duration_days INTEGER NULL,
                is_lifetime INTEGER NOT NULL DEFAULT 0,
                expires_utc TEXT NULL,
                is_banned INTEGER NOT NULL DEFAULT 0,
                user_id INTEGER NULL REFERENCES users(id) ON DELETE SET NULL,
                redeemed_utc TEXT NULL,
                device_id TEXT NULL,
                activated_utc TEXT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash TEXT NOT NULL UNIQUE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_utc TEXT NOT NULL,
                expires_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS ix_licenses_app ON licenses(app_id);
            CREATE INDEX IF NOT EXISTS ix_sessions_user ON sessions(user_id);
            """;
        command.ExecuteNonQuery();
    }

    public static string ToDb(DateTime utc) =>
        utc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    public static DateTime FromDb(string value) =>
        DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
}

internal static class DbExtensions
{
    public static SqliteCommand Make(this SqliteConnection connection, string sql, SqliteTransaction? transaction = null)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        return command;
    }

    public static SqliteCommand With(this SqliteCommand command, string name, object? value)
    {
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }
}

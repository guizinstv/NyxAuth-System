using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NyxAuth;

try
{
    Console.OutputEncoding = Encoding.UTF8;
    Console.Title = "NyxAuth";
}
catch (IOException)
{
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
});

var settings = builder.Configuration.GetSection("NyxAuth").Get<NyxAuthSettings>() ?? new NyxAuthSettings();
var authLimit = Math.Max(1, settings.AuthRequestsPerMinute);
var dbPath = Path.IsPathRooted(settings.DatabaseFile)
    ? settings.DatabaseFile
    : Path.Combine(AppContext.BaseDirectory, settings.DatabaseFile);

Ui.Banner();

var db = new DatabaseService(dbPath);
try
{
    db.Initialize();
}
catch (Exception ex)
{
    Ui.Fail("Database initialization failed: " + ex.Message);
    return 1;
}

Ui.Ok("Database initialized");

var licenses = new LicenseService(db);
var users = new UserService(db, Math.Max(1, settings.SessionHours));

builder.Logging.ClearProviders();
builder.WebHost.UseUrls(settings.ListenUrl);
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
    options.Limits.MaxRequestBodySize = 16 * 1024;
});
builder.Services.AddSingleton<IHostLifetime, NoLifetime>();
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(
            new ApiResponse(false, "rate_limited", "Too many requests. Try again later."), token);
    };
    options.AddPolicy("auth", http => Limit("auth", http, authLimit));
    options.AddPolicy("session", http => Limit("session", http, 120));
    options.AddPolicy("admin", http => Limit("admin", http, 60));
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    Interlocked.Increment(ref Stats.Requests);
    try
    {
        await next(context);
    }
    catch (Exception)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new ApiResponse(false, "server_error", "Internal server error."));
        }
    }
});
app.UseRateLimiter();
Api.Map(app, settings, licenses, users);

try
{
    await app.StartAsync();
}
catch (Exception ex)
{
    Ui.Fail("API server failed to start: " + ex.Message);
    return 1;
}

var startedUtc = DateTime.UtcNow;

Ui.Ok("API server running");
Ui.Ok("Listening on " + settings.ListenUrl);
if (!Ui.IsLoopback(settings.ListenUrl))
{
    Ui.Warn("Not bound to loopback. Put NyxAuth behind an HTTPS reverse proxy before exposing it.");
}

if (!settings.IsAdminKeyUsable())
{
    Ui.Warn("Admin API disabled: set NyxAuth:AdminApiKey (32+ characters) in appsettings.json.");
}

var firstScreen = true;
while (true)
{
    if (!firstScreen)
    {
        Ui.Banner();
    }

    firstScreen = false;
    Ui.Menu(settings.ListenUrl);
    Console.Write("  > ");
    var choice = Console.ReadLine()?.Trim();
    if (choice is null || choice == "0")
    {
        break;
    }

    Console.WriteLine();
    switch (choice)
    {
        case "1":
            Cli.GenerateLicenses(licenses);
            break;
        case "2":
            Cli.ListLicenses(licenses);
            break;
        case "3":
            Cli.CreateUser(users);
            break;
        case "4":
            Cli.ListUsers(users);
            break;
        case "5":
            Cli.ExtendLicense(licenses);
            break;
        case "6":
            Cli.BanMenu(licenses, users);
            break;
        case "7":
            Cli.DeleteLicense(licenses);
            break;
        case "8":
            Cli.ShowEndpoints(settings.ListenUrl);
            break;
        case "9":
            Cli.ShowStatus(settings, db, licenses, users, startedUtc);
            break;
        case "10":
            await Cli.RunExampleClient(settings.ListenUrl);
            break;
        default:
            Ui.Warn("Unknown option.");
            break;
    }

    Ui.Pause();
}

Console.WriteLine();
Ui.Info("Stopping server...");
await app.StopAsync();
await app.DisposeAsync();
return 0;

static RateLimitPartition<string> Limit(string name, HttpContext http, int permits) =>
    RateLimitPartition.GetFixedWindowLimiter(
        $"{name}:{http.Connection.RemoteIpAddress}",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permits,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        });

static class AppInfo
{
    public const string Version = "1.0.0";
}

static class Stats
{
    public static long Requests;
}

sealed class NoLifetime : IHostLifetime
{
    public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

static class Api
{
    internal static IResult Ok(string message, object? data = null, string code = "ok", int status = StatusCodes.Status200OK) =>
        Results.Json(new ApiResponse(true, code, message, data), statusCode: status);

    internal static IResult Fail(int status, string code, string message) =>
        Results.Json(new ApiResponse(false, code, message), statusCode: status);

    private static async Task<T?> Read<T>(HttpRequest request) where T : class
    {
        try
        {
            return await request.ReadFromJsonAsync<T>();
        }
        catch
        {
            return null;
        }
    }

    private static bool ValidKey(string? key) => !string.IsNullOrWhiteSpace(key) && key.Length <= 64;

    private static bool ValidDevice(string? deviceId) => deviceId is null || deviceId.Length <= 128;

    private static bool KeysEqual(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(a)),
            SHA256.HashData(Encoding.UTF8.GetBytes(b)));

    private static IResult LicenseResult(LicenseCheck check)
    {
        var now = DateTime.UtcNow;
        return check.Code switch
        {
            "ok" => Ok("License is valid.", check.License!.ToPublicInfo(now)),
            "activated" => Ok("License activated for this device.", check.License!.ToPublicInfo(now), "activated"),
            "already_activated" => Ok("License is already activated for this device.", check.License!.ToPublicInfo(now), "already_activated"),
            "license_not_found" => Fail(404, check.Code, "License key not found."),
            "license_banned" => Fail(403, check.Code, "This license has been banned."),
            "license_expired" => Fail(403, check.Code, "This license has expired."),
            "license_redeemed" => Fail(403, check.Code, "This license was already redeemed and cannot be used directly."),
            "device_mismatch" => Fail(403, check.Code, "This license is bound to a different device."),
            _ => Fail(500, "server_error", "Unexpected license state.")
        };
    }

    private static IResult SessionResult((string Code, UserAccount? User, DateTime? ExpiresUtc) session)
    {
        var now = DateTime.UtcNow;
        return session.Code switch
        {
            "ok" => Ok("Session is valid.", new { valid = true, expiresUtc = session.ExpiresUtc, user = session.User!.ToInfo(now) }),
            "account_banned" => Fail(403, session.Code, "This account is banned."),
            "account_expired" => Fail(403, session.Code, "This account has expired. Redeem a license to renew it."),
            _ => Fail(401, "invalid_token", "Invalid or expired session token.")
        };
    }

    private static async Task<IResult> LicenseKeyOperation(HttpRequest http, Func<string, bool> operation, string message)
    {
        var request = await Read<LicenseKeyRequest>(http);
        if (request is null || !ValidKey(request.LicenseKey))
        {
            return Fail(400, "invalid_request", "licenseKey is required.");
        }

        return operation(request.LicenseKey!)
            ? Ok(message)
            : Fail(404, "license_not_found", "License key not found.");
    }

    private static async Task<IResult> UserOperation(HttpRequest http, Func<string, bool> operation, string message)
    {
        var request = await Read<UsernameRequest>(http);
        if (request is null || string.IsNullOrWhiteSpace(request.Username) || request.Username.Length > 64)
        {
            return Fail(400, "invalid_request", "username is required.");
        }

        return operation(request.Username)
            ? Ok(message)
            : Fail(404, "user_not_found", "User not found.");
    }

    public static void Map(WebApplication app, NyxAuthSettings settings, LicenseService licenses, UserService users)
    {
        var api = app.MapGroup("/api/v1");

        api.MapGet("/health", () => Ok("NyxAuth is running.", new
        {
            status = "online",
            version = AppInfo.Version,
            serverTimeUtc = DateTime.UtcNow
        }));

        api.MapPost("/license/validate", async (HttpRequest http) =>
        {
            var request = await Read<LicenseRequest>(http);
            if (request is null || !ValidKey(request.LicenseKey) || !LicenseService.IsValidAppId(request.AppId) || !ValidDevice(request.DeviceId))
            {
                return Fail(400, "invalid_request", "licenseKey and appId are required; deviceId must be at most 128 characters.");
            }

            return LicenseResult(licenses.Check(request.LicenseKey, request.AppId, request.DeviceId));
        }).RequireRateLimiting("auth");

        api.MapPost("/license/activate", async (HttpRequest http) =>
        {
            var request = await Read<LicenseRequest>(http);
            if (request is null || !ValidKey(request.LicenseKey) || !LicenseService.IsValidAppId(request.AppId)
                || string.IsNullOrWhiteSpace(request.DeviceId) || request.DeviceId.Length > 128)
            {
                return Fail(400, "invalid_request", "licenseKey, appId and deviceId (max 128 characters) are required.");
            }

            return LicenseResult(licenses.Activate(request.LicenseKey, request.AppId!, request.DeviceId));
        }).RequireRateLimiting("auth");

        api.MapPost("/license/redeem", async (HttpRequest http) =>
        {
            var request = await Read<RedeemRequest>(http);
            if (request is null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password)
                || !ValidKey(request.LicenseKey) || !LicenseService.IsValidAppId(request.AppId))
            {
                return Fail(400, "invalid_request", "username, password, licenseKey and appId are required.");
            }

            var (authCode, user) = users.Authenticate(request.Username, request.Password);
            if (authCode == "invalid_credentials")
            {
                return Fail(401, authCode, "Invalid username or password.");
            }

            if (authCode == "account_banned")
            {
                return Fail(403, authCode, "This account is banned.");
            }

            var code = licenses.Redeem(user!, request.LicenseKey, request.AppId!);
            return code switch
            {
                "ok" => Ok("License redeemed.", users.GetById(user!.Id)!.ToInfo(DateTime.UtcNow), "redeemed"),
                "license_not_found" => Fail(404, code, "License key not found."),
                "license_banned" => Fail(403, code, "This license has been banned."),
                "license_expired" => Fail(403, code, "This license has expired."),
                "license_reserved" => Fail(403, code, "This license is reserved for another user."),
                "license_redeemed" => Fail(409, code, "This license was already redeemed."),
                _ => Fail(409, "license_unavailable", "This license cannot be redeemed.")
            };
        }).RequireRateLimiting("auth");

        api.MapPost("/auth/login", async (HttpRequest http) =>
        {
            var request = await Read<LoginRequest>(http);
            if (request is null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return Fail(400, "invalid_request", "username and password are required.");
            }

            var (code, user) = users.Authenticate(request.Username, request.Password);
            if (code == "invalid_credentials")
            {
                return Fail(401, code, "Invalid username or password.");
            }

            if (code == "account_banned")
            {
                return Fail(403, code, "This account is banned.");
            }

            var now = DateTime.UtcNow;
            if (user!.GetStatus(now) == AccountStatus.Expired)
            {
                return Fail(403, "account_expired", "This account has expired. Redeem a license to renew it.");
            }

            var (token, expiresUtc) = users.CreateSession(user);
            return Ok("Login successful.", new { token, expiresUtc, user = user.ToInfo(now) });
        }).RequireRateLimiting("auth");

        api.MapPost("/auth/validate", async (HttpRequest http) =>
        {
            var request = await Read<TokenRequest>(http);
            if (request is null || string.IsNullOrWhiteSpace(request.Token))
            {
                return Fail(400, "invalid_request", "token is required.");
            }

            return SessionResult(users.ValidateSession(request.Token));
        }).RequireRateLimiting("session");

        api.MapGet("/user/me", (HttpRequest http) =>
        {
            var header = http.Headers.Authorization.ToString();
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return Fail(401, "invalid_token", "A bearer token is required.");
            }

            return SessionResult(users.ValidateSession(header[7..].Trim()));
        }).RequireRateLimiting("session");

        var admin = api.MapGroup("/admin").RequireRateLimiting("admin");
        admin.AddEndpointFilter(async (context, next) =>
        {
            if (!settings.IsAdminKeyUsable())
            {
                return Fail(503, "admin_disabled", "The admin API is disabled until NyxAuth:AdminApiKey is configured.");
            }

            var provided = context.HttpContext.Request.Headers["X-Admin-Key"].ToString();
            if (!KeysEqual(provided, settings.AdminApiKey))
            {
                return Fail(401, "unauthorized", "Missing or invalid admin key.");
            }

            return await next(context);
        });

        admin.MapPost("/license/generate", async (HttpRequest http) =>
        {
            var request = await Read<GenerateLicensesRequest>(http);
            if (request is null || !LicenseService.IsValidAppId(request.AppId))
            {
                return Fail(400, "invalid_request", "appId is required.");
            }

            if (request.Count < 1 || request.Count > 500)
            {
                return Fail(400, "invalid_count", "count must be between 1 and 500.");
            }

            int? days = null;
            if (!request.Lifetime)
            {
                if (request.DurationDays is not int duration || !LicenseService.AllowedDurations.Contains(duration))
                {
                    return Fail(400, "invalid_duration", "durationDays must be 1, 7, 30, 90 or 365, or set lifetime to true.");
                }

                days = duration;
            }

            try
            {
                var now = DateTime.UtcNow;
                var created = licenses.Generate(request.AppId!, request.Count, days, request.Username);
                return Ok("Licenses created.", created.Select(l => l.ToAdminInfo(now)).ToList(), "created", StatusCodes.Status201Created);
            }
            catch (InvalidOperationException)
            {
                return Fail(404, "user_not_found", "User not found.");
            }
        });

        admin.MapGet("/license/list", (string? search) =>
        {
            var now = DateTime.UtcNow;
            return Ok("Licenses.", licenses.List(search).Select(l => l.ToAdminInfo(now)).ToList());
        });

        admin.MapPost("/license/ban", async (HttpRequest http) =>
            await LicenseKeyOperation(http, key => licenses.SetBanned(key, true), "License banned."));

        admin.MapPost("/license/unban", async (HttpRequest http) =>
            await LicenseKeyOperation(http, key => licenses.SetBanned(key, false), "License unbanned."));

        admin.MapPost("/license/delete", async (HttpRequest http) =>
            await LicenseKeyOperation(http, licenses.Delete, "License deleted."));

        admin.MapPost("/license/reset-device", async (HttpRequest http) =>
            await LicenseKeyOperation(http, licenses.ResetDevice, "Device binding cleared."));

        admin.MapPost("/license/extend", async (HttpRequest http) =>
        {
            var request = await Read<ExtendLicenseRequest>(http);
            if (request is null || !ValidKey(request.LicenseKey))
            {
                return Fail(400, "invalid_request", "licenseKey and days are required.");
            }

            var (code, expiry) = licenses.Extend(request.LicenseKey!, request.Days);
            return code switch
            {
                "ok" => Ok("License extended.", new { expiresUtc = expiry }),
                "not_found" => Fail(404, "license_not_found", "License key not found."),
                "lifetime" => Fail(409, "license_is_lifetime", "Lifetime licenses do not expire."),
                _ => Fail(400, "invalid_days", "days must be between 1 and 3650.")
            };
        });

        admin.MapPost("/user/create", async (HttpRequest http) =>
        {
            var request = await Read<CreateUserRequest>(http);
            if (request is null)
            {
                return Fail(400, "invalid_request", "username and password are required.");
            }

            if (!request.Lifetime && request.DurationDays is int duration && !LicenseService.AllowedDurations.Contains(duration))
            {
                return Fail(400, "invalid_duration", "durationDays must be 1, 7, 30, 90 or 365, or set lifetime to true.");
            }

            var (code, message, user) = users.Create(request.Username, request.Password, request.Lifetime, request.DurationDays);
            return code switch
            {
                "ok" => Ok(message, user!.ToInfo(DateTime.UtcNow), "created", StatusCodes.Status201Created),
                "username_taken" => Fail(409, code, message),
                _ => Fail(400, code, message)
            };
        });

        admin.MapGet("/user/list", (string? search) =>
        {
            var now = DateTime.UtcNow;
            return Ok("Users.", users.List(search).Select(u => u.ToInfo(now)).ToList());
        });

        admin.MapPost("/user/ban", async (HttpRequest http) =>
            await UserOperation(http, name => users.SetBanned(name, true), "User banned."));

        admin.MapPost("/user/unban", async (HttpRequest http) =>
            await UserOperation(http, name => users.SetBanned(name, false), "User unbanned."));

        app.MapFallback(() => Fail(404, "not_found", "Endpoint not found."));
    }
}

static class Ui
{
    public static void Banner()
    {
        try
        {
            Console.Clear();
        }
        catch (IOException)
        {
        }

        const int width = 46;
        var lines = new[] { "N Y X A U T H", "License & Authentication Server", "Version " + AppInfo.Version };

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ╔" + new string('═', width) + "╗");
        for (var i = 0; i < lines.Length; i++)
        {
            Console.Write("  ║");
            Console.ForegroundColor = i == 0 ? ConsoleColor.Cyan : ConsoleColor.Gray;
            Console.Write(Center(lines[i], width));
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("║");
        }

        Console.WriteLine("  ╚" + new string('═', width) + "╝");
        Console.ResetColor();
        Console.WriteLine();
    }

    public static void Menu(string url)
    {
        Console.WriteLine();
        Console.Write("  Server Status: ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("ONLINE");
        Console.ResetColor();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine("  " + url);
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine("  Commands:");

        var items = new[]
        {
            "1.  Generate license keys",
            "2.  List license keys",
            "3.  Create user",
            "4.  List users",
            "5.  Extend license expiration",
            "6.  Ban / unban license or user",
            "7.  Delete license",
            "8.  Show API endpoints",
            "9.  View server status",
            "10. Run example client test",
            "0.  Exit"
        };

        foreach (var item in items)
        {
            var split = item.IndexOf(' ');
            Console.Write("   ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(item[..split]);
            Console.ResetColor();
            Console.WriteLine(item[split..]);
        }

        Console.WriteLine();
    }

    public static void Title(string text)
    {
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("  ── " + text + " ──");
        Console.ResetColor();
        Console.WriteLine();
    }

    public static void Ok(string message) => Line("[+] ", ConsoleColor.Green, message);

    public static void Info(string message) => Line("[*] ", ConsoleColor.Cyan, message);

    public static void Warn(string message) => Line("[!] ", ConsoleColor.Yellow, message);

    public static void Fail(string message) => Line("[-] ", ConsoleColor.Red, message);

    public static void Pause()
    {
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("  Press Enter to return to the menu...");
        Console.ResetColor();
        Console.ReadLine();
    }

    public static bool IsLoopback(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.IsLoopback;

    private static void Line(string tag, ConsoleColor color, string message)
    {
        Console.Write("  ");
        Console.ForegroundColor = color;
        Console.Write(tag);
        Console.ResetColor();
        Console.WriteLine(message);
    }

    private static string Center(string text, int width)
    {
        var left = Math.Max(0, (width - text.Length) / 2);
        return (new string(' ', left) + text).PadRight(width);
    }
}

static class Cli
{
    private static string Ask(string label, string? defaultValue = null)
    {
        Console.Write(defaultValue is null ? $"  {label}: " : $"  {label} [{defaultValue}]: ");
        var input = Console.ReadLine()?.Trim();
        return string.IsNullOrEmpty(input) ? defaultValue ?? "" : input;
    }

    private static int AskInt(string label, int min, int max, int defaultValue)
    {
        while (true)
        {
            var input = Ask(label, defaultValue.ToString());
            if (int.TryParse(input, out var value) && value >= min && value <= max)
            {
                return value;
            }

            Ui.Warn($"Enter a number between {min} and {max}.");
        }
    }

    private static string ReadPassword(string label)
    {
        Console.Write($"  {label}: ");
        var buffer = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                break;
            }

            if (key.Key == ConsoleKey.Backspace)
            {
                if (buffer.Length > 0)
                {
                    buffer.Length--;
                    Console.Write("\b \b");
                }

                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Append(key.KeyChar);
                Console.Write('*');
            }
        }

        return buffer.ToString();
    }

    private static (bool Lifetime, int? Days) PickDuration(bool allowNone)
    {
        Console.WriteLine("  Duration:  1) 1 day   2) 7 days   3) 30 days   4) 90 days   5) 365 days   6) Lifetime"
                          + (allowNone ? "   0) No time (user must redeem a license)" : ""));
        while (true)
        {
            var choice = Ask("Choose", allowNone ? "0" : "3");
            switch (choice)
            {
                case "0" when allowNone:
                    return (false, null);
                case "1":
                    return (false, 1);
                case "2":
                    return (false, 7);
                case "3":
                    return (false, 30);
                case "4":
                    return (false, 90);
                case "5":
                    return (false, 365);
                case "6":
                    return (true, null);
            }

            Ui.Warn("Invalid choice.");
        }
    }

    private static string ExpiresText(bool lifetime, DateTime? expires, DateTime now)
    {
        if (lifetime)
        {
            return "Lifetime";
        }

        if (!expires.HasValue)
        {
            return "-";
        }

        var left = expires.Value - now;
        var stamp = expires.Value.ToString("yyyy-MM-dd HH:mm") + "Z";
        return left > TimeSpan.Zero ? $"{stamp} ({Math.Ceiling(left.TotalDays):0}d)" : stamp;
    }

    private static string Trunc(string value, int max) => value.Length <= max ? value : value[..max];

    private static ConsoleColor ColorFor(string status) => status switch
    {
        "Active" => ConsoleColor.Green,
        "Expired" => ConsoleColor.Yellow,
        "Banned" => ConsoleColor.Red,
        _ => ConsoleColor.Cyan
    };

    public static void GenerateLicenses(LicenseService licenses)
    {
        Ui.Title("Generate license keys");
        var appId = Ask("Application ID", "default");
        if (!LicenseService.IsValidAppId(appId))
        {
            Ui.Warn("Application ID must be 1-64 characters: letters, numbers, '_', '.' or '-'.");
            return;
        }

        var count = AskInt("How many keys (1-500)", 1, 500, 1);
        var (lifetime, days) = PickDuration(false);
        var username = Ask("Associate with username (blank = none)");

        try
        {
            var created = licenses.Generate(appId, count, lifetime ? null : days, string.IsNullOrWhiteSpace(username) ? null : username);
            Console.WriteLine();
            Ui.Ok($"{created.Count} key(s) created:");
            Console.ForegroundColor = ConsoleColor.Cyan;
            foreach (var license in created)
            {
                Console.WriteLine("      " + license.Key);
            }

            Console.ResetColor();
        }
        catch (InvalidOperationException ex)
        {
            Ui.Warn(ex.Message);
        }
    }

    public static void ListLicenses(LicenseService licenses)
    {
        Ui.Title("License keys");
        var search = Ask("Search (key, app, user or status; blank = all)");
        var now = DateTime.UtcNow;
        var list = licenses.List(string.IsNullOrWhiteSpace(search) ? null : search);
        Console.WriteLine();
        if (list.Count == 0)
        {
            Ui.Info("No licenses found.");
            return;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"KEY",-28}{"APP",-12}{"STATUS",-10}{"EXPIRES",-28}{"USER",-14}DEVICE");
        Console.ResetColor();
        foreach (var license in list)
        {
            var status = license.GetStatus(now).ToString();
            Console.Write($"  {license.Key,-28}{Trunc(license.AppId, 11),-12}");
            Console.ForegroundColor = ColorFor(status);
            Console.Write($"{status,-10}");
            Console.ResetColor();
            Console.WriteLine(
                $"{ExpiresText(license.IsLifetime, license.ExpiresUtc, now),-28}{Trunc(license.Username ?? "-", 13),-14}{(license.DeviceId is null ? "-" : "bound")}");
        }

        Console.WriteLine();
        Ui.Info($"{list.Count} license(s).");
    }

    public static void CreateUser(UserService users)
    {
        Ui.Title("Create user");
        var username = Ask("Username");
        var password = ReadPassword("Password");
        var repeat = ReadPassword("Repeat password");
        if (password != repeat)
        {
            Ui.Warn("Passwords do not match.");
            return;
        }

        var (lifetime, days) = PickDuration(true);
        var (_, message, user) = users.Create(username, password, lifetime, days);
        Console.WriteLine();
        if (user is null)
        {
            Ui.Warn(message);
            return;
        }

        Ui.Ok($"User '{user.Username}' created.");
    }

    public static void ListUsers(UserService users)
    {
        Ui.Title("Users");
        var search = Ask("Search (username or status; blank = all)");
        var now = DateTime.UtcNow;
        var list = users.List(string.IsNullOrWhiteSpace(search) ? null : search);
        Console.WriteLine();
        if (list.Count == 0)
        {
            Ui.Info("No users found.");
            return;
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.WriteLine($"  {"USERNAME",-22}{"STATUS",-10}{"EXPIRES",-28}LAST LOGIN");
        Console.ResetColor();
        foreach (var user in list)
        {
            var status = user.GetStatus(now).ToString();
            Console.Write($"  {Trunc(user.Username, 21),-22}");
            Console.ForegroundColor = ColorFor(status);
            Console.Write($"{status,-10}");
            Console.ResetColor();
            var lastLogin = user.LastLoginUtc.HasValue ? user.LastLoginUtc.Value.ToString("yyyy-MM-dd HH:mm") + "Z" : "-";
            Console.WriteLine($"{ExpiresText(user.IsLifetime, user.ExpiresUtc, now),-28}{lastLogin}");
        }

        Console.WriteLine();
        Ui.Info($"{list.Count} user(s).");
    }

    public static void ExtendLicense(LicenseService licenses)
    {
        Ui.Title("Extend license expiration");
        var key = Ask("License key");
        var days = AskInt("Days to add (1-3650)", 1, 3650, 30);
        var (code, expiry) = licenses.Extend(key, days);
        Console.WriteLine();
        switch (code)
        {
            case "ok":
                Ui.Ok($"New expiration: {expiry:yyyy-MM-dd HH:mm}Z");
                break;
            case "not_found":
                Ui.Warn("License key not found.");
                break;
            case "lifetime":
                Ui.Warn("Lifetime licenses do not expire.");
                break;
            default:
                Ui.Warn("Invalid number of days.");
                break;
        }
    }

    public static void BanMenu(LicenseService licenses, UserService users)
    {
        Ui.Title("Ban / unban");
        Console.WriteLine("  1) Ban license   2) Unban license   3) Ban user   4) Unban user");
        var choice = Ask("Choose", "1");
        Console.WriteLine();
        switch (choice)
        {
            case "1":
            case "2":
            {
                var banned = choice == "1";
                var key = Ask("License key");
                if (licenses.SetBanned(key, banned))
                {
                    Ui.Ok(banned ? "License banned." : "License unbanned.");
                }
                else
                {
                    Ui.Warn("License key not found.");
                }

                break;
            }
            case "3":
            case "4":
            {
                var banned = choice == "3";
                var username = Ask("Username");
                if (users.SetBanned(username, banned))
                {
                    Ui.Ok(banned ? "User banned and sessions revoked." : "User unbanned.");
                }
                else
                {
                    Ui.Warn("User not found.");
                }

                break;
            }
            default:
                Ui.Warn("Invalid choice.");
                break;
        }
    }

    public static void DeleteLicense(LicenseService licenses)
    {
        Ui.Title("Delete license");
        var key = Ask("License key");
        var license = licenses.Get(key);
        if (license is null)
        {
            Ui.Warn("License key not found.");
            return;
        }

        var confirm = Ask($"Type DELETE to permanently remove {license.Key}");
        if (confirm != "DELETE")
        {
            Ui.Info("Cancelled.");
            return;
        }

        Ui.Ok(licenses.Delete(license.Key) ? "License deleted." : "License not found.");
    }

    public static void ShowEndpoints(string baseUrl)
    {
        Ui.Title("API endpoints");
        Ui.Info("Base URL: " + baseUrl.TrimEnd('/') + "/api/v1");
        Ui.Info("Auth column: public = no credentials, token = Authorization: Bearer <token>, admin = X-Admin-Key header");
        Console.WriteLine();

        var rows = new (string Method, string Path, string Auth, string Description)[]
        {
            ("GET", "/health", "public", "Server health"),
            ("POST", "/license/validate", "public", "Check a license key"),
            ("POST", "/license/activate", "public", "Bind a license to a device"),
            ("POST", "/license/redeem", "public", "Add a license's time to a user account"),
            ("POST", "/auth/login", "public", "Log in, returns a session token"),
            ("POST", "/auth/validate", "public", "Validate a session token"),
            ("GET", "/user/me", "token", "Current user information"),
            ("POST", "/admin/license/generate", "admin", "Generate license keys"),
            ("GET", "/admin/license/list", "admin", "List licenses (?search=)"),
            ("POST", "/admin/license/ban", "admin", "Ban a license"),
            ("POST", "/admin/license/unban", "admin", "Unban a license"),
            ("POST", "/admin/license/extend", "admin", "Extend a license"),
            ("POST", "/admin/license/delete", "admin", "Delete a license"),
            ("POST", "/admin/license/reset-device", "admin", "Clear device binding"),
            ("POST", "/admin/user/create", "admin", "Create a user"),
            ("GET", "/admin/user/list", "admin", "List users (?search=)"),
            ("POST", "/admin/user/ban", "admin", "Ban a user"),
            ("POST", "/admin/user/unban", "admin", "Unban a user")
        };

        foreach (var row in rows)
        {
            Console.Write($"  {row.Method,-5} {row.Path,-30} ");
            Console.ForegroundColor = row.Auth == "admin" ? ConsoleColor.Yellow : row.Auth == "token" ? ConsoleColor.Cyan : ConsoleColor.Green;
            Console.Write($"{row.Auth,-8}");
            Console.ResetColor();
            Console.WriteLine(row.Description);
        }
    }

    public static void ShowStatus(NyxAuthSettings settings, DatabaseService db, LicenseService licenses, UserService users, DateTime startedUtc)
    {
        Ui.Title("Server status");
        var now = DateTime.UtcNow;
        var allLicenses = licenses.List(null);
        var uptime = now - startedUtc;

        Console.Write("  Server Status : ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("ONLINE");
        Console.ResetColor();
        Console.WriteLine($"  Listening on  : {settings.ListenUrl}");
        Console.WriteLine($"  Uptime        : {(int)uptime.TotalHours}h {uptime.Minutes}m {uptime.Seconds}s");
        Console.WriteLine($"  Requests      : {Interlocked.Read(ref Stats.Requests)}");
        Console.WriteLine($"  Database      : {db.FilePath}");
        Console.WriteLine($"  Licenses      : {allLicenses.Count} total, "
                          + $"{allLicenses.Count(l => l.GetStatus(now) == LicenseStatus.Active)} active, "
                          + $"{allLicenses.Count(l => l.GetStatus(now) == LicenseStatus.Expired)} expired, "
                          + $"{allLicenses.Count(l => l.GetStatus(now) == LicenseStatus.Banned)} banned, "
                          + $"{allLicenses.Count(l => l.GetStatus(now) == LicenseStatus.Redeemed)} redeemed");
        Console.WriteLine($"  Users         : {users.List(null).Count}");
        Console.WriteLine($"  Admin API     : {(settings.IsAdminKeyUsable() ? "enabled" : "disabled (no valid AdminApiKey)")}");
    }

    public static async Task RunExampleClient(string baseUrl)
    {
        Ui.Title("Example client test");
        var appId = Ask("Application ID", "default");
        var key = Ask("License key");
        var username = Ask("Username (blank = skip login test)");
        var password = string.IsNullOrEmpty(username) ? "" : ReadPassword("Password");
        Console.WriteLine();
        await ExampleClient.RunAsync(baseUrl, appId, key, username, password);
    }
}

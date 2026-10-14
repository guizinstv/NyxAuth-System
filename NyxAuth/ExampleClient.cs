using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace NyxAuth;

public static class ExampleClient
{
    public static async Task RunAsync(string baseUrl, string appId, string licenseKey, string username, string password)
    {
        using var http = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/api/v1/"),
            Timeout = TimeSpan.FromSeconds(10)
        };

        var deviceId = Environment.MachineName;

        try
        {
            Console.WriteLine("1) Health check");
            var health = await SendAsync(http, HttpMethod.Get, "health", null, null);
            Console.WriteLine($"   HTTP {health.Status}: {Text(health.Body, "message")} (version {Text(health.Body, "data", "version")})");
            Console.WriteLine();

            Console.WriteLine("2) License validation");
            var license = await SendAsync(http, HttpMethod.Post, "license/validate", new { licenseKey, appId, deviceId }, null);
            DescribeLicense(license);
            Console.WriteLine();

            if (string.IsNullOrWhiteSpace(username))
            {
                Console.WriteLine("3) Login skipped (no username given)");
                return;
            }

            Console.WriteLine("3) Login");
            var login = await SendAsync(http, HttpMethod.Post, "auth/login", new { username, password }, null);
            var loginCode = Text(login.Body, "code");
            var token = Text(login.Body, "data", "token");
            switch (loginCode)
            {
                case "ok":
                    Console.WriteLine($"   Logged in as {Text(login.Body, "data", "user", "username")}. Session expires {Text(login.Body, "data", "expiresUtc")}.");
                    break;
                case "invalid_credentials":
                    Console.WriteLine("   Wrong username or password.");
                    return;
                case "account_banned":
                    Console.WriteLine("   This account is banned.");
                    return;
                case "account_expired":
                    Console.WriteLine("   This account has expired. Redeem a license key to renew it.");
                    return;
                case "rate_limited":
                    Console.WriteLine("   Too many attempts. Wait a minute and try again.");
                    return;
                default:
                    Console.WriteLine($"   Unexpected response: HTTP {login.Status} {loginCode} {Text(login.Body, "message")}");
                    return;
            }

            Console.WriteLine();
            Console.WriteLine("4) Current user (GET /user/me)");
            var me = await SendAsync(http, HttpMethod.Get, "user/me", null, token);
            Console.WriteLine($"   HTTP {me.Status}: {Text(me.Body, "data", "user", "username")} status={Text(me.Body, "data", "user", "status")} expires={Text(me.Body, "data", "user", "expiresUtc")} lifetime={Text(me.Body, "data", "user", "isLifetime")}");
            Console.WriteLine();

            Console.WriteLine("5) Session validation");
            var session = await SendAsync(http, HttpMethod.Post, "auth/validate", new { token }, null);
            Console.WriteLine($"   HTTP {session.Status}: {Text(session.Body, "code")} - {Text(session.Body, "message")}");
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine("   Could not reach the server: " + ex.Message);
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("   The request timed out.");
        }
    }

    private static void DescribeLicense((int Status, JsonElement Body) response)
    {
        var code = Text(response.Body, "code");
        switch (code)
        {
            case "ok":
                Console.WriteLine($"   Valid. Status={Text(response.Body, "data", "status")}, lifetime={Text(response.Body, "data", "isLifetime")}, expires={Text(response.Body, "data", "expiresUtc")}, days left={Text(response.Body, "data", "daysRemaining")}");
                break;
            case "license_expired":
                Console.WriteLine("   This license has expired. Ask for a renewal.");
                break;
            case "license_banned":
                Console.WriteLine("   This license has been banned.");
                break;
            case "license_not_found":
                Console.WriteLine("   Invalid license key.");
                break;
            case "license_redeemed":
                Console.WriteLine("   This key was already redeemed into an account.");
                break;
            case "device_mismatch":
                Console.WriteLine("   This license is bound to a different device.");
                break;
            case "rate_limited":
                Console.WriteLine("   Too many requests. Wait a minute and try again.");
                break;
            case "invalid_request":
                Console.WriteLine("   The request was rejected: " + Text(response.Body, "message"));
                break;
            default:
                Console.WriteLine($"   Unexpected response: HTTP {response.Status} {code} {Text(response.Body, "message")}");
                break;
        }
    }

    private static async Task<(int Status, JsonElement Body)> SendAsync(
        HttpClient http, HttpMethod method, string path, object? body, string? bearerToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        if (!string.IsNullOrEmpty(bearerToken))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);
        }

        using var response = await http.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();

        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(string.IsNullOrWhiteSpace(text) ? "{}" : text);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            using var empty = JsonDocument.Parse("{}");
            root = empty.RootElement.Clone();
        }

        return ((int)response.StatusCode, root);
    }

    private static string Text(JsonElement root, params string[] path)
    {
        var current = root;
        foreach (var name in path)
        {
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(name, out var next))
            {
                return "";
            }

            current = next;
        }

        return current.ValueKind switch
        {
            JsonValueKind.String => current.GetString() ?? "",
            JsonValueKind.Null => "",
            JsonValueKind.Undefined => "",
            _ => current.ToString()
        };
    }
}

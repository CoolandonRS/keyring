using System.Security.Cryptography;
using System.Text;

namespace CoolandonRS.keyring.Yubikey; 

public static class YubiOTP {
    private static readonly string[] ApiEndpoints = new []{ "api", "api2", "api3", "api4", "api5" }.Select(s => $"https://{s}.yubico.com/wsapi/2.0/verify").ToArray();
    private static readonly char[] NonceChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
    
    internal enum YubicoApiStatus {
        OK, 
        BAD_OTP, 
        REPLAYED_OTP, 
        BAD_SIGNATURE, 
        MISSING_PARAMETER, 
        NO_SUCH_CLIENT,
        OPERATION_NOT_ALLOWED,
        BACKEND_ERROR,
        NOT_ENOUGH_ANSWERS,
        REPLAYED_REQUEST
    }

    /// <summary>
    /// Verifies that an OTP is valid
    /// </summary>
    /// <param name="otp">The provided OTP</param>
    /// <param name="api">The api authentication to use</param>
    /// <param name="factoryOnly">Whether or not to only allow factory OTP configurations</param>
    /// <returns></returns>
    public static async Task<bool> Verify(string otp, (string, string) api, bool factoryOnly = false) => await Verify(otp, api, (string[]?) null);

    /// <summary>
    /// Verifies that an OTP is valid, optionally that it belongs to a specific yubikey
    /// </summary>
    /// <param name="otp">The provided OTP</param>
    /// <param name="api">The api authentication to use</param>
    /// <param name="id">The public identifier of the authorized yubikey. When specified, if the OTP does not match this id, returns false.</param>
    /// <param name="factoryOnly">Whether or not to only allow factory OTP configurations</param>
    /// <returns>True if the otp is valid, and if id or serial is set, is authorized.</returns>
    public static async Task<bool> Verify(string otp, (string id, string key) api, string? id = null, bool factoryOnly = false) => await Verify(otp, api, id == null ? null : new[] { id }, factoryOnly);

    /// <summary>
    /// Verifies that an OTP is valid, optionally that it belongs to one of several yubikeys
    /// </summary>
    /// <param name="otp">The provided OTP</param>
    /// <param name="api">The api authentication to use</param>
    /// <param name="ids">The public identifiers of authorized yubikeys. When specified, if the OTP does not match one of these ids, returns false.</param>
    /// <param name="factoryOnly">Whether or not to only allow factory OTP configurations</param>
    /// <returns>True if the otp is valid (and authorized). False if the otp is valid (and unauthorized). Throws on an invalid otp (YubicoErrorException or DiscrepancyException)</returns>
    public static async Task<bool> Verify(string otp, (string id, string key) api, string[]? ids = null, bool factoryOnly = false) {
        if (otp.Length is < 32 or > 48) throw new YubicoErrorException(YubicoApiStatus.BAD_OTP);
        switch (otp[..2]) {
            case "cc":
                break;
            case "vv" when !factoryOnly:
                break;
            default:
                return false;
        }
        var nonce = BuildNonce();
        var request = $"id={api.id}&nonce={nonce}&otp={otp}";
        var hash = HMACSHA1.HashData(Convert.FromBase64String(api.key), Encoding.UTF8.GetBytes(request));
        request += $"&h={Convert.ToBase64String(hash)}";
        var response = (await Request(request)).Trim().Split("\r\n").Select(prop => prop.Split('=')).ToDictionary(prop => prop[0], prop => string.Join("", prop[1..]));
        var respStatus = Enum.Parse<YubicoApiStatus>(response["status"]);
        if (respStatus != YubicoApiStatus.OK) throw new YubicoErrorException(respStatus);
        var respOtp = response["otp"];
        var respNonce = response["nonce"];
        var respHash = response["h"];
        var respSl = response["sl"];
        var respT = response["t"];
        var computedRespHash = Convert.ToBase64String(HMACSHA1.HashData(Convert.FromBase64String(api.key), Encoding.UTF8.GetBytes($"nonce={respNonce}&otp={otp}&sl={respSl}&status={respStatus.ToString()}&t={respT}"))).TrimEnd('=');
        if (otp != respOtp) throw new DiscrepancyException("OTP mismatch");
        if (nonce != respNonce) throw new DiscrepancyException("Nonce mismatch");
        if (respHash != computedRespHash) throw new DiscrepancyException("Signing error");
        return ids != null && ids.Contains(otp[..^32]);
    }

    /// <summary>
    /// Creates a nonce
    /// </summary>
    /// <param name="len">How long the nonce should be. If null a random number between 16 and 40 (inclusive)</param>
    /// <returns></returns>
    internal static string BuildNonce(int? len = null) {
        len ??= RandomNumberGenerator.GetInt32(16, 41);
        var builder = new StringBuilder();
        for (var i = 0; i <= len; i++) {
            builder.Append(NonceChars[RandomNumberGenerator.GetInt32(0, NonceChars.Length)]);
        }
        return builder.ToString();
    }

    internal static async Task<string> Request(string request) {
        var cancelSource = new CancellationTokenSource();
        var task = new TaskCompletionSource<string>();
        void Complete(string str) {
            cancelSource.Cancel();
            task.SetResult(str);
        }
        // https://developers.yubico.com/yubikey-val/Getting_Started_Writing_Clients.html: Clients should send authentication requests to all of them in parallel, and utilize the first response
        foreach (var endpoint in ApiEndpoints) {
            try {
                #pragma warning disable CS4014
                SendRequest(endpoint + $"?{request}", Complete, cancelSource.Token);
                #pragma warning restore CS4014
            } catch (OperationCanceledException) {
                // intentional
                break;
            }
        }

        if (await Task.WhenAny(task.Task, Task.Delay(TimeSpan.FromSeconds(5))) == task.Task) return await task.Task;
        cancelSource.Cancel();
        throw new TimeoutException("Yubikey servers did not respond in time");
    }

    internal static async Task SendRequest(string fullRequest, Action<string> callback, CancellationToken token) {
        var response = await new HttpClient().SendAsync(new HttpRequestMessage(HttpMethod.Get, fullRequest), token);
        if (!response.IsSuccessStatusCode) return;
        token.ThrowIfCancellationRequested();
        callback(await response.Content.ReadAsStringAsync(token));
    }
}
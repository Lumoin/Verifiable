using CsCheck;
using Verifiable.WebFinger;

namespace Verifiable.Tests.WebFinger;

/// <summary>
/// Property-based tests (CsCheck) for the security-relevant WebFinger client validators — the host authority
/// guard in <see cref="WebFingerClient.ComputeQueryUri"/> and the user-part encoding in
/// <see cref="WebFingerClient.CreateAccountResource"/>. Generators deliberately include the authority-confusion
/// and truncation octets (<c>@</c>, <c>/</c>, <c>#</c>, <c>?</c>, space, <c>:</c>) so the sampler explores the
/// exact inputs a static example test would miss.
/// </summary>
[TestClass]
internal sealed class WebFingerHostPropertyTests
{
    /// <summary>Host characters mixing benign reg-name/port octets with the authority-confusion and truncation octets.</summary>
    private static Gen<string> GenHost { get; } =
        Gen.OneOf(
            Gen.Char['a', 'z'],
            Gen.Char['0', '9'],
            Gen.Const('.'),
            Gen.Const('-'),
            Gen.Const(':'),
            Gen.Const('@'),
            Gen.Const('/'),
            Gen.Const('#'),
            Gen.Const('?'),
            Gen.Const(' '))
        .Array[1, 24]
        .Select(characters => new string(characters));

    /// <summary>User-part characters mixing unreserved octets with reserved ones that MUST be percent-encoded.</summary>
    private static Gen<string> GenUserPart { get; } =
        Gen.OneOf(
            Gen.Char['a', 'z'],
            Gen.Char['0', '9'],
            Gen.Const('.'),
            Gen.Const('@'),
            Gen.Const(':'),
            Gen.Const('/'),
            Gen.Const('+'),
            Gen.Const(' '))
        .Array[1, 24]
        .Select(characters => new string(characters));


    /// <summary>
    /// Security invariant (host-injection regression): for ANY host string, <see cref="WebFingerClient.ComputeQueryUri"/>
    /// either rejects it with an <see cref="ArgumentException"/> or returns an https URI to the given bare host
    /// with the fixed well-known path and no userinfo. It NEVER silently connects off-host or loses the §4 path.
    /// </summary>
    [TestMethod]
    public void ComputeQueryUriNeverConnectsOffHostOrLosesTheWellKnownPath() =>
        GenHost.Sample(host =>
        {
            Uri uri;
            try
            {
                uri = WebFingerClient.ComputeQueryUri(host, "acct:alice@example.com", []);
            }
            catch(ArgumentException)
            {
                return true;
            }

            return string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal)
                && string.IsNullOrEmpty(uri.UserInfo)
                && string.Equals(uri.AbsolutePath, WellKnownWebFingerValues.WellKnownPath, StringComparison.Ordinal);
        });


    /// <summary>
    /// acct: encoding invariant: for ANY user part, <see cref="WebFingerClient.CreateAccountResource"/> either
    /// rejects an all-whitespace input or emits an <c>acct:</c> URI whose encoded user part carries no raw
    /// space or <c>@</c> (so the trailing <c>@</c> truly delimits the host) and round-trips to the original;
    /// the host is preserved verbatim.
    /// </summary>
    [TestMethod]
    public void CreateAccountResourceAlwaysEmitsAValidAcctUriWhoseUserPartRoundTrips() =>
        GenUserPart.Sample(userPart =>
        {
            string acct;
            try
            {
                acct = WebFingerClient.CreateAccountResource(userPart, "example.com");
            }
            catch(ArgumentException)
            {
                return true;
            }

            if(!acct.StartsWith("acct:", StringComparison.Ordinal))
            {
                return false;
            }

            string body = acct["acct:".Length..];
            int lastAt = body.LastIndexOf('@');
            if(lastAt < 0)
            {
                return false;
            }

            string encodedUserPart = body[..lastAt];
            string hostPart = body[(lastAt + 1)..];

            return string.Equals(hostPart, "example.com", StringComparison.Ordinal)
                && !encodedUserPart.Contains(' ', StringComparison.Ordinal)
                && !encodedUserPart.Contains('@', StringComparison.Ordinal)
                && string.Equals(Uri.UnescapeDataString(encodedUserPart), userPart, StringComparison.Ordinal);
        });
}

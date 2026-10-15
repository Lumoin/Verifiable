using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Rebuilds a compact JWS the server issued and signs it again with a private half the
/// <see cref="TestHostShell"/> holds, so a test can present a token that verifies under a key of
/// its choosing and differs from the issued one only in the part the test names: the protected
/// header (<see cref="ResignWithHeaderAsync(TestHostShell, string, KeyId, string?, CancellationToken)"/>) or the payload
/// (<see cref="ResignWithPayloadAsync"/>).
/// </summary>
/// <remarks>
/// The header written is <c>{"alg":…,"typ":…,"kid":…}</c> with the issued token's <c>alg</c>; the
/// values are written verbatim into the JSON text, so a caller passes values that need no JSON
/// escaping. The signing key is looked up in the default host's signing-key store.
/// </remarks>
internal static class CompactJwsResigning
{
    /// <summary>
    /// Rebuilds <paramref name="compactJws"/> with a protected header of the token's <c>alg</c>, the
    /// given <c>typ</c> and a <c>kid</c> naming <paramref name="keyId"/>, the payload segment
    /// unchanged, and signs it with the private half the host holds for <paramref name="keyId"/>.
    /// </summary>
    /// <param name="host">The host whose signing-key store holds the key's private half.</param>
    /// <param name="compactJws">The compact JWS the server issued.</param>
    /// <param name="keyId">The key the rebuilt token names and is signed under.</param>
    /// <param name="typ">The <c>typ</c> header value, or <see langword="null"/> to write no <c>typ</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The re-signed compact JWS.</returns>
    public static Task<string> ResignWithHeaderAsync(TestHostShell host, string compactJws, KeyId keyId, string? typ, CancellationToken cancellationToken) =>
        ResignWithHeaderAsync(host, compactJws, keyId, keyId.Value, typ, cancellationToken);


    /// <summary>
    /// Rebuilds <paramref name="compactJws"/> with a protected header of the token's <c>alg</c>, the
    /// given <c>typ</c> and <paramref name="headerKid"/> as its <c>kid</c>, the payload segment
    /// unchanged, and signs it with the private half the host holds for
    /// <paramref name="signingKeyId"/>. The header's <c>kid</c> is written apart from the signing key
    /// so a test can name a <c>kid</c> no <see cref="KeyId"/> can hold, such as whitespace.
    /// </summary>
    /// <param name="host">The host whose signing-key store holds the signing key's private half.</param>
    /// <param name="compactJws">The compact JWS the server issued.</param>
    /// <param name="signingKeyId">The key the rebuilt token is signed under.</param>
    /// <param name="headerKid">The <c>kid</c> the rebuilt header carries.</param>
    /// <param name="typ">The <c>typ</c> header value, or <see langword="null"/> to write no <c>typ</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The re-signed compact JWS.</returns>
    public static async Task<string> ResignWithHeaderAsync(
        TestHostShell host, string compactJws, KeyId signingKeyId, string headerKid, string? typ,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrEmpty(compactJws);
        ArgumentNullException.ThrowIfNull(headerKid);

        string[] parts = compactJws.Split('.');
        string algorithm = ReadHeaderAlgorithm(parts[0]);

        string typMember = typ is null ? string.Empty : $",\"typ\":\"{typ}\"";
        string headerJson = $"{{\"alg\":\"{algorithm}\"{typMember},\"kid\":\"{headerKid}\"}}";
        string headerSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson));

        return await SignAsync(host, headerSegment, parts[1], signingKeyId, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Rebuilds <paramref name="compactJws"/> with its protected header segment unchanged and
    /// <paramref name="payloadJson"/> as its payload, and signs it with the private half the host
    /// holds for <paramref name="keyId"/>, so the token verifies and differs from the issued one only
    /// in its claims.
    /// </summary>
    /// <param name="host">The host whose signing-key store holds the key's private half.</param>
    /// <param name="compactJws">The compact JWS the server issued.</param>
    /// <param name="keyId">The key the issued header names and the rebuilt token is signed under.</param>
    /// <param name="payloadJson">The JSON text of the rebuilt payload.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The re-signed compact JWS.</returns>
    public static async Task<string> ResignWithPayloadAsync(
        TestHostShell host, string compactJws, KeyId keyId, string payloadJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrEmpty(compactJws);
        ArgumentException.ThrowIfNullOrEmpty(payloadJson);

        string[] parts = compactJws.Split('.');
        string payloadSegment = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));

        return await SignAsync(host, parts[0], payloadSegment, keyId, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads the <c>alg</c> member of a base64url-encoded protected header segment.</summary>
    /// <param name="headerSegment">The first segment of a compact JWS.</param>
    /// <returns>The header's <c>alg</c> value.</returns>
    private static string ReadHeaderAlgorithm(string headerSegment)
    {
        using IMemoryOwner<byte> headerOwner = TestSetup.Base64UrlDecoder(headerSegment, BaseMemoryPool.Shared);
        using JsonDocument headerDocument = JsonDocument.Parse(headerOwner.Memory);

        return headerDocument.RootElement.GetProperty("alg").GetString()!;
    }


    /// <summary>
    /// Signs the JWS signing input <c>header.payload</c> with the private half the default host holds
    /// for <paramref name="keyId"/> and returns the three-segment compact serialization.
    /// </summary>
    /// <param name="host">The host whose signing-key store holds the key's private half.</param>
    /// <param name="headerSegment">The base64url protected header segment.</param>
    /// <param name="payloadSegment">The base64url payload segment.</param>
    /// <param name="keyId">The key to sign under.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The compact JWS.</returns>
    private static async Task<string> SignAsync(TestHostShell host, string headerSegment, string payloadSegment, KeyId keyId, CancellationToken cancellationToken)
    {
        PrivateKeyMemory signingKey = host.Host("default").SigningKeys[keyId];
        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerSegment}.{payloadSegment}");
        using var signature = await signingKey.SignAsync(signingInput, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return $"{headerSegment}.{payloadSegment}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";
    }
}

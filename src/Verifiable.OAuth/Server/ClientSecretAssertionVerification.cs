using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Client;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The authorization server's check of the MAC a <c>client_secret_jwt</c> client assertion carries (OpenID Connect Core 1.0
/// Section 9): "The HMAC (Hash-based Message Authentication Code) is calculated using the octets of the UTF-8 representation of
/// the client_secret as the shared key." The MAC is recomputed over the assertion's JWS signing input (RFC 7515 Section 5.2)
/// through the same table of RFC 7518 Section 3.2's HMAC algorithms the client's composition MACs under
/// (<see cref="ClientAssertionCredential.OfClientSecret"/>), and compared through the registered <see cref="VerifyHmacDelegate"/>
/// in constant time, so the client and the server share one MAC composition.
/// </summary>
/// <remarks>
/// <para>
/// The check is the signature step of RFC 7523 Section 3 item 9 alone: the caller decides which algorithm the client's
/// registered method admits before any secret is read - an HMAC algorithm never verifies an assertion of a client registered
/// under a key, and a signature algorithm never one of a client registered under a secret - and judges the claims set
/// (<c>iss</c>, <c>sub</c>, <c>aud</c>, <c>exp</c>, <c>jti</c> and its replay) only once the MAC verified, as RFC 7519
/// Section 7.2 validates a JWS before its payload is read.
/// </para>
/// <para>
/// The secret's octets are not owned: the caller keeps the <see cref="PrivateKeyMemory"/> alive, and clears and disposes it.
/// </para>
/// </remarks>
public static class ClientSecretAssertionVerification
{
    /// <summary>
    /// Verifies the MAC of a <c>client_secret_jwt</c> assertion under the client secret and the HMAC algorithm judged: the
    /// algorithm must be one of RFC 7518 Section 3.2's, the secret no shorter than its hash output ("A key of the same size as
    /// the hash output ... or larger MUST be used with this algorithm"), the assertion a compact JWS of three base64url segments
    /// no longer than <see cref="Jws.DefaultMaxJwsLength"/>, and its signature segment the secret's HMAC of its signing input.
    /// Nothing the assertion presents throws: a value of any other shape carries no MAC that verifies.
    /// </summary>
    /// <param name="clientAssertion">The compact JWS the request presented.</param>
    /// <param name="clientSecret">The octets of the UTF-8 representation of the client secret, not owned.</param>
    /// <param name="algorithm">The HMAC algorithm the assertion is judged under, the one its protected header names and the client's registration admits.</param>
    /// <param name="base64UrlDecoder">Decodes the signature segment.</param>
    /// <param name="pool">The pool the decoded signature and the recomputed MAC are rented from.</param>
    /// <param name="context">The operation context, handed to the HMAC function.</param>
    /// <param name="cancellationToken">Cancels the verification.</param>
    /// <returns>
    /// The algorithm the MAC verified under; or the refusal of an algorithm that is no HMAC algorithm
    /// (<see cref="ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac"/>), of a secret shorter than its hash output
    /// (<see cref="ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput"/>), or of an assertion carrying no
    /// MAC the secret verifies (<see cref="ClientAssertionCredentialRefusalReason.MacDoesNotVerify"/>).
    /// </returns>
    public static async ValueTask<Result<string, ClientAssertionCredentialRefusal>> VerifyAsync(
        string clientAssertion,
        PrivateKeyMemory clientSecret,
        string algorithm,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool,
        FrozenDictionary<string, object>? context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientAssertion);
        ArgumentNullException.ThrowIfNull(clientSecret);
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(ClientSecretMac.Of(algorithm) is not ClientSecretMac mac)
        {
            return Result<string, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.AlgorithmIsNotAnHmac,
                Algorithm = algorithm
            });
        }

        var secretOctets = clientSecret.AsReadOnlyMemory();

        if(secretOctets.Length < mac.Length)
        {
            return Result<string, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
            {
                Reason = ClientAssertionCredentialRefusalReason.ClientSecretShorterThanHashOutput,
                Algorithm = mac.Algorithm,
                SecretOctets = secretOctets.Length,
                RequiredOctets = mac.Length
            });
        }

        var refused = Result<string, ClientAssertionCredentialRefusal>.Failure(new ClientAssertionCredentialRefusal
        {
            Reason = ClientAssertionCredentialRefusalReason.MacDoesNotVerify,
            Algorithm = mac.Algorithm
        });

        //RFC 7515 Section 7.1: the compact serialization is three base64url segments joined by periods, and its signing input
        //is the ASCII octets of the first two and the period between them (Section 5.2). A segment outside the alphabet has no
        //such octets, so it carries no MAC this check could recompute.
        if(clientAssertion.Length > Jws.DefaultMaxJwsLength
            || SigningInputLengthOf(clientAssertion) is not int signingInputLength)
        {
            return refused;
        }

        var signatureSegment = clientAssertion.AsSpan(signingInputLength + 1);

        if(signatureSegment.IsEmpty || signatureSegment.ContainsAnyExcept(Base64UrlCharacters))
        {
            return refused;
        }

        IMemoryOwner<byte> presentedMac;

        try
        {
            presentedMac = base64UrlDecoder(signatureSegment, pool);
        }
        catch(FormatException)
        {
            return refused;
        }

        using(presentedMac)
        {
            using var signingInput = pool.Rent(signingInputLength);
            _ = Encoding.ASCII.GetBytes(clientAssertion.AsSpan(0, signingInputLength), signingInput.Memory.Span);

            var verified = await mac.VerifyAsync(
                secretOctets,
                signingInput.Memory[..signingInputLength],
                presentedMac.Memory[..DecodedLengthOf(signatureSegment.Length)],
                pool,
                context,
                cancellationToken).ConfigureAwait(false);

            return verified ? Result<string, ClientAssertionCredentialRefusal>.Success(mac.Algorithm) : refused;
        }
    }


    /// <summary>The characters of the base64url alphabet (RFC 4648 Section 5), unpadded as RFC 7515 Section 2 writes a segment.</summary>
    private static SearchValues<char> Base64UrlCharacters { get; } =
        SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");


    /// <summary>
    /// The length of a compact JWS's signing input - its protected header segment, the period and its payload segment - when the
    /// JWS is three non-empty base64url segments, or <see langword="null"/> when it is not.
    /// </summary>
    /// <param name="compactJws">The compact serialization.</param>
    /// <returns>The signing input's length in characters, each one octet, or <see langword="null"/>.</returns>
    private static int? SigningInputLengthOf(string compactJws)
    {
        var firstPeriod = compactJws.IndexOf('.', StringComparison.Ordinal);
        var lastPeriod = compactJws.LastIndexOf('.', StringComparison.Ordinal);

        if(firstPeriod <= 0 || lastPeriod <= firstPeriod + 1)
        {
            return null;
        }

        var header = compactJws.AsSpan(0, firstPeriod);
        var payload = compactJws.AsSpan(firstPeriod + 1, lastPeriod - firstPeriod - 1);

        return header.ContainsAnyExcept(Base64UrlCharacters) || payload.ContainsAnyExcept(Base64UrlCharacters)
            ? null
            : lastPeriod;
    }


    /// <summary>
    /// The octets an unpadded base64url segment of the given length decodes to: six bits a character, the bits short of a whole
    /// octet at the end dropped.
    /// </summary>
    /// <param name="characters">The segment's length.</param>
    /// <returns>The decoded length.</returns>
    private static int DecodedLengthOf(int characters) => characters * 3 / 4;
}

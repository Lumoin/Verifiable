using System.Collections.Frozen;
using System.Diagnostics;
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
            || ClientAssertionHeaderRules.SigningInputLengthOf(clientAssertion) is not int signingInputLength)
        {
            return refused;
        }

        var signatureSegment = clientAssertion.AsSpan(signingInputLength + 1);

        if(!ClientAssertionHeaderRules.IsSignatureSegment(signatureSegment))
        {
            return refused;
        }

        using var presentedMac = ClientAssertionHeaderRules.DecodedOrNull(signatureSegment, base64UrlDecoder, pool);

        if(presentedMac is null)
        {
            return refused;
        }

        using(var signingInput = pool.Rent(signingInputLength))
        {
            _ = Encoding.ASCII.GetBytes(clientAssertion.AsSpan(0, signingInputLength), signingInput.Memory.Span);

            var verified = await mac.VerifyAsync(
                secretOctets,
                signingInput.Memory[..signingInputLength],
                presentedMac.Memory[..ClientAssertionHeaderRules.DecodedLengthOf(signatureSegment.Length)],
                pool,
                context,
                cancellationToken).ConfigureAwait(false);

            return verified ? Result<string, ClientAssertionCredentialRefusal>.Success(mac.Algorithm) : refused;
        }
    }


    /// <summary>
    /// The authorization server's judgement of a <c>client_secret_jwt</c> assertion before its client's secret is read, by the
    /// rules nothing of the secret decides: the assertion is presented under RFC 7523 Section 2.2's JWT bearer assertion type
    /// (RFC 7521 Section 4.2), its compact form and protected header hold every rule of the shared reading every key source and
    /// method is judged by (<see cref="ClientAssertionHeaderRules.Read"/>: a compact JWS no longer than the verifier reads, a header
    /// of one JSON object naming an algorithm that is not <c>none</c>, and no critical extension listed, RFC 7515 Section 4.1.11),
    /// and the algorithm is one the server accepts such an assertion under - an HMAC algorithm, since
    /// the client's registered method chose that family (<see cref="ClientAssertionFamilies"/>), whatever the header names. An
    /// admitted assertion's MAC is then checked under the secret (<see cref="VerifyAsync"/>) and its claims judged
    /// (<see cref="ClientAssertionClaimRules"/>). Nothing the assertion presents throws.
    /// </summary>
    /// <param name="assertionType">The request's <c>client_assertion_type</c>, or <see langword="null"/> when it carries none.</param>
    /// <param name="clientAssertion">The request's <c>client_assertion</c>.</param>
    /// <param name="accepted">The HMAC algorithms the server accepts a <c>client_secret_jwt</c> assertion under.</param>
    /// <param name="base64UrlDecoder">Decodes the protected header segment.</param>
    /// <param name="headerDeserializer">Reads the protected header's members.</param>
    /// <param name="pool">The pool the decoded header is rented from.</param>
    /// <returns>The algorithm admitted, or the rule refused.</returns>
    public static ClientSecretAssertionHeaderAdmission AdmitHeader(
        string? assertionType,
        string clientAssertion,
        ClientSecretAssertionAlgorithms accepted,
        DecodeDelegate base64UrlDecoder,
        JwtHeaderDeserializer headerDeserializer,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(clientAssertion);
        ArgumentNullException.ThrowIfNull(accepted);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(pool);

        if(assertionType is null || !WellKnownClientAssertionTypes.IsJwtBearer(assertionType))
        {
            return ClientSecretAssertionHeaderAdmission.Refused(ClientSecretAssertionHeaderRefusal.NotJwtBearer);
        }

        var reading = ClientAssertionHeaderRules.Read(clientAssertion, base64UrlDecoder, headerDeserializer, pool);

        if(reading.Refusal is ClientAssertionHeaderRefusal refusal)
        {
            return ClientSecretAssertionHeaderAdmission.Refused(RefusalOf(refusal));
        }

        return reading.Algorithm is { } algorithm && accepted.Accepts(algorithm)
            ? ClientSecretAssertionHeaderAdmission.Admitted(algorithm)
            : ClientSecretAssertionHeaderAdmission.Refused(ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotAccepted);
    }


    /// <summary>The rule a <c>client_secret_jwt</c> assertion breaks for the shared reading's refusal of its header, under the same name.</summary>
    /// <param name="refusal">The shared reading's refusal.</param>
    /// <returns>The rule.</returns>
    /// <exception cref="UnreachableException">The shared reading named a rule this admission names no rule for: the two lists are kept as one.</exception>
    private static ClientSecretAssertionHeaderRefusal RefusalOf(ClientAssertionHeaderRefusal refusal) => refusal switch
    {
        ClientAssertionHeaderRefusal.NotACompactJws => ClientSecretAssertionHeaderRefusal.NotACompactJws,
        ClientAssertionHeaderRefusal.HeaderNotAnObject => ClientSecretAssertionHeaderRefusal.HeaderNotAnObject,
        ClientAssertionHeaderRefusal.SignatureAlgorithmNotNamed => ClientSecretAssertionHeaderRefusal.SignatureAlgorithmNotNamed,
        ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood => ClientSecretAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood,
        _ => throw new UnreachableException($"The shared reading refused a client assertion's header under {refusal}, a rule this admission names no rule for.")
    };
}

/// <summary>
/// The rules a <c>client_secret_jwt</c> assertion breaks before its client's secret is read
/// (<see cref="ClientSecretAssertionVerification.AdmitHeader"/>), each naming one fact about the request, never a value judged.
/// </summary>
public enum ClientSecretAssertionHeaderRefusal
{
    /// <summary>The request's <c>client_assertion_type</c> is not RFC 7523 Section 2.2's JWT bearer assertion type (RFC 7521 Section 4.2).</summary>
    NotJwtBearer,

    /// <summary>
    /// The assertion is not a compact JWS of three non-empty base64url segments (RFC 7515 Section 7.1), or it is longer than the
    /// verifier reads: no valid JWT, which RFC 7523 Section 3.2 answers <c>invalid_client</c>.
    /// </summary>
    NotACompactJws,

    /// <summary>The assertion's protected header is not one JSON object naming each member once (RFC 7515 Section 4).</summary>
    HeaderNotAnObject,

    /// <summary>
    /// The protected header names no signature algorithm: its <c>alg</c> is absent, is no string, is empty, or is <c>none</c> in
    /// any letter case (RFC 7515 Section 4.1.1: the parameter "MUST be present"; RFC 7518 Section 3.6; RFC 8725 Section 3.2).
    /// </summary>
    SignatureAlgorithmNotNamed,

    /// <summary>
    /// The protected header names an algorithm the server accepts no <c>client_secret_jwt</c> assertion under - a signature
    /// algorithm of the other family among them - so no secret is read for it (RFC 8725 Section 3.1).
    /// </summary>
    SignatureAlgorithmNotAccepted,

    /// <summary>
    /// The protected header carries <c>crit</c>, listing extensions the server must understand, and it understands none (RFC 7515
    /// Section 4.1.11; <see cref="ClientAssertionHeaderRefusal.CriticalHeaderParameterNotUnderstood"/>).
    /// </summary>
    CriticalHeaderParameterNotUnderstood
}


/// <summary>
/// The admission of a <c>client_secret_jwt</c> assertion before its client's secret is read
/// (<see cref="ClientSecretAssertionVerification.AdmitHeader"/>): the HMAC algorithm its MAC is to be checked under, or the rule
/// refused.
/// </summary>
public sealed record ClientSecretAssertionHeaderAdmission
{
    /// <summary>Creates an admission.</summary>
    /// <param name="algorithm">The algorithm admitted, or <see langword="null"/> for a refusal.</param>
    /// <param name="refusal">The rule refused, or <see langword="null"/> for an admission.</param>
    private ClientSecretAssertionHeaderAdmission(string? algorithm, ClientSecretAssertionHeaderRefusal? refusal)
    {
        Algorithm = algorithm;
        Refusal = refusal;
    }


    /// <summary>The HMAC algorithm admitted; <see langword="null"/> for a refusal.</summary>
    public string? Algorithm { get; }

    /// <summary>The rule refused; <see langword="null"/> for an admission.</summary>
    public ClientSecretAssertionHeaderRefusal? Refusal { get; }

    /// <summary>Whether the assertion is admitted to the MAC check.</summary>
    public bool IsAdmitted => Algorithm is not null;


    /// <summary>The admission of an assertion under an algorithm.</summary>
    /// <param name="algorithm">The HMAC algorithm.</param>
    /// <returns>The admission.</returns>
    public static ClientSecretAssertionHeaderAdmission Admitted(string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        return new ClientSecretAssertionHeaderAdmission(algorithm, refusal: null);
    }


    /// <summary>The refusal of an assertion under a rule.</summary>
    /// <param name="refusal">The rule.</param>
    /// <returns>The refusal.</returns>
    public static ClientSecretAssertionHeaderAdmission Refused(ClientSecretAssertionHeaderRefusal refusal) => new(algorithm: null, refusal);
}

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// Mint and verify for the DIDComm <c>from_prior</c> header — the DID Rotation JWT that notifies a
/// recipient the sender has switched from a prior DID to a new one, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#did-rotation">DIDComm Messaging v2.1 §DID Rotation</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>from_prior</c> value is a compact JWT whose <c>iss</c> is the prior DID and <c>sub</c> is the
/// new DID, signed by a key authorized for the <c>authentication</c> relationship of the prior DID.
/// Minting produces that JWT and assigns it to <see cref="DidCommMessage.FromPrior"/>; verification —
/// invoked by every unpack path that recovers a plaintext — resolves the prior DID, requires the
/// signing <c>kid</c> be authorized for <c>authentication</c>, and checks the signature with the key
/// the resolved verification method specifies, never the JWT <c>alg</c> header (algorithm-substitution
/// defense). Verification is fail-closed: it returns a typed outcome and never throws to the caller.
/// </para>
/// <para>
/// The JWT engine stays in <c>Verifiable.JCose</c> (<see cref="UnsignedJwt"/> +
/// <see cref="JwtSigningExtensions.SignAsync"/> for mint, <see cref="JwsParsing.ParseCompact"/> for
/// verify); this project orchestrates the rotation semantics and receives the (de)serialization as
/// injected named delegates, keeping it free of <see cref="System.Text.Json"/>.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The JwsMessage minted for the from_prior JWT is disposed via 'using' once serialized to compact form; the UnverifiedJwsMessage parsed on verify is disposed via 'using'.")]
public static class DidCommFromPriorExtensions
{
    //The Unix epoch, used to convert the injected rotation DateTimeOffset to the iat claim's seconds.
    private static readonly DateTimeOffset UnixEpoch = DateTimeOffset.UnixEpoch;

    //An upper bound on the from_prior compact JWS length. A rotation JWT carries a handful of claims, so this
    //is generous; it bounds the compact-JWS parse + base64url decode on the signed path, where (unlike the
    //encrypted path) the surrounding message is not wire-capped.
    private const int MaximumFromPriorLength = 16 * 1024;


    /// <summary>
    /// Mints the <c>from_prior</c> DID Rotation JWT for <paramref name="message"/> and assigns it to
    /// <see cref="DidCommMessage.FromPrior"/>, resolving the signing function from
    /// <paramref name="priorSigningKey"/>'s <see cref="SensitiveData.Tag"/> via the
    /// <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/>.
    /// </summary>
    /// <param name="message">The rotation message. Its <c>from</c> is the new DID (and the JWT <c>sub</c>), or absent for rotate-to-nothing.</param>
    /// <param name="priorDid">The prior DID — the JWT <c>iss</c>.</param>
    /// <param name="priorKid">The signing key id — a DID URL with a fragment whose base DID equals <paramref name="priorDid"/>.</param>
    /// <param name="priorSigningKey">The prior DID's authentication signing key. Its tag selects the signing function and the JWS <c>alg</c>.</param>
    /// <param name="rotationTimestamp">The datetime of the DID rotation. Becomes the JWT <c>iat</c> (DIDComm v2.1 §DID Rotation: iat MUST be the rotation datetime, not the message's).</param>
    /// <param name="headerSerializer">Serializer for the JWT protected header.</param>
    /// <param name="payloadSerializer">Serializer for the JWT payload.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder.</param>
    /// <param name="memoryPool">Memory pool for the signing-input and signature buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static ValueTask PackFromPriorAsync(
        this DidCommMessage message,
        string priorDid,
        string priorKid,
        PrivateKeyMemory priorSigningKey,
        DateTimeOffset rotationTimestamp,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(priorSigningKey);

        CryptoAlgorithm algorithm = priorSigningKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = priorSigningKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate =
            CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        return message.PackFromPriorAsync(
            priorDid,
            priorKid,
            priorSigningKey,
            rotationTimestamp,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            signingDelegate,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Mints the <c>from_prior</c> DID Rotation JWT using an explicit <see cref="SigningDelegate"/>. The
    /// registry-resolving overload above delegates here after resolving the function from
    /// <paramref name="priorSigningKey"/>'s <see cref="SensitiveData.Tag"/>.
    /// </summary>
    /// <inheritdoc cref="PackFromPriorAsync(DidCommMessage, string, string, PrivateKeyMemory, DateTimeOffset, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, MemoryPool{byte}, CancellationToken)"/>
    /// <param name="signingDelegate">The signing function to use.</param>
    public static async ValueTask PackFromPriorAsync(
        this DidCommMessage message,
        string priorDid,
        string priorKid,
        PrivateKeyMemory priorSigningKey,
        DateTimeOffset rotationTimestamp,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        SigningDelegate signingDelegate,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(priorDid);
        ArgumentException.ThrowIfNullOrEmpty(priorKid);
        ArgumentNullException.ThrowIfNull(priorSigningKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(signingDelegate);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The signing kid MUST be a DID URL with a fragment whose base DID is the prior DID (iss). The
        //recipient enforces the same MUST on verify; enforcing it here keeps the producer from emitting a
        //rotation every conformant recipient would reject.
        if(!DidUrl.TryParse(priorKid, out DidUrl? priorKidUrl) || priorKidUrl.Fragment is null || priorKidUrl.BaseDid is not string priorKidDid)
        {
            throw new ArgumentException("The from_prior kid MUST be a DID URL carrying a fragment.", nameof(priorKid));
        }

        if(!string.Equals(priorKidDid, priorDid, StringComparison.Ordinal))
        {
            throw new ArgumentException("The from_prior kid's base DID MUST equal the prior DID (iss).", nameof(priorKid));
        }

        //The new DID is the message `from`: a normal rotation carries it (and it becomes the JWT sub),
        //while a rotate-to-nothing omits both `from` and sub (DIDComm v2.1 §Ending a Relationship).
        string? newDid = message.From;

        if(newDid is not null && string.Equals(newDid, priorDid, StringComparison.Ordinal))
        {
            throw new ArgumentException("A rotation MUST move to a different DID — sub (the new DID) MUST NOT equal iss (the prior DID).", nameof(message));
        }

        var payload = new JwtPayload
        {
            [WellKnownJwtClaimNames.Iss] = priorDid,
            [WellKnownJwtClaimNames.Iat] = (rotationTimestamp - UnixEpoch).Ticks / TimeSpan.TicksPerSecond
        };

        //sub is the new DID for a normal rotation; it is omitted for rotate-to-nothing.
        if(newDid is not null)
        {
            payload[WellKnownJwtClaimNames.Sub] = newDid;
        }

        //The protected header carries only typ, the key-derived alg, and kid — the shape both DIDComm
        //reference impls emit (didcomm-python: {alg, kid}; didcomm-rust reads typ/alg/kid). crv is a JWK
        //member, not a JWS header parameter, and verify resolves the algorithm from the prior-DID key, not
        //the header — so a crv here would be dead and, for a non-Ed25519 prior key, inconsistent with alg.
        var header = new JwtHeader
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt,
            [WellKnownJwkMemberNames.Alg] = CryptoFormatConversions.DefaultTagToJwaConverter(priorSigningKey.Tag),
            [WellKnownJwkMemberNames.Kid] = priorKid
        };

        var unsigned = new UnsignedJwt(header, payload);

        using JwsMessage jws = await unsigned.SignAsync(
            priorSigningKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            signingDelegate,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        message.FromPrior = JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// Verifies the <c>from_prior</c> DID Rotation JWT carried by <paramref name="message"/> against the
    /// resolved prior DID, mirroring the signed-message resolve→key block with two deltas: the <c>kid</c>
    /// is read from the integrity-protected header, and it is gated on the prior DID's
    /// <c>authentication</c> relationship.
    /// </summary>
    /// <remarks>
    /// The check sequence is, in order: parse the compact JWS; require <c>typ</c> == <c>JWT</c>; require
    /// <c>kid</c> be a DID URL with a fragment; read <c>iss</c>/<c>sub</c> from the payload; require
    /// <c>kid</c>'s base DID == <c>iss</c> and <c>iss</c> != <c>sub</c>; require <c>sub</c> == the message
    /// <c>from</c> (the new DID) for a normal rotation, or both absent for rotate-to-nothing; resolve the
    /// prior DID (<c>iss</c>) — not the sender — and require the <c>kid</c> be authorized for
    /// <c>authentication</c>; and only then verify the signature with the key the resolved verification
    /// method specifies. Returns a fail-closed outcome; never throws.
    /// </remarks>
    /// <param name="message">The (already plaintext-recovered) message carrying the <c>from_prior</c> header. Its <c>from</c> is the new DID.</param>
    /// <param name="didResolver">Resolver for the prior DID. Reuses the app-side resolution seam.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="payloadDeserializer">Deserializer for the JWT payload claims.</param>
    /// <param name="headerDeserializer">Deserializer for the JWT protected header.</param>
    /// <param name="base64UrlDecoder">Base64Url decoder for the JWT segments.</param>
    /// <param name="base64UrlEncoder">Base64Url encoder, used to reconstruct the JWS signing input.</param>
    /// <param name="memoryPool">Memory pool for parsing and the signing-input buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed rotation-verification outcome.</returns>
    internal static async ValueTask<FromPriorVerificationOutcome> VerifyFromPriorAsync(
        DidCommMessage message,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        JwtClaimsDeserializer payloadDeserializer,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        //Bound the from_prior JWS length before parsing. On the encrypted path the envelope already bounds it;
        //on the signed path the message is not wire-capped, so an oversized from_prior is rejected here rather
        //than driving an unbounded compact-JWS parse + base64url decode.
        if(message.FromPrior!.Length > MaximumFromPriorLength)
        {
            return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
        }

        //Parse the compact from_prior JWS. A malformed compact serialization (or a JSON-malformed header)
        //is a malformed rotation JWT — fail closed, never throw to the caller.
        UnverifiedJwsMessage parsed;
        try
        {
            parsed = JwsParsing.ParseCompact(message.FromPrior!, base64UrlDecoder, headerDeserializer, memoryPool);
        }
        catch(Exception ex) when(ex is FormatException or System.Text.Json.JsonException)
        {
            return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
        }

        using(parsed)
        {
            UnverifiedJwsSignature jwsSignature = parsed.Signatures[0];

            //typ MUST be "JWT" (DIDComm v2.1 §DID Rotation JWT header).
            if(!(jwsSignature.ProtectedHeader.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typValue)
                && typValue is string typ
                && string.Equals(typ, WellKnownJwkValues.TypeJwt, StringComparison.Ordinal)))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
            }

            //The kid is read from the integrity-protected header and MUST be a DID URL with a fragment
            //(DIDComm v2.1 §DID Rotation: the validity is checked against the key indicated by kid).
            if(!(jwsSignature.ProtectedHeader.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue)
                && kidValue is string kid
                && !string.IsNullOrEmpty(kid)))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
            }

            if(!DidUrl.TryParse(kid, out DidUrl? kidUrl) || kidUrl.Fragment is null || kidUrl.BaseDid is not string kidDid)
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
            }

            //iss / sub come from the payload (a compact JWT). A wire-type or JSON-malformed payload fails
            //closed.
            JwtPayload payload;
            try
            {
                payload = payloadDeserializer(parsed.Payload.Span);
            }
            catch(Exception ex) when(ex is FormatException or ArgumentException or NotSupportedException)
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
            }

            if(!(payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issValue) && issValue is string iss && !string.IsNullOrEmpty(iss)))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationJwtMalformed);
            }

            string? sub = payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subValue) ? subValue as string : null;

            //The rotation iat (issued-at, Unix epoch seconds) is surfaced, not gated: the library cannot
            //enforce the "ignore pre-rotation messages" ordering statelessly, so it hands the rotation instant
            //to the application (DIDComm v2.1 §DID Rotation). The JSON deserializer may box a numeric claim as
            //any CLR numeric type, so all are accepted; a non-numeric iat is ignored.
            long? iat = payload.TryGetValue(WellKnownJwtClaimNames.Iat, out object? iatValue)
                ? iatValue switch
                {
                    long l => l,
                    int i => i,
                    decimal m => (long)m,
                    double d => (long)d,
                    _ => (long?)null
                }
                : null;

            //kid's base DID MUST equal iss, and a rotation MUST move to a different DID (iss != sub).
            if(!string.Equals(kidDid, iss, StringComparison.Ordinal))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationIssuerKidMismatch);
            }

            if(sub is not null && string.Equals(iss, sub, StringComparison.Ordinal))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationIssuerKidMismatch);
            }

            //sub MUST be the message `from` (the new DID) for a normal rotation, or both absent for
            //rotate-to-nothing (DIDComm v2.1 §DID Rotation / §Ending a Relationship).
            string? from = string.IsNullOrEmpty(message.From) ? null : message.From;

            if(!string.Equals(sub, from, StringComparison.Ordinal))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationSubjectMismatch);
            }

            //Resolve the PRIOR DID (iss), not the sender, and require the kid be authorized for the
            //authentication relationship before trusting the signature (DIDComm v2.1 §DID Rotation:
            //"The indicated key MUST be authorized in the DID Document of the prior DID (iss).").
            DidResolutionResult resolution = await didResolver
                .ResolveAsync(iss, exchangeContext, options: null, cancellationToken)
                .ConfigureAwait(false);

            if(!resolution.IsSuccessful || resolution.Document is null)
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.PriorDidResolutionFailed);
            }

            if(!DidCommSignedExtensions.TryResolveAuthenticationKey(resolution.Document, kid, out VerificationMethod? verificationMethod))
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationSignerNotAuthorized);
            }

            //Reconstruct the JWS signing input (ASCII(b64url(protected) "." b64url(payload))) and verify
            //with the key resolved from the verification method. The algorithm is taken from that key via
            //the registry, never from the claimed `alg`, defeating algorithm-substitution.
            using IMemoryOwner<byte> signingInputOwner = RentSigningInput(
                jwsSignature.Protected, base64UrlEncoder(parsed.Payload.Span), memoryPool, out int signingInputLength);

            //The verifying key is reached via the attacker-influenced kid; a structurally malformed or
            //unsupported method makes the converter (or registry/verify) throw. Map that to a fail-closed
            //result rather than letting it escape — a cryptographically wrong (but well-formed) signature is
            //reported as not valid below, not as a thrown exception.
            bool isValid;
            try
            {
                (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) keyMaterial =
                    VerificationMethodCryptoConversions.DefaultConverter(verificationMethod!, memoryPool);

                using(keyMaterial.KeyMaterial)
                {
                    VerificationDelegate verificationDelegate =
                        CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(keyMaterial.Algorithm, keyMaterial.Purpose);

                    isValid = await verificationDelegate(
                        signingInputOwner.Memory[..signingInputLength],
                        jwsSignature.SignatureBytes.Memory,
                        keyMaterial.KeyMaterial.Memory,
                        context: null,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                }
            }
            catch(Exception ex) when(ex is ArgumentException or FormatException or NotSupportedException or CryptographicException)
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationSignerNotAuthorized);
            }

            if(!isValid)
            {
                return FromPriorVerificationOutcome.Failed(DidCommRotationError.RotationSignatureInvalid);
            }

            return FromPriorVerificationOutcome.Verified(iss, kid, iat);
        }
    }


    //Rents a pooled buffer and writes the JWS signing input ("<segment1>.<segment2>" as ASCII octets per
    //RFC 7515 §5.1) directly into it. Both segments are base64url-encoded (already ASCII), so byte length
    //equals char length. The returned owner must be disposed by the caller; the slice [..signingInputLength]
    //holds the content. The `checked` block makes the int-overflow assumption explicit.
    private static IMemoryOwner<byte> RentSigningInput(
        string segment1,
        string segment2,
        MemoryPool<byte> pool,
        out int signingInputLength)
    {
        signingInputLength = checked(segment1.Length + 1 + segment2.Length);
        IMemoryOwner<byte> owner = pool.Rent(signingInputLength);
        Span<byte> span = owner.Memory.Span[..signingInputLength];
        Encoding.ASCII.GetBytes(segment1, span);
        span[segment1.Length] = (byte)'.';
        Encoding.ASCII.GetBytes(segment2, span[(segment1.Length + 1)..]);

        return owner;
    }
}


/// <summary>
/// The reason a <c>from_prior</c> DID Rotation JWT failed verification, or <see cref="None"/> when it
/// verified. The canonical rotation rejection vocabulary the shared verify helper returns; each unpack
/// result type maps these onto its own error enum (DIDComm v2.1 §DID Rotation).
/// </summary>
internal enum DidCommRotationError
{
    /// <summary>The rotation JWT verified; the new DID may be trusted for further communication.</summary>
    None = 0,

    /// <summary>The <c>from_prior</c> is not a parseable compact JWS, or its <c>typ</c> is not <c>JWT</c>, or its <c>kid</c> is not a DID URL with a fragment, or its payload is malformed.</summary>
    RotationJwtMalformed,

    /// <summary>The JWT <c>sub</c> does not match the message <c>from</c> (the new DID), or the rotate-to-nothing presence rule is violated.</summary>
    RotationSubjectMismatch,

    /// <summary>The <c>kid</c>'s base DID does not equal <c>iss</c>, or <c>iss</c> equals <c>sub</c> (a rotation MUST move to a different DID).</summary>
    RotationIssuerKidMismatch,

    /// <summary>The prior DID (<c>iss</c>) could not be resolved to a DID document.</summary>
    PriorDidResolutionFailed,

    /// <summary>The <c>kid</c> is not authorized for the prior DID's <c>authentication</c> relationship, its verification method is missing, or its key type is unsupported.</summary>
    RotationSignerNotAuthorized,

    /// <summary>The cryptographic signature did not verify against the resolved prior-DID key.</summary>
    RotationSignatureInvalid
}


/// <summary>
/// The outcome of verifying a <c>from_prior</c> DID Rotation JWT — the prior DID and issuer <c>kid</c>
/// when <see cref="IsVerified"/> is <see langword="true"/>, or an <see cref="Error"/> reason otherwise.
/// </summary>
/// <remarks>
/// Internal: produced only by <see cref="DidCommFromPriorExtensions.VerifyFromPriorAsync"/> and consumed
/// only by the unpack wiring sites, which fold its verified fields into the public unpack result types
/// through their existing internal mint factories. The new DID is the message <c>from</c>, already
/// carried by the recovered plaintext, so only the prior DID and issuer kid are surfaced here.
/// </remarks>
internal readonly struct FromPriorVerificationOutcome
{
    private FromPriorVerificationOutcome(bool isVerified, string? priorDid, string? issuerKid, long? iat, DidCommRotationError error)
    {
        IsVerified = isVerified;
        PriorDid = priorDid;
        IssuerKid = issuerKid;
        Iat = iat;
        Error = error;
    }


    /// <summary>Whether the rotation JWT verified and every rotation MUST passed.</summary>
    public bool IsVerified { get; }

    /// <summary>The verified prior DID (the JWT <c>iss</c>), or <see langword="null"/> when verification failed.</summary>
    public string? PriorDid { get; }

    /// <summary>The verified issuer key id (the JWT <c>kid</c>), or <see langword="null"/> when verification failed.</summary>
    public string? IssuerKid { get; }

    /// <summary>The rotation JWT's <c>iat</c> (issued-at, Unix epoch seconds) when present, else <see langword="null"/>.</summary>
    public long? Iat { get; }

    /// <summary>The reason verification failed, or <see cref="DidCommRotationError.None"/> when it succeeded.</summary>
    public DidCommRotationError Error { get; }


    //Mints a verified outcome carrying the prior DID, issuer kid, and the rotation iat (when present).
    internal static FromPriorVerificationOutcome Verified(string priorDid, string issuerKid, long? iat)
    {
        return new FromPriorVerificationOutcome(true, priorDid, issuerKid, iat, DidCommRotationError.None);
    }


    //Mints a failed outcome carrying the rejection reason.
    internal static FromPriorVerificationOutcome Failed(DidCommRotationError error)
    {
        return new FromPriorVerificationOutcome(false, priorDid: null, issuerKid: null, iat: null, error);
    }
}

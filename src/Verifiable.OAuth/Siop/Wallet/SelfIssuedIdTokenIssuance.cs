using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Dpop;

namespace Verifiable.OAuth.Siop.Wallet;

/// <summary>
/// Issues a Self-Issued ID Token — the wallet (Self-Issued OP) side of
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11">SIOPv2 §11</see>.
/// The Relying Party counterpart is <see cref="SelfIssuedIdTokenValidation"/>.
/// </summary>
/// <remarks>
/// <para>
/// The token is signed with key material under the End-User's control and is
/// self-issued by construction: <c>iss</c> equals <c>sub</c>. One method per
/// SIOPv2 §8 Subject Syntax Type:
/// <see cref="IssueWithJwkThumbprintAsync"/> derives <c>sub</c> from the subject
/// key's RFC 7638 thumbprint as an RFC 9278 Thumbprint URI and embeds the bare
/// public key as <c>sub_jwk</c>; <see cref="IssueWithDecentralizedIdentifierAsync"/>
/// uses the caller's DID as the subject, names the DID Document verification
/// method in the header <c>kid</c>, and omits <c>sub_jwk</c> (§8: MUST NOT be
/// present).
/// </para>
/// <para>
/// Signing flows through <see cref="JwtSigningExtensions.SignAsync"/> with the
/// JWS <c>alg</c> derived from the subject key's <see cref="Tag"/> via
/// <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/> — the standard
/// JCose composition shared with KB-JWT issuance and JAR signing. The JWK
/// projection and thumbprint reuse <see cref="DpopJwkUtilities"/>, the library's
/// RFC 7638 helpers; nothing about them is DPoP-specific.
/// </para>
/// </remarks>
[DebuggerDisplay("SelfIssuedIdTokenIssuance")]
public static class SelfIssuedIdTokenIssuance
{
    /// <summary>
    /// Issues a compact-serialised Self-Issued ID Token of the JWK Thumbprint
    /// Subject Syntax Type: <c>iss</c> and <c>sub</c> are the RFC 9278 Thumbprint
    /// URI of <paramref name="subjectPublicKey"/>, which rides in <c>sub_jwk</c>.
    /// </summary>
    /// <param name="subjectPrivateKey">The End-User's signing key. The JWS <c>alg</c> is derived from its <see cref="Tag"/>.</param>
    /// <param name="subjectPublicKey">The public half of the same key pair; projected to <c>sub_jwk</c> and hashed into <c>sub</c>.</param>
    /// <param name="audience">The <c>aud</c> claim value — the RP's Client ID from the Authorization Request.</param>
    /// <param name="nonce">The <c>nonce</c> from the Authorization Request, echoed per §11.1.</param>
    /// <param name="issuedAt">The <c>iat</c> instant.</param>
    /// <param name="lifetime">The validity period; <c>exp</c> is <paramref name="issuedAt"/> plus this.</param>
    /// <param name="base64UrlEncoder">Base64url encoder, used for the thumbprint and compact JWS serialisation.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised Self-Issued ID Token.</returns>
    public static async ValueTask<string> IssueWithJwkThumbprintAsync(
        PrivateKeyMemory subjectPrivateKey,
        PublicKeyMemory subjectPublicKey,
        string audience,
        string nonce,
        DateTimeOffset issuedAt,
        TimeSpan lifetime,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subjectPrivateKey);
        ArgumentNullException.ThrowIfNull(subjectPublicKey);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(subjectPrivateKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            subjectPublicKey, algorithm, base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, base64UrlEncoder, memoryPool);
        string subject = SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;

        //Projected to object values to match the payload dictionary's JSON
        //converter, which writes object-valued maps but not the
        //variance-incompatible IReadOnlyDictionary<string, string>.
        Dictionary<string, object> subJwk = new(jwk.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in jwk)
        {
            subJwk[member.Key] = member.Value;
        }

        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };

        return await IssueAsync(
            subjectPrivateKey, header, subject, subJwk, audience, nonce, issuedAt, lifetime,
            base64UrlEncoder, headerSerializer, payloadSerializer, memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a compact-serialised Self-Issued ID Token of the Decentralized
    /// Identifier Subject Syntax Type: <c>iss</c> and <c>sub</c> are
    /// <paramref name="did"/>, the header <c>kid</c> names the DID Document
    /// verification method backing <paramref name="subjectPrivateKey"/>, and
    /// <c>sub_jwk</c> is omitted per §8.
    /// </summary>
    /// <param name="subjectPrivateKey">The End-User's signing key. The JWS <c>alg</c> is derived from its <see cref="Tag"/>.</param>
    /// <param name="did">The End-User's DID — the <c>iss</c>/<c>sub</c> claim value. The RP validates against the resolved DID Document.</param>
    /// <param name="keyId">The DID Document verification method id for the header <c>kid</c> (e.g. <c>did:example:123#key-1</c>), so the RP selects the right key among multiple verification methods (§11.1).</param>
    /// <param name="audience">The <c>aud</c> claim value — the RP's Client ID from the Authorization Request.</param>
    /// <param name="nonce">The <c>nonce</c> from the Authorization Request, echoed per §11.1.</param>
    /// <param name="issuedAt">The <c>iat</c> instant.</param>
    /// <param name="lifetime">The validity period; <c>exp</c> is <paramref name="issuedAt"/> plus this.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="headerSerializer">Serialises the protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the payload claims to UTF-8 JSON bytes.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised Self-Issued ID Token.</returns>
    public static async ValueTask<string> IssueWithDecentralizedIdentifierAsync(
        PrivateKeyMemory subjectPrivateKey,
        string did,
        string keyId,
        string audience,
        string nonce,
        DateTimeOffset issuedAt,
        TimeSpan lifetime,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subjectPrivateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(did);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);

        if(!did.StartsWith(SiopSubjectSyntaxTypes.DidPrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The subject must be a DID ('{SiopSubjectSyntaxTypes.DidPrefix}…') for the Decentralized Identifier Subject Syntax Type.",
                nameof(did));
        }

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(subjectPrivateKey.Tag);
        JwtHeader header = new(capacity: 3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt,
            [WellKnownJwkMemberNames.Kid] = keyId
        };

        return await IssueAsync(
            subjectPrivateKey, header, did, subJwk: null, audience, nonce, issuedAt, lifetime,
            base64UrlEncoder, headerSerializer, payloadSerializer, memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    private static async ValueTask<string> IssueAsync(
        PrivateKeyMemory subjectPrivateKey,
        JwtHeader header,
        string subject,
        Dictionary<string, object>? subJwk,
        string audience,
        string nonce,
        DateTimeOffset issuedAt,
        TimeSpan lifetime,
        EncodeDelegate base64UrlEncoder,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        ArgumentException.ThrowIfNullOrWhiteSpace(nonce);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        //§11.1: an ID Token is self-issued when iss equals sub — composed here by
        //construction so a caller cannot produce a structurally non-self-issued token.
        JwtPayload payload = new(capacity: 7)
        {
            [WellKnownJwtClaimNames.Iss] = subject,
            [WellKnownJwtClaimNames.Sub] = subject,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Nonce] = nonce,
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = issuedAt.Add(lifetime).ToUnixTimeSeconds()
        };

        if(subJwk is not null)
        {
            payload[WellKnownJwtClaimNames.SubJwk] = subJwk;
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            subjectPrivateKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }
}

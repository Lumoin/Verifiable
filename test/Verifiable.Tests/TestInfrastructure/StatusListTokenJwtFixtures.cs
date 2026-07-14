using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.StatusList;
using Verifiable.OAuth;
using Verifiable.Tests.DataIntegrity;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds and reads the Token Status List JWT wire form
/// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-13.html#section-5.1">draft-ietf-oauth-status-list §5.1</see>)
/// for real-wire capstones: a <see cref="StatusListToken"/>'s registered claims (<c>sub</c>/<c>iat</c>) plus the
/// embedded <c>status_list</c> object round trip through a genuine JWS compact serialization, signed and
/// verified with the library's own JOSE seams (<see cref="UnsignedJwt"/>, <see cref="JwsSerialization"/>,
/// <see cref="Jws"/>, <see cref="JwtClaimsJson"/>).
/// </summary>
internal static class StatusListTokenJwtFixtures
{
    /// <summary>The shared memory pool backing every pooled carrier this fixture allocates.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Issues a compact-serialized JWT Status List Token: <c>sub</c>/<c>iat</c> from <paramref name="token"/>
    /// plus the embedded <c>status_list</c> object (<c>bits</c>/<c>lst</c>), signed by
    /// <paramref name="issuerPrivate"/> with the <c>typ</c> header
    /// <see cref="StatusListMediaTypes.StatusListJwt"/>.
    /// </summary>
    /// <param name="token">The Status List Token to serialize and sign.</param>
    /// <param name="issuerPrivate">The issuer's signing key; its <see cref="Tag"/> resolves the JWA algorithm and the signing function.</param>
    /// <param name="keyId">The <c>kid</c> header value identifying the signing key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWT (<c>header.payload.signature</c>).</returns>
    public static async Task<string> IssueJwtAsync(
        StatusListToken token, PrivateKeyMemory issuerPrivate, string keyId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(issuerPrivate);

        var statusListClaim = new Dictionary<string, object>
        {
            [StatusListJsonConstants.Bits] = (long)token.StatusList.BitSize,
            [StatusListJsonConstants.List] = TestSetup.Base64UrlEncoder(token.StatusList.Compress())
        };

        JwtPayload payload = new(3)
        {
            [WellKnownJwtClaimNames.Sub] = token.Subject,
            [WellKnownJwtClaimNames.Iat] = token.IssuedAt.ToUnixTimeSeconds(),
            [StatusListJsonConstants.StatusList] = statusListClaim
        };

        UnsignedJwt unsigned = UnsignedJwt.ForSigning(issuerPrivate, keyId, payload, StatusListMediaTypes.StatusListJwt);
        using JwsMessage jws = await unsigned.SignAsync(
            issuerPrivate,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Fetches a Status List Token JWT over a real HTTP GET (the
    /// <see cref="StatusListMediaTypes.StatusListJwtContentType"/> media type carried in <c>Accept</c>), verifies
    /// its JWS signature against <paramref name="issuerPublic"/>, and parses the verified claims into a
    /// <see cref="StatusListToken"/>. A failed signature check throws — an unverified list is never handed back,
    /// mirroring the "already verified" contract of <see cref="ResolveVerifiedStatusListTokenDelegate"/>.
    /// </summary>
    /// <param name="httpClient">The HTTP client used for the fetch.</param>
    /// <param name="uri">The Status List Token's absolute URI.</param>
    /// <param name="issuerPublic">The issuer's public key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The response's <c>Content-Type</c> and the verified, parsed token. The caller disposes the token's <see cref="StatusListToken.StatusList"/>.</returns>
    public static async Task<(string? ContentType, StatusListToken Token)> FetchAndParseJwtAsync(
        HttpClient httpClient, string uri, PublicKeyMemory issuerPublic, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(issuerPublic);

        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(StatusListMediaTypes.StatusListJwtContentType));

        using HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        string? contentType = response.Content.Headers.ContentType?.ToString();
        string compactJwt = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        bool isValid = await Jws.VerifyAsync(compactJwt, TestSetup.Base64UrlDecoder, Pool, issuerPublic, cancellationToken).ConfigureAwait(false);
        if(!isValid)
        {
            throw new InvalidOperationException("The fetched Status List Token's JWS signature did not verify.");
        }

        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(parts[1], Pool);
        JwtPayload claims = JwtClaimsJson.PayloadDeserializer(payloadOwner.Memory.Span);

        //DictionaryStringObjectJsonConverter.ExtractValue boxes every integer-valued JWT/CWT claim as
        //System.Int64 (Utf8JsonReader.TryGetInt64 succeeds for both iat and bits here), falling back to
        //System.Decimal only for a value too large or fractional to fit a long.
        string subject = (string)claims[WellKnownJwtClaimNames.Sub];
        long issuedAtSeconds = (long)claims[WellKnownJwtClaimNames.Iat];
        var statusListClaim = (Dictionary<string, object>)claims[StatusListJsonConstants.StatusList];
        var bitSize = (StatusListBitSize)(long)statusListClaim[StatusListJsonConstants.Bits];
        string compressed = (string)statusListClaim[StatusListJsonConstants.List];

        using IMemoryOwner<byte> compressedOwner = TestSetup.Base64UrlDecoder(compressed, Pool);
        StatusListType statusList = StatusListType.FromCompressed(compressedOwner.Memory.Span, bitSize, Pool, BitOrder.LeastSignificantFirst);

        var token = new StatusListToken(subject, DateTimeOffset.FromUnixTimeSeconds(issuedAtSeconds), statusList);

        return (contentType, token);
    }


    /// <summary>
    /// Deserializes <paramref name="template"/> as a <see cref="VerifiableCredential"/> and patches its
    /// first credential subject's <see cref="BitstringStatusListConstants.EncodedListProperty"/> to
    /// <paramref name="encodedList"/> — the VC-DM 2.0 Bitstring Status List credential wire shape, distinct
    /// from this class's JWT/CWT Status List Token shape above.
    /// </summary>
    /// <param name="template">The status list credential's fixed JSON-LD template text.</param>
    /// <param name="encodedList">The base64url, zlib-compressed bitstring to install as <c>encodedList</c>.</param>
    /// <returns>The patched credential.</returns>
    public static VerifiableCredential BuildStatusListCredential(string template, string encodedList)
    {
        var credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(template, CredentialSecuringMaterial.JsonOptions)!;
        credential.CredentialSubject![0].AdditionalData![BitstringStatusListConstants.EncodedListProperty] = encodedList;

        return credential;
    }
}

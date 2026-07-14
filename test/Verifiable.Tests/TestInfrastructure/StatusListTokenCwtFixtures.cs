using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Builds and reads the Token Status List CWT wire form
/// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-13.html#section-5.2">draft-ietf-oauth-status-list §5.2</see>)
/// for real-wire capstones: a <see cref="StatusListToken"/> round trips as a COSE_Sign1 whose payload is the CBOR
/// Claims Set <see cref="StatusListTokenCborConverter"/> reads and writes.
/// </summary>
internal static class StatusListTokenCwtFixtures
{
    /// <summary>The shared memory pool backing every pooled carrier this fixture allocates.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The CBOR converter reading and writing the Status List Token Claims Set (§5.2).</summary>
    private static StatusListTokenCborConverter Converter { get; } = new(BaseMemoryPool.Shared);


    /// <summary>
    /// Issues a tagged COSE_Sign1 CWT Status List Token: the CBOR Claims Set
    /// (<see cref="StatusListTokenCborConverter"/>) signed by <paramref name="issuerPrivate"/>.
    /// </summary>
    /// <param name="token">The Status List Token to serialize and sign.</param>
    /// <param name="issuerPrivate">The issuer's signing key; its <see cref="Tag"/> resolves the COSE algorithm and the signing function.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The tagged COSE_Sign1 CBOR bytes.</returns>
    public static async Task<byte[]> IssueCwtAsync(StatusListToken token, PrivateKeyMemory issuerPrivate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(issuerPrivate);

        byte[] payload = EncodeClaims(token);

        var headerMap = new Dictionary<int, object> { [CoseHeaderParameters.Alg] = WellKnownCoseAlgorithms.Es256 };
        EncodedCoseProtectedHeader protectedHeader = EncodedCoseProtectedHeader.FromBytes(CoseSerialization.SerializeProtectedHeader(headerMap), Pool);

        using CoseSign1Message message = await Verifiable.JCose.Cose.SignAsync(
            protectedHeader,
            unprotectedHeader: null,
            payload,
            CoseSerialization.BuildSigStructure,
            issuerPrivate,
            Pool,
            cancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 encoded = CoseSerialization.SerializeCoseSign1(message, Pool);

        return encoded.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Fetches a Status List Token CWT over a real HTTP GET (the
    /// <see cref="StatusListMediaTypes.StatusListCwt"/> media type carried in <c>Accept</c>), verifies its
    /// COSE_Sign1 signature against <paramref name="issuerPublic"/>, and parses the verified Claims Set into a
    /// <see cref="StatusListToken"/>. A failed signature check throws — an unverified list is never handed back.
    /// </summary>
    /// <param name="httpClient">The HTTP client used for the fetch.</param>
    /// <param name="uri">The Status List Token's absolute URI.</param>
    /// <param name="issuerPublic">The issuer's public key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The response's <c>Content-Type</c> and the verified, parsed token. The caller disposes the token's <see cref="StatusListToken.StatusList"/>.</returns>
    public static async Task<(string? ContentType, StatusListToken Token)> FetchAndParseCwtAsync(
        HttpClient httpClient, string uri, PublicKeyMemory issuerPublic, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(issuerPublic);

        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(StatusListMediaTypes.StatusListCwt));

        using HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        string? contentType = response.Content.Headers.ContentType?.ToString();
        byte[] coseSign1Bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

        using CoseSign1Message message = CoseSerialization.ParseCoseSign1(coseSign1Bytes, Pool);

        bool isValid = await Verifiable.JCose.Cose.VerifyAsync(message, CoseSerialization.BuildSigStructure, issuerPublic, cancellationToken).ConfigureAwait(false);
        if(!isValid)
        {
            throw new InvalidOperationException("The fetched Status List Token's COSE_Sign1 signature did not verify.");
        }

        StatusListToken token = DecodeClaims(message.Payload);

        return (contentType, token);
    }


    /// <summary>Writes the Status List Token's CWT Claims Set (Section 5.2) with the shared canonical-mode converter.</summary>
    private static byte[] EncodeClaims(StatusListToken token)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        Converter.Write(writer, token, CborSerializerOptions.Default);

        return writer.Encode();
    }


    /// <summary>Reads a Status List Token's CWT Claims Set back from the verified COSE_Sign1 payload bytes.</summary>
    private static StatusListToken DecodeClaims(ReadOnlyMemory<byte> payload)
    {
        var reader = new CborReader(payload, CborConformanceMode.Lax);

        return Converter.Read(ref reader, typeof(StatusListToken), CborSerializerOptions.Default);
    }
}

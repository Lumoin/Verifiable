using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did;
using Verifiable.Core.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Sd;
using Verifiable.Jose;

namespace Verifiable.Json.Sd;

/// <summary>
/// Internal implementation of <see cref="RedactPayloadDelegate"/> and
/// <see cref="SignPayloadDelegate"/> for SD-JWT.
/// </summary>
/// <remarks>
/// <para>
/// Wired into <see cref="SdJwtIssuance.IssueAsync"/> automatically. Not visible to callers.
/// Custom format libraries implement their own pipeline classes following the same pattern.
/// </para>
/// </remarks>
internal static class SdJwtPipeline
{
    /// <summary>
    /// Redacts selectively disclosable claims from a JSON-encoded JWT claims set.
    /// </summary>
    internal static (ReadOnlyMemory<byte> RedactedPayload, IReadOnlyList<SdDisclosure> Disclosures) Redact(
        ReadOnlyMemory<byte> payload,
        IReadOnlySet<CredentialPath> disclosablePaths,
        SaltFactoryDelegate saltFactory,
        string hashAlgorithm)
    {
        string json = Encoding.UTF8.GetString(payload.Span);

        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        var (jwtPayload, disclosures) = SdJwtClaimRedaction.Redact(
            json, disclosablePaths, saltFactory,
            SdJwtSerializer.SerializeDisclosure,
            SdJwtPathExtraction.ComputeDisclosureDigest,
            encoder,
            hashAlgorithm);

        byte[] redactedBytes = JsonSerializer.SerializeToUtf8Bytes(jwtPayload);
        return (redactedBytes, disclosures);
    }


    /// <summary>
    /// Signs a redacted JSON payload as a JWS compact serialization.
    /// </summary>
    internal static async ValueTask<ReadOnlyMemory<byte>> Sign(
        ReadOnlyMemory<byte> redactedPayload,
        string hashAlgorithm,
        string mediaType,
        PrivateKeyMemory privateKey,
        string keyId,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        string resolvedMediaType = string.IsNullOrEmpty(mediaType)
            ? WellKnownMediaTypes.Jwt.SdJwt
            : mediaType;

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

        var header = new JwtHeader
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = resolvedMediaType,
            [JwkProperties.Kid] = keyId
        };

        byte[] headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        string headerSegment = encoder(headerBytes);
        string payloadSegment = encoder(redactedPayload.Span);

        //Per RFC 7515 Section 5.1, the JWS signing input is the ASCII representation
        //of the base64url-encoded header and payload joined by a period character.
        int signingInputLength = headerSegment.Length + 1 + payloadSegment.Length;
        using IMemoryOwner<byte> signingInputOwner = memoryPool.Rent(signingInputLength);
        Memory<byte> signingInputMemory = signingInputOwner.Memory[..signingInputLength];

        int written = Encoding.ASCII.GetBytes(headerSegment, signingInputMemory.Span);
        signingInputMemory.Span[written] = (byte)'.';
        written += 1;
        written += Encoding.ASCII.GetBytes(payloadSegment, signingInputMemory.Span[written..]);

        Debug.Assert(written == signingInputLength, "Signing input length must match the expected size.");

        CryptoAlgorithm cryptoAlgorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(cryptoAlgorithm, purpose);

        Signature signature = await signingDelegate(
            privateKey.AsReadOnlyMemory(),
            signingInputMemory,
            memoryPool).ConfigureAwait(false);

        string signatureSegment = encoder(signature.AsReadOnlyMemory().Span);
        string compactJws = $"{headerSegment}.{payloadSegment}.{signatureSegment}";

        return Encoding.UTF8.GetBytes(compactJws);
    }
}
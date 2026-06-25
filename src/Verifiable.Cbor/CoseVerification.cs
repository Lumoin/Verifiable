using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// Verifies a serialized COSE_Sign1 and surfaces the decoded result — the COSE counterpart of
/// <see cref="Verifiable.JCose.Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, MemoryPool{byte}, PublicKeyMemory, CancellationToken)"/>.
/// </summary>
/// <remarks>
/// This lives in Verifiable.Cbor rather than the lower JCose layer because parsing the wire bytes and
/// reading the protected-header parameters is CBOR work (<see cref="CoseSerialization"/>); the signature
/// math drops out to <see cref="Verifiable.JCose.Cose"/>. The result is <see cref="CoseVerificationResult"/>,
/// which lives in this assembly for the same reason.
/// </remarks>
public static class CoseVerification
{
    /// <summary>
    /// Parses, verifies, and decodes a serialized (tag 18) COSE_Sign1, returning a
    /// <see cref="CoseVerificationResult"/>.
    /// </summary>
    /// <remarks>
    /// Fail-closed over untrusted input: malformed bytes or a failed signature yield a result with
    /// <see cref="CoseVerificationResult.IsValid"/> <see langword="false"/>, never a thrown exception —
    /// matching the JWS verify paths. The verifying function is resolved from <paramref name="publicKey"/>'s
    /// tag through the crypto-function registry, so the caller supplies only the key.
    /// </remarks>
    /// <param name="encodedCoseSign1">The tagged COSE_Sign1 wire bytes.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="pool">Memory pool for the transient parse buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result; <see cref="CoseVerificationResult.IsValid"/> is <see langword="false"/> on any failure.</returns>
    public static async ValueTask<CoseVerificationResult> VerifyAndDecodeAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        PublicKeyMemory publicKey,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        CoseSign1Message message;
        try
        {
            message = CoseSerialization.ParseCoseSign1(encodedCoseSign1, pool);
        }
        catch(Exception ex) when(ex is CborContentException or InvalidOperationException or ArgumentException or IndexOutOfRangeException)
        {
            //Malformed, untagged, or wrong-shape COSE on untrusted input — fail closed, like the JWS
            //verify paths, rather than letting the CBOR reader's exception escape.
            return CoseVerificationResult.Failed();
        }

        using(message)
        {
            //Copy the bytes the result exposes out of the message before dispose releases its pooled
            //protected-header carrier and the borrowed payload view.
            byte[] protectedHeaderCopy = message.ProtectedHeader.AsReadOnlySpan().ToArray();
            int? algorithm = ReadAlgorithm(protectedHeaderCopy, out IReadOnlyDictionary<int, object>? protectedMap);
            string? keyId = ReadKeyId(protectedMap, message.UnprotectedHeader);

            bool isValid = await Cose.VerifyAsync(
                message,
                CoseSerialization.BuildSigStructure,
                publicKey,
                cancellationToken).ConfigureAwait(false);

            if(!isValid)
            {
                return CoseVerificationResult.Failed(protectedHeaderCopy, algorithm, keyId);
            }

            byte[] payloadCopy = message.Payload.ToArray();

            return CoseVerificationResult.Success(payloadCopy, protectedHeaderCopy, algorithm, keyId);
        }
    }


    //Reads the COSE algorithm (protected-header label 1) and hands back the parsed protected-header map
    //for a subsequent kid lookup. An empty or unparseable protected header yields a null algorithm/map.
    private static int? ReadAlgorithm(byte[] protectedHeader, out IReadOnlyDictionary<int, object>? protectedMap)
    {
        protectedMap = null;
        if(protectedHeader.Length == 0)
        {
            return null;
        }

        try
        {
            protectedMap = CoseSerialization.ParseProtectedHeader(protectedHeader);
        }
        catch(Exception ex) when(ex is CborContentException or InvalidOperationException)
        {
            return null;
        }

        return protectedMap.TryGetValue(CoseHeaderParameters.Alg, out object? value) && value is int algorithm
            ? algorithm
            : null;
    }


    //Reads the key identifier (header label 4) — protected header first, then unprotected — as a UTF-8
    //string when the bytes are valid UTF-8 (a binary kid yields null; the caller reads the raw header).
    private static string? ReadKeyId(
        IReadOnlyDictionary<int, object>? protectedMap,
        IReadOnlyDictionary<int, object>? unprotectedMap)
    {
        object? keyId = null;
        if(protectedMap is not null && protectedMap.TryGetValue(CoseHeaderParameters.Kid, out object? fromProtected))
        {
            keyId = fromProtected;
        }
        else if(unprotectedMap is not null && unprotectedMap.TryGetValue(CoseHeaderParameters.Kid, out object? fromUnprotected))
        {
            keyId = fromUnprotected;
        }

        return keyId switch
        {
            string text => text,
            byte[] bytes => TryDecodeUtf8(bytes),
            _ => null
        };
    }


    //Strict UTF-8 decode; null when the bytes are not valid UTF-8, so a binary kid is not misrepresented.
    private static string? TryDecodeUtf8(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);
        }
        catch(DecoderFallbackException)
        {
            return null;
        }
    }
}

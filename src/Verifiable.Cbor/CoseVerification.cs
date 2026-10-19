using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// Verifies a serialized COSE_Sign1 and surfaces the decoded result — the COSE counterpart of
/// <see cref="Verifiable.JCose.Jws.VerifyAndDecodeAsync(string, DecodeDelegate, JwtPartDecoder, BaseMemoryPool, PublicKeyMemory, CancellationToken)"/>.
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
    /// <para>
    /// Fail-closed over untrusted input: malformed bytes or a failed signature yield a result with
    /// <see cref="CoseVerificationResult.IsValid"/> <see langword="false"/>, never a thrown exception —
    /// matching the JWS verify paths. A protected bucket the parser refuses as malformed, one that is not a
    /// well-formed map of labels or that carries a label twice, fails the verification; it is never read as an
    /// absent algorithm (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When
    /// processing messages, if a label appears multiple times, the message MUST be rejected as malformed."). A
    /// well-formed protected bucket carrying a label the header dictionary does not carry, a text string or an
    /// integer outside the 32-bit signed range, is read, and its algorithm is read from it as usual
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr").
    /// </para>
    /// <para>
    /// The verifying function is resolved from <paramref name="publicKey"/>'s tag through the crypto-function
    /// registry, so the caller supplies only the key.
    /// </para>
    /// </remarks>
    /// <param name="encodedCoseSign1">The tagged COSE_Sign1 wire bytes.</param>
    /// <param name="publicKey">The verifying public key; its tag selects the verification function.</param>
    /// <param name="pool">Memory pool for the transient parse buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result; <see cref="CoseVerificationResult.IsValid"/> is <see langword="false"/> on any failure.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="publicKey"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> is cancelled.</exception>
    public static async ValueTask<CoseVerificationResult> VerifyAndDecodeAsync(
        ReadOnlyMemory<byte> encodedCoseSign1,
        PublicKeyMemory publicKey,
        BaseMemoryPool pool,
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
        catch(Exception ex) when(CoseSerialization.IsMalformedInputException(ex))
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
            if(!TryReadProtectedHeader(protectedHeaderCopy, out IReadOnlyDictionary<int, object>? protectedMap))
            {
                //A protected bucket the parser refuses (a repeated label among them) is a malformed
                //message: the verification fails rather than going on without an algorithm.
                return CoseVerificationResult.Failed();
            }

            int? algorithm = ReadAlgorithm(protectedMap);
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


    /// <summary>
    /// Parses the protected bucket, telling an ABSENT bucket (zero bytes: a null map, the read succeeds)
    /// apart from a MALFORMED one (the parser refuses it: the read fails).
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When
    /// processing messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// </remarks>
    /// <param name="protectedHeader">The serialized protected bucket.</param>
    /// <param name="protectedMap">The parsed map, or <see langword="null"/> when the bucket is empty or refused.</param>
    /// <returns><see langword="false"/> when the parser refuses the bucket as malformed; otherwise <see langword="true"/>.</returns>
    private static bool TryReadProtectedHeader(byte[] protectedHeader, out IReadOnlyDictionary<int, object>? protectedMap)
    {
        protectedMap = null;
        if(protectedHeader.Length == 0)
        {
            return true;
        }

        try
        {
            protectedMap = CoseSerialization.ParseProtectedHeader(protectedHeader);
        }
        catch(Exception ex) when(CoseSerialization.IsMalformedInputException(ex))
        {
            return false;
        }

        return true;
    }


    /// <summary>
    /// Reads the COSE algorithm (protected-header label 1) from an already parsed protected bucket.
    /// </summary>
    /// <param name="protectedMap">The parsed protected bucket, or <see langword="null"/> when it is empty.</param>
    /// <returns>The algorithm identifier, or <see langword="null"/> when the bucket carries no integer <c>alg</c>.</returns>
    private static int? ReadAlgorithm(IReadOnlyDictionary<int, object>? protectedMap)
    {
        return protectedMap is not null && protectedMap.TryGetValue(CoseHeaderParameters.Alg, out object? value) && value is int algorithm
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

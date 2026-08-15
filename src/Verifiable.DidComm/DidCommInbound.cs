using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.DidComm;

/// <summary>
/// How a received DIDComm envelope is protected — the unpack path a receiver dispatches to once bytes arrive
/// off a transport (DIDComm Messaging v2.1 §IANA Media Types, §ECDH-ES / §ECDH-1PU key wrapping).
/// </summary>
public enum DidCommMessageClass
{
    /// <summary>The media type was not a recognized DIDComm message, or an encrypted envelope's <c>alg</c> was neither ECDH-ES nor ECDH-1PU.</summary>
    Unknown = 0,

    /// <summary>A plaintext JWM (<c>application/didcomm-plain+json</c>) — unpack with the plaintext parser.</summary>
    Plaintext,

    /// <summary>A signed JWM (<c>application/didcomm-signed+json</c>) — verify with the signed unpack.</summary>
    Signed,

    /// <summary>Anonymous encryption (ECDH-ES key wrapping) — unpack with the anoncrypt path.</summary>
    Anoncrypt,

    /// <summary>Authenticated encryption (ECDH-1PU key wrapping) — unpack with the authcrypt path.</summary>
    Authcrypt
}


/// <summary>
/// Classifies a received DIDComm envelope so a receiver — having taken bytes off ANY transport (an HTTPS body,
/// a WebSocket frame, a Bluetooth characteristic) together with the media type the transport conveyed — can
/// dispatch to the matching unpack without sniffing the wire by hand.
/// </summary>
/// <remarks>
/// The classification is the receive-side counterpart to <see cref="DidCommSendDelegate"/>: the send seam is
/// channel-agnostic, and so is dispatch — the same routing applies whatever transport delivered the bytes. The
/// media type distinguishes plaintext / signed / encrypted (DIDComm v2.1 §IANA Media Types); the three
/// encryption wrappings share one media type, so for an encrypted envelope the protected-header <c>alg</c>
/// distinguishes anoncrypt (ECDH-ES) from authcrypt (ECDH-1PU). Most DIDComm transports convey the content's
/// media type (DIDComm v2.1 §Transport Requirements), so it is the primary input here rather than something
/// guessed from the bytes.
/// <para>
/// A raw WebSocket conveys no per-frame media type at all — measured directly from shipping implementations:
/// zero deployments convey one at the WS layer, and the one shipping DIDComm v2 WS mediator
/// (affinidi-messaging) classifies every inbound frame by envelope shape alone, on the identical code path
/// its HTTP inbound uses (a Rust <c>serde</c> untagged enum that tries a JWE shape, then a JWS shape, then
/// falls back to a plain message). When <c>mediaType</c> is <see langword="null"/> or empty AND the bytes at
/// least look like a JSON object, <see cref="Classify"/> takes a related but more cautious path: a JWE JSON
/// serialization carries a top-level <c>ciphertext</c> member (RFC 7516 §7.2), a JWS JSON serialization a
/// top-level <c>payload</c> plus <c>signatures</c> (general) or <c>signature</c> (flattened) (RFC 7515 §7.2),
/// and a DIDComm plaintext JWM carries none of those. An envelope carrying BOTH a <c>ciphertext</c> member
/// AND a JWS shape at once is structurally ambiguous — no legitimate DIDComm envelope is both — so it
/// classifies <see cref="DidCommMessageClass.Unknown"/> rather than guessing; this deliberately diverges from
/// the serde-untagged, ciphertext-tried-first precedent above, because refusing an ambiguous shape is safer
/// than silently preferring one interpretation. Empty or non-object bytes stay
/// <see cref="DidCommMessageClass.Unknown"/> for the same reason: there is no message to classify at all. A
/// caller that DOES have a media type (an HTTPS <c>Content-Type</c>, or a channel-specific convention that
/// conveys one) keeps using it unchanged — this path activates only in its absence.
/// </para>
/// <para>
/// The returned <see cref="DidCommMessageClass"/> is a routing/dispatch hint derived ONLY from the media type and
/// the protected-header <c>alg</c>; it asserts NOTHING about sender authentication. An envelope may declare
/// <c>alg=ECDH-1PU</c> (classified <see cref="DidCommMessageClass.Authcrypt"/>) yet omit the <c>skid</c>/<c>apu</c>
/// sender binding — the authcrypt unpack still fails closed. The unpack is the authority and independently
/// re-validates; a caller MUST NOT treat an <see cref="DidCommMessageClass.Authcrypt"/> classification as proof the
/// sender is authenticated.
/// </para>
/// </remarks>
public static class DidCommInbound
{
    /// <summary>
    /// Classifies <paramref name="wire"/> by its <paramref name="mediaType"/> when one accompanied the frame,
    /// or by envelope shape when it did not (see the type remarks), reading the encrypted envelope's
    /// <c>alg</c> to split anoncrypt from authcrypt either way.
    /// </summary>
    /// <param name="mediaType">
    /// The media type the transport conveyed (DIDComm v2.1 §Transport Requirements: most transports carry
    /// the IANA media type of the content), or <see langword="null"/>/empty when the channel conveys none (a
    /// raw WebSocket frame) — see the type remarks for the envelope-shape path that activates in that case.
    /// </param>
    /// <param name="wire">The received envelope bytes (UTF-8 JSON).</param>
    /// <param name="base64UrlDecoder">Decoder for the encrypted envelope's protected header.</param>
    /// <param name="memoryPool">Pool backing the header decode.</param>
    /// <returns>
    /// The class the receiver dispatches on; <see cref="DidCommMessageClass.Unknown"/> for an unrecognized
    /// media type, for an encrypted envelope whose <c>alg</c> is neither ECDH-ES nor ECDH-1PU, or — on the
    /// no-media-type envelope-shape path — for bytes that are empty/non-object, or that carry both a JWE and
    /// a JWS shape at once (structurally ambiguous; see the type remarks).
    /// </returns>
    public static DidCommMessageClass Classify(string? mediaType, ReadOnlySpan<byte> wire, DecodeDelegate base64UrlDecoder, BaseMemoryPool memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(string.IsNullOrEmpty(mediaType))
        {
            return ClassifyByEnvelopeShape(wire, base64UrlDecoder, memoryPool);
        }

        if(DidCommMediaTypes.IsPlaintext(mediaType))
        {
            return DidCommMessageClass.Plaintext;
        }

        if(DidCommMediaTypes.IsSigned(mediaType))
        {
            return DidCommMessageClass.Signed;
        }

        if(!DidCommMediaTypes.IsEncrypted(mediaType))
        {
            return DidCommMessageClass.Unknown;
        }

        return ClassifyEncrypted(wire, base64UrlDecoder, memoryPool);
    }


    //An encrypted envelope shares one media type across anoncrypt and authcrypt, so the protected-header alg
    //selects the path: ECDH-ES is anoncrypt, ECDH-1PU is authcrypt. A protected header that is absent, not
    //decodable, or carries an unrecognized alg is Unknown — the receiver then rejects it rather than guessing.
    private static DidCommMessageClass ClassifyEncrypted(ReadOnlySpan<byte> wire, DecodeDelegate base64UrlDecoder, BaseMemoryPool memoryPool)
    {
        if(!DidCommEncryptedExtensions.TryReadProtectedAlgorithms(wire, base64UrlDecoder, memoryPool, out string? algorithm, out _, out _, out _, out _)
            || string.IsNullOrEmpty(algorithm))
        {
            return DidCommMessageClass.Unknown;
        }

        if(DidCommEncryptedExtensions.IsAnoncryptKeyManagementAlgorithm(algorithm))
        {
            return DidCommMessageClass.Anoncrypt;
        }

        if(DidCommEncryptedExtensions.IsAuthcryptKeyManagementAlgorithm(algorithm))
        {
            return DidCommMessageClass.Authcrypt;
        }

        return DidCommMessageClass.Unknown;
    }


    //No media type accompanied the frame, so classification falls back to envelope shape alone — the
    //measured interop behavior (see the type remarks): a top-level `ciphertext` member means JWE (dispatch
    //through the same alg-based anoncrypt/authcrypt split ClassifyEncrypted applies for the encrypted media
    //type), a top-level `payload` plus `signatures`/`signature` means JWS, and neither means a plaintext JWM
    //— a plaintext message legitimately carries none of those members, so a bare JWM is the expected common
    //case here, not a malformed input; this deliberately diverges from JoseTokenClassifier.ClassifyJson,
    //whose contract is that EVERY input is a JOSE token, so having neither shape there IS malformed. An
    //object carrying BOTH a ciphertext member and a JWS shape is structurally ambiguous — no legitimate
    //DIDComm envelope is both at once — so it classifies Unknown rather than guessing; this deliberately
    //diverges from the serde-untagged precedent (ciphertext tried first, described in the type remarks),
    //because refusing an ambiguous shape is safer than silently preferring one interpretation over the
    //other. Members are matched at depth 0 only (JwkJsonReader.ContainsKey), so a `ciphertext`/`payload`/
    //`signature` nested inside `body` or an attachment cannot trigger a false positive. Empty or non-object
    //bytes carry no message to classify at all, so they stay Unknown rather than being guessed at.
    private static DidCommMessageClass ClassifyByEnvelopeShape(ReadOnlySpan<byte> wire, DecodeDelegate base64UrlDecoder, BaseMemoryPool memoryPool)
    {
        if(!LooksLikeJsonObject(wire))
        {
            return DidCommMessageClass.Unknown;
        }

        bool hasCiphertext = JwkJsonReader.ContainsKey(wire, WellKnownJoseSerializationNames.CiphertextUtf8);
        bool hasPayload = JwkJsonReader.ContainsKey(wire, WellKnownJoseSerializationNames.PayloadUtf8);
        bool hasSignature = JwkJsonReader.ContainsKey(wire, WellKnownJoseSerializationNames.SignaturesUtf8)
            || JwkJsonReader.ContainsKey(wire, WellKnownJoseSerializationNames.SignatureUtf8);
        bool looksLikeJws = hasPayload && hasSignature;

        if(hasCiphertext && looksLikeJws)
        {
            return DidCommMessageClass.Unknown;
        }

        if(hasCiphertext)
        {
            return ClassifyEncrypted(wire, base64UrlDecoder, memoryPool);
        }

        return looksLikeJws
            ? DidCommMessageClass.Signed
            : DidCommMessageClass.Plaintext;
    }


    //Whether wire begins, after leading JSON whitespace, with a JSON object's opening brace — the minimal
    //shape check gating envelope-shape classification. All-whitespace or empty input returns false.
    private static bool LooksLikeJsonObject(ReadOnlySpan<byte> wire)
    {
        foreach(byte candidate in wire)
        {
            if(candidate is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
            {
                continue;
            }

            return candidate == (byte)'{';
        }

        return false;
    }
}

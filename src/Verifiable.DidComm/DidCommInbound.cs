using System;
using System.Buffers;
using Verifiable.Cryptography;

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
/// distinguishes anoncrypt (ECDH-ES) from authcrypt (ECDH-1PU). Every DIDComm transport conveys the content's
/// media type (DIDComm v2.1 §Transport Requirements), so it is an input here rather than something guessed from
/// the bytes.
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
    /// Classifies <paramref name="wire"/> by its <paramref name="mediaType"/>, reading the encrypted envelope's
    /// <c>alg</c> to split anoncrypt from authcrypt.
    /// </summary>
    /// <param name="mediaType">The media type the transport conveyed (DIDComm v2.1 §Transport Requirements: every transport carries the IANA media type of the content).</param>
    /// <param name="wire">The received envelope bytes (UTF-8 JSON).</param>
    /// <param name="base64UrlDecoder">Decoder for the encrypted envelope's protected header.</param>
    /// <param name="memoryPool">Pool backing the header decode.</param>
    /// <returns>The class the receiver dispatches on; <see cref="DidCommMessageClass.Unknown"/> for an unrecognized media type or an encrypted envelope whose <c>alg</c> is neither ECDH-ES nor ECDH-1PU.</returns>
    public static DidCommMessageClass Classify(string? mediaType, ReadOnlySpan<byte> wire, DecodeDelegate base64UrlDecoder, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

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
    private static DidCommMessageClass ClassifyEncrypted(ReadOnlySpan<byte> wire, DecodeDelegate base64UrlDecoder, MemoryPool<byte> memoryPool)
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
}

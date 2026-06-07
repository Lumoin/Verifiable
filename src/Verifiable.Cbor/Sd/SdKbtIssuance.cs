using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// CBOR (de)serialization parts for the SD-CWT Key Binding Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. These are the concrete implementations of
/// the <see cref="BuildKbtProtectedHeaderDelegate"/> and
/// <see cref="BuildKbtPayloadDelegate"/> seams the serialization-agnostic
/// <see cref="KbCwtIssuance"/> orchestrator coordinates — the CBOR construction
/// that the JCose and OAuth layers do not perform themselves.
/// </summary>
/// <remarks>
/// <para>
/// The KBT is a COSE_Sign1 the holder signs. There is no <c>sd_hash</c>: the
/// binding is that the holder signs over the embedded presentation SD-CWT, which
/// rides in the protected header under the <c>kcwt</c> parameter (label 13). The
/// embedded SD-CWT is the <em>presentation</em> form — the issuer's COSE_Sign1
/// carrying the holder-selected disclosures in its <c>sd_claims</c> unprotected
/// header.
/// </para>
/// </remarks>
public static class SdKbtIssuance
{
    /// <summary>
    /// The COSE <c>typ</c> value identifying an SD-CWT Key Binding Token per
    /// draft-ietf-spice-sd-cwt §7.1. Emitted as an integer under
    /// <see cref="CoseHeaderParameters.Typ"/> (label 16) in the KBT protected
    /// header.
    /// </summary>
    public const int KbtTypeValue = 294;


    /// <summary>
    /// Builds the KBT protected header CBOR map carrying <c>typ</c> (16),
    /// <c>alg</c> (1), and <c>kcwt</c> (13). The <c>kcwt</c> value is the
    /// presentation SD-CWT re-serialized from <paramref name="presentationToken"/>:
    /// the issuer's COSE_Sign1 with the holder-selected disclosures in its
    /// <c>sd_claims</c> unprotected header.
    /// </summary>
    /// <param name="coseAlgorithm">The holder key's COSE algorithm identifier.</param>
    /// <param name="presentationToken">The SD-CWT presentation token to embed.</param>
    /// <param name="pool">Memory pool the returned carrier and the transient re-parse rent from.</param>
    /// <returns>The CBOR-encoded protected header wrapped in a pool-routed carrier.</returns>
    public static EncodedCoseProtectedHeader BuildProtectedHeader(
        int coseAlgorithm,
        SdToken<ReadOnlyMemory<byte>> presentationToken,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(presentationToken);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] presentationBytes = BuildPresentationSdCwt(presentationToken, pool);

        //Keys are written in canonical (ascending) label order — alg(1),
        //kcwt(13), typ(16) — so the wire form matches what the canonical
        //conformance mode requires for the integrity-protected header.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);

        writer.WriteInt32(CoseHeaderParameters.Alg);
        writer.WriteInt32(coseAlgorithm);

        writer.WriteInt32(CoseHeaderParameters.Kcwt);
        writer.WriteEncodedValue(presentationBytes);

        writer.WriteInt32(CoseHeaderParameters.Typ);
        writer.WriteInt32(KbtTypeValue);

        writer.WriteEndMap();

        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return new EncodedCoseProtectedHeader(owner, CryptoTags.CoseEncodedProtectedHeader);
    }


    /// <summary>
    /// Builds the KBT payload CBOR map: <c>aud</c> (3, MUST), <c>iat</c> (6),
    /// and — when <paramref name="cnonce"/> is non-<see langword="null"/> —
    /// <c>cnonce</c> (39). The <c>iss</c> (1) and <c>sub</c> (2) claims are never
    /// emitted, per draft-ietf-spice-sd-cwt §7.1.
    /// </summary>
    /// <param name="aud">The verifier audience for the <c>aud</c> claim.</param>
    /// <param name="iat">The issuance timestamp in Unix seconds for the <c>iat</c> claim.</param>
    /// <param name="cnonce">The verifier nonce for the <c>cnonce</c> claim, or <see langword="null"/> to omit it.</param>
    /// <param name="pool">Memory pool the returned buffer is rented from.</param>
    /// <returns>The CBOR-encoded payload in a pool-rented buffer the caller owns.</returns>
    public static IMemoryOwner<byte> BuildPayload(
        string aud,
        long iat,
        string? cnonce,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(aud);
        ArgumentNullException.ThrowIfNull(pool);

        var writer = new CborWriter(CborConformanceMode.Canonical);

        int mapSize = cnonce is null ? 2 : 3;
        writer.WriteStartMap(mapSize);

        writer.WriteInt32(WellKnownCwtClaimNames.Aud);
        writer.WriteTextString(aud);

        writer.WriteInt32(WellKnownCwtClaimNames.Iat);
        writer.WriteInt64(iat);

        if(cnonce is not null)
        {
            writer.WriteInt32(WellKnownCwtClaimNames.Cnonce);
            writer.WriteTextString(cnonce);
        }

        writer.WriteEndMap();

        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return owner;
    }


    //Re-serializes the presentation SD-CWT. SelectDisclosures keeps the original
    //issuer COSE_Sign1 in token.IssuerSigned and carries the holder-selected
    //disclosures separately in token.Disclosures, so the presentation is built by
    //recovering payload/protected/signature from IssuerSigned and pairing them
    //with token.Disclosures in a fresh SdCwtMessage. The disclosures parsed out of
    //IssuerSigned's own unprotected header are the issuer's original full set and
    //are discarded — they are disposed here, not embedded.
    private static byte[] BuildPresentationSdCwt(
        SdToken<ReadOnlyMemory<byte>> presentationToken,
        MemoryPool<byte> pool)
    {
        //Parse recovers payload/protected/signature plus the issuer's original full
        //disclosure set. SdCwtMessage is not itself IDisposable, but it owns those
        //parsed disclosures (and their salts); they are the issuer set, never embedded,
        //so dispose them once the wire structure is recovered.
        SdCwtMessage issuerMessage = SdCwtSerializer.Parse(
            presentationToken.IssuerSigned, CryptoTags.WireDecodedDisclosureSalt, pool);

        try
        {
            var presentation = new SdCwtMessage(
                issuerMessage.Payload,
                issuerMessage.ProtectedHeader,
                issuerMessage.Signature,
                presentationToken.Disclosures);

            return SdCwtSerializer.Serialize(presentation);
        }
        finally
        {
            foreach(SdDisclosure disclosure in issuerMessage.Disclosures)
            {
                disclosure.Dispose();
            }
        }
    }
}

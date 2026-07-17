using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Cbor.Sd;

/// <summary>
/// CBOR (de)serialization parts for verifying an SD-CWT VP token presented as an
/// SD-CWT Key Binding Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. These are the concrete implementations of the
/// CBOR parse/extraction seams the serialization-agnostic
/// <c>KbCwtVerification</c> orchestrator (in <c>Verifiable.JCose.Sd</c>) coordinates.
/// </summary>
/// <remarks>
/// <para>
/// Strictly serialization parts — extracting the embedded SD-CWT from the KBT
/// <c>kcwt</c> header, parsing the embedded SD-CWT into an
/// <see cref="SdToken{TEnvelope}"/>, reading the issuer-signed payload's <c>iss</c>
/// and <c>cnf</c> claims, and reading the KBT payload's session-binding claims. No
/// cryptographic validation happens here; the orchestrator composes
/// <c>Cose.VerifyAsync</c> and the existing SD-CWT verification for that.
/// </para>
/// </remarks>
public static class SdCwtVpParsing
{
    /// <summary>
    /// The <c>cnf</c> confirmation-method map key for an embedded COSE_Key per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8747#section-3.1">RFC 8747 §3.1</see>.
    /// </summary>
    private const int CnfCoseKeyMember = 1;


    /// <summary>
    /// Extracts the embedded presentation SD-CWT carried under the <c>kcwt</c>
    /// parameter (label 13 = <see cref="CoseHeaderParameters.Kcwt"/>) of the KBT
    /// protected header. The wire form is returned verbatim as the encoded CBOR value.
    /// </summary>
    /// <param name="kbtProtectedHeader">The CBOR-encoded KBT protected header map.</param>
    /// <returns>The embedded SD-CWT COSE_Sign1 wire bytes.</returns>
    /// <exception cref="CborContentException">Thrown when <c>kcwt</c> is absent from the header.</exception>
    public static ReadOnlyMemory<byte> ExtractKcwt(ReadOnlyMemory<byte> kbtProtectedHeader)
    {
        var reader = new CborReader(kbtProtectedHeader, CborConformanceMode.Lax);

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int label = reader.ReadInt32();
            read++;

            if(label == CoseHeaderParameters.Kcwt)
            {
                return reader.ReadEncodedValue();
            }

            reader.SkipValue();
        }

        throw new CborContentException(
            "The KBT protected header does not carry the kcwt (13) parameter.");
    }


    /// <summary>
    /// Parses the embedded presentation SD-CWT wire bytes into a structured
    /// <see cref="SdToken{TEnvelope}"/> whose <see cref="SdToken{TEnvelope}.IssuerSigned"/>
    /// is the issuer COSE_Sign1 and whose <see cref="SdToken{TEnvelope}.Disclosures"/> are
    /// the holder-selected disclosures recovered from the <c>sd_claims</c> unprotected header.
    /// </summary>
    /// <param name="sdCwt">The embedded SD-CWT COSE_Sign1 wire bytes.</param>
    /// <param name="saltTag">The tag stamped on each wrapped disclosure salt (a wire-decode tag).</param>
    /// <param name="pool">Memory pool the parsed disclosures' salt buffers rent from.</param>
    /// <returns>
    /// The structured token owning the parsed disclosures; the caller disposes it.
    /// </returns>
    public static SdToken<ReadOnlyMemory<byte>> ParseEmbeddedSdCwt(
        ReadOnlyMemory<byte> sdCwt,
        Tag saltTag,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        //SdCwtSerializer.Parse recovers payload/protected/signature plus the
        //holder-selected disclosures (with their salts). The SdToken takes ownership of
        //those disclosures; copying sdCwt into an owned array keeps IssuerSigned valid
        //after the source buffer is released.
        SdCwtMessage message = SdCwtSerializer.Parse(sdCwt, saltTag, pool);

        return new SdToken<ReadOnlyMemory<byte>>(sdCwt.ToArray(), message.Disclosures);
    }


    /// <summary>
    /// Reads the <c>iss</c> claim (CWT claim 1 = <see cref="WellKnownCwtClaimNames.Iss"/>)
    /// from the embedded SD-CWT's issuer-signed payload.
    /// </summary>
    /// <param name="sdCwt">The embedded presentation SD-CWT.</param>
    /// <returns>The <c>iss</c> claim value, or <see langword="null"/> when absent.</returns>
    public static string? ExtractIssuer(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        ReadOnlyMemory<byte> payload = ReadCoseSign1Payload(sdCwt.IssuerSigned);
        var reader = new CborReader(payload, CborConformanceMode.Lax);

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int key = reader.ReadInt32();
            read++;

            if(key == WellKnownCwtClaimNames.Iss)
            {
                return reader.ReadTextString();
            }

            reader.SkipValue();
        }

        return null;
    }


    /// <summary>
    /// Reads the holder COSE_Key from the embedded SD-CWT's <c>cnf</c> claim
    /// (CWT claim 8 = <see cref="WellKnownCwtClaimNames.Cnf"/>, RFC 8747 confirmation
    /// method) and reconstructs it as a tracked <see cref="PublicKeyMemory"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The COSE_Key is read with <see cref="MdocCborCoseKeyReader"/>; its (kty, crv)
    /// tuple is bridged onto an internal <see cref="Tag"/> via
    /// <see cref="CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter"/> and the
    /// EC point coordinates are compressed to the canonical SEC1 internal form. Only EC2
    /// keys carry an uncompressed (x, y) pair; OKP keys (Ed25519) carry the public bytes
    /// in x with no y, and are passed through verbatim.
    /// </para>
    /// </remarks>
    /// <param name="sdCwt">The embedded presentation SD-CWT whose payload carries the <c>cnf</c> COSE_Key.</param>
    /// <param name="pool">Memory pool the returned key's buffer rents from.</param>
    /// <returns>
    /// The holder public key the caller owns and disposes, or <see langword="null"/>
    /// when no <c>cnf</c> COSE_Key is present.
    /// </returns>
    public static PublicKeyMemory? ExtractHolderKey(
        SdToken<ReadOnlyMemory<byte>> sdCwt,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);
        ArgumentNullException.ThrowIfNull(pool);

        CoseKey? coseKey = ReadCnfCoseKey(sdCwt.IssuerSigned);
        if(coseKey is null)
        {
            return null;
        }

        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            coseKey.Kty, coseKey.Curve, Purpose.Verification);

        //EC2 keys carry an uncompressed (x, y) pair; the internal form is the
        //SEC1 compressed point. OKP keys (e.g. Ed25519) carry the public bytes in x
        //with no y and are used verbatim.
        byte[] keyMaterial = coseKey switch
        {
            { X: ReadOnlyMemory<byte> x, Y: ReadOnlyMemory<byte> y } => EllipticCurveUtilities.Compress(x.Span, y.Span),
            { X: ReadOnlyMemory<byte> okpX } => okpX.ToArray(),
            _ => throw new CborContentException(
                "The cnf COSE_Key carries no x coordinate, so a public key cannot be reconstructed.")
        };

        IMemoryOwner<byte> owner = pool.Rent(keyMaterial.Length);
        keyMaterial.AsSpan().CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, tag);
    }


    /// <summary>
    /// Reads the session-binding claims <c>aud</c> (3), <c>iat</c> (6), and the optional
    /// <c>cnonce</c> (39) from the KBT payload.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>iat</c> claim is read as Unix seconds and converted to a
    /// <see cref="DateTimeOffset"/> here so the returned <see cref="KbtCwtClaims"/> is the
    /// orchestrator's neutral session-claims type, carried verbatim by the
    /// <c>ReadKbtCwtClaimsDelegate</c> seam.
    /// </para>
    /// </remarks>
    /// <param name="kbtPayload">The CBOR-encoded KBT payload claims map.</param>
    /// <returns>The parsed claims as a <see cref="KbtCwtClaims"/>.</returns>
    public static KbtCwtClaims ReadKbtClaims(ReadOnlyMemory<byte> kbtPayload)
    {
        var reader = new CborReader(kbtPayload, CborConformanceMode.Lax);

        string? aud = null;
        long? iat = null;
        string? cnonce = null;

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int key = reader.ReadInt32();
            read++;

            _ = key switch
            {
                WellKnownCwtClaimNames.Aud => AssignAud(reader, ref aud),
                WellKnownCwtClaimNames.Iat => AssignIat(reader, ref iat),
                WellKnownCwtClaimNames.Cnonce => AssignCnonce(reader, ref cnonce),
                _ => SkipValue(reader)
            };
        }

        return new KbtCwtClaims
        {
            Aud = aud,
            Iat = iat is long seconds ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null,
            Cnonce = cnonce
        };

        //Assigns the decoded aud claim.
        static bool AssignAud(CborReader reader, ref string? aud)
        {
            aud = reader.ReadTextString();

            return true;
        }

        //Assigns the decoded iat claim.
        static bool AssignIat(CborReader reader, ref long? iat)
        {
            iat = reader.ReadInt64();

            return true;
        }

        //Assigns the decoded cnonce claim.
        static bool AssignCnonce(CborReader reader, ref string? cnonce)
        {
            cnonce = reader.ReadTextString();

            return true;
        }

        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    //Reads the payload byte string out of a COSE_Sign1 wire form without
    //materializing the disclosures (those ride in the unprotected header).
    private static ReadOnlyMemory<byte> ReadCoseSign1Payload(ReadOnlyMemory<byte> coseSign1)
    {
        var reader = new CborReader(coseSign1, CborConformanceMode.Lax);

        CborTag tag = reader.ReadTag();
        if((int)tag != CoseTags.Sign1)
        {
            throw new CborContentException($"Expected COSE_Sign1 tag (18), got {(int)tag}.");
        }

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new CborContentException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        //protected header (bstr), unprotected header (map), payload (bstr), signature (bstr).
        reader.SkipValue();
        reader.SkipValue();

        return reader.ReadByteString();
    }


    //Reads the cnf (8) claim from a COSE_Sign1 payload and, when it carries an embedded
    //COSE_Key confirmation method (cnf map key 1), parses it into a CoseKey view.
    private static CoseKey? ReadCnfCoseKey(ReadOnlyMemory<byte> coseSign1)
    {
        ReadOnlyMemory<byte> payload = ReadCoseSign1Payload(coseSign1);
        var reader = new CborReader(payload, CborConformanceMode.Lax);

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int key = reader.ReadInt32();
            read++;

            if(key != WellKnownCwtClaimNames.Cnf)
            {
                reader.SkipValue();

                continue;
            }

            //cnf is a confirmation-method map; the COSE_Key method lives under member 1.
            int? cnfCount = reader.ReadStartMap();
            int cnfRead = 0;
            CoseKey? coseKey = null;
            while(cnfCount is null ? reader.PeekState() != CborReaderState.EndMap : cnfRead < cnfCount.Value)
            {
                int cnfKey = reader.ReadInt32();
                cnfRead++;

                if(cnfKey == CnfCoseKeyMember)
                {
                    coseKey = MdocCborCoseKeyReader.ReadFromReader(reader);
                }
                else
                {
                    reader.SkipValue();
                }
            }
            reader.ReadEndMap();

            return coseKey;
        }

        return null;
    }
}

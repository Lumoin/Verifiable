using System.Buffers;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;

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
    /// This is the seam-boundary method: <see cref="ExtractKcwtFromKbtDelegate"/> — the
    /// OID4VP verifier's SD-CWT parse seam — documents its implementations as throwing
    /// <see cref="FormatException"/> for a wire-shape rejection, so a missing-<c>kcwt</c>
    /// rejection is normalized to <see cref="FormatException"/> here, at the public
    /// boundary, rather than left to a caller who cannot name <see cref="CborContentException"/>
    /// (the project's CBOR-leaf layering rule keeps the <c>Lumoin.Veritas.Cbor</c> namespace from
    /// being referenced outside this project).
    /// </summary>
    /// <param name="kbtProtectedHeader">The CBOR-encoded KBT protected header map.</param>
    /// <returns>The embedded SD-CWT COSE_Sign1 wire bytes.</returns>
    /// <exception cref="FormatException">
    /// Thrown when <c>kcwt</c> is absent from the header or the header is not well-formed CBOR
    /// (the <see cref="CborContentException"/> or <see cref="InvalidOperationException"/> the CBOR
    /// reader raises rides as the <see cref="Exception.InnerException"/>, when one was raised).
    /// </exception>
    public static ReadOnlyMemory<byte> ExtractKcwt(ReadOnlyMemory<byte> kbtProtectedHeader)
    {
        try
        {
            var reader = new CborReader(kbtProtectedHeader, CborOptions.Lax);

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

            throw new FormatException(
                "The KBT protected header does not carry the kcwt (13) parameter.");
        }
        catch(Exception exception) when(exception is CborException or InvalidOperationException)
        {
            throw new FormatException(
                "The KBT protected header does not carry the kcwt (13) parameter.", exception);
        }
    }


    /// <summary>
    /// Parses the embedded presentation SD-CWT wire bytes into a structured
    /// <see cref="SdToken{TEnvelope}"/> whose <see cref="SdToken{TEnvelope}.IssuerSigned"/>
    /// is the issuer COSE_Sign1 and whose <see cref="SdToken{TEnvelope}.Disclosures"/> are
    /// the holder-selected disclosures recovered from the <c>sd_claims</c> unprotected header.
    /// This is the seam-boundary method (partially applied over the closed-over
    /// <paramref name="saltTag"/>/<paramref name="pool"/>/<paramref name="encoder"/>):
    /// <see cref="ParseSdCwtTokenDelegate"/> — the OID4VP verifier's SD-CWT parse seam — documents its
    /// implementations as throwing <see cref="FormatException"/> for a wire-shape rejection, so a
    /// malformed-CBOR rejection <see cref="SdCwtSerializer.ParseToken"/>'s own reading produces is
    /// normalized to <see cref="FormatException"/> here, at the public boundary, rather than left to a
    /// caller who cannot name <see cref="CborContentException"/> (the project's CBOR-leaf layering rule
    /// keeps the <c>Lumoin.Veritas.Cbor</c> namespace from being referenced outside this project).
    /// <see cref="SdCwtSerializer.ParseToken"/> also throws bare <see cref="FormatException"/> directly
    /// for some wire-shape failures (a duplicate disclosure salt, an unreferenced disclosure); those
    /// pass through unchanged.
    /// </summary>
    /// <param name="sdCwt">The embedded SD-CWT COSE_Sign1 wire bytes.</param>
    /// <param name="saltTag">The tag stamped on each wrapped disclosure salt (a wire-decode tag).</param>
    /// <param name="pool">Memory pool the parsed disclosures' salt buffers rent from.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <returns>
    /// The structured token owning the parsed disclosures, with
    /// <see cref="SdToken{TEnvelope}.DisclosurePaths"/> and
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> resolved from the payload's digest
    /// tree; the caller disposes it.
    /// </returns>
    /// <exception cref="FormatException">
    /// Thrown when the embedded SD-CWT is not well-formed (the <see cref="CborContentException"/> or
    /// <see cref="InvalidOperationException"/> the CBOR reader raises rides as the
    /// <see cref="Exception.InnerException"/>, when one was raised).
    /// </exception>
    public static SdToken<ReadOnlyMemory<byte>> ParseEmbeddedSdCwt(
        ReadOnlyMemory<byte> sdCwt,
        Tag saltTag,
        BaseMemoryPool pool,
        EncodeDelegate encoder,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        try
        {
            return SdCwtSerializer.ParseToken(sdCwt, saltTag, pool, encoder, hashAlgorithm);
        }
        catch(Exception exception) when(exception is CborException or InvalidOperationException)
        {
            throw new FormatException("The embedded SD-CWT is not well-formed.", exception);
        }
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
        var reader = new CborReader(payload, CborOptions.Lax);

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            read++;

            //A redacted-claim-keys entry (draft-ietf-spice-sd-cwt) is keyed by a CBOR simple
            //value, not an integer or text string — skip the key and its digest array without
            //attempting to read it as a claim key.
            if(reader.PeekState() == CborReaderState.SimpleValue)
            {
                reader.SkipValue();
                reader.SkipValue();
                continue;
            }

            //RFC 8392 Section 4: "The Claim Key MUST be an integer or a text string." A claim
            //whose key is neither is not a CWT claim key at all, and one keyed by a text string
            //is skipped by name rather than misread as an integer.
            if(!TryReadClaimKey(reader, out int key))
            {
                reader.SkipValue();
                continue;
            }

            if(key == WellKnownCwtClaimNames.Iss)
            {
                return reader.ReadTextString();
            }

            reader.SkipValue();
        }

        return null;
    }


    /// <summary>
    /// Reads the <c>vct</c> claim (CWT claim 11 = <see cref="WellKnownCwtClaimNames.Vct"/>)
    /// from the embedded SD-CWT's issuer-signed payload — the credential's own declared type.
    /// </summary>
    /// <param name="sdCwt">The embedded presentation SD-CWT.</param>
    /// <returns>The <c>vct</c> claim value, or <see langword="null"/> when absent.</returns>
    public static string? ExtractCredentialType(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        ReadOnlyMemory<byte> payload = ReadCoseSign1Payload(sdCwt.IssuerSigned);
        var reader = new CborReader(payload, CborOptions.Lax);

        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            read++;

            //A redacted-claim-keys entry (draft-ietf-spice-sd-cwt) is keyed by a CBOR simple
            //value, not an integer or text string — skip the key and its digest array without
            //attempting to read it as a claim key.
            if(reader.PeekState() == CborReaderState.SimpleValue)
            {
                reader.SkipValue();
                reader.SkipValue();
                continue;
            }

            //RFC 8392 Section 4: "The Claim Key MUST be an integer or a text string." A claim
            //whose key is neither is not a CWT claim key at all, and one keyed by a text string
            //is skipped by name rather than misread as an integer.
            if(!TryReadClaimKey(reader, out int key))
            {
                reader.SkipValue();
                continue;
            }

            if(key == WellKnownCwtClaimNames.Vct)
            {
                return reader.ReadTextString();
            }

            reader.SkipValue();
        }

        return null;
    }


    /// <summary>
    /// Reads the <c>status</c> claim (CWT claim 65535 =
    /// <see cref="StatusListCborConstants.Status"/>) from the embedded SD-CWT's issuer-signed
    /// payload — the Token Status List Status CBOR structure the verifier's status step reads.
    /// </summary>
    /// <remarks>
    /// The claim's value decodes through <see cref="StatusClaimCborReader"/>, the same reader the
    /// mdoc Mobile Security Object's <c>status</c> member flows through, per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Token Status List, Section 6.3</see>: "The Referenced Token MAY be encoded as a "CBOR Web
    /// Token (CWT)" object according to [RFC8392], as an SD-CWTs [I-D.ietf-spice-sd-cwt] or as an
    /// ISO mdoc". The Status structure is bound to the CWT claim key, not to a text-string
    /// <c>status</c> key: a text-string key is not a CWT claim key at all and is skipped by
    /// <see cref="TryReadClaimKey"/> along with its value.
    /// <see cref="ExtractSdCwtStatusDelegate"/> declares implementations as throwing
    /// <see cref="FormatException"/> for a wire-shape rejection, so a malformed Status structure is
    /// normalized to <see cref="FormatException"/> here, at the public boundary, rather than left to
    /// a caller who cannot name <see cref="CborContentException"/> (the project's CBOR-leaf layering
    /// rule bans that namespace outside <c>Verifiable.Cbor</c>).
    /// </remarks>
    /// <param name="sdCwt">The embedded presentation SD-CWT.</param>
    /// <returns>The decoded status claim, or <see langword="null"/> when the claim is absent.</returns>
    /// <exception cref="FormatException">
    /// Thrown when the <c>status</c> claim is present but its Status structure is not well-formed
    /// (the <see cref="CborContentException"/> or <see cref="InvalidOperationException"/> the CBOR
    /// reader raised rides as the inner exception).
    /// </exception>
    public static StatusClaim? ExtractStatus(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        try
        {
            ReadOnlyMemory<byte> payload = ReadCoseSign1Payload(sdCwt.IssuerSigned);
            var reader = new CborReader(payload, CborOptions.Lax);

            int? count = reader.ReadStartMap();
            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
            {
                read++;

                //A redacted-claim-keys entry (draft-ietf-spice-sd-cwt) is keyed by a CBOR simple
                //value, not an integer or text string — skip the key and its digest array without
                //attempting to read it as a claim key.
                if(reader.PeekState() == CborReaderState.SimpleValue)
                {
                    reader.SkipValue();
                    reader.SkipValue();
                    continue;
                }

                //RFC 8392 Section 4: "The Claim Key MUST be an integer or a text string." A claim
                //whose key is neither is not a CWT claim key at all, and one keyed by a text string
                //is skipped by name rather than misread as an integer.
                if(!TryReadClaimKey(reader, out int key))
                {
                    reader.SkipValue();
                    continue;
                }

                if(key == StatusListCborConstants.Status)
                {
                    return StatusClaimCborReader.Read(reader);
                }

                reader.SkipValue();
            }

            return null;
        }
        catch(Exception exception) when(exception is CborException or InvalidOperationException)
        {
            throw new FormatException(
                "The embedded SD-CWT's status claim is not a well-formed Token Status List Status structure.",
                exception);
        }
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
        BaseMemoryPool pool)
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
        var reader = new CborReader(kbtPayload, CborOptions.Lax);

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


    /// <summary>
    /// Reads one CWT claim key, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc8392#section-4">RFC 8392 Section 4</see>
    /// defines as "an integer or a text string": an integer key is returned as itself, while a
    /// text-string key is consumed and reported as no integer key, so the caller passes over its
    /// value instead of misreading the key as an integer and faulting the reader.
    /// </summary>
    /// <param name="reader">The reader, positioned at a claim key.</param>
    /// <param name="key">The integer claim key, when the key is an integer.</param>
    /// <returns><see langword="true"/> when the key is an integer claim key.</returns>
    private static bool TryReadClaimKey(CborReader reader, out int key)
    {
        CborReaderState state = reader.PeekState();

        if(state is CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger)
        {
            key = reader.ReadInt32();

            return true;
        }

        if(state == CborReaderState.TextString)
        {
            reader.ReadTextString();
        }
        else
        {
            reader.SkipValue();
        }

        key = 0;

        return false;
    }


    //Reads the payload byte string out of a COSE_Sign1 wire form without
    //materializing the disclosures (those ride in the unprotected header).
    private static ReadOnlyMemory<byte> ReadCoseSign1Payload(ReadOnlyMemory<byte> coseSign1)
    {
        var reader = new CborReader(coseSign1, CborOptions.Lax);

        CborTag tag = reader.ReadTag();
        if((int)tag.Value != CoseTags.Sign1)
        {
            throw new CborContentException($"Expected COSE_Sign1 tag (18), got {(int)tag.Value}.");
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
        var reader = new CborReader(payload, CborOptions.Lax);

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

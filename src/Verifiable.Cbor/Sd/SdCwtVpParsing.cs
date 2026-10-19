using Lumoin.Veritas.Cbor;
using System.Buffers;
using System.Globalization;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

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
/// <para>
/// Every reader here is a seam an application wires into the verifier, so input a reader refuses is answered as
/// <see cref="FormatException"/>, the failure the verifier answers as a malformed presentation, with the CBOR
/// reader's own exception as the <see cref="Exception.InnerException"/>; a caller outside this leaf cannot name the
/// CBOR reader's exceptions (the project's CBOR-leaf layering rule keeps the <c>Lumoin.Veritas.Cbor</c> namespace from
/// being referenced outside this project).
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
    /// <remarks>
    /// The whole header is read, so a label it carries twice, <c>kcwt</c> among them, is seen wherever it sits. Every
    /// label is read as RFC 9052 Section 1.5 defines it, any CBOR integer read whole or a text string, and a well-formed
    /// label other than <c>kcwt</c> is passed over with its value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 Section 3</see>: "When processing
    /// messages, if a label appears multiple times, the message MUST be rejected as malformed."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-1.5">RFC 9052 Section 1.5</see>: "label = int / tstr".
    /// </remarks>
    /// <param name="kbtProtectedHeader">The CBOR-encoded KBT protected header map.</param>
    /// <returns>The embedded SD-CWT COSE_Sign1 wire bytes.</returns>
    /// <exception cref="FormatException">
    /// Thrown when <c>kcwt</c> is absent from the header, when a label appears twice in the header, when the header
    /// carries a map key that is neither an integer nor a text string, or when the header is not well-formed CBOR
    /// (the CBOR reader's exception rides as the <see cref="Exception.InnerException"/>, when one was raised).
    /// </exception>
    public static ReadOnlyMemory<byte> ExtractKcwt(ReadOnlyMemory<byte> kbtProtectedHeader)
    {
        try
        {
            var reader = new CborReader(kbtProtectedHeader, CborOptions.Lax);

            ReadOnlyMemory<byte>? kcwt = null;
            HashSet<(bool IsSimpleValue, Int128 Number, string? Text)> seenLabels = [];
            HashSet<object> seenOtherMapKeys = new(CborValueConverter.MapKeyEquivalence.Instance);
            int? count = reader.ReadStartMap();
            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
            {
                (bool IsSimpleValue, Int128 Number, string? Text)? label = ReadMapKey(reader, seenLabels, seenOtherMapKeys);
                read++;

                if(label is not { IsSimpleValue: false })
                {
                    throw new FormatException(
                        "The KBT protected header carries a label that is neither an integer nor a text string; the header is malformed (RFC 9052 Section 1.5).");
                }

                if(IntegerKeyOf(label) == CoseHeaderParameters.Kcwt)
                {
                    kcwt = reader.ReadEncodedValue();
                }
                else
                {
                    reader.SkipValue();
                }
            }

            reader.ReadEndMap();

            return kcwt ?? throw new FormatException(
                "The KBT protected header does not carry the kcwt (13) parameter.");
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The KBT protected header is not a well-formed map of labels, or carries one label twice (RFC 9052 Section 3).", exception);
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
    /// for some wire-shape failures (a duplicate disclosure salt, an unreferenced disclosure, a claims-map level
    /// carrying one map key twice); those pass through unchanged.
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
    /// Thrown when the embedded SD-CWT is not well-formed (the CBOR reader's exception rides as the
    /// <see cref="Exception.InnerException"/>, when one was raised).
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="saltTag"/>, <paramref name="pool"/> or <paramref name="encoder"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException"><paramref name="hashAlgorithm"/> names no supported digest algorithm.</exception>
    /// <remarks>
    /// The caller's own arguments are judged before the wire bytes are read, so a fault in them surfaces as itself and
    /// is never answered as a malformed presentation.
    /// </remarks>
    public static SdToken<ReadOnlyMemory<byte>> ParseEmbeddedSdCwt(
        ReadOnlyMemory<byte> sdCwt,
        Tag saltTag,
        BaseMemoryPool pool,
        EncodeDelegate encoder,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm);
        _ = SdCwtSerializer.ResolveDigestTag(hashAlgorithm);

        try
        {
            return SdCwtSerializer.ParseToken(sdCwt, saltTag, pool, encoder, hashAlgorithm);
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
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
    /// <exception cref="ArgumentNullException"><paramref name="sdCwt"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// Thrown when the claims map carries one map key twice
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of
    /// the listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input."
    /// and its step 7, "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map.", read
    /// with <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that
    /// has duplicate keys may be well-formed, but it is not valid"), or when the
    /// COSE_Sign1 envelope or the claims map is not well-formed; the CBOR reader's exception rides as the
    /// <see cref="Exception.InnerException"/>.
    /// </exception>
    public static string? ExtractIssuer(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        try
        {
            return ReadIssuerSignedClaim(sdCwt.IssuerSigned, WellKnownCwtClaimNames.Iss, static reader => reader.ReadTextString());
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The embedded SD-CWT's issuer-signed claims map is not well-formed, or carries one map key twice.", exception);
        }
    }


    /// <summary>
    /// Reads the <c>vct</c> claim (CWT claim 11 = <see cref="WellKnownCwtClaimNames.Vct"/>)
    /// from the embedded SD-CWT's issuer-signed payload — the credential's own declared type.
    /// </summary>
    /// <param name="sdCwt">The embedded presentation SD-CWT.</param>
    /// <returns>The <c>vct</c> claim value, or <see langword="null"/> when absent.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="sdCwt"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// Thrown when the claims map carries one map key twice
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of
    /// the listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input."
    /// and its step 7, "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map.", read
    /// with <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that
    /// has duplicate keys may be well-formed, but it is not valid"), or when the
    /// COSE_Sign1 envelope or the claims map is not well-formed; the CBOR reader's exception rides as the
    /// <see cref="Exception.InnerException"/>.
    /// </exception>
    public static string? ExtractCredentialType(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        try
        {
            return ReadIssuerSignedClaim(sdCwt.IssuerSigned, WellKnownCwtClaimNames.Vct, static reader => reader.ReadTextString());
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The embedded SD-CWT's issuer-signed claims map is not well-formed, or carries one map key twice.", exception);
        }
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
    /// <c>status</c> claim key: a text-string claim key is a label of its own, read by
    /// <see cref="ReadMapKey"/> and passed over with its value.
    /// <see cref="ExtractSdCwtStatusDelegate"/> declares implementations as throwing
    /// <see cref="FormatException"/> for a wire-shape rejection, so a malformed Status structure is
    /// normalized to <see cref="FormatException"/> here, at the public boundary, rather than left to
    /// a caller who cannot name <see cref="CborContentException"/> (the project's CBOR-leaf layering
    /// rule bans that namespace outside <c>Verifiable.Cbor</c>).
    /// </remarks>
    /// <param name="sdCwt">The embedded presentation SD-CWT.</param>
    /// <returns>The decoded status claim, or <see langword="null"/> when the claim is absent.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="sdCwt"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// Thrown when the <c>status</c> claim is present but its Status structure is not well-formed, or
    /// when the claims map carries one map key twice
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of
    /// the listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input."
    /// and its step 7, "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map.", read
    /// with <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that
    /// has duplicate keys may be well-formed, but it is not valid")
    /// (the CBOR reader's exception rides as the inner exception).
    /// </exception>
    public static StatusClaim? ExtractStatus(SdToken<ReadOnlyMemory<byte>> sdCwt)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);

        try
        {
            return ReadIssuerSignedClaim(sdCwt.IssuerSigned, StatusListCborConstants.Status, StatusClaimCborReader.Read);
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
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
    /// <exception cref="ArgumentNullException"><paramref name="sdCwt"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="FormatException">
    /// Thrown when the claims map, the <c>cnf</c> confirmation map or the COSE_Key carries one map key twice
    /// (for the claims map, <see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of
    /// the listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input."
    /// and its step 7, "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map.", read
    /// with <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that
    /// has duplicate keys may be well-formed, but it is not valid"; for the COSE_Key,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST
    /// NOT parse and process messages with the same label used twice as a key in a single map."), when any of them
    /// is not well-formed, or when the COSE_Key carries no <c>x</c> coordinate; the CBOR reader's exception rides as
    /// the <see cref="Exception.InnerException"/>.
    /// </exception>
    public static PublicKeyMemory? ExtractHolderKey(
        SdToken<ReadOnlyMemory<byte>> sdCwt,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(sdCwt);
        ArgumentNullException.ThrowIfNull(pool);

        CoseKey coseKey;
        byte[] keyMaterial;
        try
        {
            CoseKey? readKey = ReadIssuerSignedClaim(sdCwt.IssuerSigned, WellKnownCwtClaimNames.Cnf, ReadConfirmationMethods);
            if(readKey is null)
            {
                return null;
            }

            coseKey = readKey;

            //EC2 keys carry an uncompressed (x, y) pair; the internal form is the
            //SEC1 compressed point. OKP keys (e.g. Ed25519) carry the public bytes in x
            //with no y and are used verbatim.
            keyMaterial = coseKey switch
            {
                { X: ReadOnlyMemory<byte> x, Y: ReadOnlyMemory<byte> y } => EllipticCurveUtilities.Compress(x.Span, y.Span),
                { X: ReadOnlyMemory<byte> okpX } => okpX.ToArray(),
                _ => throw new CborContentException(
                    "The cnf COSE_Key carries no x coordinate, so a public key cannot be reconstructed.")
            };
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The embedded SD-CWT's cnf claim is not a well-formed confirmation map holding a COSE_Key, or a map in it carries one map key twice.",
                exception);
        }

        Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
            coseKey.Kty, coseKey.Curve, Purpose.Verification);

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
    /// <para>
    /// Every map key of the claims map is judged: a claim key, an integer or a text string, by its decoded value, and
    /// a map key of any other kind by the equivalence of map keys of RFC 8949 Section 5.6.1.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of
    /// the listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input."
    /// and its step 7, "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map.", read
    /// with <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that
    /// has duplicate keys may be well-formed, but it is not valid".
    /// </para>
    /// </remarks>
    /// <param name="kbtPayload">The CBOR-encoded KBT payload claims map.</param>
    /// <returns>The parsed claims as a <see cref="KbtCwtClaims"/>.</returns>
    /// <exception cref="FormatException">
    /// Thrown when a map key appears twice in the map, or when the map or a claim it carries is not well-formed; the
    /// CBOR reader's exception rides as the <see cref="Exception.InnerException"/>.
    /// </exception>
    public static KbtCwtClaims ReadKbtClaims(ReadOnlyMemory<byte> kbtPayload)
    {
        try
        {
            var reader = new CborReader(kbtPayload, CborOptions.Lax);

            string? aud = null;
            long? iat = null;
            string? cnonce = null;

            HashSet<(bool IsSimpleValue, Int128 Number, string? Text)> seenLabels = [];
            HashSet<object> seenOtherMapKeys = new(CborValueConverter.MapKeyEquivalence.Instance);
            int? count = reader.ReadStartMap();
            int read = 0;
            while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
            {
                int? claimKey = IntegerKeyOf(ReadMapKey(reader, seenLabels, seenOtherMapKeys));
                read++;

                _ = claimKey switch
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
        }
        catch(Exception exception) when(exception is not FormatException && CoseSerialization.IsMalformedInputException(exception))
        {
            throw new FormatException(
                "The KBT claims map is not well-formed, or carries one map key twice (RFC 9052 Section 9).", exception);
        }

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

        //Passes over the value of a claim key the session-binding claims do not carry.
        static bool SkipValue(CborReader reader)
        {
            reader.SkipValue();

            return true;
        }
    }


    /// <summary>
    /// Reads the claims map of a COSE_Sign1's payload whole and answers the value of the integer claim key
    /// <paramref name="claimKey"/>. Every entry is read, so a map key the map carries twice is seen wherever it
    /// sits, also after the claim asked for, and the map is refused; every map key is judged, a claim key on its
    /// decoded value (an integer written in two widths is one claim key) and a map key of any other kind by the
    /// equivalence of map keys of RFC 8949 Section 5.6.1.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8392#section-7.2">RFC 8392 Section 7.2</see>: "If any of the
    /// listed steps fail, then the CWT MUST be rejected -- that is, treated by the application as invalid input." Its
    /// step 7: "Verify that the Message is a valid CBOR map; let the CWT Claims Set be this CBOR map."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map that has
    /// duplicate keys may be well-formed, but it is not valid, and thus it causes indeterminate decoding; see also
    /// Section 5.6." The claim keys a CWT claims map carries are those of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8392#section-3">RFC 8392 Section 3</see> ("To keep CWTs as small as
    /// possible, the Claim Keys are represented using integers or text strings."), beside the CBOR simple value SD-CWT
    /// keys its redacted claim keys with; <see cref="ReadMapKey"/> reads each one.
    /// </remarks>
    /// <typeparam name="TClaim">The decoded claim's type.</typeparam>
    /// <param name="coseSign1">The COSE_Sign1 wire form whose payload is the claims map.</param>
    /// <param name="claimKey">The integer claim key whose value is answered.</param>
    /// <param name="readClaim">Reads the claim's value, the reader positioned at it.</param>
    /// <returns>The decoded claim, or the default when the map carries no such claim.</returns>
    /// <exception cref="CborContentException">Thrown when a map key appears twice in the claims map, or the envelope is malformed.</exception>
    private static TClaim? ReadIssuerSignedClaim<TClaim>(ReadOnlyMemory<byte> coseSign1, int claimKey, Func<CborReader, TClaim> readClaim)
    {
        ReadOnlyMemory<byte> payload = ReadCoseSign1Payload(coseSign1);
        var reader = new CborReader(payload, CborOptions.Lax);

        TClaim? claim = default;
        HashSet<(bool IsSimpleValue, Int128 Number, string? Text)> seenLabels = [];
        HashSet<object> seenOtherMapKeys = new(CborValueConverter.MapKeyEquivalence.Instance);
        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            read++;

            if(IntegerKeyOf(ReadMapKey(reader, seenLabels, seenOtherMapKeys)) == claimKey)
            {
                claim = readClaim(reader);
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        return claim;
    }


    /// <summary>
    /// Reads one map key of a CWT claims map, a <c>cnf</c> confirmation map or a COSE header map and judges it for a
    /// repeat. An integer map key, read whole and never cast down, a text-string map key, and a simple-value map key
    /// (<see langword="false"/>, <see langword="true"/> and <see langword="null"/> among them, by their simple-value
    /// numbers) are answered as a label judged on its decoded value; a map key of any other kind is decoded and judged
    /// by the equivalence of map keys of RFC 8949 Section 5.6.1, <see cref="CborValueConverter.MapKeyEquivalence"/>,
    /// and answers no label. This is the one map-key read of this file.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see>: "Simple values are
    /// equal if they simply have the same value. Nothing else is equal in the generic data model; a simple value 2 is
    /// not equivalent to an integer 2, and an array is never equivalent to a map." The groups never meet: a label of
    /// one group is never the same map key as a label of another or as a decoded map key of another kind.
    /// </remarks>
    /// <param name="reader">The reader, positioned at a map key.</param>
    /// <param name="seenLabels">The labels already read from the same map.</param>
    /// <param name="seenOtherMapKeys">The decoded map keys of other kinds already read from the same map.</param>
    /// <returns>
    /// The label: whether it is a simple value, its number (an integer map key or the simple value) and its text (a
    /// text-string map key); <see langword="null"/> for a map key of another kind.
    /// </returns>
    /// <exception cref="CborContentException">The map already carried the same map key, or the map key is malformed.</exception>
    private static (bool IsSimpleValue, Int128 Number, string? Text)? ReadMapKey(
        CborReader reader, HashSet<(bool IsSimpleValue, Int128 Number, string? Text)> seenLabels, HashSet<object> seenOtherMapKeys)
    {
        (bool IsSimpleValue, Int128 Number, string? Text)? label = reader.PeekState() switch
        {
            CborReaderState.UnsignedInteger => (false, (Int128)reader.ReadUInt64(), null),
            CborReaderState.NegativeInteger => (false, -1 - (Int128)reader.ReadCborNegativeIntegerRepresentation(), null),
            CborReaderState.TextString => (false, Int128.Zero, reader.ReadTextString()),
            CborReaderState.SimpleValue => (true, (Int128)reader.ReadSimpleValue(), null),
            CborReaderState.Boolean => (true, reader.ReadBoolean() ? SimpleValueTrue : SimpleValueFalse, null),
            CborReaderState.Null => ReadNullMapKey(reader),
            _ => null
        };

        if(label is { } readLabel)
        {
            if(!seenLabels.Add(readLabel))
            {
                string labelText = readLabel switch
                {
                    { Text: string text } => text,
                    { IsSimpleValue: true } => string.Create(CultureInfo.InvariantCulture, $"simple({readLabel.Number})"),
                    _ => readLabel.Number.ToString(CultureInfo.InvariantCulture)
                };

                throw new CborContentException(
                    $"The map carries the map key {labelText} more than once; the map is not valid (RFC 9052 Section 9, RFC 8949 Section 3.1).");
            }

            return readLabel;
        }

        object mapKey = CborValueConverter.ReadValue(reader)
            ?? throw new CborContentException("A map key of another kind decoded to no value.");
        if(!seenOtherMapKeys.Add(mapKey))
        {
            throw new CborContentException(
                "The map carries one map key twice by the equivalence of map keys; the map is not valid (RFC 9052 Section 9, RFC 8949 Section 5.6.1).");
        }

        return null;
    }


    /// <summary>The number of the CBOR simple value <see langword="false"/> (RFC 8949 Section 3.3).</summary>
    private static Int128 SimpleValueFalse { get; } = 20;


    /// <summary>The number of the CBOR simple value <see langword="true"/> (RFC 8949 Section 3.3).</summary>
    private static Int128 SimpleValueTrue { get; } = 21;


    /// <summary>The number of the CBOR simple value <see langword="null"/> (RFC 8949 Section 3.3).</summary>
    private static Int128 SimpleValueNull { get; } = 22;


    /// <summary>Reads a <see langword="null"/> map key and answers it as the simple-value label it is.</summary>
    /// <param name="reader">The reader, positioned at the map key.</param>
    /// <returns>The simple-value label of <see langword="null"/>.</returns>
    private static (bool IsSimpleValue, Int128 Number, string? Text)? ReadNullMapKey(CborReader reader)
    {
        reader.ReadNull();

        return (true, SimpleValueNull, null);
    }


    /// <summary>
    /// Answers the integer a label stands for when it is an integer map key within the 32-bit signed range of the claim
    /// keys and header labels this file compares with, or <see langword="null"/> for any other map key.
    /// </summary>
    /// <param name="label">The label <see cref="ReadMapKey"/> answered, or <see langword="null"/> for a map key of another kind.</param>
    /// <returns>The integer, or <see langword="null"/>.</returns>
    private static int? IntegerKeyOf((bool IsSimpleValue, Int128 Number, string? Text)? label)
    {
        return label is { IsSimpleValue: false, Text: null } integerLabel && integerLabel.Number >= int.MinValue && integerLabel.Number <= int.MaxValue
            ? (int)integerLabel.Number
            : null;
    }


    /// <summary>
    /// Reads the payload byte string out of a COSE_Sign1 wire form without materializing the disclosures (those ride
    /// in the unprotected header).
    /// </summary>
    /// <param name="coseSign1">The COSE_Sign1 wire form.</param>
    /// <returns>The payload bytes.</returns>
    /// <exception cref="CborContentException">The bytes are not a tagged four-element COSE_Sign1.</exception>
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


    /// <summary>
    /// Reads the <c>cnf</c> (8) claim's confirmation-method map whole and parses its embedded COSE_Key
    /// confirmation method (member 1) into a <see cref="CoseKey"/> view. Every map key is read and judged, a member on
    /// its decoded value and a map key of any other kind by the equivalence of map keys, so a map key the map carries
    /// twice is seen and the map refused.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST
    /// NOT parse and process messages with the same label used twice as a key in a single map." The COSE_Key
    /// itself is read by <see cref="MdocCborCoseKeyReader.ReadFromReader(CborReader)"/>, which refuses a label
    /// the COSE_Key carries twice.
    /// </remarks>
    /// <param name="reader">The reader, positioned at the confirmation-method map.</param>
    /// <returns>The COSE_Key view, or <see langword="null"/> when the map carries no COSE_Key member.</returns>
    /// <exception cref="CborContentException">Thrown when a map key appears twice in the confirmation-method map.</exception>
    private static CoseKey? ReadConfirmationMethods(CborReader reader)
    {
        CoseKey? coseKey = null;
        HashSet<(bool IsSimpleValue, Int128 Number, string? Text)> seenMembers = [];
        HashSet<object> seenOtherMapKeys = new(CborValueConverter.MapKeyEquivalence.Instance);
        int? count = reader.ReadStartMap();
        int read = 0;
        while(count is null ? reader.PeekState() != CborReaderState.EndMap : read < count.Value)
        {
            int? member = IntegerKeyOf(ReadMapKey(reader, seenMembers, seenOtherMapKeys));
            read++;

            if(member == CnfCoseKeyMember)
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
}

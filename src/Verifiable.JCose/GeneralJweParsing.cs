using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// JWE General JSON Serialization parsing for multi-recipient encrypted messages per
/// <see href="https://www.rfc-editor.org/rfc/rfc7516#section-7.2">RFC 7516 §7.2</see>.
/// </summary>
/// <remarks>
/// <para>
/// The counterpart to <see cref="JweParsing"/>, which handles the single-recipient compact
/// serialization. <see cref="ParseGeneralJson"/> decodes the JSON object into a validated
/// <see cref="AeadGeneralMessage"/> ready for per-recipient unwrap and decryption.
/// </para>
/// <para>
/// Unlike <see cref="JweParsing"/> — which is pinned to AES-GCM structural lengths — this
/// parser handles both the AES-GCM and AES_CBC_HMAC_SHA2 content encryption families, so it
/// validates IV and tag lengths against the declared <c>enc</c> value rather than against a
/// single fixed size.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Ownership of the returned AeadGeneralMessage transfers to the caller; the nullable-with-finally pattern releases partial state on any failure path.")]
public static class GeneralJweParsing
{
    /// <summary>
    /// Maximum permitted General JSON JWE byte count. Larger documents are rejected before
    /// any parsing begins to prevent memory exhaustion.
    /// </summary>
    public const int MaxGeneralJweByteCount = 262_144;


    /// <summary>
    /// Parses and validates a JWE General JSON Serialization string, returning an
    /// <see cref="AeadGeneralMessage"/> ready for per-recipient unwrap and decryption.
    /// </summary>
    /// <param name="generalJson">The General JSON JWE serialization to parse.</param>
    /// <param name="expectedAlgorithm">
    /// The key management algorithm the caller accepts as policy, e.g.
    /// <see cref="WellKnownJweAlgorithms.Ecdh1PuA256Kw"/>.
    /// </param>
    /// <param name="expectedEncryption">
    /// The content encryption algorithm the caller accepts, e.g.
    /// <see cref="WellKnownJweEncryptionAlgorithms.A256CbcHs512"/>.
    /// </param>
    /// <param name="base64UrlDecoder">Delegate for Base64url decoding into pooled memory.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <returns>The validated <see cref="AeadGeneralMessage"/>. The caller owns and must dispose.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="generalJson"/> exceeds <see cref="MaxGeneralJweByteCount"/>.
    /// </exception>
    /// <exception cref="FormatException">
    /// Thrown when any structural or security invariant is violated.
    /// </exception>
    public static AeadGeneralMessage ParseGeneralJson(
        string generalJson,
        string expectedAlgorithm,
        string expectedEncryption,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(generalJson);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedEncryption);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(generalJson.Length > MaxGeneralJweByteCount)
        {
            throw new ArgumentException(
                $"General JSON JWE exceeds the maximum permitted size of {MaxGeneralJweByteCount} bytes.",
                nameof(generalJson));
        }

        byte[] jsonBytes = Encoding.UTF8.GetBytes(generalJson);
        ReadOnlySpan<byte> json = jsonBytes;

        string? protectedEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.ProtectedUtf8);
        if(protectedEncoded is null)
        {
            throw new FormatException(
                "General JSON JWE must contain a 'protected' member per RFC 7516 §7.2.1.");
        }

        //This library sources every cryptographic JOSE Header parameter (alg, enc, apu, apv,
        //skid, zip) from the integrity-protected header, as DIDComm Messaging v2 requires. A
        //Shared Unprotected Header MAY still carry non-cryptographic hints such as 'jku' (the
        //ECDH-1PU Appendix B vector does exactly this), so the member is permitted — but if it
        //carries a cryptographic parameter the library would otherwise read from 'protected',
        //the message is rejected rather than silently ignoring an unprotected value that would
        //feed the key derivation (a wrong-key vector).
        RejectCryptographicParametersInUnprotectedHeader(json);

        string? ivEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.IvUtf8);
        string? ciphertextEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.CiphertextUtf8);
        string? tagEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.TagUtf8);

        if(ivEncoded is null || ciphertextEncoded is null || tagEncoded is null)
        {
            throw new FormatException(
                "General JSON JWE must contain 'iv', 'ciphertext', and 'tag' members per RFC 7516 §7.2.1.");
        }

        //Optional top-level 'aad' (RFC 7516 §7.2.1): when present, the AAD computed for content
        //decryption is ASCII(BASE64URL(protected) || '.' || aad) per §5.1 step 14 / §5.2 step 15.
        string? aadEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.AadUtf8);

        List<(string KeyId, string EncryptedKey, List<string> HeaderNames)> recipientPairs = ParseRecipients(json);
        if(recipientPairs.Count == 0)
        {
            throw new FormatException(
                "General JSON JWE 'recipients' must contain at least one entry per RFC 7516 §7.2.1.");
        }

        AdditionalData? aad = null;
        PublicKeyMemory? epk = null;
        Nonce? iv = null;
        Ciphertext? ciphertext = null;
        AuthenticationTag? tag = null;
        List<AeadGeneralRecipient> recipients = [];

        try
        {
            using IMemoryOwner<byte> headerOwner = base64UrlDecoder(protectedEncoded, pool);
            epk = ParseAndValidateHeader(
                headerOwner.Memory.Span,
                expectedAlgorithm,
                expectedEncryption,
                base64UrlDecoder,
                CryptoFormatConversions.DefaultEpkCrvToTagConverter,
                pool,
                out IReadOnlyDictionary<string, object> header,
                out JweContentEncryption contentEncryption);

            //RFC 7516 §5.2 step 4 / §7.2.1: the JOSE Header for each recipient (protected ∪
            //unprotected ∪ that recipient's header) must have disjoint parameter names, and the
            //envelope members must be unique.
            ValidateHeaderUniqueness(json, headerOwner.Memory.Span, recipientPairs.ConvertAll(r => r.HeaderNames));

            aad = BuildAdditionalData(protectedEncoded, aadEncoded, contentEncryption.Family, pool);

            iv = DecodeAndValidateContentParts(
                ivEncoded, ciphertextEncoded, tagEncoded, contentEncryption, base64UrlDecoder, pool,
                out ciphertext, out tag);

            foreach((string keyId, string encryptedKey, List<string> _) in recipientPairs)
            {
                IMemoryOwner<byte> wrappedKeyOwner = base64UrlDecoder(encryptedKey, pool);
                recipients.Add(new AeadGeneralRecipient(keyId, wrappedKeyOwner));
            }

            AeadGeneralMessage result = new AeadGeneralMessage(
                header, epk, iv, ciphertext, tag, aad, recipients, expectedEncryption, expectedAlgorithm);

            //Ownership transferred to AeadGeneralMessage.
            aad = null;
            epk = null;
            iv = null;
            ciphertext = null;
            tag = null;
            recipients = [];

            return result;
        }
        finally
        {
            aad?.Dispose();
            epk?.Dispose();
            iv?.Dispose();
            ciphertext?.Dispose();
            tag?.Dispose();
            for(int i = 0; i < recipients.Count; ++i)
            {
                recipients[i].Dispose();
            }
        }
    }


    /// <summary>
    /// Parses and validates a JWE Flattened JSON Serialization string (RFC 7516 §7.2.2),
    /// returning a single-recipient <see cref="AeadGeneralMessage"/> ready for unwrap and
    /// decryption.
    /// </summary>
    /// <remarks>
    /// The flattened form is the general form optimized for one recipient: the <c>recipients</c>
    /// array is removed and that recipient's <c>header</c> and <c>encrypted_key</c> sit at the
    /// top level. RFC 7516 §7.2.2: a <c>recipients</c> member MUST NOT be present. The returned
    /// message has exactly one recipient, so it decrypts identically to a single-recipient
    /// general serialization through the General decrypt extensions.
    /// </remarks>
    /// <param name="flattenedJson">The Flattened JSON JWE serialization to parse.</param>
    /// <param name="expectedAlgorithm">The key management algorithm the caller accepts.</param>
    /// <param name="expectedEncryption">The content encryption algorithm the caller accepts.</param>
    /// <param name="base64UrlDecoder">Delegate for Base64url decoding into pooled memory.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <returns>The validated single-recipient <see cref="AeadGeneralMessage"/>. The caller owns and must dispose.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="flattenedJson"/> exceeds <see cref="MaxGeneralJweByteCount"/>.</exception>
    /// <exception cref="FormatException">Thrown when any structural or security invariant is violated.</exception>
    public static AeadGeneralMessage ParseFlattenedJson(
        string flattenedJson,
        string expectedAlgorithm,
        string expectedEncryption,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(flattenedJson);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedEncryption);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(flattenedJson.Length > MaxGeneralJweByteCount)
        {
            throw new ArgumentException(
                $"Flattened JSON JWE exceeds the maximum permitted size of {MaxGeneralJweByteCount} bytes.",
                nameof(flattenedJson));
        }

        byte[] jsonBytes = Encoding.UTF8.GetBytes(flattenedJson);
        ReadOnlySpan<byte> json = jsonBytes;

        //RFC 7516 §7.2.2: "The 'recipients' member MUST NOT be present when using this syntax."
        if(JwkJsonReader.ContainsKey(json, WellKnownJoseSerializationNames.RecipientsUtf8))
        {
            throw new FormatException(
                "Flattened JSON JWE MUST NOT contain a 'recipients' member (RFC 7516 §7.2.2).");
        }

        RejectCryptographicParametersInUnprotectedHeader(json);

        string? protectedEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.ProtectedUtf8);
        if(protectedEncoded is null)
        {
            throw new FormatException(
                "Flattened JSON JWE must contain a 'protected' member per RFC 7516 §7.2.2.");
        }

        string? ivEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.IvUtf8);
        string? ciphertextEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.CiphertextUtf8);
        string? tagEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.TagUtf8);

        if(ivEncoded is null || ciphertextEncoded is null || tagEncoded is null)
        {
            throw new FormatException(
                "Flattened JSON JWE must contain 'iv', 'ciphertext', and 'tag' members per RFC 7516 §7.2.2.");
        }

        //Optional top-level 'aad' (RFC 7516 §7.2.1, shared with §7.2.2): the AAD becomes
        //ASCII(BASE64URL(protected) || '.' || aad) per §5.1 step 14 / §5.2 step 15.
        string? aadEncoded = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.AadUtf8);

        //The top-level "header.kid" and "encrypted_key" are the single recipient's members,
        //hoisted out of the "recipients" array element per RFC 7516 §7.2.2.
        string? kid = JwkJsonReader.ExtractNestedStringValue(json, WellKnownJoseSerializationNames.HeaderUtf8, "kid"u8);
        string? encryptedKey = JwkJsonReader.ExtractStringValue(json, WellKnownJoseSerializationNames.EncryptedKeyUtf8);

        if(kid is null)
        {
            throw new FormatException(
                "Flattened JSON JWE must carry a top-level 'header.kid' identifying the recipient.");
        }

        if(encryptedKey is null)
        {
            throw new FormatException(
                "Flattened JSON JWE must carry a top-level 'encrypted_key'.");
        }

        AdditionalData? aad = null;
        PublicKeyMemory? epk = null;
        Nonce? iv = null;
        Ciphertext? ciphertext = null;
        AuthenticationTag? tag = null;
        List<AeadGeneralRecipient> recipients = [];

        try
        {
            using IMemoryOwner<byte> headerOwner = base64UrlDecoder(protectedEncoded, pool);
            epk = ParseAndValidateHeader(
                headerOwner.Memory.Span,
                expectedAlgorithm,
                expectedEncryption,
                base64UrlDecoder,
                CryptoFormatConversions.DefaultEpkCrvToTagConverter,
                pool,
                out IReadOnlyDictionary<string, object> header,
                out JweContentEncryption contentEncryption);

            //RFC 7516 §5.2 step 4 / §7.2.1: protected ∪ (the single top-level header) must have
            //disjoint names, and the envelope members must be unique.
            ValidateHeaderUniqueness(
                json,
                headerOwner.Memory.Span,
                [JwkJsonReader.GetObjectMemberNames(json, WellKnownJoseSerializationNames.HeaderUtf8)]);

            aad = BuildAdditionalData(protectedEncoded, aadEncoded, contentEncryption.Family, pool);

            iv = DecodeAndValidateContentParts(
                ivEncoded, ciphertextEncoded, tagEncoded, contentEncryption, base64UrlDecoder, pool,
                out ciphertext, out tag);

            recipients.Add(new AeadGeneralRecipient(kid, base64UrlDecoder(encryptedKey, pool)));

            AeadGeneralMessage result = new AeadGeneralMessage(
                header, epk, iv, ciphertext, tag, aad, recipients, expectedEncryption, expectedAlgorithm);

            //Ownership transferred to AeadGeneralMessage.
            aad = null;
            epk = null;
            iv = null;
            ciphertext = null;
            tag = null;
            recipients = [];

            return result;
        }
        finally
        {
            aad?.Dispose();
            epk?.Dispose();
            iv?.Dispose();
            ciphertext?.Dispose();
            tag?.Dispose();
            for(int i = 0; i < recipients.Count; ++i)
            {
                recipients[i].Dispose();
            }
        }
    }


    //Walks the "recipients" array and extracts each element's per-recipient "header.kid"
    //and "encrypted_key". Each element is sliced and the two string values read from the
    //slice — a string-aware brace scan keeps nested objects from biasing the depth counter.
    private static List<(string KeyId, string EncryptedKey, List<string> HeaderNames)> ParseRecipients(ReadOnlySpan<byte> json)
    {
        int recipientsKey = JwkJsonReader.IndexOfKey(json, WellKnownJoseSerializationNames.RecipientsUtf8);
        if(recipientsKey < 0)
        {
            throw new FormatException(
                "General JSON JWE must contain a 'recipients' member per RFC 7516 §7.2.1.");
        }

        int afterKey = recipientsKey + WellKnownJoseSerializationNames.RecipientsUtf8.Length + 1;
        afterKey = JwkJsonReader.SkipWhitespaceAndColon(json, afterKey);
        if(afterKey < 0 || afterKey >= json.Length || json[afterKey] != (byte)'[')
        {
            throw new FormatException("General JSON JWE 'recipients' must be an array.");
        }

        List<(string, string, List<string>)> result = [];
        int pos = afterKey + 1;

        while(pos < json.Length)
        {
            pos = SkipWhitespace(json, pos);
            if(pos >= json.Length)
            {
                break;
            }

            if(json[pos] == (byte)']')
            {
                break;
            }

            if(json[pos] == (byte)',')
            {
                pos++;
                continue;
            }

            if(json[pos] != (byte)'{')
            {
                throw new FormatException("General JSON JWE 'recipients' elements must be objects.");
            }

            int objectStart = pos;
            int depth = 1;
            pos++;
            while(pos < json.Length && depth > 0)
            {
                byte b = json[pos];
                if(b == (byte)'"')
                {
                    pos++;
                    while(pos < json.Length && json[pos] != (byte)'"')
                    {
                        if(json[pos] == (byte)'\\')
                        {
                            pos++;
                        }

                        pos++;
                    }
                }
                else if(b == (byte)'{')
                {
                    depth++;
                }
                else if(b == (byte)'}')
                {
                    depth--;
                }

                pos++;
            }

            if(depth != 0)
            {
                throw new FormatException("General JSON JWE 'recipients' element is not a well-formed object.");
            }

            ReadOnlySpan<byte> element = json[objectStart..pos];
            string? kid = JwkJsonReader.ExtractNestedStringValue(element, WellKnownJoseSerializationNames.HeaderUtf8, "kid"u8);
            string? encryptedKey = JwkJsonReader.ExtractStringValue(element, WellKnownJoseSerializationNames.EncryptedKeyUtf8);

            if(kid is null)
            {
                throw new FormatException(
                    "General JSON JWE 'recipients' element must carry a 'header.kid' identifying the recipient.");
            }

            if(encryptedKey is null)
            {
                throw new FormatException(
                    "General JSON JWE 'recipients' element must carry an 'encrypted_key'.");
            }

            List<string> headerNames = JwkJsonReader.GetObjectMemberNames(element, WellKnownJoseSerializationNames.HeaderUtf8);
            result.Add((kid, encryptedKey, headerNames));
        }

        return result;
    }


    //Validates alg/enc against the caller's policy and builds the epk public key. Shared
    //between Compact and General parsing in spirit; the General parser owns its own copy to
    //handle the OKP (X25519) and EC (NIST) epk shapes the DIDComm curves use.
    private static PublicKeyMemory ParseAndValidateHeader(
        ReadOnlySpan<byte> headerJson,
        string expectedAlgorithm,
        string expectedEncryption,
        DecodeDelegate base64UrlDecoder,
        EpkCrvToTagDelegate crvToTagConverter,
        MemoryPool<byte> pool,
        out IReadOnlyDictionary<string, object> header,
        out JweContentEncryption contentEncryption)
    {
        string? alg = JwkJsonReader.ExtractStringValue(headerJson, "alg"u8);
        string? enc = JwkJsonReader.ExtractStringValue(headerJson, "enc"u8);

        if(alg is null)
        {
            throw new FormatException(
                $"JWE protected header must contain the '{WellKnownJwkMemberNames.Alg}' parameter.");
        }

        if(!string.Equals(alg, expectedAlgorithm, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"JWE '{WellKnownJwkMemberNames.Alg}' value '{alg}' does not match the expected " +
                $"algorithm '{expectedAlgorithm}'.");
        }

        if(enc is null)
        {
            throw new FormatException(
                $"JWE protected header must contain the '{WellKnownJoseHeaderNames.Enc}' parameter.");
        }

        if(!string.Equals(enc, expectedEncryption, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Enc}' value '{enc}' does not match the expected " +
                $"encryption '{expectedEncryption}'.");
        }

        //RFC 7516 §5.2 step 5 precedes any cryptographic work: reject duplicate header names
        //(§4 / §5.2 step 4), an unsupported or malformed "crit" (RFC 7515 §4.1.11), the
        //rejected-by-design "zip" (RFC 8725 §3.6), and RSA1_5 (RFC 8725 §3.2) before key
        //agreement runs.
        JweHeaderProcessing.Validate(headerJson, alg);

        //Dispatch on the RFC 7516 §2 key management mode via the descriptor rather than on the
        //alg string. The JSON serialization paths implement only Key Agreement with Key Wrapping
        //(the DIDComm anoncrypt ECDH-ES+A*KW and authcrypt ECDH-1PU+A*KW modes); a well-formed
        //message naming any other mode is rejected here rather than silently mishandled. Direct
        //Key Agreement, Direct Encryption, and standalone Key Wrapping in the JSON serializations
        //are a separate piece of work.
        JweAlgorithm algorithm = JweAlgorithm.FromWellKnownName(alg)
            ?? throw new FormatException(
                $"JWE '{WellKnownJwkMemberNames.Alg}' value '{alg}' is not a key management algorithm " +
                "this library implements for the JSON serializations.");

        if(algorithm.Mode != JweKeyManagementMode.KeyAgreementWithKeyWrapping)
        {
            throw new NotSupportedException(
                $"JWE '{WellKnownJwkMemberNames.Alg}' value '{alg}' uses the {algorithm.Mode} key " +
                "management mode, which the JSON serialization paths do not implement. Only Key " +
                "Agreement with Key Wrapping (ECDH-ES+A*KW, ECDH-1PU+A*KW) is supported here.");
        }

        JweContentEncryption encryption = JweContentEncryption.FromWellKnownName(enc)
            ?? throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Enc}' value '{enc}' is not a content encryption " +
                "algorithm this library implements.");

        //ECDH-1PU Key Agreement with Key Wrapping commits the JWE Authentication Tag into the
        //key derivation, which is sound only for a compactly committing AEAD. draft-madden-jose-
        //ecdh-1pu-04 §2.1: "Key Agreement with Key Wrapping mode MUST only be used with content
        //encryption algorithms that are compactly committing AEADs ... Other content encryption
        //algorithms MUST be rejected." This is enforced on the parse/decrypt boundary — not only
        //on encrypt — so a forged ECDH-1PU+A*KW message naming an AES-GCM enc cannot reach the
        //key derivation, closing the multi-recipient insider-forgery vector §2.1 exists to prevent.
        if(IsEcdh1PuKeyWrap(alg) && encryption.Family != JweContentEncryptionFamily.AesCbcHmac)
        {
            throw new FormatException(
                $"JWE authcrypt algorithm '{alg}' (ECDH-1PU Key Agreement with Key Wrapping) MUST NOT " +
                $"be used with the non-committing content encryption algorithm '{enc}'; only the " +
                "AES_CBC_HMAC_SHA2 family is permitted (draft-madden-jose-ecdh-1pu-04 §2.1).");
        }

        contentEncryption = encryption;

        string? kty = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "kty"u8);
        string? crv = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "crv"u8);
        string? x = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "x"u8);
        string? y = JwkJsonReader.ExtractNestedStringValue(headerJson, "epk"u8, "y"u8);

        bool isEc = kty is not null && WellKnownKeyTypeValues.IsEc(kty);
        bool isOkp = kty is not null && WellKnownKeyTypeValues.IsOkp(kty);

        if(kty is null || crv is null || x is null)
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Epk}' must contain '{WellKnownJwkMemberNames.Kty}', " +
                $"'{WellKnownJwkMemberNames.Crv}', and '{WellKnownJwkMemberNames.X}'.");
        }

        if(!isEc && !isOkp)
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Epk}' must have '{WellKnownJwkMemberNames.Kty}' equal to " +
                $"'{WellKnownKeyTypeValues.Ec}' or '{WellKnownKeyTypeValues.Okp}'. Received '{kty}'.");
        }

        if(isEc && y is null)
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Epk}' with '{WellKnownJwkMemberNames.Kty}'='{WellKnownKeyTypeValues.Ec}' " +
                $"must contain the '{WellKnownJwkMemberNames.Y}' coordinate.");
        }

        PublicKeyMemory epk = DecodeAndValidateEpk(x, y, crv, base64UrlDecoder, crvToTagConverter, pool);

        var epkDict = new Dictionary<string, object>(4)
        {
            [WellKnownJwkMemberNames.Kty] = kty,
            [WellKnownJwkMemberNames.Crv] = crv,
            [WellKnownJwkMemberNames.X] = x
        };

        if(y is not null)
        {
            epkDict[WellKnownJwkMemberNames.Y] = y;
        }

        var headerDict = new Dictionary<string, object>(5)
        {
            [WellKnownJwkMemberNames.Alg] = alg,
            [WellKnownJoseHeaderNames.Enc] = enc,
            [WellKnownJoseHeaderNames.Epk] = epkDict
        };

        //apu/apv are integrity-protected agreement info; carry them forward so the decrypt
        //orchestrator can feed the exact base64url-decoded bytes into the KDF.
        string? apu = JwkJsonReader.ExtractStringValue(headerJson, "apu"u8);
        if(apu is not null)
        {
            headerDict[WellKnownJoseHeaderNames.Apu] = apu;
        }

        string? apv = JwkJsonReader.ExtractStringValue(headerJson, "apv"u8);
        if(apv is not null)
        {
            headerDict[WellKnownJoseHeaderNames.Apv] = apv;
        }

        string? skid = JwkJsonReader.ExtractStringValue(headerJson, "skid"u8);
        if(skid is not null)
        {
            headerDict[WellKnownJoseHeaderNames.Skid] = skid;
        }

        header = headerDict;

        return epk;
    }


    private static PublicKeyMemory DecodeAndValidateEpk(
        string xEncoded,
        string? yEncoded,
        string crv,
        DecodeDelegate base64UrlDecoder,
        EpkCrvToTagDelegate crvToTagConverter,
        MemoryPool<byte> pool)
    {
        (Tag epkTag, EllipticCurveTypes curveType) = crvToTagConverter(crv);

        //A Raw-encoded exchange tag (OKP, e.g. X25519 per RFC 8037) is a single public key,
        //not an EC point: decode x as the whole key and skip the EC point-on-curve check.
        if(epkTag.Get<EncodingScheme>().Equals(EncodingScheme.Raw))
        {
            return new PublicKeyMemory(base64UrlDecoder(xEncoded, pool), epkTag);
        }

        if(yEncoded is null)
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Epk}' for curve '{crv}' requires the " +
                $"'{WellKnownJwkMemberNames.Y}' coordinate.");
        }

        using IMemoryOwner<byte> xDecoded = base64UrlDecoder(xEncoded, pool);
        using IMemoryOwner<byte> yDecoded = base64UrlDecoder(yEncoded, pool);

        ReadOnlySpan<byte> xSpan = xDecoded.Memory.Span;
        ReadOnlySpan<byte> ySpan = yDecoded.Memory.Span;

        if(!EllipticCurveUtilities.CheckPointOnCurve(xSpan, ySpan, curveType))
        {
            throw new FormatException(
                $"JWE '{WellKnownJoseHeaderNames.Epk}' point is not on the {crv} curve. " +
                $"Possible invalid curve attack.");
        }

        IMemoryOwner<byte> pointOwner = pool.Rent(1 + xSpan.Length + ySpan.Length);
        pointOwner.Memory.Span[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        xSpan.CopyTo(pointOwner.Memory.Span[1..]);
        ySpan.CopyTo(pointOwner.Memory.Span[(1 + xSpan.Length)..]);

        return new PublicKeyMemory(pointOwner, epkTag);
    }


    //Builds the AEAD additional authenticated data. RFC 7516 §5.1 step 14 sets AAD to
    //ASCII(BASE64URL(protected)); §7.2.1 extends it to ASCII(BASE64URL(protected) || '.' || aad)
    //when the optional 'aad' member is present. The tag is family-appropriate so the value's
    //CBOM provenance reflects whether it feeds an AES-GCM or AES_CBC_HMAC_SHA2 operation.
    private static AdditionalData BuildAdditionalData(
        string protectedEncoded,
        string? aadEncoded,
        JweContentEncryptionFamily family,
        MemoryPool<byte> pool)
    {
        string aadString = aadEncoded is null
            ? protectedEncoded
            : string.Concat(protectedEncoded, ".", aadEncoded);

        int aadByteCount = Encoding.ASCII.GetByteCount(aadString);
        IMemoryOwner<byte> aadOwner = pool.Rent(aadByteCount);
        Encoding.ASCII.GetBytes(aadString, aadOwner.Memory.Span);

        Tag aadTag = family switch
        {
            JweContentEncryptionFamily.AesGcm => CryptoTags.AesGcmAad,
            JweContentEncryptionFamily.XChaCha20Poly1305 => CryptoTags.Xc20pAad,
            _ => CryptoTags.AesCbcHmacAad
        };

        return new AdditionalData(aadOwner, aadTag);
    }


    //Decodes the IV, ciphertext, and tag with family-appropriate tags and validates the IV and
    //tag lengths against the declared content encryption algorithm (RFC 7516 §5.2 step 5). The
    //IV is returned; the ciphertext and tag are out parameters. On any failure every component
    //created here is disposed and the out parameters are left null, so the caller's own cleanup
    //has nothing partially constructed to release.
    private static Nonce DecodeAndValidateContentParts(
        string ivEncoded,
        string ciphertextEncoded,
        string tagEncoded,
        JweContentEncryption contentEncryption,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> pool,
        out Ciphertext ciphertext,
        out AuthenticationTag tag)
    {
        (Tag ivTag, Tag ciphertextTag, Tag authTag) = contentEncryption.Family switch
        {
            JweContentEncryptionFamily.AesGcm => (CryptoTags.AesGcmIv, CryptoTags.AesGcmCiphertext, CryptoTags.AesGcmAuthTag),
            JweContentEncryptionFamily.XChaCha20Poly1305 => (CryptoTags.Xc20pIv, CryptoTags.Xc20pCiphertext, CryptoTags.Xc20pAuthTag),
            _ => (CryptoTags.AesCbcHmacIv, CryptoTags.AesCbcHmacCiphertext, CryptoTags.AesCbcHmacAuthTag)
        };

        Nonce? iv = null;
        ciphertext = null!;
        tag = null!;
        bool isComplete = false;
        try
        {
            iv = new Nonce(base64UrlDecoder(ivEncoded, pool), ivTag);
            ciphertext = new Ciphertext(base64UrlDecoder(ciphertextEncoded, pool), ciphertextTag);
            tag = new AuthenticationTag(base64UrlDecoder(tagEncoded, pool), authTag);

            if(iv.AsReadOnlySpan().Length != contentEncryption.IvByteLength)
            {
                throw new FormatException(
                    $"JWE 'iv' length {iv.AsReadOnlySpan().Length} does not match the " +
                    $"{contentEncryption.IvByteLength}-byte IV required by '{contentEncryption.Name}'.");
            }

            if(tag.AsReadOnlySpan().Length != contentEncryption.TagByteLength)
            {
                throw new FormatException(
                    $"JWE 'tag' length {tag.AsReadOnlySpan().Length} does not match the " +
                    $"{contentEncryption.TagByteLength}-byte tag required by '{contentEncryption.Name}'.");
            }

            isComplete = true;

            return iv;
        }
        finally
        {
            if(!isComplete)
            {
                iv?.Dispose();
                ciphertext?.Dispose();
                tag?.Dispose();
                ciphertext = null!;
                tag = null!;
            }
        }
    }


    //Enforces RFC 7516 §5.2 step 4 ("the resulting JOSE Header does not contain duplicate Header
    //Parameter names ... including that the same name MUST NOT occur in distinct JSON object
    //values that together comprise the JOSE Header") and §7.2.1 ("the Header Parameter names in
    //the three locations MUST be disjoint"). The check is per recipient: the JOSE Header for
    //recipient i is protected ∪ unprotected ∪ header_i, so two different recipients may each carry
    //their own 'kid' — that is not a collision — but a name shared between protected/unprotected or
    //between either of those and a recipient's own header is rejected. Envelope-level duplicate
    //members (a repeated 'protected'/'iv'/'ciphertext'/'tag') are rejected too, since the readers
    //here take the first occurrence while a last-value parser would diverge.
    private static void ValidateHeaderUniqueness(
        ReadOnlySpan<byte> envelopeJson,
        ReadOnlySpan<byte> protectedHeaderJson,
        IReadOnlyList<List<string>> recipientHeaderNames)
    {
        if(JwkJsonReader.HasDuplicateTopLevelKeys(envelopeJson))
        {
            throw new FormatException(
                "JWE JSON serialization contains a duplicate top-level member; envelope members "
                + "MUST be unique (RFC 7516 §7.2.1 / §5.2 step 4).");
        }

        //The protected header is already verified internally unique by JweHeaderProcessing.Validate.
        HashSet<string> shared = new(JwkJsonReader.GetTopLevelKeyNames(protectedHeaderJson), StringComparer.Ordinal);

        foreach(string name in JwkJsonReader.GetObjectMemberNames(envelopeJson, "unprotected"u8))
        {
            if(!shared.Add(name))
            {
                throw new FormatException(
                    $"JWE JOSE Header parameter '{name}' occurs more than once across the protected "
                    + "and shared unprotected headers; the names MUST be unique and the locations "
                    + "disjoint (RFC 7516 §7.2.1 / §5.2 step 4).");
            }
        }

        foreach(List<string> headerNames in recipientHeaderNames)
        {
            HashSet<string> perRecipient = new(StringComparer.Ordinal);
            foreach(string name in headerNames)
            {
                if(shared.Contains(name) || !perRecipient.Add(name))
                {
                    throw new FormatException(
                        $"JWE JOSE Header parameter '{name}' appears in more than one of the "
                        + "protected, shared unprotected, and per-recipient header locations; they "
                        + "MUST be disjoint (RFC 7516 §7.2.1 / §5.2 step 4).");
                }
            }
        }
    }


    //The cryptographic JOSE Header parameters this library reads from the protected header. A
    //Shared Unprotected Header that carries any of them would change key agreement, derivation
    //(apu/apv), or algorithm selection without integrity protection; such a message is rejected
    //rather than processed against the protected values while silently ignoring the unprotected
    //ones. Benign, non-cryptographic members (e.g. the 'jku' key hint) are not listed and are
    //permitted, matching the ECDH-1PU Appendix B vector.
    private static (byte[] Utf8, string Name)[] CryptographicHeaderParameters { get; } =
    [
        ("alg"u8.ToArray(), WellKnownJwkMemberNames.Alg),
        ("enc"u8.ToArray(), WellKnownJoseHeaderNames.Enc),
        ("apu"u8.ToArray(), WellKnownJoseHeaderNames.Apu),
        ("apv"u8.ToArray(), WellKnownJoseHeaderNames.Apv),
        ("skid"u8.ToArray(), WellKnownJoseHeaderNames.Skid),
        ("zip"u8.ToArray(), "zip"),
    ];


    //Rejects a Shared Unprotected Header that carries a cryptographic parameter. The check reads
    //inside the 'unprotected' object only — the 'protected' member is an opaque base64url string
    //at this level, so a parameter found here is genuinely in the unprotected location.
    private static void RejectCryptographicParametersInUnprotectedHeader(ReadOnlySpan<byte> json)
    {
        if(!JwkJsonReader.ContainsKey(json, "unprotected"u8))
        {
            return;
        }

        foreach((byte[] utf8, string name) in CryptographicHeaderParameters)
        {
            if(JwkJsonReader.ExtractNestedStringValue(json, "unprotected"u8, utf8) is not null)
            {
                throw new FormatException(
                    $"JWE Shared Unprotected Header carries the cryptographic parameter '{name}'; "
                    + "this library reads cryptographic JOSE Header parameters only from the "
                    + "integrity-protected 'protected' header.");
            }
        }
    }


    //Whether the alg is one of the ECDH-1PU Key Agreement with Key Wrapping algorithms, whose
    //§2.1 compactly-committing-AEAD constraint the parse boundary enforces. ECDH-ES+A*KW
    //(anoncrypt) carries no sender authentication and places no such constraint on enc.
    private static bool IsEcdh1PuKeyWrap(string algorithm) =>
        WellKnownJweAlgorithms.IsEcdh1PuA128Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdh1PuA192Kw(algorithm)
        || WellKnownJweAlgorithms.IsEcdh1PuA256Kw(algorithm);


    private static int SkipWhitespace(ReadOnlySpan<byte> json, int pos)
    {
        while(pos < json.Length
            && (json[pos] == (byte)' ' || json[pos] == (byte)'\t'
                || json[pos] == (byte)'\r' || json[pos] == (byte)'\n'))
        {
            pos++;
        }

        return pos;
    }
}
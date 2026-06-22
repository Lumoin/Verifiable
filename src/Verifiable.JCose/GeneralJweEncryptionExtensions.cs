using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Recipient input for a multi-recipient JWE encryption: the recipient's static public key
/// for ECDH agreement and the <c>kid</c> placed in that recipient's per-recipient header.
/// </summary>
/// <param name="KeyId">
/// The recipient's <c>kid</c>. In DIDComm v2 a DID URL to a <c>keyAgreement</c>
/// verification method.
/// </param>
/// <param name="PublicKey">The recipient's static public key on the shared curve.</param>
public readonly record struct GeneralJweRecipientInput(string KeyId, PublicKeyMemory PublicKey);


/// <summary>
/// Encrypt-side orchestration for multi-recipient JWE in General JSON Serialization —
/// anoncrypt (ECDH-ES+A*KW) and authcrypt (ECDH-1PU+A*KW) for DIDComm v2.
/// </summary>
/// <remarks>
/// <para>
/// One Content Encryption Key (CEK) encrypts the content once; the CEK is then wrapped once
/// per recipient under a key encryption key derived from that recipient's ECDH agreement
/// against a single shared ephemeral key. The ephemeral key pair is generated once and
/// carried in the JWE Protected Header, per
/// <see href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#section-2.1">draft-madden-jose-ecdh-1pu-04 §2.1</see>
/// and RFC 7516 §7.2.
/// </para>
/// <para>
/// <strong>Order of operations (1PU §2.1).</strong> Key Agreement with Key Wrapping commits
/// the JWE Authentication Tag into each recipient's key derivation, which requires the
/// content to be encrypted before the per-recipient wrap. The flow therefore is: generate a
/// random CEK → assemble and encode the protected header (the AAD) → encrypt the content,
/// producing the tag → for each recipient, agree, derive the KEK (tag-committed for 1PU,
/// no tag for ECDH-ES per RFC 7518 §4.6) and wrap the CEK. This is the §2.1 deferral of
/// RFC 7516 §5.1 steps 3–8 until after step 15.
/// </para>
/// </remarks>
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "The caller takes ownership of the returned GeneralJweMessage and is responsible for disposing it; transient state is released on every path.")]
public static class GeneralJweEncryptionExtensions
{
    /// <summary>
    /// Encrypts an anoncrypt (ECDH-ES+A*KW) multi-recipient JWE in General JSON Serialization.
    /// </summary>
    /// <param name="plaintext">The plaintext bytes to encrypt once for all recipients.</param>
    /// <param name="recipients">The recipients, each with a public key and a <c>kid</c>.</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> value, e.g. <see cref="WellKnownJweAlgorithms.EcdhEsA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c> value, e.g. <see cref="WellKnownJweEncryptionAlgorithms.A256Gcm"/>.</param>
    /// <param name="protectedHeaderExtras">
    /// Extra integrity-protected header parameters (e.g. <c>apu</c>/<c>apv</c>) merged into the
    /// protected header, or <see langword="null"/>. <c>alg</c>, <c>enc</c>, and <c>epk</c> are
    /// added by this method and must not be supplied here.
    /// </param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, generated on the recipients' curve.</param>
    /// <param name="headerSerializer">Delegate for serializing the completed header to UTF-8 JSON.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the EPK tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-ES agreement delegate.</param>
    /// <param name="keyDerivationDelegate">The Concat KDF delegate (no tag commitment for ECDH-ES).</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The content encryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="GeneralJweMessage"/>. The caller owns and must dispose it.</returns>
    public static async ValueTask<GeneralJweMessage> EncryptAnoncryptAsync(
        ReadOnlyMemory<byte> plaintext,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        IReadOnlyDictionary<string, object>? protectedHeaderExtras,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientKeyAgreementEncryptDelegate agreementDelegate,
        KeyDerivationDelegate keyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(keyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        }

        //ECDH-ES anoncrypt has no sender static key. Each recipient's agreement uses the
        //caller-held ephemeral private key only; the per-recipient wrap derives without tag
        //commitment per RFC 7518 §4.6 (ECDH-ES does not commit the content tag).
        return await EncryptCoreAsync(
            plaintext,
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            protectedHeaderExtras,
            ephemeralKey,
            senderPrivateKey: null,
            isTagCommitted: false,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            anoncryptAgreement: agreementDelegate,
            authcryptAgreement: null,
            keyDerivationDelegate,
            authenticatedKeyDerivationDelegate: null,
            keyWrapDelegate,
            aeadEncryptDelegate,
            pool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Encrypts an authcrypt (ECDH-1PU+A*KW) multi-recipient JWE in General JSON Serialization.
    /// </summary>
    /// <remarks>
    /// Key Agreement with Key Wrapping mode MUST only be used with the AES_CBC_HMAC_SHA2
    /// content encryption family (1PU §2.1, compactly committing AEAD requirement). This
    /// method rejects any other <paramref name="contentEncryptionAlgorithm"/>.
    /// </remarks>
    /// <param name="plaintext">The plaintext bytes to encrypt once for all recipients.</param>
    /// <param name="recipients">The recipients, each with a public key and a <c>kid</c>.</param>
    /// <param name="keyManagementAlgorithm">The <c>alg</c> value, e.g. <see cref="WellKnownJweAlgorithms.Ecdh1PuA256Kw"/>.</param>
    /// <param name="contentEncryptionAlgorithm">The <c>enc</c> value; MUST be an AES_CBC_HMAC_SHA2 algorithm.</param>
    /// <param name="protectedHeaderExtras">Extra integrity-protected header parameters (typically <c>apu</c>/<c>apv</c>/<c>skid</c>), or <see langword="null"/>.</param>
    /// <param name="ephemeralKey">The shared ephemeral key pair, generated on the recipients' curve.</param>
    /// <param name="senderStaticPrivateKey">The sender's static private key for the authenticating agreement (Zs).</param>
    /// <param name="headerSerializer">Delegate for serializing the completed header to UTF-8 JSON.</param>
    /// <param name="base64UrlEncoder">Delegate for Base64url encoding.</param>
    /// <param name="tagToCrvConverter">Delegate mapping the EPK tag to a JWK curve name.</param>
    /// <param name="generateContentEncryptionKey">Entropy delegate producing the random CEK bytes.</param>
    /// <param name="agreementDelegate">The multi-recipient ECDH-1PU agreement delegate.</param>
    /// <param name="authenticatedKeyDerivationDelegate">The tag-committed Concat KDF delegate.</param>
    /// <param name="keyWrapDelegate">The RFC 3394 key wrap delegate.</param>
    /// <param name="aeadEncryptDelegate">The AES_CBC_HMAC_SHA2 content encryption delegate.</param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A <see cref="GeneralJweMessage"/>. The caller owns and must dispose it.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="contentEncryptionAlgorithm"/> is not an AES_CBC_HMAC_SHA2
    /// algorithm, per 1PU §2.1.
    /// </exception>
    public static async ValueTask<GeneralJweMessage> EncryptAuthcryptAsync(
        ReadOnlyMemory<byte> plaintext,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        IReadOnlyDictionary<string, object>? protectedHeaderExtras,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        PrivateKeyMemory senderStaticPrivateKey,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreementDelegate,
        AuthenticatedKeyDerivationDelegate authenticatedKeyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyManagementAlgorithm);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
        ArgumentNullException.ThrowIfNull(ephemeralKey);
        ArgumentNullException.ThrowIfNull(senderStaticPrivateKey);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(tagToCrvConverter);
        ArgumentNullException.ThrowIfNull(generateContentEncryptionKey);
        ArgumentNullException.ThrowIfNull(agreementDelegate);
        ArgumentNullException.ThrowIfNull(authenticatedKeyDerivationDelegate);
        ArgumentNullException.ThrowIfNull(keyWrapDelegate);
        ArgumentNullException.ThrowIfNull(aeadEncryptDelegate);
        ArgumentNullException.ThrowIfNull(pool);

        if(recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        }

        //1PU §2.1: Key Agreement with Key Wrapping MUST only be used with compactly committing
        //AEADs — the AES_CBC_HMAC_SHA2 family. Any other content encryption algorithm MUST be
        //rejected because the tag commitment that authenticates the sender to multiple
        //recipients holds only for those algorithms.
        if(JweContentEncryption.FromWellKnownName(contentEncryptionAlgorithm)
            is not { Family: JweContentEncryptionFamily.AesCbcHmac })
        {
            throw new ArgumentException(
                $"ECDH-1PU Key Agreement with Key Wrapping mode MUST only be used with the " +
                $"AES_CBC_HMAC_SHA2 content encryption family (draft-madden-jose-ecdh-1pu-04 §2.1). " +
                $"'{contentEncryptionAlgorithm}' is not compactly committing and is rejected.",
                nameof(contentEncryptionAlgorithm));
        }

        return await EncryptCoreAsync(
            plaintext,
            recipients,
            keyManagementAlgorithm,
            contentEncryptionAlgorithm,
            protectedHeaderExtras,
            ephemeralKey,
            senderStaticPrivateKey,
            isTagCommitted: true,
            headerSerializer,
            base64UrlEncoder,
            tagToCrvConverter,
            generateContentEncryptionKey,
            anoncryptAgreement: null,
            authcryptAgreement: agreementDelegate,
            keyDerivationDelegate: null,
            authenticatedKeyDerivationDelegate,
            keyWrapDelegate,
            aeadEncryptDelegate,
            pool,
            cancellationToken).ConfigureAwait(false);
    }


    private static async ValueTask<GeneralJweMessage> EncryptCoreAsync(
        ReadOnlyMemory<byte> plaintext,
        IReadOnlyList<GeneralJweRecipientInput> recipients,
        string keyManagementAlgorithm,
        string contentEncryptionAlgorithm,
        IReadOnlyDictionary<string, object>? protectedHeaderExtras,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeralKey,
        PrivateKeyMemory? senderPrivateKey,
        bool isTagCommitted,
        JwtHeaderSerializer headerSerializer,
        EncodeDelegate base64UrlEncoder,
        TagToEpkCrvDelegate tagToCrvConverter,
        GenerateNonceDelegate generateContentEncryptionKey,
        MultiRecipientKeyAgreementEncryptDelegate? anoncryptAgreement,
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate? authcryptAgreement,
        KeyDerivationDelegate? keyDerivationDelegate,
        AuthenticatedKeyDerivationDelegate? authenticatedKeyDerivationDelegate,
        KeyWrapDelegate keyWrapDelegate,
        AeadEncryptDelegate aeadEncryptDelegate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        PublicKeyMemory ephemeralPublic = ephemeralKey.PublicKey;
        PrivateKeyMemory ephemeralPrivate = ephemeralKey.PrivateKey;

        //Build the epk JWK shape from the shared ephemeral public key. Coordinate strings are
        //computed before any await so the ReadOnlySpan does not cross an await boundary.
        Dictionary<string, object> epkJwk = BuildEpkJwk(ephemeralPublic, tagToCrvConverter, base64UrlEncoder);

        var completeHeader = new JwtHeader(3 + (protectedHeaderExtras?.Count ?? 0))
        {
            [WellKnownJwkMemberNames.Alg] = keyManagementAlgorithm,
            [WellKnownJoseHeaderNames.Enc] = contentEncryptionAlgorithm,
            [WellKnownJoseHeaderNames.Epk] = epkJwk
        };

        if(protectedHeaderExtras is not null)
        {
            foreach(KeyValuePair<string, object> extra in protectedHeaderExtras)
            {
                completeHeader[extra.Key] = extra.Value;
            }
        }

        ReadOnlySpan<byte> headerJsonSpan = headerSerializer(completeHeader);
        using IMemoryOwner<byte> headerJsonOwner = pool.Rent(headerJsonSpan.Length);
        headerJsonSpan.CopyTo(headerJsonOwner.Memory.Span);

        string headerEncoded = base64UrlEncoder(headerJsonOwner.Memory.Span);

        int aadByteCount = Encoding.ASCII.GetByteCount(headerEncoded);
        IMemoryOwner<byte> aadRawOwner = pool.Rent(aadByteCount);
        Encoding.ASCII.GetBytes(headerEncoded, aadRawOwner.Memory.Span);
        using AdditionalData aad = new AdditionalData(aadRawOwner, CryptoTags.AesCbcHmacAad);

        //apu/apv are the integrity-protected agreement info already on the wire as base64url
        //strings; the KDF needs their decoded bytes. Decode once here for every recipient.
        using IMemoryOwner<byte>? apuOwner = DecodeOptionalHeaderValue(completeHeader, WellKnownJoseHeaderNames.Apu, pool, out int apuLength);
        using IMemoryOwner<byte>? apvOwner = DecodeOptionalHeaderValue(completeHeader, WellKnownJoseHeaderNames.Apv, pool, out int apvLength);

        //RFC 7516 §5.1 step 2: generate a random CEK of the content algorithm's key length.
        //The entropy seam produces a Nonce purely as a random-bytes carrier; its bytes are
        //copied into a SymmetricKeyMemory tagged as the CEK and the transient Nonce disposed.
        JweContentEncryption contentEncryption = JweContentEncryption.FromWellKnownName(contentEncryptionAlgorithm)
            ?? throw new ArgumentException(
                $"Unsupported content encryption algorithm '{contentEncryptionAlgorithm}'.",
                nameof(contentEncryptionAlgorithm));
        int cekByteLength = contentEncryption.CekByteLength;
        Tag cekTag = contentEncryption.Family switch
        {
            JweContentEncryptionFamily.AesCbcHmac => CryptoTags.AesCbcHmacCek,
            JweContentEncryptionFamily.XChaCha20Poly1305 => CryptoTags.Xc20pCek,
            _ => CryptoTags.AesGcmCek
        };

        //Tag the CEK entropy with the content family's CEK tag (not a hardcoded AES-CBC-HMAC IV tag) so
        //CBOM/telemetry attributes it to the actual algorithm (GCM/XC20P/CBC-HMAC). Provenance only — no
        //cryptographic behaviour depends on the tag.
        (Nonce cekEntropy, _) = generateContentEncryptionKey(cekByteLength, cekTag, pool);
        IMemoryOwner<byte> cekOwner = pool.Rent(cekByteLength);
        AeadEncryptResult? encryptResult = null;
        var recipientEntries = new List<GeneralJweRecipient>(recipients.Count);

        try
        {
            cekEntropy.AsReadOnlySpan().CopyTo(cekOwner.Memory.Span[..cekByteLength]);
        }
        finally
        {
            cekEntropy.Dispose();
        }

        using SymmetricKeyMemory cek = new SymmetricKeyMemory(cekOwner, cekTag);

        try
        {
            //RFC 7516 §5.1 step 15 (1PU §2.1: performed before the per-recipient wrap so the
            //resulting tag can be committed into each recipient's key derivation).
            encryptResult = await aeadEncryptDelegate(
                plaintext, cek, aad, pool, cancellationToken).ConfigureAwait(false);

            int keydataLenBits = JweKeyManagement.RequireKeyWrapBits(keyManagementAlgorithm);

            //The committed tag is the just-produced JWE Authentication Tag (1PU §2.1). Copy
            //it into pooled memory so the span does not cross the per-recipient await points.
            IMemoryOwner<byte>? committedTagOwner = null;
            ReadOnlyMemory<byte> tagForCommitment = ReadOnlyMemory<byte>.Empty;
            if(isTagCommitted)
            {
                ReadOnlySpan<byte> tagSpan = encryptResult.Tag.AsReadOnlySpan();
                committedTagOwner = pool.Rent(tagSpan.Length);
                tagSpan.CopyTo(committedTagOwner.Memory.Span);
                tagForCommitment = committedTagOwner.Memory[..tagSpan.Length];
            }

            using IMemoryOwner<byte>? committedTagOwnerScope = committedTagOwner;

            for(int i = 0; i < recipients.Count; ++i)
            {
                GeneralJweRecipientInput recipient = recipients[i];

                using SharedSecret sharedSecret = isTagCommitted
                    ? await AgreeAuthcryptAsync(
                        authcryptAgreement!, recipient.PublicKey, ephemeralPrivate, senderPrivateKey!, pool, cancellationToken).ConfigureAwait(false)
                    : await AgreeAnoncryptAsync(
                        anoncryptAgreement!, recipient.PublicKey, ephemeralPrivate, pool, cancellationToken).ConfigureAwait(false);

                using ContentEncryptionKey kek = isTagCommitted
                    ? authenticatedKeyDerivationDelegate!(
                        sharedSecret,
                        keyManagementAlgorithm,
                        apuOwner is null ? ReadOnlySpan<byte>.Empty : apuOwner.Memory.Span[..apuLength],
                        apvOwner is null ? ReadOnlySpan<byte>.Empty : apvOwner.Memory.Span[..apvLength],
                        keydataLenBits,
                        tagForCommitment.Span,
                        pool)
                    : keyDerivationDelegate!(
                        sharedSecret,
                        keyManagementAlgorithm,
                        apuOwner is null ? ReadOnlySpan<byte>.Empty : apuOwner.Memory.Span[..apuLength],
                        apvOwner is null ? ReadOnlySpan<byte>.Empty : apvOwner.Memory.Span[..apvLength],
                        keydataLenBits,
                        pool);

                using SymmetricKeyMemory kekKey = kek.UseKey();
                Ciphertext wrapped = await keyWrapDelegate(
                    kekKey, cek, pool, cancellationToken).ConfigureAwait(false);

                recipientEntries.Add(new GeneralJweRecipient(recipient.KeyId, wrapped));
            }

            //Ownership of the shared ephemeral public key transfers into the message; the
            //private half remains the caller's to dispose.
            PublicKeyMemory epkForMessage = CopyPublicKey(ephemeralPublic, pool);

            GeneralJweMessage message = new GeneralJweMessage(
                completeHeader, headerEncoded, epkForMessage, encryptResult, recipientEntries, contentEncryptionAlgorithm);

            encryptResult = null;
            recipientEntries = [];

            return message;
        }
        finally
        {
            encryptResult?.Dispose();
            for(int i = 0; i < recipientEntries.Count; ++i)
            {
                recipientEntries[i].Dispose();
            }
        }
    }


    private static ValueTask<SharedSecret> AgreeAnoncryptAsync(
        MultiRecipientKeyAgreementEncryptDelegate agreement,
        PublicKeyMemory recipientPublicKey,
        PrivateKeyMemory ephemeralPrivate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken) =>
        ephemeralPrivate.WithKeyBytesAsync(
            static (ephemeralBytes, state) =>
                state.Agreement(state.RecipientPublicKey, ephemeralBytes, state.Pool, state.CancellationToken),
            (Agreement: agreement,
             RecipientPublicKey: recipientPublicKey,
             Pool: pool,
             CancellationToken: cancellationToken));


    //Both the ephemeral and the sender static private key bytes are needed at the same time
    //for Z = Ze || Zs. WithKeyBytesAsync exposes one key's bytes per call, so the calls
    //nest: the outer exposes the ephemeral bytes, the inner exposes the sender bytes, and
    //the inner static lambda runs the agreement with both in scope. State tuples thread all
    //needed values so neither lambda captures a local (no closure allocation).
    private static ValueTask<SharedSecret> AgreeAuthcryptAsync(
        MultiRecipientAuthenticatedKeyAgreementEncryptDelegate agreement,
        PublicKeyMemory recipientPublicKey,
        PrivateKeyMemory ephemeralPrivate,
        PrivateKeyMemory senderPrivate,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken) =>
        ephemeralPrivate.WithKeyBytesAsync(
            static (ephemeralBytes, outer) =>
                outer.SenderPrivate.WithKeyBytesAsync(
                    static (senderBytes, inner) =>
                        inner.Agreement(
                            inner.RecipientPublicKey,
                            inner.EphemeralBytes,
                            senderBytes,
                            inner.Pool,
                            inner.CancellationToken),
                    (outer.Agreement,
                     outer.RecipientPublicKey,
                     EphemeralBytes: ephemeralBytes,
                     outer.Pool,
                     outer.CancellationToken)),
            (Agreement: agreement,
             RecipientPublicKey: recipientPublicKey,
             SenderPrivate: senderPrivate,
             Pool: pool,
             CancellationToken: cancellationToken));


    private static Dictionary<string, object> BuildEpkJwk(
        PublicKeyMemory ephemeralPublic,
        TagToEpkCrvDelegate tagToCrvConverter,
        EncodeDelegate base64UrlEncoder)
    {
        Tag epkTag = ephemeralPublic.Tag;
        ReadOnlySpan<byte> epkKeySpan = ephemeralPublic.AsReadOnlySpan();
        string crv = tagToCrvConverter(epkTag);

        if(epkTag.Get<EncodingScheme>().Equals(EncodingScheme.Raw))
        {
            return new Dictionary<string, object>(3)
            {
                [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Okp,
                [WellKnownJwkMemberNames.Crv] = crv,
                [WellKnownJwkMemberNames.X] = base64UrlEncoder(epkKeySpan)
            };
        }

        int coordinateLength = (epkKeySpan.Length - 1) / 2;

        return new Dictionary<string, object>(4)
        {
            [WellKnownJwkMemberNames.Kty] = WellKnownKeyTypeValues.Ec,
            [WellKnownJwkMemberNames.Crv] = crv,
            [WellKnownJwkMemberNames.X] = base64UrlEncoder(epkKeySpan.Slice(1, coordinateLength)),
            [WellKnownJwkMemberNames.Y] = base64UrlEncoder(epkKeySpan.Slice(1 + coordinateLength, coordinateLength))
        };
    }


    private static PublicKeyMemory CopyPublicKey(PublicKeyMemory source, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> span = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(span.Length);
        span.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }


    //Decodes a base64url header value (apu/apv) into pooled bytes, or returns null with a
    //zero length when the header parameter is absent. base64url is a BCL transform (not a
    //crypto-driver concern), so the in-box Base64Url API is used directly here.
    private static IMemoryOwner<byte>? DecodeOptionalHeaderValue(
        JwtHeader header,
        string parameterName,
        MemoryPool<byte> pool,
        out int length)
    {
        length = 0;
        if(!header.TryGetValue(parameterName, out object? value) || value is not string encoded || encoded.Length == 0)
        {
            return null;
        }

        int maxLength = System.Buffers.Text.Base64Url.GetMaxDecodedLength(encoded.Length);
        IMemoryOwner<byte> owner = pool.Rent(maxLength);
        if(!System.Buffers.Text.Base64Url.TryDecodeFromChars(encoded, owner.Memory.Span, out int written))
        {
            owner.Dispose();
            throw new FormatException($"Header parameter '{parameterName}' is not valid base64url.");
        }

        length = written;

        return owner;
    }


}

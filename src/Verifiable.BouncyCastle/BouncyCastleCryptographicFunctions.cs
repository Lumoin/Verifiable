using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle
{
    /// <summary>
    /// Provides cryptographic signing, verification, and digest functions using the BouncyCastle
    /// library. This includes Ed25519, ECDSA (P-256, P-384, P-521, secp256k1), RSA PKCS#1 v1.5, RSA-PSS,
    /// and X25519 key agreement. All signing operations produce pool-allocated signatures tagged
    /// with their algorithm. All ECDSA signatures use the fixed-size IEEE P1363 (r || s) encoding.
    /// Every verification member answers <c>false</c>, raising nothing, for presented public key and
    /// signature octets it or BouncyCastle refuses, and reads only the encodings its algorithm
    /// defines (for RSA also the bare modulus under the exponent 65537, this library's own
    /// convention, not RFC 8017's). Every RSA member reads the public key octets by one rule. The
    /// octets do not state their own encoding, so they are read by form, in this order. (1) Octets
    /// that are exactly the DER <c>RSAPublicKey</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix A.1.1</see>
    /// (a SEQUENCE of two INTEGERs with nothing after them inside the SEQUENCE and nothing after the
    /// SEQUENCE), whatever their length, are that modulus and that exponent. (2) Any other octets
    /// are the bare modulus they spell, under the exponent 65537, and octets whose first octet is
    /// zero are no modulus. So a bare modulus whose octets happen to be exactly such a structure is
    /// read as that structure. The JWK reader hands a bare modulus of 256 or 512 octets, and the
    /// library's managed certificate verifiers one of the certificate's own size after holding its
    /// exponent to 65537 themselves; <c>did:key</c>, a COSE_Key and a certificate's subject public
    /// key hand the DER <c>RSAPublicKey</c>, which the first arm reads. A bare modulus is held to the minimum number
    /// of octets, the rule <see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518
    /// Section 2</see> states for the Base64urlUInt a JWK's <c>n</c> is: "The octet sequence MUST
    /// utilize the minimum number of octets needed to represent the value." Every reading is held to
    /// <see cref="RsaUtilities.IsValidPublicKey"/> before anything is constructed from it. What each
    /// member answers <c>false</c> for, by algorithm. ECDSA: a public key other than 0x02
    /// or 0x03 at the compressed length or 0x04 at the uncompressed length (the hybrid 0x06 and 0x07 and
    /// the infinity encoding included), a point the curve's decoder refuses, and a signature that is not
    /// exactly the two components. RSA (PKCS#1 v1.5 and PSS): an exact DER modulus or exponent that is
    /// not positive, a bare modulus whose first octet is zero, a reading <see cref="RsaUtilities.IsValidPublicKey"/> refuses (an exponent below 3, not
    /// below the modulus or even, a modulus that is even or below 1024 bits), parameters BouncyCastle refuses
    /// to construct (a modulus with a small prime factor), a modulus the signer's initialization refuses, a
    /// signature that is not the modulus length or whose value is 0, 1, n - 1 or more, and for PSS under a
    /// modulus whose bit length is 1 modulo 8 a signature whose recovered representative does not fit the
    /// encoded message. Ed25519: a public key that is not 32 octets, 32 octets BouncyCastle refuses to
    /// decode, and a signature that is not 64 octets. ML-DSA: a public key BouncyCastle refuses for the
    /// parameter set and a signature of the wrong length. Where BouncyCastle itself refuses a public key, it
    /// raises <see cref="ArgumentException"/> or <see cref="FormatException"/>, which each member catches only
    /// around the decoding, the parameter construction and the verifier's initialization; what its RSA engine
    /// and PSS signer would raise for a signature is checked before they run. The verification arithmetic and
    /// the provider's own faults are not caught.
    /// The registered <see cref="ComputeDigestDelegate"/> entry point for this provider
    /// (<see cref="ComputeDigest"/>, <see cref="ComputeBlake3DigestAsync"/>) lives here too — see
    /// <see cref="DigestValue"/> for how a consumer discovers and wires it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned objects.")]
    public static class BouncyCastleCryptographicFunctions
    {
        private static ProviderLibrary ProviderLib { get; } = new(
            typeof(BouncyCastleCryptographicFunctions).Assembly.GetName().Name ?? "Verifiable.BouncyCastle",
            typeof(BouncyCastleCryptographicFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

        //BouncyCastle is an independently versioned NuGet package — its assembly
        //version is the most meaningful CBOM identifier.
        private static CryptoLibraryInfo CryptoLib { get; } = new(
            "Org.BouncyCastle.Cryptography",
            typeof(Org.BouncyCastle.Security.SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

        private static ProviderClass ProviderCls { get; } = new(nameof(BouncyCastleCryptographicFunctions));


        /// <summary>
        /// Computes a <see cref="DigestValue"/> using the BouncyCastle digest implementation
        /// identified by the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>.
        /// Supports SHA-256, SHA-384, and SHA-512. The registered
        /// <see cref="ComputeDigestDelegate"/> entry point for this provider — see
        /// <see cref="DigestValue"/> for how a consumer discovers and wires it.
        /// </summary>
        /// <param name="input">The bytes to hash.</param>
        /// <param name="outputByteLength">The expected digest length in bytes.</param>
        /// <param name="tag">Metadata identifying the algorithm and purpose.</param>
        /// <param name="pool">The memory pool to allocate from.</param>
        /// <param name="timeProvider">The time source for the <see cref="DigestComputedEvent"/> timestamp.</param>
        /// <returns>
        /// The computed <see cref="DigestValue"/> and a <see cref="DigestComputedEvent"/>.
        /// </returns>
        /// <exception cref="ArgumentException">
        /// Thrown when the tag does not carry a supported <see cref="HashAlgorithmName"/>.
        /// </exception>
        public static (DigestValue Result, CryptoEvent? Event) ComputeDigest(
            ReadOnlySpan<byte> input,
            int outputByteLength,
            Tag tag,
            BaseMemoryPool pool,
            TimeProvider timeProvider)
        {
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(timeProvider);

            if(!tag.TryGet(out HashAlgorithmName algorithmName))
            {
                throw new ArgumentException("The tag must carry a HashAlgorithmName to select the hash function.", nameof(tag));
            }

            IDigest digest = algorithmName switch
            {
                var a when a == HashAlgorithmName.SHA256 => new Sha256Digest(),
                var a when a == HashAlgorithmName.SHA384 => new Sha384Digest(),
                var a when a == HashAlgorithmName.SHA512 => new Sha512Digest(),
                _ => throw new ArgumentException(
                    $"Unsupported hash algorithm: {algorithmName.Name}.", nameof(tag))
            };

            int hashFunction(ReadOnlySpan<byte> source, Span<byte> destination)
            {
                byte[] output = RunDigest(source, digest);
                output.AsSpan().CopyTo(destination);
                return output.Length;
            }

            ProviderOperation operation = new(nameof(ComputeDigest));
            Tag stamped = CryptoProviderInstrumentation.StampTag(
                tag, ProviderLib, CryptoLib, ProviderCls, operation);

            Activity? activity = CryptoActivitySource.Source.StartActivity(
                CryptoTelemetry.ActivityNames.Digest);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(
                    activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Digest.Algorithm, algorithmName.Name);
                _ = activity.SetTag(CryptoTelemetry.Digest.InputLength, input.Length);
                _ = activity.SetTag(CryptoTelemetry.Digest.OutputLength, outputByteLength);
            }

            DigestValue result = DigestValue.Compute(
                input, hashFunction, outputByteLength, stamped, pool, activity);

            Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose p)
                ? p : Purpose.Digest;
            CryptoEvent evt = DigestComputedEvent.Create(
                algorithmName.Name ?? "Unknown", input.Length, outputByteLength, evtPurpose, timeProvider: timeProvider);

            return (result, evt);
        }


        /// <summary>
        /// Computes a BLAKE3 digest of <paramref name="outputByteLength"/> bytes in the
        /// <see cref="ComputeDigestDelegate"/> shape. BLAKE3 is an extendable-output function, so the requested length
        /// is produced via its XOF output. BLAKE3 is not a <see cref="HashAlgorithmName"/>, so a digest dispatcher
        /// routes a <see cref="CryptoAlgorithm.Blake3"/> tag (<see cref="Verifiable.Cryptography.CryptoTags.Blake3Digest"/>)
        /// here while <see cref="HashAlgorithmName"/>-tagged digests go to the SHA backends.
        /// </summary>
        /// <param name="input">The bytes to hash.</param>
        /// <param name="outputByteLength">The requested digest length in bytes (32 for BLAKE3-256).</param>
        /// <param name="tag">Metadata identifying the algorithm and purpose.</param>
        /// <param name="pool">The memory pool the digest is rented from.</param>
        /// <param name="timeProvider">The time source for the <see cref="DigestComputedEvent"/> timestamp.</param>
        /// <param name="context">Unused provenance context, accepted for delegate-shape compatibility.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>The computed <see cref="DigestValue"/> and a <see cref="DigestComputedEvent"/>.</returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned DigestValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
        public static ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeBlake3DigestAsync(
            ReadOnlySequence<byte> input,
            int outputByteLength,
            Tag tag,
            BaseMemoryPool pool,
            TimeProvider timeProvider,
            FrozenDictionary<string, object>? context = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(tag);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(timeProvider);

            cancellationToken.ThrowIfCancellationRequested();

            ProviderOperation operation = new(nameof(ComputeBlake3DigestAsync));
            Tag stamped = CryptoProviderInstrumentation.StampTag(
                tag, ProviderLib, CryptoLib, ProviderCls, operation);

            Activity? activity = CryptoActivitySource.Source.StartActivity(
                CryptoTelemetry.ActivityNames.Digest);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(
                    activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Digest.Algorithm, nameof(CryptoAlgorithm.Blake3));
                _ = activity.SetTag(CryptoTelemetry.Digest.InputLength, input.Length);
                _ = activity.SetTag(CryptoTelemetry.Digest.OutputLength, outputByteLength);
            }

            IMemoryOwner<byte> owner = pool.Rent(outputByteLength, AllocationKind.Pinned);
            try
            {
                var blake3 = new Blake3Digest();
                foreach(ReadOnlyMemory<byte> segment in input)
                {
                    blake3.BlockUpdate(segment.Span);
                }

                byte[] digestBytes = new byte[outputByteLength];
                int written = blake3.OutputFinal(digestBytes, 0, outputByteLength);
                if(written != outputByteLength)
                {
                    throw new InvalidOperationException(
                        $"Digest output length mismatch: expected {outputByteLength}, got {written}.");
                }

                digestBytes.AsSpan().CopyTo(owner.Memory.Span[..outputByteLength]);
            }
            catch
            {
                owner.Dispose();
                throw;
            }

            DigestValue result = new(owner, stamped, activity);

            Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose p)
                ? p : Purpose.Digest;
            CryptoEvent evt = DigestComputedEvent.Create(
                nameof(CryptoAlgorithm.Blake3), (int)input.Length, outputByteLength, evtPurpose, timeProvider: timeProvider);

            return ValueTask.FromResult<(DigestValue, CryptoEvent?)>((result, evt));
        }


        /// <summary>
        /// Signs data using Ed25519 (EdDSA over Curve25519).
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte Ed25519 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Ed25519Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEd25519Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);

            ProviderOperation operation = new(nameof(SignEd25519Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
            }

            //The span ctor copies the scalar into BouncyCastle's own buffer — no naked byte[]
            //of private-key material for us to track and zero.
            AsymmetricKeyParameter keyParameter = new Ed25519PrivateKeyParameters(privateKeyBytes.Span);
            var privateKey = (Ed25519PrivateKeyParameters)keyParameter;

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), off: 0, len: dataToSign.Length);

            var signature = (ReadOnlySpan<byte>)signer.GenerateSignature();
            var memoryPooledSignature = signaturePool.Rent(signature.Length);
            signature.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, CryptoTags.Ed25519Signature);
            CryptoEvent evt = SignatureProducedEvent.Create(
                CryptoAlgorithm.Ed25519, dataToSign.Length, signature.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an Ed25519 signature.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte Ed25519 signature to verify.</param>
        /// <param name="publicKeyMaterial">The 32-byte Ed25519 public key.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise, <c>false</c>, which is also the answer, with no
        /// exception, for a public key that is not 32 octets, for 32 octets BouncyCastle refuses as a public key,
        /// and for a signature that is not 64 octets.
        /// </returns>
        /// <remarks>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.7">RFC 8032 Section 5.1.7</see>, step 1:
        /// "Decode the public key A as point A'.  If any of the decodings fail (including S being out of range), the
        /// signature is invalid." <see href="https://www.rfc-editor.org/rfc/rfc8032#section-5.1.3">Section 5.1.3</see>
        /// decodes a point from a 32-octet string, so a public key of any other length is refused before
        /// BouncyCastle reads it (it reads the first 32 octets of a longer buffer and refuses a shorter one with an
        /// exception). 32 octets BouncyCastle refuses to decode as a public key (a y coordinate not below p, the
        /// neutral point), which it reports with <see cref="ArgumentException"/>, answer <c>false</c>; the catch
        /// covers the public key's construction and the verifier's initialization only. BouncyCastle's verifier
        /// answers <c>false</c> for a signature that is not 64 octets.
        /// </remarks>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEd25519Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ProviderOperation operation = new(nameof(VerifyEd25519Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "Ed25519");
            }

            //RFC 8032 Section 5.1.3: a point is decoded from a 32-octet string; the presented public key of any
            //other length is no Ed25519 public key.
            if(publicKeyMaterial.Length != Ed25519PublicKeyParameters.KeySize)
            {
                return NotVerified(CryptoAlgorithm.Ed25519, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            //RFC 8032 Section 5.1.7 step 1: 32 octets BouncyCastle refuses to decode as a public key are no point
            //a signature is valid under.
            var validator = new Ed25519Signer();
            try
            {
                var publicKey = new Ed25519PublicKeyParameters(publicKeyMaterial.ToArray(), 0);
                validator.Init(forSigning: false, publicKey);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return NotVerified(CryptoAlgorithm.Ed25519, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            validator.BlockUpdate(dataToVerify.ToArray(), off: 0, len: dataToVerify.Length);

            bool isVerified = validator.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                CryptoAlgorithm.Ed25519, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using ECDSA with the P-256 (secp256r1) curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte P-256 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P256Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256r1", CryptoTags.P256Signature, 32, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-256 (secp256r1) curve and SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-256 public key.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P256, "secp256r1", 32, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-384 (secp384r1) curve and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The 48-byte P-384 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 96-byte signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P384Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp384r1", CryptoTags.P384Signature, 48, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-384 (secp384r1) curve and SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 96-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-384 public key.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P384, "secp384r1", 48, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the P-521 (secp521r1) curve and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The 66-byte P-521 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 132-byte signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.P521Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp521r1", CryptoTags.P521Signature, 66, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the P-521 (secp521r1) curve and SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 132-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed P-521 public key.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.P521, "secp521r1", 66, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-224r1 curve and SHA-224.
        /// </summary>
        /// <remarks>
        /// brainpoolP224r1 has no fully-specified ECDSA registration in RFC 9864 / IANA COSE (it is added
        /// here as an ECDH/key-agreement curve, notably for eMRTD Chip Authentication), so there is no COSE
        /// algorithm identifier for this signature; SHA-224 is the field-matched hash.
        /// </remarks>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP224r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP224r1", CryptoTags.BrainpoolP224r1Signature, 28, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-224r1 curve and SHA-224.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP224r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP224r1, "brainpoolP224r1", 28, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-256r1 curve and SHA-256
        /// (RFC 9864 fully-specified ECDSA <c>ESB256</c>, COSE alg <c>-265</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP256r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP256r1", CryptoTags.BrainpoolP256r1Signature, 32, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-256r1 curve and SHA-256.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP256r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP256r1, "brainpoolP256r1", 32, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-320r1 curve and SHA-384
        /// (RFC 9864 fully-specified ECDSA <c>ESB320</c>, COSE alg <c>-266</c>).
        /// </summary>
        /// <remarks>
        /// The hash size (SHA-384, 48 bytes) deliberately exceeds the field size
        /// (320 bits, 40 bytes) per RFC 9864 §5; ECDSA truncates the hash to the
        /// field bit length internally during signing.
        /// </remarks>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP320r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP320r1", CryptoTags.BrainpoolP320r1Signature, 40, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-320r1 curve and SHA-384.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP320r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP320r1, "brainpoolP320r1", 40, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-384r1 curve and SHA-384
        /// (RFC 9864 fully-specified ECDSA <c>ESB384</c>, COSE alg <c>-267</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP384r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP384r1", CryptoTags.BrainpoolP384r1Signature, 48, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-384r1 curve and SHA-384.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP384r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP384r1, "brainpoolP384r1", 48, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the Brainpool P-512r1 curve and SHA-512
        /// (RFC 9864 fully-specified ECDSA <c>ESB512</c>, COSE alg <c>-268</c>).
        /// </summary>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignBrainpoolP512r1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "brainpoolP512r1", CryptoTags.BrainpoolP512r1Signature, 64, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the Brainpool P-512r1 curve and SHA-512.
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyBrainpoolP512r1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.BrainpoolP512r1, "brainpoolP512r1", 64, timeProvider);
        }


        /// <summary>
        /// Signs data using ECDSA with the secp256k1 curve and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte secp256k1 private key scalar.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the 64-byte signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Secp256k1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignEcdsaAsync(privateKeyBytes, dataToSign, signaturePool, "secp256k1", CryptoTags.Secp256k1Signature, 32, timeProvider);
        }


        /// <summary>
        /// Verifies an ECDSA signature produced with the secp256k1 curve and SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The 64-byte IEEE P1363 signature to verify.</param>
        /// <param name="publicKeyMaterial">The compressed or uncompressed secp256k1 public key.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyEcdsaAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Secp256k1, "secp256k1", 32, timeProvider);
        }


        /// <summary>
        /// Derives a shared secret using X25519 (Curve25519 Diffie-Hellman key agreement).
        /// The resulting 32-byte shared secret is allocated from the provided memory pool
        /// and the intermediate secret is cleared from memory immediately after copying.
        /// </summary>
        /// <param name="privateKeyBytes">The 32-byte X25519 private key.</param>
        /// <param name="publicKeyBytes">The 32-byte X25519 public key of the other party.</param>
        /// <param name="memoryPool">The memory pool used to allocate the shared secret buffer.</param>
        /// <returns>A pool-allocated buffer containing the 32-byte shared secret.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the rented buffer is too small.</exception>
        public static ValueTask<IMemoryOwner<byte>> DeriveX25519SharedSecretAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> publicKeyBytes, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            //The span ctors copy the scalar and the peer's point into BouncyCastle's own buffers —
            //no naked byte[] of private-key material for us to track and zero.
            var privateKeyParams = new X25519PrivateKeyParameters(privateKeyBytes.Span);
            var publicKeyParams = new X25519PublicKeyParameters(publicKeyBytes.Span);

            var agreement = new X25519Agreement();
            agreement.Init(privateKeyParams);

            var sharedSecret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKeyParams, sharedSecret, 0);

            var memoryOwner = memoryPool.Rent(sharedSecret.Length, AllocationKind.Pinned);
            if(memoryOwner.Memory.Length < sharedSecret.Length)
            {
                memoryOwner.Dispose();
                throw new InvalidOperationException("The rented buffer size is smaller than the requested size.");
            }

            sharedSecret.CopyTo(memoryOwner.Memory.Span);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return ValueTask.FromResult(memoryOwner);
        }


        /// <summary>
        /// Signs data using RSA 2048 with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA 2048 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Rsa2048Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa2048Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA 2048 PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Rsa2048, new Sha256Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA 4096 with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA 4096 private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.Rsa4096Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.Rsa4096Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA 4096 PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.Rsa4096, new Sha256Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256Pkcs1Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha256, new Sha256Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-256.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha256PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha256Digest(), CryptoTags.RsaSha256PssSignature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-256.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha256Pss, new Sha256Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384Pkcs1Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha384, new Sha384Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-384.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha384PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha384Digest(), CryptoTags.RsaSha384PssSignature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-384.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha384Pss, new Sha384Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512Pkcs1Signature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPkcs1Async(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512Pkcs1Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature using SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPkcs1Async(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha512, new Sha512Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using RSA with PSS padding and SHA-512.
        /// </summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns>A pool-allocated signature tagged with <see cref="CryptoTags.RsaSha512PssSignature"/>.</returns>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsaPssAsync(privateKeyBytes, dataToSign, signaturePool, new Sha512Digest(), CryptoTags.RsaSha512PssSignature, timeProvider);
        }


        /// <summary>
        /// Verifies an RSA PSS signature using SHA-512.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <param name="context">Optional context dictionary. Reserved for future use.</param>
        /// <param name="cancellationToken">A token to observe for cancellation.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaPssAsync(dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.RsaSha512Pss, new Sha512Digest(), timeProvider);
        }


        /// <summary>
        /// Signs data using ML-DSA-44 in deterministic mode (security level 2).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa44Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_44, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa44Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an ML-DSA-44 signature (security level 2).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa44Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_44, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa44, timeProvider);
        }


        /// <summary>
        /// Signs data using ML-DSA-65 in deterministic mode (security level 3).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa65Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_65, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa65Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an ML-DSA-65 signature (security level 3).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa65Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_65, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa65, timeProvider);
        }


        /// <summary>
        /// Signs data using ML-DSA-87 in deterministic mode (security level 5).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of Signature is transferred to the caller.")]
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsa87Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignMlDsaAsync(MLDsaParameters.ml_dsa_87, privateKeyBytes, dataToSign, signaturePool, CryptoTags.MlDsa87Signature, timeProvider);
        }


        /// <summary>
        /// Verifies an ML-DSA-87 signature (security level 5).
        /// </summary>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsa87Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyMlDsaAsync(MLDsaParameters.ml_dsa_87, dataToVerify, signature, publicKeyMaterial, CryptoAlgorithm.MlDsa87, timeProvider);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-512 (security level 1).
        /// Produces a ciphertext (768 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem512(ReadOnlyMemory<byte> publicKeyBytes, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_512, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-512 ciphertext (security level 1).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem512(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_512, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-768 (security level 3).
        /// Produces a ciphertext (1088 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem768(ReadOnlyMemory<byte> publicKeyBytes, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_768, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-768 ciphertext (security level 3).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem768(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_768, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Encapsulates a shared secret using ML-KEM-1024 (security level 5).
        /// Produces a ciphertext (1568 bytes) and a shared secret (32 bytes).
        /// </summary>
        public static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem1024(ReadOnlyMemory<byte> publicKeyBytes, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return EncapsulateMlKem(MLKemParameters.ml_kem_1024, publicKeyBytes, memoryPool);
        }


        /// <summary>
        /// Decapsulates a shared secret from ML-KEM-1024 ciphertext (security level 5).
        /// </summary>
        public static IMemoryOwner<byte> DecapsulateMlKem1024(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> ciphertext, BaseMemoryPool memoryPool)
        {
            ArgumentNullException.ThrowIfNull(memoryPool);
            return DecapsulateMlKem(MLKemParameters.ml_kem_1024, privateKeyBytes, ciphertext, memoryPool);
        }


        /// <summary>
        /// Signs data using ECDSA with deterministic k generation (RFC 6979) for the specified curve.
        /// The data is hashed with the curve-appropriate hash algorithm before signing. The resulting
        /// signature is encoded in fixed-size IEEE P1363 format (r || s) where each component is
        /// zero-padded to <paramref name="componentSize"/> bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The raw private key scalar bytes.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="curveName">The SEC curve name (e.g., "secp256r1", "secp256k1").</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <param name="componentSize">The byte length of each signature component (r and s).</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <returns>A pool-allocated signature in IEEE P1363 encoding.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignEcdsaAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, string curveName, Tag signatureTag, int componentSize, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignEcdsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                _ = activity.SetTag(CryptoTelemetry.Signature.Curve, MapEcdsaCurve(curveName));
            }

            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            //The span ctor copies the scalar into BouncyCastle's own immutable magnitude — no naked
            //byte[] of private-key material for us to track and zero.
            BigInteger d = new(1, privateKeyBytes.Span);
            ECPrivateKeyParameters privateKey = new(d, domainParams);

            byte[] hash = ComputeHash(dataToSign.Span, curveName);

            ECDsaSigner signer = new(new HMacDsaKCalculator(GetDigest(curveName)));
            signer.Init(forSigning: true, privateKey);

            BigInteger[] signatureComponents = signer.GenerateSignature(hash);
            BigInteger r = signatureComponents[0];
            BigInteger s = signatureComponents[1];

            //Encode r and s into fixed-size IEEE P1363 format, left-padded with zeros.
            byte[] signatureBytes = new byte[componentSize * 2];
            byte[] rBytes = r.ToByteArrayUnsigned();
            byte[] sBytes = s.ToByteArrayUnsigned();

            Array.Copy(rBytes, 0, signatureBytes, componentSize - rBytes.Length, rBytes.Length);
            Array.Copy(sBytes, 0, signatureBytes, (componentSize * 2) - sBytes.Length, sBytes.Length);

            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an ECDSA signature in IEEE P1363 encoding against the specified curve.
        /// The public key is in compressed or uncompressed SEC1 encoding, both of which BouncyCastle's
        /// <c>DecodePoint</c> reads.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The public key is read only in the two SEC1 encodings: 0x02 or 0x03 followed by the field's octet length
        /// (compressed), or 0x04 followed by twice it (uncompressed). Presented octets of any other length or first
        /// octet (the empty ones, the hybrid encodings 0x06 and 0x07, the infinity encoding 0x00, the uncompressed
        /// prefix at the compressed length) answer <c>false</c> before any point is decoded. A point the curve's
        /// decoder or BouncyCastle's parameter construction refuses (a point not on the curve, a compressed
        /// coordinate with no point), which BouncyCastle reports with <see cref="ArgumentException"/> or
        /// <see cref="FormatException"/>, answers <c>false</c> too; the catch covers the decoding, the parameter
        /// construction and the verifier's initialization, never the verification arithmetic.
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see>: "The JWS/JWE
        /// library itself must validate these inputs before using them, or it must use underlying cryptographic
        /// libraries that do so (or both!)."
        /// </para>
        /// <para>
        /// The signature is exactly the two components and nothing else: one of any other length answers
        /// <c>false</c>. <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">RFC 7518 Section 3.4</see>
        /// for P-256: "The JWS Signature value MUST be a 64-octet sequence.  If it is not a 64-octet sequence, the
        /// validation has failed." The same section fixes P-384 and P-521: "For ECDSA P-384 SHA-384, R and S will be
        /// 384 bits each, resulting in a 96-octet sequence." and "For ECDSA P-521 SHA-512, R and S will be 521 bits
        /// each, resulting in a 132-octet sequence."
        /// <see href="https://www.rfc-editor.org/rfc/rfc8812#section-3.2">RFC 8812 Section 3.2</see> fixes
        /// secp256k1: "The resulting 64-octet sequence is the JWS Signature or COSE signature value." The Brainpool
        /// curves P256r1, P320r1, P384r1 and P512r1 are registered for COSE by
        /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-2.1">RFC 9864 Section 2.1</see>, whose ECDSA
        /// signature form is that of <see href="https://www.rfc-editor.org/rfc/rfc9053#section-2.1">RFC 9053 Section
        /// 2.1</see>, a document not quoted here; brainpoolP224r1 has no
        /// signature registration, and its length is this provider's own two components of 28 octets.
        /// </para>
        /// </remarks>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The IEEE P1363-encoded signature (r || s).</param>
        /// <param name="publicKeyMaterial">The SEC1-encoded public key (compressed or uncompressed).</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the resulting <see cref="VerificationCompletedEvent"/>.</param>
        /// <param name="curveName">The SEC curve name (e.g., "secp256r1", "secp256k1").</param>
        /// <param name="componentSize">The byte length of each signature component (r and s).</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise, <c>false</c>, which is also the answer, with no
        /// exception, for public key octets that are no SEC1 point of the curve and for a signature that is not
        /// exactly the two components.
        /// </returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyEcdsaAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, string curveName, int componentSize, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyEcdsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                _ = activity.SetTag(CryptoTelemetry.Signature.Curve, MapEcdsaCurve(curveName));
            }

            X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
            ECDomainParameters domainParams = new(curveParams.Curve, curveParams.G, curveParams.N, curveParams.H);

            //A SEC1 point is 0x02 or 0x03 and f octets compressed, or 0x04 and 2f octets uncompressed, f the field's
            //octet length; presented octets of any other length or first octet (the empty ones, the hybrid 0x06 and
            //0x07, the infinity 0x00 included) are no public key of this curve.
            int fieldLength = (curveParams.Curve.FieldSize + 7) / 8;
            ReadOnlySpan<byte> publicKeySpan = publicKeyMaterial.Span;
            bool isSec1Point = (publicKeySpan.Length == 1 + fieldLength && publicKeySpan[0] is 0x02 or 0x03)
                || (publicKeySpan.Length == 1 + (2 * fieldLength) && publicKeySpan[0] == 0x04);
            if(!isSec1Point)
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            //RFC 7518 Section 3.4: a signature that is not exactly the two components fails validation; trailing
            //octets after them are never ignored.
            if(signature.Length != 2 * componentSize)
            {
                return NotVerified(algorithm, VerificationOutcome.Invalid, dataToVerify.Length, timeProvider);
            }

            //A point the curve's decoder refuses (not on the curve, a compressed coordinate with no point) is no
            //public key; the catch covers the decoding, the parameter construction and the verifier's initialization.
            ECDsaSigner verifier = new();
            try
            {
                Org.BouncyCastle.Math.EC.ECPoint point = curveParams.Curve.DecodePoint(publicKeyMaterial.ToArray());
                ECPublicKeyParameters publicKey = new(point, domainParams);
                verifier.Init(forSigning: false, publicKey);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            byte[] hash = ComputeHash(dataToVerify.Span, curveName);

            //Split the fixed-size IEEE P1363 signature back into r and s components.
            ReadOnlySpan<byte> signatureSpan = signature.Span;
            byte[] rBytes = signatureSpan[..componentSize].ToArray();
            byte[] sBytes = signatureSpan.Slice(componentSize, componentSize).ToArray();

            BigInteger r = new(1, rBytes);
            BigInteger s = new(1, sBytes);

            bool isVerified = verifier.VerifySignature(hash, r, s);
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using RSA with PKCS#1 v1.5 signature padding.
        /// The private key is expected in PKCS#1 DER format (<c>RSAPrivateKey</c>),
        /// matching the output of <c>RSA.ExportRSAPrivateKey()</c> and the
        /// BouncyCastle key material creator.
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <returns>A pool-allocated RSA PKCS#1 v1.5 signature.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaPkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, IDigest digest, Tag signatureTag, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignRsaPkcs1Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            RsaDigestSigner signer = new(digest);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an RSA PKCS#1 v1.5 signature. <see cref="ParseRsaPublicKey"/> reads the public key octets by
        /// the rule the class summary states.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA PKCS#1 v1.5 signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the resulting <see cref="VerificationCompletedEvent"/>.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise, <c>false</c>, which is also the answer, with no
        /// exception, for public key octets <see cref="ParseRsaPublicKey"/> answers no valid RSA public key for (a
        /// bare modulus whose first octet is zero, and an exponent below 3, not below the modulus or even, a modulus
        /// that is even, below 1024 bits or with a small prime factor, whichever arm of the rule reads the octets),
        /// for a public key the signer's initialization refuses (which
        /// BouncyCastle reports with <see cref="ArgumentException"/>; the catch covers the initialization only) and
        /// for a signature <see cref="IsRsaSignatureRepresentative"/> refuses (not k octets, or a value of 0, 1, n - 1
        /// or more).
        /// </returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaPkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, IDigest digest, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyRsaPkcs1Async));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            if(ParseRsaPublicKey(publicKeyMaterial.Span) is not RsaKeyParameters publicKey)
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            if(!IsRsaSignatureRepresentative(signature.Span, publicKey.Modulus))
            {
                return NotVerified(algorithm, VerificationOutcome.Invalid, dataToVerify.Length, timeProvider);
            }

            RsaDigestSigner verifier = new(digest);
            try
            {
                verifier.Init(forSigning: false, publicKey);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using RSA with PSS (Probabilistic Signature Scheme) padding.
        /// The salt length is set to the digest size. The private key is expected in
        /// PKCS#1 DER format (<c>RSAPrivateKey</c>).
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded RSA private key.</param>
        /// <param name="dataToSign">The data to sign.</param>
        /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="signatureTag">The tag identifying the signature algorithm.</param>
        /// <param name="timeProvider">The time source for the <see cref="SignatureProducedEvent"/> timestamp.</param>
        /// <returns>A pool-allocated RSA-PSS signature.</returns>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaPssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, IDigest digest, Tag signatureTag, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignRsaPssAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
            PssSigner signer = new(new RsaEngine(), digest, digest.GetDigestSize());
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies an RSA PSS signature. <see cref="ParseRsaPublicKey"/> reads the public key octets by the rule
        /// the class summary states. The salt length is set to the digest size.
        /// </summary>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The RSA-PSS signature to verify.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the resulting <see cref="VerificationCompletedEvent"/>.</param>
        /// <param name="digest">The hash digest to use (e.g., SHA-256, SHA-384, SHA-512).</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise, <c>false</c>, which is also the answer, with no
        /// exception, for public key octets <see cref="ParseRsaPublicKey"/> answers no valid RSA public key for (a
        /// bare modulus whose first octet is zero, and an exponent below 3, not below the modulus or even, a modulus
        /// that is even, below 1024 bits or with a small prime factor, whichever arm of the rule reads the octets),
        /// for a modulus the PSS signer's initialization refuses as too small for the digest and the salt
        /// (<see href="https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2">RFC 8017 Section 9.1.2</see>, step 3:
        /// "If emLen &lt; hLen + sLen + 2, output "inconsistent" and stop."; BouncyCastle reports it with
        /// <see cref="ArgumentException"/>, and the catch covers the initialization only), for a signature
        /// <see cref="IsRsaSignatureRepresentative"/> refuses (not k octets, or a value of 0, 1, n - 1 or more, which
        /// BouncyCastle's RSA engine would otherwise refuse with <see cref="DataLengthException"/>) and for a signature
        /// whose recovered representative does not fit the encoded message under a modulus whose bit length is 1
        /// modulo 8 (<see cref="IsWithinPssEncodedMessageLength"/>), which BouncyCastle's PSS signer would otherwise
        /// raise for.
        /// </returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaPssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, CryptoAlgorithm algorithm, IDigest digest, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyRsaPssAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            if(ParseRsaPublicKey(publicKeyMaterial.Span) is not RsaKeyParameters publicKey)
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            if(!IsRsaSignatureRepresentative(signature.Span, publicKey.Modulus))
            {
                return NotVerified(algorithm, VerificationOutcome.Invalid, dataToVerify.Length, timeProvider);
            }

            //RFC 8017 Section 8.1.2 step 2.c: under a modulus whose bit length is 1 modulo 8 a recovered representative
            //that needs k octets does not fit emLen = k - 1 and is "invalid signature", before the signer runs.
            if(!IsWithinPssEncodedMessageLength(signature.Span, publicKey))
            {
                return NotVerified(algorithm, VerificationOutcome.Invalid, dataToVerify.Length, timeProvider);
            }

            //RFC 8017 Section 9.1.2 step 3: a modulus too small for the digest and the salt (emLen < hLen + sLen + 2)
            //holds no RSASSA-PSS signature; BouncyCastle's signer refuses it at initialization.
            PssSigner verifier = new(new RsaEngine(), digest, digest.GetDigestSize());
            try
            {
                verifier.Init(forSigning: false, publicKey);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Signs data using the specified ML-DSA parameter set in deterministic mode.
        /// Reconstructs key parameters from raw encoded bytes.
        /// </summary>
        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignMlDsaAsync(
            MLDsaParameters parameters,
            ReadOnlyMemory<byte> privateKeyBytes,
            ReadOnlyMemory<byte> dataToSign,
            BaseMemoryPool signaturePool,
            Tag signatureTag,
            TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignMlDsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ML-DSA");
            }

            //MLDsaPrivateKeyParameters exposes no public constructor or span-accepting static factory,
            //only this byte[]-only FromEncoding, so the private key is copied once here and zeroed
            //immediately after decoding. The decoded MLDsaPrivateKeyParameters retains its own internal
            //copy of the key material, which cannot be zeroed from outside BouncyCastle.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            MLDsaPrivateKeyParameters privateKey;
            try
            {
                privateKey = MLDsaPrivateKeyParameters.FromEncoding(parameters, privateKeyArray);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var signer = new MLDsaSigner(parameters, deterministic: true);
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(dataToSign.ToArray(), 0, dataToSign.Length);

            byte[] signatureBytes = signer.GenerateSignature();
            IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }


        /// <summary>
        /// Verifies a signature using the specified ML-DSA parameter set.
        /// Reconstructs key parameters from raw encoded bytes.
        /// </summary>
        /// <remarks>
        /// Presented public key octets BouncyCastle refuses to decode for the parameter set (a length other than the
        /// set's encoded public key), which it reports with <see cref="ArgumentException"/>, answer <c>false</c>
        /// raising nothing; the catch covers the decoding and the verifier's initialization only. A signature of the
        /// wrong length answers <c>false</c> from BouncyCastle's verifier.
        /// </remarks>
        /// <param name="parameters">The ML-DSA parameter set.</param>
        /// <param name="dataToVerify">The original data that was signed.</param>
        /// <param name="signature">The ML-DSA signature to verify.</param>
        /// <param name="publicKeyMaterial">The encoded ML-DSA public key.</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the resulting <see cref="VerificationCompletedEvent"/>.</param>
        /// <param name="timeProvider">The time source for the <see cref="VerificationCompletedEvent"/> timestamp.</param>
        /// <returns>
        /// <c>true</c> if the signature is valid; otherwise, <c>false</c>, which is also the answer, with no
        /// exception, for public key octets that are no public key of the parameter set.
        /// </returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyMlDsaAsync(
            MLDsaParameters parameters,
            ReadOnlyMemory<byte> dataToVerify,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> publicKeyMaterial,
            CryptoAlgorithm algorithm,
            TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyMlDsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ML-DSA");
            }

            var verifier = new MLDsaSigner(parameters, deterministic: true);
            try
            {
                var publicKey = MLDsaPublicKeyParameters.FromEncoding(parameters, publicKeyMaterial.ToArray());
                verifier.Init(forSigning: false, publicKey);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return NotVerified(algorithm, VerificationOutcome.Error, dataToVerify.Length, timeProvider);
            }

            verifier.BlockUpdate(dataToVerify.ToArray(), 0, dataToVerify.Length);

            bool isVerified = verifier.VerifySignature(signature.ToArray());
            CryptoEvent evt = VerificationCompletedEvent.Create(
                algorithm, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, dataToVerify.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        /// <summary>
        /// Encapsulates a shared secret using the specified ML-KEM parameter set.
        /// Produces a ciphertext and a shared secret from the recipient's public key.
        /// </summary>
        private static (IMemoryOwner<byte> Ciphertext, IMemoryOwner<byte> SharedSecret) EncapsulateMlKem(
            MLKemParameters parameters,
            ReadOnlyMemory<byte> publicKeyBytes,
            BaseMemoryPool memoryPool)
        {
            var publicKey = MLKemPublicKeyParameters.FromEncoding(parameters, publicKeyBytes.ToArray());
            var encapsulator = new MLKemEncapsulator(parameters);
            encapsulator.Init(publicKey);

            byte[] ciphertext = new byte[encapsulator.EncapsulationLength];
            byte[] sharedSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

            IMemoryOwner<byte> ciphertextMemory = memoryPool.Rent(ciphertext.Length);
            ciphertext.CopyTo(ciphertextMemory.Memory.Span);

            IMemoryOwner<byte> secretMemory = memoryPool.Rent(sharedSecret.Length, AllocationKind.Pinned);
            sharedSecret.CopyTo(secretMemory.Memory.Span);

            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return (ciphertextMemory, secretMemory);
        }


        /// <summary>
        /// Decapsulates a shared secret from ciphertext using the specified ML-KEM parameter set
        /// and the recipient's private key.
        /// </summary>
        private static IMemoryOwner<byte> DecapsulateMlKem(
            MLKemParameters parameters,
            ReadOnlyMemory<byte> privateKeyBytes,
            ReadOnlyMemory<byte> ciphertext,
            BaseMemoryPool memoryPool)
        {
            //MLKemPrivateKeyParameters exposes no public constructor or span-accepting static factory,
            //only this byte[]-only FromEncoding, so the private key is copied once here and zeroed
            //immediately after decoding. The decoded MLKemPrivateKeyParameters retains its own internal
            //copy of the key material, which cannot be zeroed from outside BouncyCastle.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            MLKemPrivateKeyParameters privateKey;
            try
            {
                privateKey = MLKemPrivateKeyParameters.FromEncoding(parameters, privateKeyArray);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var decapsulator = new MLKemDecapsulator(parameters);
            decapsulator.Init(privateKey);

            byte[] sharedSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext.ToArray(), 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);

            IMemoryOwner<byte> secretMemory = memoryPool.Rent(sharedSecret.Length, AllocationKind.Pinned);
            sharedSecret.CopyTo(secretMemory.Memory.Span);
            Array.Clear(sharedSecret, 0, sharedSecret.Length);

            return secretMemory;
        }


        /// <summary>
        /// Parses a PKCS#1 DER-encoded RSA private key (<c>RSAPrivateKey</c>) into BouncyCastle
        /// key parameters. This format is produced by both <c>RSA.ExportRSAPrivateKey()</c>
        /// and <see cref="BouncyCastleKeyMaterialCreator"/>.
        /// </summary>
        /// <param name="privateKeyBytes">The PKCS#1 DER-encoded private key.</param>
        /// <returns>The parsed private key parameters with CRT components.</returns>
        private static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(ReadOnlySpan<byte> privateKeyBytes)
        {
            //BouncyCastle's classic ASN.1 object model (Asn1Sequence, RsaPrivateKeyStructure) accepts
            //only byte[], so the DER-encoded private key is copied once here and zeroed immediately
            //after the ASN.1 structure is parsed. The resulting RsaPrivateCrtKeyParameters holds the
            //modulus, exponents, and CRT factors as BigInteger magnitudes — BigInteger's internal int[]
            //magnitude is immutable and cannot be zeroed from outside BouncyCastle, so those copies
            //remain for the key's lifetime.
            byte[] derBytes = privateKeyBytes.ToArray();
            try
            {
                RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(Asn1Sequence.GetInstance(derBytes));
                return new RsaPrivateCrtKeyParameters(
                    rsa.Modulus,
                    rsa.PublicExponent,
                    rsa.PrivateExponent,
                    rsa.Prime1,
                    rsa.Prime2,
                    rsa.Exponent1,
                    rsa.Exponent2,
                    rsa.Coefficient);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derBytes);
            }
        }


        /// <summary>
        /// Parses presented RSA public key octets by the rule the class summary states. The first arm is
        /// read with <see cref="AsnReader"/>: the octets are exactly a DER PKCS#1
        /// <c>RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c> (the same shape the
        /// COSE RSA <c>n</c>/<c>e</c> labels of RFC 8230 Section 4 carry) when the SEQUENCE holds exactly the
        /// two INTEGERs and nothing follows it, and that modulus and that exponent are read, which the DER form
        /// carries rather than assumes; a DER modulus or exponent that is not positive answers
        /// <see langword="null"/>. Content the reader refuses (<see cref="AsnContentException"/>, the type
        /// <c>System.Formats.Asn1</c> documents for content that is not valid under the encoding rules), DER
        /// with a trailing octet and a SEQUENCE with a third INTEGER among them, goes to the second arm, where
        /// octets whose first octet is zero answer <see langword="null"/>. Every reading answers
        /// <see langword="null"/> when it is no valid RSA public key (<see cref="ConstructRsaPublicKey"/>: an
        /// exponent below 3, not below the modulus or even, a modulus that is even or below 1024 bits, held to
        /// <see cref="RsaUtilities.IsValidPublicKey"/> before anything is constructed, and a modulus with a
        /// small prime factor, which BouncyCastle refuses to construct with <see cref="ArgumentException"/>; the
        /// catch covers the construction only).
        /// </summary>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class summary states.</param>
        /// <returns>The parsed public key parameters, or <see langword="null"/> when the octets are no valid RSA public key.</returns>
        private static RsaKeyParameters? ParseRsaPublicKey(ReadOnlySpan<byte> publicKeyMaterial)
        {
            System.Numerics.BigInteger modulus;
            System.Numerics.BigInteger exponent;
            try
            {
                AsnReader outerReader = new(publicKeyMaterial.ToArray(), AsnEncodingRules.DER);
                AsnReader sequenceReader = outerReader.ReadSequence();
                modulus = sequenceReader.ReadInteger();
                exponent = sequenceReader.ReadInteger();
                sequenceReader.ThrowIfNotEmpty();
                outerReader.ThrowIfNotEmpty();
            }
            catch(AsnContentException)
            {
                //The second arm: octets that are not exactly a DER RSAPublicKey are the bare modulus they spell, under
                //65537, held to the minimum number of octets, so a first octet of zero is no modulus.
                return publicKeyMaterial is [0x00, ..]
                    ? null
                    : ConstructRsaPublicKey(new BigInteger(1, publicKeyMaterial.ToArray()), BigInteger.ValueOf(65537));
            }

            if(modulus.Sign <= 0 || exponent.Sign <= 0)
            {
                return null;
            }

            //The sign-magnitude constructor (sign = 1) is used rather than the two's-complement one,
            //since System.Numerics.BigInteger's unsigned big-endian byte form always encodes a
            //positive RSA modulus/exponent, and a two's-complement read would misinterpret an
            //MSB-set modulus as negative.
            return ConstructRsaPublicKey(
                new BigInteger(1, modulus.ToByteArray(isUnsigned: true, isBigEndian: true)),
                new BigInteger(1, exponent.ToByteArray(isUnsigned: true, isBigEndian: true)));
        }


        /// <summary>
        /// Constructs BouncyCastle's RSA public key parameters from a presented modulus and exponent, the one place
        /// both encodings <see cref="ParseRsaPublicKey"/> reads construct their parameters. The pair is first held to
        /// <see cref="RsaUtilities.IsValidPublicKey"/> with its defaults (an odd exponent with 3 &lt;= e &lt; n, an odd
        /// modulus of at least <see cref="RsaUtilities.MinimumModulusBitLength"/> bits):
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section 3.1</see>: "In a valid RSA
        /// public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2, ..., u, where u &gt;= 2,
        /// and the RSA public exponent e is an integer between 3 and n - 1 satisfying GCD(e,\lambda(n)) = 1, where
        /// \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." A pair that fails it answers <see langword="null"/> before
        /// anything is constructed, and so does a pair BouncyCastle refuses to construct (a modulus with a small prime
        /// factor), which it reports with <see cref="ArgumentException"/>.
        /// </summary>
        /// <param name="modulus">The presented modulus n.</param>
        /// <param name="exponent">The presented public exponent e.</param>
        /// <returns>The parameters, or <see langword="null"/> when the pair is no valid RSA public key.</returns>
        private static RsaKeyParameters? ConstructRsaPublicKey(BigInteger modulus, BigInteger exponent)
        {
            if(!RsaUtilities.IsValidPublicKey(modulus.ToByteArrayUnsigned(), exponent.ToByteArrayUnsigned()))
            {
                return null;
            }

            try
            {
                return new RsaKeyParameters(isPrivate: false, modulus, exponent);
            }
            catch(Exception ex) when(IsMaterialRefusal(ex))
            {
                return null;
            }
        }


        /// <summary>
        /// Whether <paramref name="exception"/>, raised by BouncyCastle while it decoded presented public key
        /// octets, constructed parameters from them or initialized a verifier with them, is its refusal of that
        /// material: <see cref="ArgumentException"/> (an off-curve or badly encoded point, an Ed25519 encoding it
        /// does not decode, an RSA modulus with a small prime factor, a modulus the PSS signer refuses, an ML-DSA
        /// public key of the wrong length) or <see cref="FormatException"/> (a point encoding
        /// it does not know). Each verification member catches with it only around those calls, never around the
        /// verification arithmetic, so a fault of the provider propagates.
        /// </summary>
        /// <param name="exception">The exception BouncyCastle raised.</param>
        /// <returns><see langword="true"/> when the exception is BouncyCastle's refusal of the presented material.</returns>
        private static bool IsMaterialRefusal(Exception exception) => exception is ArgumentException or FormatException;


        /// <summary>
        /// Whether <paramref name="signature"/> can be an RSA signature under <paramref name="modulus"/> that
        /// BouncyCastle's RSA engine is asked about: it is exactly k octets, k the modulus's octet length, and its
        /// value s satisfies 1 &lt; s &lt; n - 1.
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>
        /// (RSASSA-PSS-VERIFY) and <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.2.2">Section 8.2.2</see>
        /// (RSASSA-PKCS1-V1_5-VERIFY), step 1: "Length checking: If the length of the signature S is not k octets,
        /// output "invalid signature" and stop."
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-5.2.2">Section 5.2.2</see> (RSAVP1), step 1:
        /// "If the signature representative s is not between 0 and n - 1, output "signature representative out of
        /// range" and stop.", which both verification operations answer as "invalid signature". RSAVP1 admits 0 to
        /// n - 1; BouncyCastle's RSA engine refuses 0, 1 and n - 1 too, with <see cref="DataLengthException"/>.
        /// RSAVP1 maps each of those three to itself (the public exponent is odd), and none is the encoded message of
        /// either scheme: an EMSA-PKCS1-v1_5 encoded message starts 0x00 0x01, so its value is above 1 and below
        /// n - 1; an EMSA-PSS encoded message ends 0xBC, which neither 0 nor 1 does, and n - 1 either does not fit
        /// emLen octets or sets a leftmost bit that step 6 of
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2">Section 9.1.2</see> requires to be zero.
        /// Refusing the three changes no answer, and checking all of this before the engine runs answers such a
        /// signature as not verified rather than as the exception.
        /// </summary>
        /// <param name="signature">The presented signature octets.</param>
        /// <param name="modulus">The public key's modulus n.</param>
        /// <returns><see langword="true"/> when the signature is k octets and 1 &lt; s &lt; n - 1.</returns>
        private static bool IsRsaSignatureRepresentative(ReadOnlySpan<byte> signature, BigInteger modulus)
        {
            if(signature.Length != (modulus.BitLength + 7) / 8)
            {
                return false;
            }

            BigInteger representative = new(1, signature);

            return representative.CompareTo(BigInteger.One) > 0 && representative.CompareTo(modulus.Subtract(BigInteger.One)) < 0;
        }


        /// <summary>
        /// Whether the message representative <paramref name="signature"/> recovers under
        /// <paramref name="publicKey"/> fits the encoded message of RSASSA-PSS.
        /// <see href="https://www.rfc-editor.org/rfc/rfc8017#section-8.1.2">RFC 8017 Section 8.1.2</see>, step 2.c:
        /// "Convert the message representative m to an encoded message EM of length emLen = \ceil ((modBits - 1)/8)
        /// octets, where modBits is the length in bits of the RSA modulus n (see Section 4.1): EM = I2OSP (m, emLen).
        /// Note that emLen will be one less than k if modBits - 1 is divisible by 8 and equal to k otherwise. If I2OSP
        /// outputs "integer too large", output "invalid signature" and stop." Only under a modulus whose bit length is
        /// 1 modulo 8 is emLen one less than k, so only there can a recovered representative below n need more than
        /// emLen octets; BouncyCastle's PSS signer copies it into a block of emLen octets and raises for one that does
        /// not fit. For such a modulus this member makes the one exponentiation with the public exponent and answers
        /// whether m is below 2^(modBits - 1); for every other modulus it answers <see langword="true"/> without it.
        /// </summary>
        /// <param name="signature">The presented signature octets, already held to <see cref="IsRsaSignatureRepresentative"/>.</param>
        /// <param name="publicKey">The public key.</param>
        /// <returns><see langword="true"/> when the recovered representative fits emLen octets.</returns>
        private static bool IsWithinPssEncodedMessageLength(ReadOnlySpan<byte> signature, RsaKeyParameters publicKey)
        {
            int modulusBitLength = publicKey.Modulus.BitLength;
            if(modulusBitLength % 8 != 1)
            {
                return true;
            }

            BigInteger messageRepresentative = new BigInteger(1, signature).ModPow(publicKey.Exponent, publicKey.Modulus);

            return messageRepresentative.BitLength <= modulusBitLength - 1;
        }


        /// <summary>
        /// The answer of a verifier for presented material it cannot verify: <c>false</c> with a
        /// <see cref="VerificationCompletedEvent"/> of <paramref name="outcome"/>, raising nothing. A verify body
        /// reads it as a signature that does not verify.
        /// </summary>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the event.</param>
        /// <param name="outcome">
        /// <see cref="VerificationOutcome.Error"/> for a public key the verifier cannot read,
        /// <see cref="VerificationOutcome.Invalid"/> for a signature that cannot be one under the public key.
        /// </param>
        /// <param name="dataLength">The length of the data that was to be verified.</param>
        /// <param name="timeProvider">The time source for the event's timestamp.</param>
        /// <returns>The not-verified answer with its event.</returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> NotVerified(CryptoAlgorithm algorithm, VerificationOutcome outcome, int dataLength, TimeProvider timeProvider)
        {
            CryptoEvent evt = VerificationCompletedEvent.Create(algorithm, outcome, dataLength, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((false, evt));
        }


        /// <summary>
        /// Maps a SEC/Brainpool curve name to the JOSE display form used in telemetry.
        /// NIST <c>secpNNNr1</c> names map to the <c>P-NNN</c> display form; secp256k1 and
        /// the Brainpool curves pass through unchanged.
        /// </summary>
        /// <param name="curveName">The SEC or Brainpool curve name.</param>
        /// <returns>The telemetry display name for the curve.</returns>
        private static string MapEcdsaCurve(string curveName) => curveName switch
        {
            "secp256r1" => "P-256",
            "secp384r1" => "P-384",
            "secp521r1" => "P-521",
            _ => curveName
        };


        /// <summary>
        /// Computes the appropriate hash for the given ECDSA curve. Both secp256r1 and secp256k1
        /// use SHA-256, secp384r1 uses SHA-384, and secp521r1 uses SHA-512.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <param name="curveName">The SEC curve name.</param>
        /// <returns>The hash digest of the data.</returns>
        /// <exception cref="NotSupportedException">Thrown if the curve is not recognized.</exception>
        private static byte[] ComputeHash(ReadOnlySpan<byte> data, string curveName)
        {
            //Brainpool hash bindings per RFC 9864 §5: BP-256 → SHA-256,
            //BP-320 → SHA-384, BP-384 → SHA-384, BP-512 → SHA-512. Note that
            //BP-320 uses SHA-384 even though SHA-384 output exceeds the field
            //size — ECDSA truncates internally. brainpoolP224r1 (not an RFC 9864
            //fully-specified algorithm) uses the field-matched SHA-224, which the
            //framework has no managed implementation of.
            //
            //Routed through GetDigest — the same curve-to-BouncyCastle-IDigest mapping the RFC 6979
            //k-calculator below uses — and RunDigest, this provider's one internal digest path, rather
            //than framework SHA256/384/512.HashData. That keeps the ECDSA pre-hash on a single digest
            //implementation for every curve instead of framework hashing for three curves and
            //BouncyCastle only for the SHA-224 outlier.
            return RunDigest(data, GetDigest(curveName));
        }


        /// <summary>
        /// Runs a BouncyCastle <see cref="IDigest"/> instance to completion over <paramref name="data"/> and
        /// returns the digest bytes. The one internal digest path this provider uses, whether for the public
        /// <see cref="ComputeDigest"/> entry point or the private ECDSA pre-hash in <see cref="ComputeHash"/>.
        /// </summary>
        /// <param name="data">The bytes to hash.</param>
        /// <param name="digest">The digest instance to run. Reset before use, so a caller may reuse an instance.</param>
        /// <returns>The computed digest bytes, sized to <c>digest.GetDigestSize()</c>.</returns>
        private static byte[] RunDigest(ReadOnlySpan<byte> data, IDigest digest)
        {
            digest.Reset();
            byte[] inputArray = data.ToArray();
            digest.BlockUpdate(inputArray, 0, inputArray.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            _ = digest.DoFinal(output, 0);

            return output;
        }


        /// <summary>
        /// Returns the BouncyCastle digest instance appropriate for deterministic ECDSA k generation
        /// (RFC 6979 via <see cref="HMacDsaKCalculator"/>) on the specified curve. Also the source of
        /// the digest <see cref="ComputeHash"/> runs the ECDSA pre-hash through, so the k-derivation
        /// hash and the message-digest hash always agree for a given curve. brainpoolP224r1 resolves to
        /// <see cref="Sha224Digest"/> because the framework has no managed SHA-224 implementation —
        /// the one documented exception to this provider hashing exclusively through BouncyCastle's own
        /// <see cref="IDigest"/> implementations.
        /// </summary>
        /// <param name="curveName">The SEC curve name.</param>
        /// <returns>A new <see cref="IDigest"/> instance for the curve.</returns>
        /// <exception cref="NotSupportedException">Thrown if the curve is not recognized.</exception>
        private static IDigest GetDigest(string curveName)
        {
            //Mirrors ComputeHash's RFC 9864 §5 mapping so that the RFC 6979
            //k-derivation uses the same hash family as the message digest.
            return curveName switch
            {
                "brainpoolP224r1" => new Sha224Digest(),
                "secp256r1" or "secp256k1" or "brainpoolP256r1" => new Sha256Digest(),
                "secp384r1" or "brainpoolP320r1" or "brainpoolP384r1" => new Sha384Digest(),
                "secp521r1" or "brainpoolP512r1" => new Sha512Digest(),
                _ => throw new NotSupportedException($"Curve '{curveName}' is not supported.")
            };
        }
    }
}

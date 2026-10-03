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

namespace Verifiable.Microsoft
{
    /// <summary>
    /// Provides cryptographic functions for digital signatures and digest computation using
    /// Microsoft cryptographic libraries. The registered <see cref="ComputeDigestDelegate"/>
    /// entry point for this provider lives here, alongside the signing and verification
    /// functions it shares its backend with — see <see cref="DigestValue"/> for how a
    /// consumer discovers and wires it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every RSA verification member reads the presented public key octets by one rule. The octets do not state
    /// their own encoding, so they are read by form, in this order. (1) Octets that are exactly the DER
    /// <c>RSAPublicKey</c> of <see href="https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1">RFC 8017 Appendix
    /// A.1.1</see>, a SEQUENCE of two INTEGERs with nothing after them inside the SEQUENCE and nothing after the
    /// SEQUENCE, whatever their length, are that modulus and that exponent; such DER with an INTEGER that is
    /// negative is no public key. (2) Any other octets are the bare modulus they spell, under the exponent 65537,
    /// and octets whose first octet is zero are no modulus. So a bare modulus whose octets happen to be exactly
    /// such a structure is read as that structure.
    /// </para>
    /// <para>
    /// The bare modulus is this library's convention, not RFC 8017's: the JWK reader hands one of 256 or 512
    /// octets, and the library's managed certificate verifiers hand one of the certificate's own size after holding
    /// its exponent to 65537 themselves; <c>did:key</c>, a COSE_Key and a certificate's subject public key hand the
    /// DER <c>RSAPublicKey</c>, which the first arm reads. It is held to the minimum number of octets, the rule
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-2">RFC 7518 Section 2</see> states for the
    /// Base64urlUInt a JWK's <c>n</c> is: "The octet sequence MUST utilize the minimum number of octets needed to
    /// represent the value." Both providers so read the same modulus from the same octets and hold a signature to
    /// the same length k. An import the platform's backend refuses is answered <c>false</c>; the Windows CNG
    /// backend refuses a public exponent of more than 8 octets that way, under which BouncyCastle verifies.
    /// </para>
    /// <para>
    /// Every reading, the modulus and the exponent, is held to <see cref="RsaUtilities.IsValidPublicKey"/> before
    /// anything is imported: <see href="https://www.rfc-editor.org/rfc/rfc8017#section-3.1">RFC 8017 Section
    /// 3.1</see>: "In a valid RSA public key, the RSA modulus n is a product of u distinct odd primes r_i, i = 1, 2,
    /// ..., u, where u &gt;= 2, and the RSA public exponent e is an integer between 3 and n - 1 satisfying
    /// GCD(e,\lambda(n)) = 1, where \lambda(n) = LCM(r_1 - 1, ..., r_u - 1)." Octets that are no public key by the
    /// rule, and a reading that fails the check, answer <c>false</c>; no presented octets raise.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The caller is responsible for disposing the returned objects.")]
    public static class MicrosoftCryptographicFunctions
    {
        private static ProviderLibrary ProviderLib { get; } = new(
            typeof(MicrosoftCryptographicFunctions).Assembly.GetName().Name
                ?? "Verifiable.Microsoft",
            typeof(MicrosoftCryptographicFunctions).Assembly.GetName().Version?.ToString()
                ?? "Unknown");

        private static CryptoLibraryInfo CryptoLib { get; } = new(
            "System.Security.Cryptography",
            typeof(RandomNumberGenerator).Assembly.GetName().Version?.ToString()
                ?? System.Environment.Version.ToString());

        private static ProviderClass ProviderCls { get; } =
            new(nameof(MicrosoftCryptographicFunctions));


        /// <summary>
        /// Computes a <see cref="DigestValue"/> using the .NET platform hash implementation
        /// identified by the <see cref="HashAlgorithmName"/> in <paramref name="tag"/>.
        /// Supports SHA-256, SHA-384, SHA-512, and SHA-1 (the SHA-1 path exists for TPM
        /// session protocol compatibility). The registered <see cref="ComputeDigestDelegate"/>
        /// entry point for this provider — see <see cref="DigestValue"/> for how a consumer
        /// discovers and wires it.
        /// </summary>
        /// <remarks>
        /// Single-segment input uses the .NET BCL one-shot hash methods. Multi-segment
        /// input streams via <see cref="IncrementalHash"/>, iterating
        /// <see cref="ReadOnlySequence{T}"/> segments and feeding each to
        /// <c>AppendData</c> without pre-buffering. Returns a synchronously-completed
        /// <see cref="ValueTask{TResult}"/>.
        /// </remarks>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned DigestValue takes ownership of the IMemoryOwner and is disposed by the caller.")]
        [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "SHA-1 is dispatched only when the consumer composes a Tag inline with HashAlgorithmName.SHA1 — exclusively the TPM command-parameter hashing path. Convenience tags in CryptoTags omit SHA-1 so new protocol code cannot use it.")]
        public static ValueTask<(DigestValue Result, CryptoEvent? Event)> ComputeDigestAsync(
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

            if(!tag.TryGet<HashAlgorithmName>(out HashAlgorithmName algorithmName))
            {
                throw new ArgumentException(
                    "The tag must carry a HashAlgorithmName to select the hash function.",
                    nameof(tag));
            }

            ProviderOperation operation = new(nameof(ComputeDigestAsync));
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

            IMemoryOwner<byte> owner = pool.Rent(outputByteLength, AllocationKind.Pinned);
            int written;
            try
            {
                Span<byte> destination = owner.Memory.Span[..outputByteLength];

                if(input.IsSingleSegment)
                {
                    ReadOnlySpan<byte> inputSpan = input.FirstSpan;
                    written = algorithmName switch
                    {
                        var a when a == HashAlgorithmName.SHA256 => SHA256.HashData(inputSpan, destination),
                        var a when a == HashAlgorithmName.SHA384 => SHA384.HashData(inputSpan, destination),
                        var a when a == HashAlgorithmName.SHA512 => SHA512.HashData(inputSpan, destination),
                        var a when a == HashAlgorithmName.SHA1 => SHA1.HashData(inputSpan, destination),
                        _ => throw new ArgumentException(
                            $"Unsupported digest hash algorithm: {algorithmName.Name}.", nameof(tag))
                    };
                }
                else
                {
                    using IncrementalHash hasher = IncrementalHash.CreateHash(algorithmName);
                    foreach(ReadOnlyMemory<byte> segment in input)
                    {
                        hasher.AppendData(segment.Span);
                    }
                    written = hasher.GetHashAndReset(destination);
                }
            }
            catch
            {
                owner.Dispose();
                throw;
            }

            if(written != outputByteLength)
            {
                owner.Dispose();
                throw new InvalidOperationException(
                    $"Digest output length mismatch: expected {outputByteLength}, got {written}.");
            }

            DigestValue result = new(owner, stamped, activity);

            Purpose evtPurpose = stamped.TryGet<Purpose>(out Purpose p)
                ? p : Purpose.Digest;
            CryptoEvent evt = DigestComputedEvent.Create(
                algorithmName.Name ?? "Unknown", (int)input.Length, outputByteLength, evtPurpose, timeProvider: timeProvider);

            return ValueTask.FromResult<(DigestValue, CryptoEvent?)>((result, evt));
        }


        /// <summary>Verifies an ECDSA P-256/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/> against <paramref name="publicKeyMaterial"/>.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The IEEE P1363 fixed-length signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The SEC1 public key of P-256: 0x02 or 0x03 and 32 octets, or 0x04 and 64 octets.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no point of P-256 and for a signature the platform does not verify, as <see cref="VerifyECDsa"/> answers.
        /// </returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not serve P-256.</exception>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP256Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P256, ECCurve.NamedCurves.nistP256, EllipticCurveTypes.P256, 32, HashAlgorithmName.SHA256, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a P-256 private key using ECDSA/SHA-256.</summary>
        /// <param name="privateKeyBytes">The P-256 private key's scalar bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP256Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, CryptoTags.P256Signature, timeProvider);
        }

        /// <summary>Verifies an ECDSA P-384/SHA-384 <paramref name="signature"/> over <paramref name="dataToVerify"/> against <paramref name="publicKeyMaterial"/>.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The IEEE P1363 fixed-length signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The SEC1 public key of P-384: 0x02 or 0x03 and 48 octets, or 0x04 and 96 octets.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no point of P-384 and for a signature the platform does not verify, as <see cref="VerifyECDsa"/> answers.
        /// </returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not serve P-384.</exception>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP384Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P384, ECCurve.NamedCurves.nistP384, EllipticCurveTypes.P384, 48, HashAlgorithmName.SHA384, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a P-384 private key using ECDSA/SHA-384.</summary>
        /// <param name="privateKeyBytes">The P-384 private key's scalar bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP384Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, CryptoTags.P384Signature, timeProvider);
        }

        /// <summary>Verifies an ECDSA P-521/SHA-512 <paramref name="signature"/> over <paramref name="dataToVerify"/> against <paramref name="publicKeyMaterial"/>.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The IEEE P1363 fixed-length signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The SEC1 public key of P-521: 0x02 or 0x03 and 66 octets, or 0x04 and 132 octets.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no point of P-521 and for a signature the platform does not verify, as <see cref="VerifyECDsa"/> answers.
        /// </returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not serve P-521.</exception>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyP521Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.P521, ECCurve.NamedCurves.nistP521, EllipticCurveTypes.P521, 66, HashAlgorithmName.SHA512, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a P-521 private key using ECDSA/SHA-512.</summary>
        /// <param name="privateKeyBytes">The P-521 private key's scalar bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignP521Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, CryptoTags.P521Signature, timeProvider);
        }

        /// <summary>Verifies an ECDSA secp256k1/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/> against <paramref name="publicKeyMaterial"/>.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The IEEE P1363 fixed-length signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The SEC1 public key of secp256k1: 0x02 or 0x03 and 32 octets, or 0x04 and 64 octets.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no point of secp256k1 and for a signature the platform does not verify, as <see cref="VerifyECDsa"/> answers.
        /// </returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not serve secp256k1.</exception>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifySecp256k1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyECDsa(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Secp256k1, ECCurve.CreateFromFriendlyName("secP256k1"), EllipticCurveTypes.Secp256k1, 32, HashAlgorithmName.SHA256, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a secp256k1 private key using ECDSA/SHA-256.</summary>
        /// <param name="privateKeyBytes">The secp256k1 private key's scalar bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignSecp256k1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignECDsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, ECCurve.CreateFromFriendlyName("secP256k1"), HashAlgorithmName.SHA256, CryptoTags.Secp256k1Signature, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a 2048-bit RSA private key using RSASSA-PKCS1-v1_5/SHA-256.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa2048Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa2048Signature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PKCS1-v1_5/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/> under a 2048-bit RSA key.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa2048Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Rsa2048, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> with a 4096-bit RSA private key using RSASSA-PKCS1-v1_5/SHA-256.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa4096Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.Rsa4096Signature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PKCS1-v1_5/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/> under a 4096-bit RSA key.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsa4096Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.Rsa4096, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PKCS1-v1_5/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>RS256</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha256, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PKCS1-v1_5/SHA-256, tagged for the <c>RS256</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha256Pkcs1Signature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PSS/SHA-256 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>PS256</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha256PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha256Pss, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PSS/SHA-256, tagged for the <c>PS256</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha256PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA256, RSASignaturePadding.Pss, CryptoTags.RsaSha256PssSignature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PKCS1-v1_5/SHA-384 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>RS384</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha384, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PKCS1-v1_5/SHA-384, tagged for the <c>RS384</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha384Pkcs1Signature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PSS/SHA-384 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>PS384</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha384PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha384Pss, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PSS/SHA-384, tagged for the <c>PS384</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha384PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA384, RSASignaturePadding.Pss, CryptoTags.RsaSha384PssSignature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PKCS1-v1_5/SHA-512 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>RS512</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512Pkcs1Async(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha512, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PKCS1-v1_5/SHA-512, tagged for the <c>RS512</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512Pkcs1Async(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, CryptoTags.RsaSha512Pkcs1Signature, timeProvider);
        }

        /// <summary>Verifies an RSASSA-PSS/SHA-512 <paramref name="signature"/> over <paramref name="dataToVerify"/>, tagged for the <c>PS512</c> JOSE algorithm identity.</summary>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature bytes to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the verification.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify, as
        /// <see cref="VerifyRsaAsync"/> answers.
        /// </returns>
        public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaSha512PssAsync(ReadOnlyMemory<byte> dataToVerify, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeyMaterial, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            return VerifyRsaAsync(dataToVerify.Span, signature.Span, publicKeyMaterial.Span, CryptoAlgorithm.RsaSha512Pss, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, timeProvider);
        }

        /// <summary>Signs <paramref name="dataToSign"/> using RSASSA-PSS/SHA-512, tagged for the <c>PS512</c> JOSE algorithm identity.</summary>
        /// <param name="privateKeyBytes">The DER-encoded RSA private key bytes.</param>
        /// <param name="dataToSign">The bytes to produce the signature over.</param>
        /// <param name="signaturePool">The pool the returned <see cref="Signature"/> buffer is rented from.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <param name="context">Optional caller-supplied context forwarded onto telemetry.</param>
        /// <param name="cancellationToken">Cancels the signing operation.</param>
        public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaSha512PssAsync(ReadOnlyMemory<byte> privateKeyBytes, ReadOnlyMemory<byte> dataToSign, BaseMemoryPool signaturePool, TimeProvider timeProvider, FrozenDictionary<string, object>? context = null, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(signaturePool);
            return SignRsa(privateKeyBytes.Span, dataToSign.Span, signaturePool, HashAlgorithmName.SHA512, RSASignaturePadding.Pss, CryptoTags.RsaSha512PssSignature, timeProvider);
        }

        /// <summary>
        /// Verifies an ECDSA signature over <paramref name="dataToVerify"/> under a SEC1-encoded public key, the
        /// one body of this provider's ECDSA verification members.
        /// </summary>
        /// <remarks>
        /// The public key is checked before the platform is asked. It is read only in the two SEC1 encodings of the
        /// curve the public member names: 0x02 or 0x03 followed by <paramref name="fieldLength"/> octets
        /// (compressed), or 0x04 followed by twice that (uncompressed); presented octets of any other length or first
        /// octet answer <c>false</c>. A compressed point is decompressed, and a point whose coordinates
        /// <see cref="EllipticCurveUtilities.CheckPointOnCurve"/> refuses (a coordinate not below the field prime, a
        /// point not on the curve) answers <c>false</c>; what the decompression or the coordinate slicing raises for
        /// such octets (<see cref="ArgumentException"/> or <see cref="ArgumentOutOfRangeException"/>) is inside the
        /// member's one refusal and answers <c>false</c> too. A point the platform refuses to import with
        /// <see cref="CryptographicException"/> answers <c>false</c>, and so does a signature the platform does not
        /// verify, one of the wrong length included. <see cref="PlatformNotSupportedException"/> is not caught: it
        /// leaves this member only when the platform does not serve the curve.
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.4">RFC 8725 Section 3.4</see>: "The JWS/JWE
        /// library itself must validate these inputs before using them, or it must use underlying cryptographic
        /// libraries that do so (or both!)."
        /// </remarks>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The IEEE P1363 signature (r || s) to check.</param>
        /// <param name="publicKeyMaterial">The SEC1-encoded public key, compressed or uncompressed.</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the produced event.</param>
        /// <param name="curve">The named curve the platform is asked to verify on.</param>
        /// <param name="curveType">The curve the public member names, for the decompression and the on-curve check.</param>
        /// <param name="fieldLength">The field length of that curve in octets, stated by the public member.</param>
        /// <param name="hashAlgorithmName">The digest the signature was produced with.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no point of the curve and for a signature the platform does not verify.
        /// </returns>
        /// <exception cref="PlatformNotSupportedException">The platform does not serve <paramref name="curve"/>.</exception>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyECDsa(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, CryptoAlgorithm algorithm, ECCurve curve, EllipticCurveTypes curveType, int fieldLength, HashAlgorithmName hashAlgorithmName, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyECDsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                _ = activity.SetTag(CryptoTelemetry.Signature.Curve, MapCurveDisplay(curve));
            }

            //A SEC1 point of the curve is 0x02 or 0x03 and f octets compressed, or 0x04 and 2f octets uncompressed, f
            //the curve's field length; presented octets of any other length or first octet are no public key of it.
            bool isSec1Point = (publicKeyMaterial.Length == 1 + fieldLength && publicKeyMaterial[0] is 0x02 or 0x03)
                || (publicKeyMaterial.Length == 1 + (2 * fieldLength) && publicKeyMaterial[0] == 0x04);
            if(!isSec1Point)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
            }

            //The compressed form the library uses for verification keys is decompressed, the uncompressed point an
            //eMRTD SubjectPublicKeyInfo (EF.DG14 / EF.DG15) carries is copied through; then the coordinates are held
            //to the curve before the platform sees them. What the decompression or the slicing raises is the refusal.
            ECParameters parameters;
            try
            {
                byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(publicKeyMaterial, curveType);
                ReadOnlySpan<byte> x = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint);
                ReadOnlySpan<byte> y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint);
                if(!EllipticCurveUtilities.CheckPointOnCurve(x, y, curveType))
                {
                    return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
                }

                parameters = new()
                {
                    Curve = curve,
                    Q = new ECPoint
                    {
                        X = x.ToArray(),
                        Y = y.ToArray()
                    }
                };
            }
            catch(ArgumentException)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
            }

            try
            {
                using ECDsa key = ECDsa.Create(parameters);
                bool isVerified = key.VerifyData(dataToVerify, signature, hashAlgorithmName);

                return CompletedVerification(isVerified, algorithm, dataToVerify.Length, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, timeProvider);
            }
            catch(CryptographicException)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
            }
        }


        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignECDsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, BaseMemoryPool signaturePool, ECCurve curve, HashAlgorithmName hashAlgorithmName, Tag signatureTag, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignECDsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "ECDSA");
                _ = activity.SetTag(CryptoTelemetry.Signature.Curve, MapCurveDisplay(curve));
            }

            //ECParameters.D is a byte[]-typed BCL struct field, so importing the raw scalar always
            //needs a byte[] copy; it is zeroed in finally once ECDsa.Create has imported it, and the
            //ECDsa handle is disposed deterministically rather than left for the GC.
            byte[] privateKeyArray = privateKeyBytes.ToArray();
            byte[] signatureBytes;
            try
            {
                using ECDsa key = ECDsa.Create(new ECParameters
                {
                    Curve = curve,
                    D = privateKeyArray
                });

                signatureBytes = key.SignData(dataToSign, hashAlgorithmName);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateKeyArray);
            }

            var memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
            signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

            var signatureResult = new Signature(memoryPooledSignature, signatureTag);
            CryptoEvent evt = SignatureProducedEvent.Create(
                signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
        }

        /// <summary>
        /// Verifies an RSA signature over <paramref name="dataToVerify"/>, the one body of this provider's RSA
        /// verification members.
        /// </summary>
        /// <remarks>
        /// <see cref="TryReadRsaPublicKey"/> reads the public key octets by the rule the class remarks state, and the
        /// reading is held to <see cref="RsaUtilities.IsValidPublicKey"/> before anything is imported; octets that are
        /// no public key by the rule, and a reading that fails the check, answer <c>false</c>, and no presented octets
        /// raise. The platform's refusal of the import or of the verification, <see cref="CryptographicException"/>,
        /// answers <c>false</c>; no other exception type is caught. A signature the platform does not verify answers
        /// <c>false</c>: one that is not k octets, one not below the modulus, and any signature under a modulus too
        /// small for the digest and the salt among them.
        /// </remarks>
        /// <param name="dataToVerify">The bytes the signature was produced over.</param>
        /// <param name="signature">The signature to check.</param>
        /// <param name="publicKeyMaterial">The RSA public key octets, read by the rule the class remarks state.</param>
        /// <param name="algorithm">The <see cref="CryptoAlgorithm"/> stamped on the produced event.</param>
        /// <param name="hashAlgorithmName">The digest the signature was produced with.</param>
        /// <param name="padding">The signature scheme's padding.</param>
        /// <param name="timeProvider">The clock the produced <see cref="CryptoEvent"/> is stamped with.</param>
        /// <returns>
        /// Whether the signature verifies, with the event; <c>false</c>, raising nothing, for public key octets that are
        /// no valid RSA public key this member reads and for a signature the platform does not verify.
        /// </returns>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaAsync(ReadOnlySpan<byte> dataToVerify, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyMaterial, CryptoAlgorithm algorithm, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(VerifyRsaAsync));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            if(!TryReadRsaPublicKey(publicKeyMaterial, out byte[]? modulus, out byte[]? exponent)
                || !RsaUtilities.IsValidPublicKey(modulus, exponent))
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
            }

            try
            {
                using RSA rsa = RSA.Create();
                rsa.ImportParameters(new RSAParameters
                {
                    Modulus = modulus,
                    Exponent = exponent
                });

                bool isVerified = rsa.VerifyData(dataToVerify, signature, hashAlgorithmName, padding);

                return CompletedVerification(isVerified, algorithm, dataToVerify.Length, isVerified ? VerificationOutcome.Valid : VerificationOutcome.Invalid, timeProvider);
            }
            catch(CryptographicException)
            {
                return CompletedVerification(false, algorithm, dataToVerify.Length, VerificationOutcome.Error, timeProvider);
            }
        }


        /// <summary>
        /// Reads presented RSA public key octets by the rule the class remarks state. The first arm is read with
        /// <see cref="AsnDecoder"/>: the octets are exactly a DER <c>RSAPublicKey</c> when the SEQUENCE spans every
        /// octet and its two INTEGERs span its whole content; content the decoder refuses
        /// (<see cref="AsnContentException"/>, the type <c>System.Formats.Asn1</c> documents for content that is not
        /// valid under the encoding rules), DER with a trailing octet and a SEQUENCE with a third INTEGER among them,
        /// goes to the second arm. The reading is not a check: <see cref="VerifyRsaAsync"/> holds every reading to
        /// <see cref="RsaUtilities.IsValidPublicKey"/> before it is used.
        /// </summary>
        /// <param name="publicKeyMaterial">The presented public key octets.</param>
        /// <param name="modulus">The modulus as unsigned big-endian octets, when read.</param>
        /// <param name="exponent">The public exponent as unsigned big-endian octets, when read.</param>
        /// <returns>
        /// <see langword="true"/> with the reading of the arm that reads the octets; <see langword="false"/> for an
        /// exact DER <c>RSAPublicKey</c> with a negative INTEGER and for other octets whose first octet is zero.
        /// </returns>
        private static bool TryReadRsaPublicKey(ReadOnlySpan<byte> publicKeyMaterial, [NotNullWhen(true)] out byte[]? modulus, [NotNullWhen(true)] out byte[]? exponent)
        {
            modulus = null;
            exponent = null;
            ReadOnlySpan<byte> modulusInteger = default;
            ReadOnlySpan<byte> exponentInteger = default;
            bool isExactRsaPublicKey;
            try
            {
                AsnDecoder.ReadSequence(publicKeyMaterial, AsnEncodingRules.DER, out int contentOffset, out int contentLength, out int sequenceLength);
                ReadOnlySpan<byte> content = publicKeyMaterial.Slice(contentOffset, contentLength);
                modulusInteger = AsnDecoder.ReadIntegerBytes(content, AsnEncodingRules.DER, out int modulusLength);
                exponentInteger = AsnDecoder.ReadIntegerBytes(content[modulusLength..], AsnEncodingRules.DER, out int exponentLength);
                isExactRsaPublicKey = sequenceLength == publicKeyMaterial.Length && modulusLength + exponentLength == content.Length;
            }
            catch(AsnContentException)
            {
                isExactRsaPublicKey = false;
            }

            if(!isExactRsaPublicKey)
            {
                //The second arm: octets that are not exactly a DER RSAPublicKey are the bare modulus they spell, under
                //65537, held to the minimum number of octets, so a first octet of zero is no modulus.
                if(publicKeyMaterial is [0x00, ..])
                {
                    return false;
                }

                modulus = publicKeyMaterial.ToArray();
                exponent = [0x01, 0x00, 0x01];

                return true;
            }

            //A DER INTEGER is two's complement: a set top bit is a negative value, which is no modulus or exponent.
            if((modulusInteger[0] & 0x80) != 0 || (exponentInteger[0] & 0x80) != 0)
            {
                return false;
            }

            modulus = modulusInteger.TrimStart((byte)0x00).ToArray();
            exponent = exponentInteger.TrimStart((byte)0x00).ToArray();

            return true;
        }

        private static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsa(ReadOnlySpan<byte> privateKeyBytes, ReadOnlySpan<byte> dataToSign, BaseMemoryPool signaturePool, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding, Tag signatureTag, TimeProvider timeProvider)
        {
            ProviderOperation operation = new(nameof(SignRsa));
            using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
            if(activity is not null)
            {
                CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
                _ = activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA");
            }

            using(RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKeyBytes, out _);
                byte[] signatureBytes = rsa.SignData(dataToSign, hashAlgorithmName, padding);
                IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
                signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

                var signatureResult = new Signature(memoryPooledSignature, signatureTag);
                CryptoEvent evt = SignatureProducedEvent.Create(
                    signatureTag.Get<CryptoAlgorithm>(), dataToSign.Length, signatureBytes.Length, CryptoLib.Name, timeProvider: timeProvider);

                return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
            }
        }


        /// <summary>
        /// Builds the completed <see cref="ValueTask{TResult}"/> tuple a <see cref="VerificationDelegate"/>
        /// returns: the verification result paired with the <see cref="VerificationCompletedEvent"/> describing it.
        /// </summary>
        private static ValueTask<(bool IsVerified, CryptoEvent? Event)> CompletedVerification(bool isVerified, CryptoAlgorithm algorithm, int dataLength, VerificationOutcome outcome, TimeProvider timeProvider)
        {
            CryptoEvent evt = VerificationCompletedEvent.Create(algorithm, outcome, dataLength, CryptoLib.Name, timeProvider: timeProvider);

            return ValueTask.FromResult<(bool, CryptoEvent?)>((isVerified, evt));
        }


        private static string MapCurveDisplay(ECCurve curve) =>
            curve.Oid.FriendlyName switch
            {
                "nistP256" => "P-256",
                "nistP384" => "P-384",
                "nistP521" => "P-521",
                "secP256k1" => "secp256k1",
                _ => curve.Oid.FriendlyName ?? "Unknown"
            };
    }
}

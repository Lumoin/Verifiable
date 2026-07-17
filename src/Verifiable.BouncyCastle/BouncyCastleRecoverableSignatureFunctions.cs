using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Provider;
using CryptoLibraryInfo = Verifiable.Cryptography.Provider.CryptoLibrary;

namespace Verifiable.BouncyCastle;

/// <summary>
/// RSA digital signatures with message recovery per ISO/IEC 9796-2 Digital Signature scheme 1, using the
/// BouncyCastle library (the .NET base class library provides no ISO-9796-2 implementation). This is the
/// scheme ICAO Doc 9303 Part 11 §6.1 Active Authentication uses for RSA chip keys, exposed behind
/// <see cref="RecoverableSigningDelegate"/> and <see cref="RecoverableVerificationDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// In the eMRTD construction the signed message is <c>M1 ‖ M2</c>, where <c>M2</c> is the terminal's
/// 8-byte challenge RND.IFD (supplied to the verifier) and <c>M1</c> is a random block the chip generates
/// to exactly fill the key's recoverable capacity, so the signature opens to
/// <c>header ‖ M1 ‖ Hash(M1 ‖ M2) ‖ trailer</c>. The verifier recovers <c>M1</c>, recomputes the hash over
/// it and the supplied <c>M2</c>, and checks the embedded value. The hash function is identified by the
/// signature trailer, so verification tries the standard ISO-9796-2 trailer/hash pairings rather than being
/// told the hash in advance.
/// </para>
/// </remarks>
public static class BouncyCastleRecoverableSignatureFunctions
{
    private static ProviderLibrary ProviderLib { get; } = new(
        typeof(BouncyCastleRecoverableSignatureFunctions).Assembly.GetName().Name ?? "Verifiable.BouncyCastle",
        typeof(BouncyCastleRecoverableSignatureFunctions).Assembly.GetName().Version?.ToString() ?? "Unknown");

    //BouncyCastle is an independently versioned NuGet package — its assembly version is the
    //most meaningful CBOM identifier.
    private static CryptoLibraryInfo CryptoLib { get; } = new(
        "Org.BouncyCastle.Cryptography",
        typeof(Org.BouncyCastle.Security.SecureRandom).Assembly.GetName().Version?.ToString() ?? "Unknown");

    private static ProviderClass ProviderCls { get; } = new(nameof(BouncyCastleRecoverableSignatureFunctions));


    /// <summary>
    /// Signs an eMRTD RSA Active Authentication challenge with ISO/IEC 9796-2 Digital Signature scheme 1,
    /// using SHA-256 with an explicit trailer. Matches <see cref="RecoverableSigningDelegate"/>.
    /// </summary>
    /// <param name="privateKeyBytes">The PKCS#1 DER-encoded RSA private key (<c>RSAPrivateKey</c>).</param>
    /// <param name="nonRecoverableMessage">The non-recovered message part M2 — the terminal's challenge RND.IFD.</param>
    /// <param name="signaturePool">The memory pool used to allocate the signature buffer.</param>
    /// <param name="context">Optional context dictionary. Reserved for future use.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A pool-allocated signature tagged with <see cref="CryptoTags.RsaIso9796d2Signature"/>, paired with
    /// the <see cref="SignatureProducedEvent"/> describing the operation. Matches
    /// <see cref="RecoverableSigningDelegate"/>.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Signature transfers to the caller.")]
    public static ValueTask<(Signature Signature, CryptoEvent? Event)> SignRsaIso9796d2Async(
        ReadOnlyMemory<byte> privateKeyBytes,
        ReadOnlyMemory<byte> nonRecoverableMessage,
        MemoryPool<byte> signaturePool,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signaturePool);

        ProviderOperation operation = new(nameof(SignRsaIso9796d2Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Sign);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA-ISO9796-2");
        }

        RsaPrivateCrtKeyParameters privateKey = ParseRsaPrivateKey(privateKeyBytes.Span);
        var publicKey = new RsaKeyParameters(isPrivate: false, privateKey.Modulus, privateKey.PublicExponent);

        //The random recoverable block M1 must exactly fill the key's recoverable capacity so that signing
        //M1 ‖ M2 leaves M2 (the challenge) as the whole non-recovered remainder. BouncyCastle exposes no
        //recoverable capacity for a signing key, so it is measured from the library itself.
        int recoverableCapacity = MeasureRecoverableCapacity(privateKey, publicKey, signaturePool);

        var signer = new Iso9796d2Signer(new RsaEngine(), new Sha256Digest(), isImplicit: false);
        signer.Init(forSigning: true, privateKey);

        //M1 is signature-internal randomness drawn from the provider's CSPRNG, like the ephemeral keys and IVs
        //the other BouncyCastle provider functions draw; M2 is the terminal's challenge. M1 is rented from the
        //pool (zeroized on disposal) and fed to the signer as a span, and M2 passes through as a span — no
        //naked arrays. BouncyCastle's GenerateSignature still allocates the output array, which is copied
        //straight into the pooled Signature carrier the caller owns.
        using IMemoryOwner<byte> recoverableBlock = signaturePool.Rent(recoverableCapacity);
        Span<byte> m1 = recoverableBlock.Memory.Span[..recoverableCapacity];
        new SecureRandom().NextBytes(m1);
        signer.BlockUpdate(m1);
        signer.BlockUpdate(nonRecoverableMessage.Span);

        byte[] signatureBytes = signer.GenerateSignature();
        IMemoryOwner<byte> memoryPooledSignature = signaturePool.Rent(signatureBytes.Length);
        signatureBytes.CopyTo(memoryPooledSignature.Memory.Span);

        var signatureResult = new Signature(memoryPooledSignature, CryptoTags.RsaIso9796d2Signature);

        //DataLength reports the whole signed message (M1 ‖ M2) — the recoverable block this call generated
        //plus the caller-supplied non-recovered challenge — matching what SignatureProducedEvent means by
        //"the data that was signed" for every other signing backend.
        CryptoEvent evt = SignatureProducedEvent.Create(
            CryptoAlgorithm.RsaIso9796d2, recoverableCapacity + nonRecoverableMessage.Length, signatureBytes.Length, CryptoLib.Name);

        return ValueTask.FromResult<(Signature, CryptoEvent?)>((signatureResult, evt));
    }


    /// <summary>
    /// Verifies an eMRTD RSA Active Authentication signature (ISO/IEC 9796-2 Digital Signature scheme 1),
    /// recovering the chip's random block and checking the embedded hash over it and the supplied challenge.
    /// Matches <see cref="RecoverableVerificationDelegate"/>.
    /// </summary>
    /// <param name="nonRecoverableMessage">The non-recovered message part M2 — the terminal's challenge RND.IFD.</param>
    /// <param name="signature">The chip's ISO-9796-2 signature.</param>
    /// <param name="publicKeyMaterial">The DER <c>RSAPublicKey</c> (modulus and public exponent), as carried in EF.DG15.</param>
    /// <param name="context">Optional context dictionary. Reserved for future use.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// <see langword="true"/> if the signature verifies under any recognised trailer/hash pairing; otherwise
    /// <see langword="false"/>, paired with a <see cref="VerificationCompletedEvent"/> when the verification
    /// actually ran. Matches <see cref="RecoverableVerificationDelegate"/>.
    /// </returns>
    public static ValueTask<(bool IsVerified, CryptoEvent? Event)> VerifyRsaIso9796d2Async(
        ReadOnlyMemory<byte> nonRecoverableMessage,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> publicKeyMaterial,
        FrozenDictionary<string, object>? context = null,
        CancellationToken cancellationToken = default)
    {
        ProviderOperation operation = new(nameof(VerifyRsaIso9796d2Async));
        using Activity? activity = CryptoActivitySource.Source.StartActivity(CryptoTelemetry.ActivityNames.Verify);
        if(activity is not null)
        {
            CryptoProviderInstrumentation.SetProviderAttributes(activity, ProviderLib, CryptoLib, ProviderCls, operation);
            activity.SetTag(CryptoTelemetry.Signature.Algorithm, "RSA-ISO9796-2");
        }

        RsaKeyParameters publicKey;
        try
        {
            publicKey = ParseDerRsaPublicKey(publicKeyMaterial.Span);
        }
        catch(Exception exception) when(exception is ArgumentException or InvalidOperationException or InvalidCastException or System.IO.IOException or FormatException)
        {
            //A malformed DER public key, or a degenerate/undersized RSA key, fails closed to a non-verifying result
            //rather than throwing out of this bool-returning API — inspection is fail-closed (Doc 9303 Part 11 §6.1):
            //a non-conformant chip response is rejected, not allowed to crash the terminal. No event is emitted:
            //verification never actually ran against a key, so there is nothing a VerificationCompletedEvent could
            //truthfully describe (its Outcome distinguishes Valid/Invalid/Error for an attempted verification, not
            //"the key itself was unusable").
            return ValueTask.FromResult<(bool, CryptoEvent?)>((false, null));
        }

        //BouncyCastle's recovery API takes the signature as a byte[] (UpdateWithRecoveredMessage and
        //VerifySignature have no span overload); it is public material, copied once here for that interop.
        //M2 (the challenge) passes through as a span.
        byte[] signatureBytes = signature.ToArray();

        //The hash is identified by the recovered trailer, which is not known before recovery, so each
        //standard ISO-9796-2 trailer/hash pairing is tried until one verifies. A forgery verifies under none.
        //SHA-256 (this implementation's signing default) is tried first; SHA-1 with the implicit trailer is
        //the classic eMRTD pairing. A pairing whose trailer does not match throws inside BouncyCastle's block
        //parsing — that is a non-match, not a fault, so it falls through to the next candidate.
        foreach((Func<IDigest> digestFactory, bool isImplicit) in TrailerCandidates)
        {
            var verifier = new Iso9796d2Signer(new RsaEngine(), digestFactory(), isImplicit);
            verifier.Init(forSigning: false, publicKey);

            bool verified;
            try
            {
                //Recover M1 from the signature and feed it to the digest, then append the non-recovered M2, so
                //the hash is computed over M1 ‖ M2 in order. UpdateWithRecoveredMessage throws when the trailer
                //does not match this candidate's hash — that is a non-match, handled by trying the next pairing.
                //A signature from a different key is a raw integer that may equal or exceed this key's modulus,
                //which the RSA core rejects with DataLengthException ("input too large for RSA cipher"); that is
                //also a non-match, so verification fails closed rather than throwing.
                verifier.UpdateWithRecoveredMessage(signatureBytes);
                verifier.BlockUpdate(nonRecoverableMessage.Span);
                verified = verifier.VerifySignature(signatureBytes);
            }
            catch(Exception exception) when(exception is InvalidCipherTextException or DataLengthException or ArgumentException or InvalidOperationException)
            {
                verified = false;
            }

            if(verified)
            {
                //DataLength reports the whole verified message (recovered M1 ‖ the caller-supplied M2), matching
                //what the sign side reports and what SignatureProducedEvent/VerificationCompletedEvent mean by
                //"the data" elsewhere: the recovered length comes straight from the signer that just verified it,
                //not recomputed.
                int recoveredLength = verifier.GetRecoveredMessage().Length;
                CryptoEvent verifiedEvt = VerificationCompletedEvent.Create(
                    CryptoAlgorithm.RsaIso9796d2, VerificationOutcome.Valid, recoveredLength + nonRecoverableMessage.Length, CryptoLib.Name);

                return ValueTask.FromResult<(bool, CryptoEvent?)>((true, verifiedEvt));
            }
        }

        CryptoEvent invalidEvt = VerificationCompletedEvent.Create(
            CryptoAlgorithm.RsaIso9796d2, VerificationOutcome.Invalid, nonRecoverableMessage.Length, CryptoLib.Name);

        return ValueTask.FromResult<(bool, CryptoEvent?)>((false, invalidEvt));
    }


    /// <summary>
    /// The standard ISO/IEC 9796-2 trailer/hash pairings a verifier tries, the SHA-256 explicit trailer first
    /// (this implementation's signing default), then the classic SHA-1 implicit trailer, then the remaining
    /// explicit trailers. A fresh digest is produced per attempt because BouncyCastle digests are stateful.
    /// </summary>
    private static (Func<IDigest> DigestFactory, bool IsImplicit)[] TrailerCandidates { get; } =
    [
        (static () => new Sha256Digest(), false),
        (static () => new Sha1Digest(), true),
        (static () => new Sha1Digest(), false),
        (static () => new Sha224Digest(), false),
        (static () => new Sha384Digest(), false),
        (static () => new Sha512Digest(), false)
    ];


    /// <summary>
    /// Measures the recoverable-message capacity (in bytes) for the key under SHA-256 with an explicit trailer
    /// — the exact length the random block M1 must have so that M2 becomes the whole non-recovered remainder.
    /// </summary>
    /// <remarks>
    /// The capacity is a finicky function of the key, hash, and trailer sizes, so rather than reproduce
    /// BouncyCastle's block layout it is read back from the library: a throwaway signature over a message
    /// longer than any capacity forces partial recovery, and recovering it yields exactly the capacity-many
    /// leading bytes. Returns an <see cref="int"/>, not a buffer — no signature material crosses this boundary.
    /// </remarks>
    private static int MeasureRecoverableCapacity(RsaPrivateCrtKeyParameters privateKey, RsaKeyParameters publicKey, MemoryPool<byte> pool)
    {
        var probeSigner = new Iso9796d2Signer(new RsaEngine(), new Sha256Digest(), isImplicit: false);
        probeSigner.Init(forSigning: true, privateKey);

        //A message the length of the modulus exceeds the recoverable capacity for any hash, so the signature
        //recovers exactly the capacity-many leading bytes. The probe message is a throwaway (its content does
        //not matter); it is rented from the pool and zeroized rather than a naked array. GenerateSignature
        //allocates the probe signature, a confined BouncyCastle-interop local that is discarded.
        int modulusByteLength = (privateKey.Modulus.BitLength + 7) / 8;
        using IMemoryOwner<byte> overlongMessage = pool.Rent(modulusByteLength);
        Span<byte> probeMessage = overlongMessage.Memory.Span[..modulusByteLength];
        probeMessage.Clear();
        probeSigner.BlockUpdate(probeMessage);
        byte[] probeSignature = probeSigner.GenerateSignature();

        var recoverer = new Iso9796d2Signer(new RsaEngine(), new Sha256Digest(), isImplicit: false);
        recoverer.Init(forSigning: false, publicKey);
        recoverer.UpdateWithRecoveredMessage(probeSignature);

        return recoverer.GetRecoveredMessage().Length;
    }


    /// <summary>
    /// Parses a PKCS#1 DER-encoded RSA private key (<c>RSAPrivateKey</c>) into BouncyCastle key parameters —
    /// the format <c>RSA.ExportRSAPrivateKey()</c> produces.
    /// </summary>
    private static RsaPrivateCrtKeyParameters ParseRsaPrivateKey(ReadOnlySpan<byte> privateKeyBytes)
    {
        //BouncyCastle's classic ASN.1 object model (Asn1Sequence, RsaPrivateKeyStructure) accepts only
        //byte[], so the DER-encoded private key is copied once here and zeroed immediately after the
        //ASN.1 structure is parsed. The resulting RsaPrivateCrtKeyParameters holds the modulus,
        //exponents, and CRT factors as BigInteger magnitudes — BigInteger's internal int[] magnitude is
        //immutable and cannot be zeroed from outside BouncyCastle, so those copies remain for the key's
        //lifetime.
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
    /// Parses a DER <c>RSAPublicKey</c> (<c>SEQUENCE { modulus INTEGER, publicExponent INTEGER }</c>) into
    /// BouncyCastle key parameters, keeping the exact public exponent the eMRTD EF.DG15 carries — unlike the
    /// modulus-only PKCS#1/PSS path, which assumes the exponent is 65537.
    /// </summary>
    private static RsaKeyParameters ParseDerRsaPublicKey(ReadOnlySpan<byte> publicKeyMaterial)
    {
        Asn1Sequence sequence = Asn1Sequence.GetInstance(publicKeyMaterial.ToArray());
        if(sequence.Count < 2)
        {
            throw new ArgumentException(
                "An RSA public key must be a DER SEQUENCE of a modulus and a public exponent.", nameof(publicKeyMaterial));
        }

        var modulus = DerInteger.GetInstance(sequence[0]).PositiveValue;
        var publicExponent = DerInteger.GetInstance(sequence[1]).PositiveValue;

        //Reject a degenerate self-declared key before verification. A chip announcing e = 1 makes RSA the identity
        //map (x^1 mod n == x), so a forged block verifies against the chip's own key with no private-key possession —
        //defeating Active Authentication's anti-cloning purpose (ICAO Doc 9303 Part 11 §6.1).
        if(!RsaUtilities.IsValidPublicKey(modulus.ToByteArrayUnsigned(), publicExponent.ToByteArrayUnsigned()))
        {
            throw new ArgumentException(
                "The RSA public key is not valid: the exponent is degenerate (for example e = 1) or the modulus is too small or even.", nameof(publicKeyMaterial));
        }

        return new RsaKeyParameters(isPrivate: false, modulus, publicExponent);
    }
}
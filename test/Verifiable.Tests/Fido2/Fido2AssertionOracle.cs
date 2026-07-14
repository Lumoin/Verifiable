using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// A minted WebAuthn L3 §7.2 authentication assertion's wire-shaped output: the raw
/// <c>authData</c> and <c>clientDataJSON</c> bytes, and the detached signature over their
/// transcript. Owns the pooled <see cref="Cryptography.Signature"/>; dispose to release it.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>.
/// </remarks>
/// <param name="AuthenticatorData">The raw <c>authData</c> wire bytes.</param>
/// <param name="ClientDataJson">The raw, UTF-8-encoded <c>clientDataJSON</c> wire bytes.</param>
/// <param name="Signature">The detached assertion signature, computed independently of the verifier under test.</param>
internal sealed record MintedAssertion(byte[] AuthenticatorData, byte[] ClientDataJson, Signature Signature): IDisposable
{
    /// <summary>Releases the pooled <see cref="Signature"/> carrier.</summary>
    public void Dispose() => Signature.Dispose();
}


/// <summary>
/// A test-only owned-authenticator oracle for the WebAuthn L3 §7.2 authentication ceremony: holds
/// a credential key pair and mints a genuinely independent, wire-shaped assertion so
/// <c>Fido2AssertionVerifierTests</c> reconstructs everything under test from wire bytes only,
/// never sharing key material or in-memory objects with the verifier under test.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">W3C Web Authentication
/// Level 3, section 7.2: Verifying an Authentication Assertion</see>.
/// </para>
/// <para>
/// The assertion signature is minted through a BouncyCastle primitive called directly — never
/// through <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> — so minting
/// never reuses whatever function the registry happens to have wired up for verification. For the
/// P-256/384/521 and secp256k1 (ES256K) cases, and for every RSA padding/hash family the alg-aware
/// tag resolution in <c>CoseKeyExtensions.ToPublicKeyMemory</c> now resolves (RS256/384/512,
/// PS256/384/512), this is a genuinely different backend than the registered (Microsoft)
/// verification path; for EdDSA — where no independent .NET BCL primitive exists — the
/// independence is that no key object crosses the issuer/verifier firewall, only wire bytes,
/// mirroring the precedent in <c>CoseKeyRsaTests</c>.
/// </para>
/// <para>
/// The BouncyCastle EC primitive returns the fixed-width IEEE P1363 <c>r ‖ s</c> encoding (see its own
/// documentation), but <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">section
/// 6.5.5, Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures</see>
/// requires an ECDSA <c>sig</c> value to be ASN.1 DER-encoded. <see cref="MintAsync"/> re-encodes an
/// ES256/384/512/256K signature to DER after minting, via <see cref="EcdsaSignatureEncoding.ConvertP1363ToDer"/>,
/// so the minted wire value is the spec-conformant one <see cref="Fido2AssertionVerifier"/> expects.
/// </para>
/// </remarks>
internal sealed class Fido2AssertionOracle: IDisposable
{
    /// <summary>The credential key pair minting and verification is exercised against.</summary>
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial;

    /// <summary>The independent BouncyCastle signing primitive minting calls directly.</summary>
    private readonly SigningDelegate independentSigner;

    /// <summary>Guards against double disposal.</summary>
    private bool disposed;


    /// <summary>
    /// Initializes the oracle from a key pair, its COSE credential public key view, and the
    /// independent BouncyCastle signing primitive to mint with.
    /// </summary>
    private Fido2AssertionOracle(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial,
        CoseKey credentialPublicKey,
        SigningDelegate independentSigner)
    {
        this.keyMaterial = keyMaterial;
        CredentialPublicKey = credentialPublicKey;
        this.independentSigner = independentSigner;
    }


    /// <summary>
    /// The stored credential public key a relying party would have recorded at registration
    /// time — the only key material <c>Fido2AssertionVerifierTests</c> hands to the verifier
    /// under test.
    /// </summary>
    public CoseKey CredentialPublicKey { get; }


    /// <summary>Builds an oracle for ES256 (ECDSA P-256 / SHA-256), per RFC 9053 §2.1.</summary>
    public static Fido2AssertionOracle CreateEs256()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        CoseKey coseKey = BuildEc2CoseKey(keys.PublicKey, CoseKeyCurves.P256, WellKnownCoseAlgorithms.Es256);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignP256Async);
    }


    /// <summary>Builds an oracle for ES384 (ECDSA P-384 / SHA-384), per RFC 9053 §2.1.</summary>
    public static Fido2AssertionOracle CreateEs384()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP384KeyMaterial();
        CoseKey coseKey = BuildEc2CoseKey(keys.PublicKey, CoseKeyCurves.P384, WellKnownCoseAlgorithms.Es384);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignP384Async);
    }


    /// <summary>Builds an oracle for ES512 (ECDSA P-521 / SHA-512), per RFC 9053 §2.1.</summary>
    public static Fido2AssertionOracle CreateEs512()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP521KeyMaterial();
        CoseKey coseKey = BuildEc2CoseKey(keys.PublicKey, CoseKeyCurves.P521, WellKnownCoseAlgorithms.Es512);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignP521Async);
    }


    /// <summary>Builds an oracle for RS256 (RSASSA-PKCS1-v1_5 / SHA-256), per RFC 8812 §2.</summary>
    public static Fido2AssertionOracle CreateRs256()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Rs256);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsa2048Async);
    }


    /// <summary>Builds an oracle for RS384 (RSASSA-PKCS1-v1_5 / SHA-384), per RFC 8812 §2.</summary>
    public static Fido2AssertionOracle CreateRs384()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Rs384);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsaSha384Pkcs1Async);
    }


    /// <summary>Builds an oracle for RS512 (RSASSA-PKCS1-v1_5 / SHA-512), per RFC 8812 §2.</summary>
    public static Fido2AssertionOracle CreateRs512()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Rs512);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsaSha512Pkcs1Async);
    }


    /// <summary>
    /// Builds an oracle for PS256 (RSASSA-PSS / SHA-256), per RFC 8230 §2. Mints through the
    /// independent BouncyCastle PSS signer — the registered PS256 verify path is Microsoft-backed —
    /// so a genuine PSS signature exercises the alg-aware RSA tag resolution this oracle regression-tests.
    /// </summary>
    public static Fido2AssertionOracle CreatePs256()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Ps256);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsaSha256PssAsync);
    }


    /// <summary>Builds an oracle for PS384 (RSASSA-PSS / SHA-384), per RFC 8230 §2.</summary>
    public static Fido2AssertionOracle CreatePs384()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Ps384);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsaSha384PssAsync);
    }


    /// <summary>Builds an oracle for PS512 (RSASSA-PSS / SHA-512), per RFC 8230 §2.</summary>
    public static Fido2AssertionOracle CreatePs512()
    {
        var keys = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        CoseKey coseKey = BuildRsaCoseKey(keys.PublicKey, WellKnownCoseAlgorithms.Ps512);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignRsaSha512PssAsync);
    }


    /// <summary>
    /// Builds an oracle for ES256K (ECDSA secp256k1 / SHA-256), per RFC 8812 §3. The wire signature
    /// re-encodes P1363 to ASN.1 DER exactly as the NIST-curve oracles do — WebAuthn L3
    /// section 6.5.5 makes no distinction between NIST and secp256k1 ECDSA signature encoding.
    /// </summary>
    public static Fido2AssertionOracle CreateEs256K()
    {
        var keys = TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial();
        CoseKey coseKey = BuildEc2CoseKey(keys.PublicKey, CoseKeyCurves.Secp256k1, WellKnownCoseAlgorithms.Es256K);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignSecp256k1Async);
    }


    /// <summary>Builds an oracle for EdDSA (Ed25519), per RFC 9053 §2.2.</summary>
    public static Fido2AssertionOracle CreateEdDsa()
    {
        var keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        CoseKey coseKey = BuildOkpCoseKey(keys.PublicKey, CoseKeyCurves.Ed25519, WellKnownCoseAlgorithms.EdDsa);

        return new Fido2AssertionOracle(keys, coseKey, BouncyCastleCryptographicFunctions.SignEd25519Async);
    }


    /// <summary>
    /// Mints a full authentication assertion: builds <c>authData</c> (no attested credential data,
    /// per section 6.1's assertion layout), a <c>webauthn.get</c> <c>clientDataJSON</c>, and signs
    /// their transcript with the oracle's independent BouncyCastle signer.
    /// </summary>
    /// <param name="challenge">The base64url-encoded challenge to embed in <c>clientDataJSON</c>.</param>
    /// <param name="origin">The origin to embed in <c>clientDataJSON</c>.</param>
    /// <param name="rpIdHash">The 32-byte relying party ID hash to embed in <c>authData</c>. Defaults to a fixed test vector.</param>
    /// <param name="signCount">The signature counter to embed in <c>authData</c>.</param>
    /// <param name="userPresent">The <c>UP</c> flag value.</param>
    /// <param name="userVerified">The <c>UV</c> flag value.</param>
    /// <param name="backupEligible">The <c>BE</c> flag value.</param>
    /// <param name="backupState">The <c>BS</c> flag value.</param>
    /// <param name="clientDataType">The client data <c>type</c> member. Defaults to <see cref="WellKnownClientDataTypes.Get"/>.</param>
    /// <param name="crossOrigin">The client data <c>crossOrigin</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="topOrigin">The client data <c>topOrigin</c> member, or <see langword="null"/> to omit it.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>The minted wire-shaped assertion; the caller owns and disposes it.</returns>
    public async ValueTask<MintedAssertion> MintAsync(
        string challenge,
        string origin,
        byte[]? rpIdHash = null,
        uint signCount = 1,
        bool userPresent = true,
        bool userVerified = true,
        bool backupEligible = false,
        bool backupState = false,
        string? clientDataType = null,
        bool? crossOrigin = null,
        string? topOrigin = null,
        CancellationToken cancellationToken = default)
    {
        byte[] effectiveRpIdHash = rpIdHash ?? Fido2TestVectors.CreateRpIdHash();
        byte flags = ComposeFlags(userPresent, userVerified, backupEligible, backupState);
        byte[] authenticatorData = Fido2TestVectors.BuildAuthenticatorData(effectiveRpIdHash, flags, signCount);
        byte[] clientDataJson = BuildClientDataJson(clientDataType ?? WellKnownClientDataTypes.Get, challenge, origin, crossOrigin, topOrigin);

        using DigestValue clientDataHash = Fido2ClientDataHash.Compute(clientDataJson, BaseMemoryPool.Shared);
        byte[] toBeSigned = Fido2TestVectors.Concat(authenticatorData, clientDataHash.AsReadOnlySpan().ToArray());

        Signature mintedSignature = await keyMaterial.PrivateKey.SignAsync(
            toBeSigned, independentSigner, BaseMemoryPool.Shared, context: null).ConfigureAwait(false);
        Signature signature = ReencodeToDerIfEc(mintedSignature, CredentialPublicKey.Alg, BaseMemoryPool.Shared);

        return new MintedAssertion(authenticatorData, clientDataJson, signature);
    }


    /// <summary>Releases the oracle's credential key pair.</summary>
    public void Dispose()
    {
        if(!disposed)
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
            disposed = true;
        }
    }


    /// <summary>
    /// Re-encodes <paramref name="mintedSignature"/> from IEEE P1363 to ASN.1 DER when
    /// <paramref name="coseAlgorithm"/> is ES256, ES384, ES512, or ES256K — the section 6.5.5
    /// requirement the raw BouncyCastle EC primitive does not itself apply. RSA and EdDSA pass through unchanged.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature (re-encoded or passed through) transfers to the returned MintedAssertion, which the test disposes.")]
    private static Signature ReencodeToDerIfEc(Signature mintedSignature, int? coseAlgorithm, MemoryPool<byte> pool)
    {
        bool isEc = coseAlgorithm is { } alg
            && (WellKnownCoseAlgorithms.IsEs256(alg) || WellKnownCoseAlgorithms.IsEs384(alg) || WellKnownCoseAlgorithms.IsEs512(alg) || WellKnownCoseAlgorithms.IsEs256K(alg));

        if(!isEc)
        {
            return mintedSignature;
        }

        using(mintedSignature)
        {
            IMemoryOwner<byte> derOwner = EcdsaSignatureEncoding.ConvertP1363ToDer(mintedSignature.AsReadOnlySpan(), pool, out _);

            return new Signature(derOwner, CryptoTags.AlgorithmAgnosticSignature);
        }
    }


    /// <summary>
    /// Composes an assertion <c>authData</c> flags byte from its named bits. Assertion ceremonies
    /// carry no attested credential data or extensions, so only the presence/verification/backup
    /// bits are set.
    /// </summary>
    private static byte ComposeFlags(bool userPresent, bool userVerified, bool backupEligible, bool backupState)
    {
        byte flags = AuthenticatorDataFlags.None;
        if(userPresent) { flags |= AuthenticatorDataFlags.UserPresentBit; }
        if(userVerified) { flags |= AuthenticatorDataFlags.UserVerifiedBit; }
        if(backupEligible) { flags |= AuthenticatorDataFlags.BackupEligibleBit; }
        if(backupState) { flags |= AuthenticatorDataFlags.BackupStateBit; }

        return flags;
    }


    /// <summary>
    /// Builds a minimal, well-formed <c>CollectedClientData</c> JSON encoding matching the shape
    /// <see cref="Verifiable.Json.ClientDataJsonReader"/> parses, per WebAuthn L3 section 5.8.1.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> so <c>Fido2CredentialSignerTests</c> can build the same wire-shaped
    /// <c>clientDataJSON</c> around a signature <see cref="Fido2CredentialSigner"/> produces, without
    /// duplicating this shape.
    /// </remarks>
    internal static byte[] BuildClientDataJson(string type, string challenge, string origin, bool? crossOrigin, string? topOrigin)
    {
        var builder = new StringBuilder();
        builder.Append('{');
        builder.Append("\"type\":\"").Append(type).Append("\",");
        builder.Append("\"challenge\":\"").Append(challenge).Append("\",");
        builder.Append("\"origin\":\"").Append(origin).Append('"');
        if(crossOrigin is bool cross)
        {
            builder.Append(",\"crossOrigin\":").Append(cross ? "true" : "false");
        }

        if(topOrigin is not null)
        {
            builder.Append(",\"topOrigin\":\"").Append(topOrigin).Append('"');
        }

        builder.Append('}');

        return Encoding.UTF8.GetBytes(builder.ToString());
    }


    /// <summary>
    /// Builds a P-256/384/521 EC2 <see cref="CoseKey"/> from a compressed public key point,
    /// decompressing to recover the Y coordinate — the credential public key view a relying party
    /// would have stored at registration time.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> so <c>Fido2CredentialSignerTests</c> can build the same stored credential-key
    /// view for a credential it mints and signs with <see cref="Fido2CredentialSigner"/>, without
    /// duplicating this shape.
    /// </remarks>
    internal static CoseKey BuildEc2CoseKey(PublicKeyMemory publicKey, int coseCurve, int alg)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        EllipticCurveTypes curveType = EllipticCurveUtilities.CurveTypeFor(publicKey.Tag.Get<CryptoAlgorithm>());
        byte[] y = EllipticCurveUtilities.Decompress(compressed, curveType);

        return new CoseKey(kty: CoseKeyTypes.Ec2, alg: alg, curve: coseCurve, x: compressed[1..].ToArray(), y: y);
    }


    /// <summary>
    /// Builds an OKP (Ed25519) <see cref="CoseKey"/> from its raw public-key bytes.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> so <c>Fido2CredentialSignerTests</c> can build the same stored credential-key
    /// view for a credential it mints and signs with <see cref="Fido2CredentialSigner"/>, without
    /// duplicating this shape.
    /// </remarks>
    internal static CoseKey BuildOkpCoseKey(PublicKeyMemory publicKey, int coseCurve, int alg) =>
        new(kty: CoseKeyTypes.Okp, alg: alg, curve: coseCurve, x: publicKey.AsReadOnlySpan().ToArray());


    /// <summary>
    /// Builds an RSA <see cref="CoseKey"/> from a DER PKCS#1 <c>RSAPublicKey</c>'s <c>n</c>/<c>e</c>
    /// fields, per RFC 8230 §4.
    /// </summary>
    /// <remarks>
    /// <c>internal</c> so <c>Fido2CredentialSignerTests</c> can build the same stored credential-key
    /// view for a credential it mints and signs with <see cref="Fido2CredentialSigner"/>, without
    /// duplicating this shape.
    /// </remarks>
    internal static CoseKey BuildRsaCoseKey(PublicKeyMemory publicKey, int alg)
    {
        (ReadOnlyMemory<byte> modulus, ReadOnlyMemory<byte> exponent) = ExtractRsaPublicKeyComponents(publicKey.AsReadOnlyMemory());

        return new CoseKey(kty: CoseKeyTypes.Rsa, alg: alg, n: modulus, e: exponent);
    }


    /// <summary>
    /// Extracts the modulus and public exponent from a DER PKCS#1 <c>RSAPublicKey ::= SEQUENCE
    /// { modulus INTEGER, publicExponent INTEGER }</c>.
    /// </summary>
    private static (ReadOnlyMemory<byte> Modulus, ReadOnlyMemory<byte> Exponent) ExtractRsaPublicKeyComponents(ReadOnlyMemory<byte> derEncodedPublicKey)
    {
        AsnReader sequence = new AsnReader(derEncodedPublicKey, AsnEncodingRules.DER).ReadSequence();
        ReadOnlyMemory<byte> modulus = StripLeadingZero(sequence.ReadIntegerBytes());
        ReadOnlyMemory<byte> exponent = StripLeadingZero(sequence.ReadIntegerBytes());

        return (modulus, exponent);
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement
    /// encoding, recovering the unsigned big-endian magnitude RFC 8230 §4 expects.
    /// </summary>
    private static ReadOnlyMemory<byte> StripLeadingZero(ReadOnlyMemory<byte> integer) =>
        integer.Length > 1 && integer.Span[0] == 0x00 ? integer[1..] : integer;
}

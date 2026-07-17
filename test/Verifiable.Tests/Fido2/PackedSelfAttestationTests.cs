using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the self-attestation branch of <see cref="PackedAttestation"/> — the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">WebAuthn L3 section 8.2</see>
/// verification procedure taken when <c>x5c</c> is absent: the signature is checked against the credential
/// public key itself, and <c>alg</c> must match the credential public key's own <c>alg</c> member.
/// </summary>
/// <remarks>
/// The attestation statements under test are minted with an independent oracle — raw <see cref="ECDsa"/>, never
/// the library's own signing seam (<see cref="Fido2AttestationTestVectors.SignWithEcdsaP256"/>) — so
/// <see cref="PackedAttestation"/> is exercised against genuinely external wire material reconstructed solely
/// from the <see cref="AttestationVerificationRequest"/>'s wire-shaped members.
/// </remarks>
[TestClass]
internal sealed class PackedSelfAttestationTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A statement signed with the credential's own private key, with <c>alg</c> matching the credential public
    /// key's <c>alg</c>, verifies to <see cref="SelfAttestationResult"/>.
    /// </summary>
    [TestMethod]
    public async Task MatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        //Independent oracle: this ECDsa both derives the credentialPublicKey below and signs the transcript
        //further down, so PackedAttestation's own COSE verify is exercised against externally produced wire material.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A statement claiming an <c>alg</c> (RS256) different from the credential public key's own <c>alg</c>
    /// (ES256) is rejected with <see cref="Fido2AttestationErrors.AlgorithmMismatch"/>, per the section 8.2
    /// self-attestation step "Validate that alg matches the algorithm of the credentialPublicKey".
    /// </summary>
    [TestMethod]
    public async Task AlgDifferentFromCredentialPublicKeyAlgIsRejectedWithAlgorithmMismatch()
    {
        //Independent oracle: this ECDsa both derives the credentialPublicKey below and signs the transcript
        //further down; the mismatch under test is the statement's declared alg, not the signing key itself.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Rs256, Signature: signature, X5c: null);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>
    /// A credential public key that carries no <c>alg</c> member (<see langword="null"/>) is rejected with
    /// <see cref="Fido2AttestationErrors.AlgorithmMismatch"/> — there is nothing for the statement's <c>alg</c>
    /// to match.
    /// </summary>
    [TestMethod]
    public async Task CredentialPublicKeyWithNullAlgIsRejectedWithAlgorithmMismatch()
    {
        //Independent oracle: this ECDsa both derives the credentialPublicKey below and signs the transcript
        //further down; the missing alg under test lives on the CoseKey, not on the signing key.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, alg: null);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: null);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.AlgorithmMismatch.Code, error.Code);
    }


    /// <summary>
    /// A statement whose signature has been tampered with after minting is rejected with
    /// <see cref="Fido2AttestationErrors.InvalidSignature"/>.
    /// </summary>
    [TestMethod]
    public async Task TamperedSignatureIsRejectedWithInvalidSignature()
    {
        //Independent oracle: this ECDsa both derives the credentialPublicKey below and signs the transcript
        //further down, before the resulting signature is deliberately corrupted.
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP256CoseKey(credentialKey, WellKnownCoseAlgorithms.Es256);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP256(credentialKey, toBeSigned);
        signature[0] ^= 0xFF;

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signature, X5c: null);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.InvalidSignature.Code, error.Code);
    }


    /// <summary>
    /// An <c>authData</c> with the <c>AT</c> flag clear (no attested credential data) is rejected with
    /// <see cref="Fido2AttestationErrors.MissingAttestedCredentialData"/> before any key or signature is examined.
    /// </summary>
    [TestMethod]
    public async Task NoAttestedCredentialDataIsRejectedWithMissingAttestedCredentialData()
    {
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        //The AT flag is clear, so no key resolution is reachable — a fixed pooled placeholder signature is fine.
        using IMemoryOwner<byte> signatureOwner = BaseMemoryPool.Shared.Rent(64);
        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256, Signature: signatureOwner.Memory, X5c: null);

        Fido2AttestationError? error = await VerifyAndGetRejectionErrorAsync(statement, authDataBytes, authenticatorData, clientDataHash);

        Assert.IsNotNull(error);
        Assert.AreEqual(Fido2AttestationErrors.MissingAttestedCredentialData.Code, error.Code);
    }


    /// <summary>
    /// A parse delegate that throws <see cref="Fido2FormatException"/> — simulating a malformed <c>attStmt</c>
    /// CBOR payload — is caught and mapped to <see cref="Fido2AttestationErrors.MalformedStatement"/>.
    /// </summary>
    [TestMethod]
    public async Task ParseDelegateThrowingFido2FormatExceptionIsRejectedWithMalformedStatement()
    {
        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), null, out byte[] authDataBytes);

        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateThrowingParser("Malformed CBOR for test."));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<RejectedAttestationResult>(result);
        Assert.AreEqual(Fido2AttestationErrors.MalformedStatement.Code, ((RejectedAttestationResult)result).Error.Code);
    }


    /// <summary>
    /// A statement signed with an ES384 credential's own private key, with matching <c>alg</c>, verifies to
    /// <see cref="SelfAttestationResult"/> — the ES384 packed self-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Es384MatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        //Independent oracle for the ES384 matrix row: this ECDsa both derives the credentialPublicKey below
        //and signs the transcript further down (see class remarks).
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP384CoseKey(credentialKey, WellKnownCoseAlgorithms.Es384);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP384(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es384, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A statement signed with an ES512 credential's own private key, with matching <c>alg</c>, verifies to
    /// <see cref="SelfAttestationResult"/> — the ES512 packed self-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Es512MatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        //Independent oracle for the ES512 matrix row: this ECDsa both derives the credentialPublicKey below
        //and signs the transcript further down (see class remarks).
        using ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateP521CoseKey(credentialKey, WellKnownCoseAlgorithms.Es512);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithEcdsaP521(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es512, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A statement signed with an RS256 credential's own private key, with matching <c>alg</c>, verifies to
    /// <see cref="SelfAttestationResult"/> — the RS256 packed self-attestation algorithm-matrix row.
    /// </summary>
    [TestMethod]
    public async Task Rs256MatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        //Independent oracle for the RS256 matrix row: this RSA both derives the credentialPublicKey below
        //and signs the transcript further down (see class remarks).
        using RSA credentialKey = RSA.Create(2048);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateRsaCoseKey(credentialKey, WellKnownCoseAlgorithms.Rs256);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = Fido2AttestationTestVectors.SignWithRsaPkcs1Sha256(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Rs256, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A statement signed with an EdDSA (Ed25519) credential's own private key, with matching <c>alg</c>,
    /// verifies to <see cref="SelfAttestationResult"/> — the EdDSA packed self-attestation algorithm-matrix
    /// row. No independent .NET BCL Ed25519 primitive exists, so the independence here is that no key
    /// object crosses the issuer/verifier boundary — only the minted wire signature does.
    /// </summary>
    [TestMethod]
    public async Task EdDsaMatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateEd25519CoseKey(keyMaterial.PublicKey, WellKnownCoseAlgorithms.EdDsa);

            using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
            using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
            byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
            byte[] signature = await Fido2AttestationTestVectors.SignWithEd25519Async(keyMaterial.PrivateKey, toBeSigned);

            var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.EdDsa, Signature: signature, X5c: null);
            AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
            AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
                authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

            AttestationResult result = await verify(request, TestContext.CancellationToken);

            Assert.IsInstanceOfType<SelfAttestationResult>(result);
        }
    }


    /// <summary>
    /// A statement signed with a PS256 (RSASSA-PSS/SHA-256) credential's own private key via an independent
    /// BouncyCastle signer, with matching <c>alg</c>, verifies to <see cref="SelfAttestationResult"/> — the
    /// PS256 packed self-attestation algorithm-matrix row deferred until the alg-aware RSA tag resolution
    /// (<c>CoseKeyExtensions.ToPublicKeyMemory</c>) landed.
    /// </summary>
    [TestMethod]
    public async Task Ps256MatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        //Independent oracle for the PS256 matrix row: this RSA derives the credentialPublicKey below and
        //supplies the private key DER the BouncyCastle PSS oracle signs with further down (see
        //Fido2AttestationTestVectors.SignWithRsaPssSha256Async remarks — the registered PS256 verify path is
        //Microsoft-backed, so the BouncyCastle signer keeps the sign/verify implementations independent).
        using RSA credentialKey = RSA.Create(2048);
        CoseKey credentialPublicKey = Fido2AttestationTestVectors.CreateRsaCoseKey(credentialKey, WellKnownCoseAlgorithms.Ps256);

        using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
        using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
        byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
        byte[] signature = await Fido2AttestationTestVectors.SignWithRsaPssSha256Async(credentialKey, toBeSigned);

        var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Ps256, Signature: signature, X5c: null);
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        Assert.IsInstanceOfType<SelfAttestationResult>(result);
    }


    /// <summary>
    /// A statement signed with an ES256K (secp256k1) credential's own private key via an independent
    /// BouncyCastle signer, with matching <c>alg</c>, verifies to <see cref="SelfAttestationResult"/> — the
    /// ES256K packed self-attestation algorithm-matrix row deferred until secp256k1 end-to-end support
    /// (RFC 8812 §3.2) landed. No framework <see cref="ECDsa"/> named curve covers secp256k1.
    /// </summary>
    [TestMethod]
    public async Task Es256KMatchingAlgAndValidSignatureReturnsSelfAttestationResult()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshSecp256k1KeyMaterial();
        using(keyMaterial.PublicKey)
        using(keyMaterial.PrivateKey)
        {
            CoseKey credentialPublicKey = Fido2AssertionOracle.BuildEc2CoseKey(keyMaterial.PublicKey, CoseKeyCurves.Secp256k1, WellKnownCoseAlgorithms.Es256K);

            using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([1, 2, 3], BaseMemoryPool.Shared);
            using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(Guid.NewGuid(), credentialPublicKey, out byte[] authDataBytes);
            byte[] toBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);
            byte[] signature = await Fido2AttestationTestVectors.SignWithSecp256k1Async(keyMaterial.PrivateKey, toBeSigned);

            var statement = new PackedAttestationStatement(Alg: WellKnownCoseAlgorithms.Es256K, Signature: signature, X5c: null);
            AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
            AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
                authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

            AttestationResult result = await verify(request, TestContext.CancellationToken);

            Assert.IsInstanceOfType<SelfAttestationResult>(result);
        }
    }


    /// <summary>Builds the <see cref="PackedAttestation"/> verifier under a given statement parser.</summary>
    /// <param name="parseStatement">The stub statement parser to wire in.</param>
    /// <returns>The assembled <see cref="AttestationVerifyDelegate"/>.</returns>
    private static AttestationVerifyDelegate BuildVerifier(ParsePackedAttestationStatementDelegate parseStatement) =>
        PackedAttestation.Build(
            parseStatement,
            MicrosoftX509Functions.ValidateChainAsync,
            MicrosoftX509Functions.ReadCertificateProfile,
            MicrosoftX509Functions.ReadCertificateExtensionValue);


    /// <summary>Runs the self-attestation verifier for <paramref name="statement"/> and returns the rejection error, if any.</summary>
    /// <param name="statement">The pre-built statement the stub parser returns.</param>
    /// <param name="authDataBytes">The raw <c>authData</c> bytes.</param>
    /// <param name="authenticatorData">The parsed <c>authData</c> view.</param>
    /// <param name="clientDataHash">The <c>clientDataHash</c> digest.</param>
    /// <returns>The <see cref="Fido2AttestationError"/> of a <see cref="RejectedAttestationResult"/>, or <see langword="null"/>.</returns>
    private async Task<Fido2AttestationError?> VerifyAndGetRejectionErrorAsync(
        PackedAttestationStatement statement,
        byte[] authDataBytes,
        AuthenticatorData authenticatorData,
        DigestValue clientDataHash)
    {
        AttestationVerifyDelegate verify = BuildVerifier(Fido2AttestationTestVectors.CreateStatementParser(statement));
        AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
            authDataBytes, authenticatorData, clientDataHash, attestationStatement: ReadOnlyMemory<byte>.Empty, trustAnchors: [], validationTime: TestClock.CanonicalEpoch);

        AttestationResult result = await verify(request, TestContext.CancellationToken);

        return result is RejectedAttestationResult rejected ? rejected.Error : null;
    }
}

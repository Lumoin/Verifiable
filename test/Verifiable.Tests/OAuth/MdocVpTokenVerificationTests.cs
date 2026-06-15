using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled tests for <see cref="MdocVpTokenVerification"/> — the OID4VP
/// server-side mdoc VP-token verifier. A toy wallet produces the
/// <c>vp_token</c> and the transmitted <c>mdoc_generated_nonce</c>; the verifier
/// reconstructs everything strictly from those wire values (no shared in-memory
/// wallet objects, salts, or device key) and runs the full issuer-auth +
/// digest-binding + device-signature verification through the OAuth-layer
/// composition, producing a <see cref="VpTokenParsed"/>.
/// </summary>
[TestClass]
internal sealed class MdocVpTokenVerificationTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;
    private const string CredentialQueryId = "pid";
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-vptoken-01";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task VerifiesEveryLayerAndExtractsClaimsFromWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            VpTokenParsed parsed = await VerifyAsync(
                vpTokenValue, TrustAnchorFor(issuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "Issuer-auth signature and MSO digest binding must both hold over the wire-reconstructed document.");
            Assert.IsTrue(parsed.SessionTranscriptValid,
                "Device signature must verify against the verifier-reconstructed SessionTranscript.");

            //mdoc carries no KB-JWT / sd_hash; those N/A axes are reported as not-a-failure.
            Assert.IsTrue(parsed.KbJwtSignatureValid, "KB-JWT axis is N/A for mdoc and must not register as a failure.");
            Assert.IsTrue(parsed.SdHashValid, "sd_hash axis is N/A for mdoc and must not register as a failure.");

            Assert.IsTrue(parsed.ExtractedClaims.TryGetValue(CredentialQueryId, out IReadOnlyDictionary<string, string>? claims),
                "Extracted claims must be keyed by the DCQL credential query id.");
            Assert.AreEqual("Mustermann", claims![EudiPid.Mdoc.FamilyName],
                "The disclosed family_name claim must decode from its CBOR element value.");
            Assert.AreEqual("Erika", claims[EudiPid.Mdoc.GivenName],
                "The disclosed given_name claim must decode from its CBOR element value.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task UntrustedIssuerKeyFailsCredentialSignature()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, string transmittedNonce) =
                await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> nonceOwner = Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                transmittedNonce, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

            //The trust framework resolves a key that did not sign the MSO — the issuer-auth
            //COSE_Sign1 verification fails, so CredentialSignatureValid is false.
            VpTokenParsed parsed = await VerifyAsync(
                vpTokenValue, TrustAnchorFor(wrongIssuerKeys.PublicKey), nonceOwner.Memory).ConfigureAwait(false);

            Assert.IsFalse(parsed.CredentialSignatureValid,
                "An issuer key that did not sign the MSO must fail the credential signature.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
            DisposeKeyMaterial(wrongIssuerKeys);
        }
    }


    [TestMethod]
    public async Task WrongMdocGeneratedNonceFailsSessionTranscriptOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (string vpTokenValue, _) = await ProduceVpTokenAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            //A nonce that differs from the one the wallet signed under yields a different
            //reconstructed SessionTranscript, so the device signature fails — but the issuer-auth
            //signature and digest binding are independent and still hold.
            using IMemoryOwner<byte> wrongNonce =
                Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, BaseMemoryPool.Shared);
            ReadOnlyMemory<byte> wrongNonceMemory =
                wrongNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

            VpTokenParsed parsed = await VerifyAsync(
                vpTokenValue, TrustAnchorFor(issuerKeys.PublicKey), wrongNonceMemory).ConfigureAwait(false);

            Assert.IsTrue(parsed.CredentialSignatureValid,
                "Issuer-auth and digest binding are independent of the SessionTranscript and must still hold.");
            Assert.IsFalse(parsed.SessionTranscriptValid,
                "A mismatched mdoc_generated_nonce must fail the device signature over the transcript.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// Wallet side: issue, device-sign over a fresh SessionTranscript, and assemble
    /// the base64url vp_token value plus the transmitted mdoc_generated_nonce.
    /// </summary>
    private async ValueTask<(string VpTokenValue, string TransmittedNonce)> ProduceVpTokenAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys)
    {
        using MdocDocument issued = await IssueAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

        using IMemoryOwner<byte> mdocGeneratedNonce =
            Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, BaseMemoryPool.Shared);
        ReadOnlyMemory<byte> nonceMemory =
            mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
        ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span);

        using MdocPresentationDocument intermediate = new(
            docType: issued.DocType,
            issuerSigned: MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
        using MdocPresentationDocument presented = await intermediate.DeviceSignAsync(
            MdocDeviceNameSpaces.Empty,
            sessionTranscript,
            deviceKeys.PrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        using MdocDeviceResponse deviceResponse = new(
            version: MdocWellKnownKeys.Version10,
            documents: [presented],
            status: MdocWellKnownKeys.StatusOk);

        string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(deviceResponse, TestSetup.Base64UrlEncoder);
        string transmittedNonce = Oid4VpMdocPresentation.EncodeMdocGeneratedNonceForTransmission(
            nonceMemory.Span, TestSetup.Base64UrlEncoder);

        return (vpTokenValue, transmittedNonce);
    }


    /// <summary>
    /// Verifier side: run <see cref="MdocVpTokenVerification.VerifyAsync"/> with the
    /// CBOR/COSE seams wired to the concrete serialization implementations.
    /// </summary>
    private ValueTask<VpTokenParsed> VerifyAsync(
        string vpTokenValue,
        ResolveMdocIssuerKeyDelegate resolveIssuerKey,
        ReadOnlyMemory<byte> mdocGeneratedNonce)
    {
        return MdocVpTokenVerification.VerifyAsync(
            vpTokenValue,
            CredentialQueryId,
            resolveIssuerKey,
            //No authority-identifier extractor: these tests do not exercise trusted_authorities.
            extractAuthorityIdentifier: null,
            VerifierClientId,
            VerifierResponseUri,
            AuthorizationRequestNonce,
            mdocGeneratedNonce,
            MdocCborDeviceResponseReader.Read,
            Oid4VpMdocSessionTranscriptEncoder.Encode,
            DecodeElementValue,
            CoseSerialization.ParseCoseSign1,
            CoseSerialization.ParseCoseSign1AllowingNilPayload,
            MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
            CoseSerialization.BuildSigStructure,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken);
    }


    /// <summary>
    /// A direct trust-anchor resolver: the verifier's trust framework already knows the
    /// issuer public key out of band (the legitimate trust input, not a wallet backchannel).
    /// Returns a fresh clone per call so the resolution owns its own carrier.
    /// </summary>
    private static ResolveMdocIssuerKeyDelegate TrustAnchorFor(PublicKeyMemory trustedIssuerKey) =>
        (issuerAuth, cancellationToken) => ValueTask.FromResult(
            MdocIacaTrustResolution.Success(ClonePublicKey(trustedIssuerKey, BaseMemoryPool.Shared)));


    private static string DecodeElementValue(ReadOnlyMemory<byte> encodedElementValue)
    {
        var reader = new CborReader(encodedElementValue, CborConformanceMode.Lax);

        return CborValueConverter.ReadValue(reader)?.ToString() ?? string.Empty;
    }


    private static PublicKeyMemory ClonePublicKey(PublicKeyMemory source, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }


    private async ValueTask<MdocDocument> IssueAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys)
    {
        MdocLogicalDocument logical = MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.FamilyName, EncodedElementValue = CborText("Mustermann") },
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.GivenName, EncodedElementValue = CborText("Erika") }
            ],
            generateRandom: () => MdocTestFixtures.ItemRandomSalt());

        return await logical.SignAsync(
            new MdocIssuerSigningConfig
            {
                DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                Validity = SampleValidity(),
                DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
            },
            issuerKeys.PrivateKey,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));
}

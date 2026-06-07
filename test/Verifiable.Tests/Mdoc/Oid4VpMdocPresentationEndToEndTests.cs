using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.MdocTestFixtures;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// End-to-end tests for the M.7a OID4VP presentation primitives — the
/// pieces a future <c>Oid4VpMdocWalletClient</c> composes. Runs the full
/// wallet-side assembly + verifier-side disassembly:
/// </summary>
/// <list type="number">
/// <item><description>Issuer signs the mdoc MSO (M.3).</description></item>
/// <item><description>Wallet generates mdoc_generated_nonce.</description></item>
/// <item><description>Wallet builds OID4VP SessionTranscript (M.7a).</description></item>
/// <item><description>Wallet device-signs over that transcript (M.3b).</description></item>
/// <item><description>Wallet packages DeviceResponse + base64url → vp_token (M.7a).</description></item>
/// <item><description>Verifier base64url-decodes the vp_token, reconstructs SessionTranscript from the transmitted mdoc_generated_nonce, runs M.5/M.4/M.3/M.3b verifications.</description></item>
/// </list>
/// <remarks>
/// <para>
/// This is the closest mdoc gets to the existing
/// <c>CrossDeviceFlowReachesAcceptUnderSigningAlgorithm</c> SD-JWT VC test
/// shape today. M.7b wires it into the actual OID4VP wallet client + flow
/// integration tests.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oid4VpMdocPresentationEndToEndTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-7f2c";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task FullOid4VpMdocPresentationLoopVerifiesEveryLayer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            //=== Wallet side ===

            using MdocDocument issued = await IssueAsync(issuerKeys, deviceKeys).ConfigureAwait(false);

            using IMemoryOwner<byte> mdocGeneratedNonce =
                Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, SensitiveMemoryPool<byte>.Shared);

            //Slice as Memory (not Span) so it survives await boundaries below.
            ReadOnlyMemory<byte> nonceMemory =
                mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

            ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span);

            //Full-disclosure presentation: wrap the issued document's
            //IssuerSigned as a view (no trimming), then device-sign over
            //the OID4VP SessionTranscript.
            using MdocPresentationDocument intermediate = new(
                docType: issued.DocType,
                issuerSigned: MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await intermediate.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                sessionTranscript,
                deviceKeys.PrivateKey,
                SensitiveMemoryPool<byte>.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using MdocDeviceResponse deviceResponse = new(
                version: MdocWellKnownKeys.Version10,
                documents: [presented],
                status: MdocWellKnownKeys.StatusOk);

            string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(
                deviceResponse, TestSetup.Base64UrlEncoder);
            string mdocGeneratedNonceForTransmission = Oid4VpMdocPresentation.EncodeMdocGeneratedNonceForTransmission(
                nonceMemory.Span, TestSetup.Base64UrlEncoder);

            Assert.IsFalse(string.IsNullOrEmpty(vpTokenValue));
            Assert.IsFalse(string.IsNullOrEmpty(mdocGeneratedNonceForTransmission));

            //=== Verifier side ===

            using IMemoryOwner<byte> roundTrippedDeviceResponseBytes = Oid4VpMdocPresentation.DecodeVpTokenValue(
                vpTokenValue, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

            using IMemoryOwner<byte> reconstructedNonceOwner =
                Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                    mdocGeneratedNonceForTransmission, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);
            ReadOnlyMemory<byte> reconstructedNonceMemory = reconstructedNonceOwner.Memory
                [..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];

            Assert.IsTrue(reconstructedNonceMemory.Span.SequenceEqual(nonceMemory.Span),
                "Base64url round-trip of the mdoc_generated_nonce must be byte-identical.");

            ReadOnlyMemory<byte> reconstructedSessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, reconstructedNonceMemory.Span);
            Assert.IsTrue(reconstructedSessionTranscript.Span.SequenceEqual(sessionTranscript.Span),
                "Verifier-side reconstruction must be byte-identical to the wallet-side encoding.");

            bool isIssuerVerified = await issued.VerifyIssuerAuthAsync(
                issuerKeys.PublicKey, SensitiveMemoryPool<byte>.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isIssuerVerified);

            MdocDigestBindingResult binding = issued.VerifyDigestBinding();
            Assert.IsTrue(binding.IsValid, $"Digest binding must hold; got {binding}.");

            bool isDeviceVerified = await presented.VerifyDeviceSignedAsync(
                reconstructedSessionTranscript,
                deviceKeys.PublicKey, SensitiveMemoryPool<byte>.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isDeviceVerified,
                "Device signature must verify against the OID4VP-reconstructed SessionTranscript.");

            AssertDeviceResponseBytesParse(roundTrippedDeviceResponseBytes.Memory.Span);
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public void SessionTranscriptIsDeterministicForFixedInputs()
    {
        Span<byte> nonce = stackalloc byte[16];
        RandomNumberGenerator.Fill(nonce);

        ReadOnlyMemory<byte> first = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonce);
        ReadOnlyMemory<byte> second = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonce);

        Assert.IsTrue(first.Span.SequenceEqual(second.Span),
            "SessionTranscript encoding must be deterministic for fixed inputs.");
    }


    [TestMethod]
    public void SessionTranscriptDiffersForDifferentClientId()
    {
        Span<byte> nonce = stackalloc byte[16];
        RandomNumberGenerator.Fill(nonce);

        ReadOnlyMemory<byte> withOriginalClientId = Oid4VpMdocSessionTranscriptEncoder.Encode(
            VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonce);
        ReadOnlyMemory<byte> withDifferentClientId = Oid4VpMdocSessionTranscriptEncoder.Encode(
            "https://other-verifier.example/oid4vp/client", VerifierResponseUri, AuthorizationRequestNonce, nonce);

        Assert.IsFalse(withOriginalClientId.Span.SequenceEqual(withDifferentClientId.Span),
            "Different client_id MUST yield different SessionTranscript bytes.");
    }


    [TestMethod]
    public void GenerateMdocGeneratedNonceProducesAtLeast16Bytes()
    {
        using IMemoryOwner<byte> nonce =
            Oid4VpMdocSessionTranscriptEncoder.GenerateMdocGeneratedNonce(System.Security.Cryptography.RandomNumberGenerator.Fill, SensitiveMemoryPool<byte>.Shared);

        Assert.IsGreaterThanOrEqualTo(
            Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength,
            nonce.Memory.Length);
    }


    [TestMethod]
    public void EncodeRejectsUnderSizedMdocGeneratedNonce()
    {
        byte[] tooShort = new byte[8];
        Assert.ThrowsExactly<ArgumentException>(() =>
            Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, tooShort));
    }


    [TestMethod]
    public void VpTokenBase64UrlRoundTripsBytesExactly()
    {
        //The base64url encoding must be lossless — verifier-side decode
        //must recover the exact CBOR bytes the wallet encoded.
        using MdocDeviceResponse minimal = new(
            version: MdocWellKnownKeys.Version10,
            documents: [],
            status: MdocWellKnownKeys.StatusOk);

        string vpToken = Oid4VpMdocPresentation.AssembleVpTokenValue(minimal, TestSetup.Base64UrlEncoder);
        using IMemoryOwner<byte> decoded = Oid4VpMdocPresentation.DecodeVpTokenValue(
            vpToken, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);
        ReadOnlyMemory<byte> reEncoded = MdocCborDeviceResponseWriter.EncodeDeviceResponse(minimal);

        Assert.IsTrue(decoded.Memory.Span[..reEncoded.Length].SequenceEqual(reEncoded.Span),
            "vp_token base64url round-trip must be byte-identical.");
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
            SensitiveMemoryPool<byte>.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static void AssertDeviceResponseBytesParse(ReadOnlySpan<byte> bytes)
    {
        var reader = new CborReader(bytes.ToArray(), CborConformanceMode.Lax);
        int? entries = reader.ReadStartMap();
        string? version = null;
        bool sawDocuments = false;
        uint? status = null;

        int read = 0;
        while(entries is null ? reader.PeekState() != CborReaderState.EndMap : read < entries.Value)
        {
            string key = reader.ReadTextString();
            read++;

            if(key == MdocWellKnownKeys.Version)
            {
                version = reader.ReadTextString();
            }
            else if(key == MdocWellKnownKeys.Documents)
            {
                sawDocuments = true;
                reader.SkipValue();
            }
            else if(key == MdocWellKnownKeys.Status)
            {
                status = (uint)reader.ReadUInt64();
            }
            else
            {
                reader.SkipValue();
            }
        }

        reader.ReadEndMap();

        Assert.AreEqual(MdocWellKnownKeys.Version10, version);
        Assert.IsTrue(sawDocuments);
        Assert.AreEqual(MdocWellKnownKeys.StatusOk, status);
    }


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));
}

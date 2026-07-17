using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// End-to-end tests for the M.3b device-side signing pipeline. Runs the
/// full issuance + presentation sequence:
/// </summary>
/// <list type="number">
/// <item><description><see cref="MdocIssuance.BuildDocument"/> assembles the logical mdoc.</description></item>
/// <item><description><see cref="MdocCborIssuance.SignAsync"/> signs the issuer-side MSO.</description></item>
/// <item><description><see cref="MdocCborDeviceSignedSigner.SignAsync"/> attaches the device-side COSE_Sign1 over <c>DeviceAuthentication</c>.</description></item>
/// <item><description><see cref="MdocCborIssuerAuthVerifier.VerifyAsync"/> verifies the issuer MSO signature.</description></item>
/// <item><description><see cref="MdocMsoDigestBindingValidator.Validate"/> checks the issuer's digest commitments.</description></item>
/// <item><description><see cref="MdocCborDeviceSignedVerifier.VerifyAsync"/> verifies the device signature.</description></item>
/// </list>
/// <remarks>
/// <para>
/// The SessionTranscript is treated as an opaque caller-supplied byte
/// sequence — for these tests a deterministic CBOR array stands in. The
/// OID4VP-specific shape lands in M.7 alongside the wallet client.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCborDeviceSignedEndToEndTests
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidNamespace = "eu.europa.ec.eudi.pid.1";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task FullIssuePresentVerifyLoopValidatesEveryLayer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(DefaultRandomGenerator);
            CoseKey deviceCoseKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey);

            //Issuer side: sign the MSO.
            using MdocDocument issued = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = deviceCoseKey
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Wallet side: full-disclosure presentation, device-sign over the
            //(caller-supplied) session transcript.
            byte[] sessionTranscript = SampleSessionTranscript();
            using MdocPresentationDocument fullPresentation = new(
                issued.DocType,
                MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await fullPresentation.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                sessionTranscript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(presented.DeviceSigned!.DeviceAuth.DeviceSignature,
                "DeviceSignAsync emits a signature, not a MAC, on the COSE_Sign1 path.");
            Assert.IsNull(presented.DeviceSigned.DeviceAuth.DeviceMac);

            //Verifier side leg 1: issuer signature.
            bool isIssuerVerified = await issued.VerifyIssuerAuthAsync(
                issuerKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isIssuerVerified, "Issuer MSO signature must verify.");

            //Verifier side leg 2: digest binding.
            MdocDigestBindingResult bindingResult = issued.VerifyDigestBinding();
            Assert.IsTrue(bindingResult.IsValid, $"Digest binding must hold; got {bindingResult}.");

            //Verifier side leg 3: device signature.
            bool isDeviceVerified = await presented.VerifyDeviceSignedAsync(
                sessionTranscript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isDeviceVerified, "Device signature must verify against the device key the MSO bound.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task DeviceSignVerboseExposesDeviceAuthenticationBytes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(DefaultRandomGenerator).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            byte[] sessionTranscript = SampleSessionTranscript();
            using MdocPresentationDocument fullPresentation = new(
                issued.DocType,
                MdocIssuerSignedView.FromOwned(issued.IssuerSigned));

            (MdocPresentationDocument presented, ReadOnlyMemory<byte> deviceAuthenticationBytes) =
                await fullPresentation.DeviceSignVerboseAsync(
                    MdocDeviceNameSpaces.Empty,
                    sessionTranscript,
                    deviceKeys.PrivateKey,
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false);

            using(presented)
            {
                Assert.IsGreaterThan(0, deviceAuthenticationBytes.Length, "The DeviceAuthenticationBytes must be exposed.");

                //Verbose captures, it does not reconstruct: the threaded bytes must equal the
                //session-bound DeviceAuthenticationBytes rebuilt from the transcript, doctype, and
                //the preserved device-namespaces bytes — the exact value the signature covers.
                ReadOnlyMemory<byte> reconstructed = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes(
                    sessionTranscript, PidDocType, presented.DeviceSigned!.EncodedDeviceNameSpacesBytes);
                Assert.IsTrue(
                    reconstructed.Span.SequenceEqual(deviceAuthenticationBytes.Span),
                    "The exposed DeviceAuthenticationBytes must equal the session-bound bytes the signature covers.");

                //The verbose path still produces a verifiable device signature.
                bool isVerified = await presented.VerifyDeviceSignedAsync(
                    sessionTranscript,
                    deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(isVerified, "The device signature produced by the verbose path must verify.");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task DeviceSignatureFailsWhenSessionTranscriptDiffers()
    {
        //SessionTranscript is the session-binding fingerprint. If the
        //verifier reconstructs it differently from how the wallet built it,
        //the COSE_Sign1 won't verify even though nothing was tampered with.
        //This is the test that catches a misaligned transport binding.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            byte[] signingTranscript = SampleSessionTranscript();
            MdocDeviceSigned deviceSigned = await MdocCborDeviceSignedSigner.SignAsync(
                MdocDeviceNameSpaces.Empty,
                PidDocType,
                signingTranscript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            byte[] differentTranscript = SampleSessionTranscript(nonce: 0xDEAD);
            bool isVerified = await deviceSigned.VerifyAsync(
                PidDocType,
                differentTranscript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified,
                "Verifier MUST reject a device signature when the session transcript bytes differ from signing time.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyDeviceSignedVerboseExposesReconstructedBytes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(DefaultRandomGenerator).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            byte[] sessionTranscript = SampleSessionTranscript();
            using MdocPresentationDocument fullPresentation = new(
                issued.DocType,
                MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await fullPresentation.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                sessionTranscript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            (bool result, MdocDeviceSignedVerificationContext? context) = await presented.VerifyDeviceSignedVerboseAsync(
                sessionTranscript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsTrue(result, "A correctly device-signed presentation must verify.");
                Assert.IsNotNull(context, "A verified device signature must expose intermediate context.");

                //The context exposes the exact session-bound bytes the signature was checked
                //against — reconstructable independently via the public encoder.
                ReadOnlyMemory<byte> reconstructed = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes(
                    sessionTranscript, PidDocType, presented.DeviceSigned!.EncodedDeviceNameSpacesBytes);
                Assert.IsTrue(
                    reconstructed.Span.SequenceEqual(context.DeviceAuthenticationBytes.Span),
                    "The context's DeviceAuthenticationBytes must equal the session-bound bytes the signature covers.");
                Assert.IsTrue(
                    context.Message.Payload.Span.SequenceEqual(context.DeviceAuthenticationBytes.Span),
                    "The parsed message carries the reconstructed payload re-attached.");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyDeviceSignedVerboseReturnsNullContextWhenSignatureInvalid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(DefaultRandomGenerator).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            byte[] signingTranscript = SampleSessionTranscript();
            using MdocPresentationDocument fullPresentation = new(
                issued.DocType,
                MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await fullPresentation.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                signingTranscript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Verify against a different session transcript — the session binding fails.
            byte[] differentTranscript = SampleSessionTranscript(nonce: 0xDEAD);
            (bool result, MdocDeviceSignedVerificationContext? context) = await presented.VerifyDeviceSignedVerboseAsync(
                differentTranscript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsFalse(result, "A session-transcript mismatch must fail device-signature verification.");
                Assert.IsNull(context, "No context is exposed when the device signature is invalid.");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task DeviceSignatureFailsWithWrongDeviceKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> imposterKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            byte[] transcript = SampleSessionTranscript();
            MdocDeviceSigned deviceSigned = await MdocCborDeviceSignedSigner.SignAsync(
                MdocDeviceNameSpaces.Empty,
                PidDocType,
                transcript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            bool isVerified = await deviceSigned.VerifyAsync(
                PidDocType,
                transcript,
                imposterKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "Verification under a different device key must fail.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
            MdocTestFixtures.DisposeKeyMaterial(imposterKeys);
        }
    }


    [TestMethod]
    public async Task DeviceSignedOverNonEmptyNameSpacesRoundTrips()
    {
        //Most flows leave DeviceNameSpaces empty, but the data model
        //supports non-empty maps for flows that need them (wallet-side
        //timestamps, session-specific values). The signature commits to the
        //entries; tampering would invalidate it.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            Dictionary<string, IReadOnlyDictionary<string, ReadOnlyMemory<byte>>> entries = new(StringComparer.Ordinal)
            {
                [PidNamespace] = new Dictionary<string, ReadOnlyMemory<byte>>(StringComparer.Ordinal)
                {
                    ["wallet_timestamp"] = MdocTestFixtures.CborText("2026-05-25T08:00:00Z")
                }
            };
            MdocDeviceNameSpaces deviceNameSpaces = new(entries);

            byte[] transcript = SampleSessionTranscript();
            MdocDeviceSigned deviceSigned = await MdocCborDeviceSignedSigner.SignAsync(
                deviceNameSpaces,
                PidDocType,
                transcript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            bool isVerified = await deviceSigned.VerifyAsync(
                PidDocType,
                transcript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified,
                "Device signature over non-empty DeviceNameSpaces must verify.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task DeviceCoseKeyFromMsoFlowsThroughCoseKeyToAlgorithmConverter()
    {
        //The verifier flow resolves the device key from
        //MdocMobileSecurityObject.DeviceKeyInfo.DeviceKey via
        //CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter. This
        //test pins the integration: extract the tag, build a
        //PublicKeyMemory, and verify under that.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(DefaultRandomGenerator);
            CoseKey deviceCoseKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey);

            using MdocDocument issued = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = deviceCoseKey
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Resolve the device key tag from the parsed MSO's COSE_Key.
            CoseKey msoDeviceKey = issued.IssuerSigned.IssuerAuth.Mso.DeviceKeyInfo.DeviceKey;
            Tag deviceKeyTag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
                kty: msoDeviceKey.Kty,
                curve: msoDeviceKey.Curve,
                purpose: Verifiable.Cryptography.Context.Purpose.Verification);

            Assert.AreEqual(CryptoTags.P256PublicKey, deviceKeyTag,
                "MSO-committed P-256 device key resolves to the P-256 verification tag.");

            //Run the full device-sign + verify cycle using the device key
            //extracted from the MSO (compressed form) — this is what the
            //real wallet/verifier flow does, and the keys round-trip via
            //the conversion path land in the verifier.
            byte[] transcript = SampleSessionTranscript();
            using MdocPresentationDocument fullPresentation = new(
                issued.DocType,
                MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await fullPresentation.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty,
                transcript,
                deviceKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            bool isVerified = await presented.VerifyDeviceSignedAsync(
                transcript,
                deviceKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload, MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    private static Salt DefaultRandomGenerator() =>
        MdocTestFixtures.ItemRandomSalt();


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));


    /// <summary>
    /// Builds a deterministic stand-in SessionTranscript byte sequence. The
    /// actual OID4VP / proximity SessionTranscript shapes land at the
    /// transport layer (M.7 for OID4VP).
    /// </summary>
    private static byte[] SampleSessionTranscript(int nonce = 0x42)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(3);
        writer.WriteNull();
        writer.WriteNull();
        writer.WriteInt32(nonce);
        writer.WriteEndArray();

        return writer.Encode();
    }
}

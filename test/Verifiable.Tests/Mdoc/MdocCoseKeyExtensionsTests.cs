using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocCoseKeyExtensions.ToPublicKeyMemory"/> — deriving the
/// device verification key from the issuer-committed MSO COSE_Key. The headline
/// test extracts the key from a wire-reconstructed MSO and verifies the device
/// signature against it, proving the verifier never needs the device key out of
/// band.
/// </summary>
[TestClass]
internal sealed class MdocCoseKeyExtensionsTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-cosekey-01";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ToPublicKeyMemoryRoundTripsP256PublicKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocCoseKey coseKey = CoseKeyFromP256Public(keys.PublicKey);

            using PublicKeyMemory extracted = coseKey.ToPublicKeyMemory(SensitiveMemoryPool<byte>.Shared);

            Assert.IsTrue(extracted.AsReadOnlySpan().SequenceEqual(keys.PublicKey.AsReadOnlySpan()),
                "Extracted key bytes must equal the original compressed SEC1 point.");
            Assert.AreEqual(keys.PublicKey.Tag, extracted.Tag,
                "Extracted key must carry the same algorithm tag (CryptoTags.P256PublicKey).");
        }
        finally
        {
            keys.PublicKey.Dispose();
            keys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task DeviceKeyExtractedFromWireMsoVerifiesDeviceSignature()
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
            ReadOnlyMemory<byte> nonceMemory =
                mdocGeneratedNonce.Memory[..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
            ReadOnlyMemory<byte> sessionTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span);

            using MdocPresentationDocument intermediate = new(
                docType: issued.DocType,
                issuerSigned: MdocIssuerSignedView.FromOwned(issued.IssuerSigned));
            using MdocPresentationDocument presented = await intermediate.DeviceSignAsync(
                MdocDeviceNameSpaces.Empty, sessionTranscript, deviceKeys.PrivateKey,
                SensitiveMemoryPool<byte>.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using MdocDeviceResponse deviceResponse = new(
                version: MdocWellKnownKeys.Version10, documents: [presented], status: MdocWellKnownKeys.StatusOk);
            string vpTokenValue = Oid4VpMdocPresentation.AssembleVpTokenValue(deviceResponse, TestSetup.Base64UrlEncoder);

            //=== Verifier side: device key comes from the wire MSO, not the backchannel ===
            using IMemoryOwner<byte> deviceResponseBytes = Oid4VpMdocPresentation.DecodeVpTokenValue(
                vpTokenValue, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);
            using MdocParsedDeviceResponse parsed = MdocCborDeviceResponseReader.Read(
                deviceResponseBytes.Memory.Span, SensitiveMemoryPool<byte>.Shared);

            MdocParsedDocument parsedDocument = parsed.Documents[0];
            using PublicKeyMemory deviceKeyFromMso =
                parsedDocument.IssuerSigned.IssuerAuth.Mso.DeviceKeyInfo.DeviceKey.ToPublicKeyMemory(
                    SensitiveMemoryPool<byte>.Shared);

            //Sanity: the MSO-derived key equals the wallet's device public key.
            Assert.IsTrue(deviceKeyFromMso.AsReadOnlySpan().SequenceEqual(deviceKeys.PublicKey.AsReadOnlySpan()),
                "Device key extracted from the MSO must equal the wallet's device public key.");

            ReadOnlyMemory<byte> reconstructedTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, nonceMemory.Span);

            bool isDeviceVerified = await parsedDocument.DeviceSigned!.VerifyAsync(
                parsedDocument.DocType, reconstructedTranscript, deviceKeyFromMso,
                SensitiveMemoryPool<byte>.Shared, CoseSerialization.ParseCoseSign1AllowingNilPayload,
                MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes, CoseSerialization.BuildSigStructure,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isDeviceVerified,
                "Device signature must verify against the key extracted from the wire-reconstructed MSO.");
        }
        finally
        {
            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            deviceKeys.PublicKey.Dispose();
            deviceKeys.PrivateKey.Dispose();
        }
    }


    private async ValueTask<MdocDocument> IssueAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys)
    {
        MdocLogicalDocument logical = MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = EudiPid.Mdoc.FamilyName, EncodedElementValue = CborText("Mustermann") }
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


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));


    private static MdocCoseKey CoseKeyFromP256Public(PublicKeyMemory publicKey)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        byte[] yCoordinate = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        return new MdocCoseKey(
            kty: MdocCoseKeyTypes.Ec2,
            curve: MdocCoseKeyCurves.P256,
            x: compressed[1..].ToArray(),
            y: yCoordinate);
    }


    private static byte[] CborText(string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);

        return writer.Encode();
    }
}

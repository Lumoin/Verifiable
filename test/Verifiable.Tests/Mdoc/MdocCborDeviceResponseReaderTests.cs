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
/// Firewalled round-trip tests for <see cref="MdocCborDeviceResponseReader"/> —
/// the verifier-side wire reader that <see cref="MdocCborDeviceResponseWriter"/>
/// is the inverse of. Unlike <see cref="Oid4VpMdocPresentationEndToEndTests"/>,
/// which verifies against the in-memory wallet objects, these tests reconstruct
/// the document strictly from the <c>vp_token</c> wire bytes and run full
/// verification against the wire-reconstructed objects — the property the
/// OID4VP verifier flow depends on.
/// </summary>
[TestClass]
internal sealed class MdocCborDeviceResponseReaderTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;
    private const string VerifierClientId = "https://verifier.example/oid4vp/client";
    private const string VerifierResponseUri = "https://verifier.example/oid4vp/response";
    private const string AuthorizationRequestNonce = "auth-req-nonce-reader-01";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task WireReconstructedDocumentVerifiesEveryLayer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            //=== Wallet side: produce the vp_token wire bytes ===
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

            //=== Verifier side: reconstruct strictly from the wire bytes ===
            using IMemoryOwner<byte> deviceResponseBytes = Oid4VpMdocPresentation.DecodeVpTokenValue(
                vpTokenValue, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

            using MdocParsedDeviceResponse parsed = MdocCborDeviceResponseReader.Read(
                deviceResponseBytes.Memory.Span, SensitiveMemoryPool<byte>.Shared);

            Assert.AreEqual(MdocWellKnownKeys.Version10, parsed.Version);
            Assert.AreEqual(MdocWellKnownKeys.StatusOk, parsed.Status);
            Assert.HasCount(1, parsed.Documents);

            MdocParsedDocument parsedDocument = parsed.Documents[0];
            Assert.AreEqual(PidDocType, parsedDocument.DocType);
            Assert.AreEqual(PidDocType, parsedDocument.IssuerSigned.IssuerAuth.Mso.DocType);

            //Issuer MSO signature (M.3) against the wire-reconstructed issuerAuth.
            bool isIssuerVerified = await parsedDocument.IssuerSigned.IssuerAuth.VerifyAsync(
                issuerKeys.PublicKey, SensitiveMemoryPool<byte>.Shared,
                CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isIssuerVerified, "Issuer signature must verify against the wire-reconstructed issuerAuth.");

            //Digest binding (M.4) over the wire-reconstructed items.
            MdocDigestBindingResult binding = MdocMsoDigestBindingValidator.Validate(parsedDocument.IssuerSigned);
            Assert.IsTrue(binding.IsValid, $"Digest binding must hold on the wire-reconstructed items; got {binding}.");

            //Device signature (M.3b) over the verifier-reconstructed SessionTranscript.
            using IMemoryOwner<byte> reconstructedNonceOwner =
                Oid4VpMdocPresentation.DecodeMdocGeneratedNonceForTransmissionRoundTrip(
                    mdocGeneratedNonceForTransmission, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);
            ReadOnlyMemory<byte> reconstructedNonce = reconstructedNonceOwner.Memory
                [..Oid4VpMdocSessionTranscriptEncoder.MinimumMdocGeneratedNonceLength];
            ReadOnlyMemory<byte> reconstructedTranscript = Oid4VpMdocSessionTranscriptEncoder.Encode(
                VerifierClientId, VerifierResponseUri, AuthorizationRequestNonce, reconstructedNonce.Span);

            Assert.IsNotNull(parsedDocument.DeviceSigned);
            bool isDeviceVerified = await parsedDocument.DeviceSigned!.VerifyAsync(
                parsedDocument.DocType,
                reconstructedTranscript,
                deviceKeys.PublicKey,
                SensitiveMemoryPool<byte>.Shared,
                CoseSerialization.ParseCoseSign1AllowingNilPayload,
                MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes,
                CoseSerialization.BuildSigStructure,
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(isDeviceVerified, "Device signature must verify against the wire-reconstructed deviceSigned.");

            //Structural fidelity: the preserved byte runs survive the round-trip byte-identically.
            IReadOnlyList<MdocIssuerSignedItem> originalItems = issued.IssuerSigned.NameSpaces[PidNamespace];
            IReadOnlyList<MdocIssuerSignedItem> parsedItems = parsedDocument.IssuerSigned.NameSpaces[PidNamespace];
            Assert.HasCount(originalItems.Count, parsedItems);

            for(int i = 0; i < originalItems.Count; i++)
            {
                Assert.AreEqual(originalItems[i].ElementIdentifier, parsedItems[i].ElementIdentifier);
                Assert.AreEqual(originalItems[i].DigestId, parsedItems[i].DigestId);
                Assert.IsTrue(originalItems[i].WireBytes.Span.SequenceEqual(parsedItems[i].WireBytes.Span),
                    "IssuerSignedItem wire bytes must round-trip byte-identically (MSO digest commitment input).");
            }

            Assert.IsTrue(
                presented.DeviceSigned!.EncodedDeviceNameSpacesBytes.Span.SequenceEqual(
                    parsedDocument.DeviceSigned!.EncodedDeviceNameSpacesBytes.Span),
                "DeviceNameSpaces wire bytes must round-trip byte-identically (DeviceAuthentication commitment input).");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public void ReadRejectsMalformedDeviceResponse()
    {
        //A verifier parses untrusted bytes; malformed input must fail cleanly with a CBOR
        //shape/encoding error rather than returning garbage or leaking. The concrete exception
        //type depends on the failure mode — a wrong-type root (a bare uint here) surfaces as
        //InvalidOperationException, a truncated/garbled encoding as CborContentException — so
        //the test pins the "rejected cleanly" property, not a single framework exception type.
        byte[] notAMap = [0x01, 0x02, 0x03];

        Exception? caught = null;
        try
        {
            using MdocParsedDeviceResponse _ = MdocCborDeviceResponseReader.Read(
                notAMap, SensitiveMemoryPool<byte>.Shared);
        }
        catch(Exception ex)
        {
            caught = ex;
        }

        Assert.IsNotNull(caught, "Malformed DeviceResponse bytes must be rejected.");
        Assert.IsTrue(caught is CborContentException or InvalidOperationException,
            $"Expected a CBOR shape/encoding error; got {caught.GetType().Name}: {caught.Message}.");
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


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validFrom: new DateTimeOffset(2026, 5, 25, 8, 0, 0, TimeSpan.Zero),
            validUntil: new DateTimeOffset(2027, 5, 25, 8, 0, 0, TimeSpan.Zero));


    private static MdocCoseKey CoseKeyFromP256Public(PublicKeyMemory publicKey)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        byte[] uncompressed = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);

        return new MdocCoseKey(
            kty: MdocCoseKeyTypes.Ec2,
            curve: MdocCoseKeyCurves.P256,
            x: compressed[1..].ToArray(),
            y: uncompressed);
    }


    private static void DisposeKeyMaterial(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial)
    {
        keyMaterial.PublicKey.Dispose();
        keyMaterial.PrivateKey.Dispose();
    }


    private static byte[] CborText(string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);

        return writer.Encode();
    }
}

using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocMsoDigestBindingValidator"/> — the verifier-side
/// gate that asserts every <see cref="MdocIssuerSignedItem.WireBytes"/>
/// hashes to the digest the MSO commits to under its declared algorithm per
/// ISO/IEC 18013-5 §9.1.2.5.
/// </summary>
/// <remarks>
/// <para>
/// Tests run the full M.3 issue → sign → validate pipeline so the validator
/// sees real freshly-signed mdoc documents. The negative cases tamper with
/// specific pieces (item bytes, MSO commitment map, digest algorithm) to
/// pin each failure-reason branch.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocMsoDigestBindingValidatorTests
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidNamespace = "eu.europa.ec.eudi.pid.1";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task FreshlySignedDocumentValidatesUnderSha256()
    {
        await AssertValidatesAsync(MdocMsoWellKnownKeys.DigestAlgorithmSha256).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task FreshlySignedDocumentValidatesUnderSha384()
    {
        await AssertValidatesAsync(MdocMsoWellKnownKeys.DigestAlgorithmSha384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task FreshlySignedDocumentValidatesUnderSha512()
    {
        await AssertValidatesAsync(MdocMsoWellKnownKeys.DigestAlgorithmSha512).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task EudiPidShapedDocumentValidatesEndToEnd()
    {
        //First-cut EUDI vector round-trip: shape an MdocDocument with the
        //eu.europa.ec.eudi.pid.1 namespace and realistic claim names from
        //the EUDI PID rulebook (family_name, given_name, birth_date,
        //age_over_18, issuing_country), sign it, then validate. Real EUDI-
        //sandbox-issued bytes plug in here when M.5/M.6 reach for them.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocIssuance.BuildDocument(
                docType: PidDocType,
                claims:
                [
                    new() { NameSpace = PidNamespace, ElementIdentifier = "family_name", EncodedElementValue = CborText("Mustermann") },
                    new() { NameSpace = PidNamespace, ElementIdentifier = "given_name", EncodedElementValue = CborText("Erika") },
                    new() { NameSpace = PidNamespace, ElementIdentifier = "birth_date", EncodedElementValue = CborText("1971-09-01") },
                    new() { NameSpace = PidNamespace, ElementIdentifier = "age_over_18", EncodedElementValue = CborBool(true) },
                    new() { NameSpace = PidNamespace, ElementIdentifier = "issuing_country", EncodedElementValue = CborText("DE") }
                ],
                generateRandom: DefaultRandomGenerator);

            using MdocDocument signed = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            MdocDigestBindingResult result = signed.VerifyDigestBinding();

            Assert.IsTrue(result.IsValid,
                $"EUDI PID-shape document must validate. Top-level failure: {result.FailureReason}.");
            Assert.HasCount(5, result.ItemResults);
            foreach(MdocDigestBindingItemResult itemResult in result.ItemResults)
            {
                Assert.IsTrue(itemResult.IsValid,
                    $"Item {itemResult.NameSpace}/{itemResult.ElementIdentifier} must validate; got {itemResult.FailureReason}.");
            }
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    //Note: tests for "IssuerAuth missing" and "ItemWireBytes missing" were
    //structurally possible only when MdocIssuerSigned.IssuerAuth and
    //MdocIssuerSignedItem.WireBytes were nullable. The MdocLogicalDocument /
    //MdocDocument split makes both non-nullable on the signed side; those
    //states are no longer representable, and the validator no longer needs
    //defensive branches for them.

    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The tampered MdocIssuerSigned shares Salt ownership with `signed`; disposing it would double-free. The original `signed` document owns and disposes the salts via its using declaration.")]
    public async Task ValidateFailsAndIdentifiesTamperedItem()
    {
        //Sign normally, then construct a sibling MdocIssuerSigned with one
        //item's wire bytes replaced (simulating in-flight tampering). The
        //validator must flag exactly the one tampered item and pass the rest.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument signed = await BuildSampleLogical().SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Build a tampered NameSpaces map: same items, but item[0] has
            //its WireBytes mutated by one byte. We swap in the tampered item
            //in a NEW MdocIssuerSigned (sharing the signer's IssuerAuth +
            //the salt with the original — the original document stays the
            //owner of the salt; this sibling is read-only and is not disposed).
            IReadOnlyList<MdocIssuerSignedItem> originalItems = signed.IssuerSigned.NameSpaces[PidNamespace];
            int wireByteLength = originalItems[0].WireBytes.Length;
            using IMemoryOwner<byte> tamperedWireBytesOwner = BaseMemoryPool.Shared.Rent(wireByteLength);
            Memory<byte> tamperedWireBytes = tamperedWireBytesOwner.Memory[..wireByteLength];
            originalItems[0].WireBytes.Span.CopyTo(tamperedWireBytes.Span);
            tamperedWireBytes.Span[^1] ^= 0xFF;

            MdocIssuerSignedItem tamperedItem = new(
                digestId: originalItems[0].DigestId,
                random: originalItems[0].Random,
                elementIdentifier: originalItems[0].ElementIdentifier,
                encodedElementValue: originalItems[0].EncodedElementValue,
                wireBytes: tamperedWireBytes);

            List<MdocIssuerSignedItem> rewrittenItems = [tamperedItem, .. originalItems.Skip(1)];

            Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> tamperedNameSpaces =
                new(StringComparer.Ordinal) { [PidNamespace] = rewrittenItems };

            //Construct the tampered IssuerSigned but never dispose it — its
            //items share Salt ownership with the original signed document.
            MdocIssuerSigned tampered = new(tamperedNameSpaces, signed.IssuerSigned.IssuerAuth);
            MdocDigestBindingResult result = MdocMsoDigestBindingValidator.Validate(tampered);

            Assert.IsFalse(result.IsValid);
            Assert.AreEqual(MdocDigestBindingFailureReason.ItemBindingFailed, result.FailureReason);
            Assert.AreEqual(MdocDigestBindingItemFailureReason.DigestMismatch, result.ItemResults[0].FailureReason);
            Assert.IsTrue(result.ItemResults[1].IsValid, "Untampered item must still validate.");
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public void ValidateFailsWhenMsoDigestAlgorithmUnsupported()
    {
        //Construct an MSO with a made-up digest algorithm string. The
        //validator gates on the SHA-256/384/512 set per ISO 18013-5 §9.1.2.5.
        Salt salt = MdocTestFixtures.ItemRandomSalt();

        using IMemoryOwner<byte> wireBytesOwner = BaseMemoryPool.Shared.Rent(10);
        using IMemoryOwner<byte> digestOwner = BaseMemoryPool.Shared.Rent(32);
        using IMemoryOwner<byte> encodedElementValueOwner = BaseMemoryPool.Shared.Rent(
            System.Text.Encoding.UTF8.GetByteCount("Mustermann"));
        int encodedElementValueLength = System.Text.Encoding.UTF8.GetBytes(
            "Mustermann", encodedElementValueOwner.Memory.Span);

        MdocIssuerSignedItem item = new(
            digestId: 0,
            random: salt,
            elementIdentifier: "family_name",
            encodedElementValue: encodedElementValueOwner.Memory[..encodedElementValueLength],
            wireBytes: wireBytesOwner.Memory[..10]);

        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces = new(StringComparer.Ordinal)
        {
            [PidNamespace] = new[] { item }
        };

        Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> valueDigests = new(StringComparer.Ordinal)
        {
            [PidNamespace] = new Dictionary<uint, ReadOnlyMemory<byte>> { [0u] = digestOwner.Memory[..32] }
        };

        MdocMobileSecurityObject mso = new(
            version: MdocMsoWellKnownKeys.Version10,
            digestAlgorithm: "MD5",  //not in the §9.1.2.5 set
            valueDigests: valueDigests,
            deviceKeyInfo: new MdocDeviceKeyInfo(new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256)),
            docType: PidDocType,
            validityInfo: SampleValidity());

        using MdocIssuerAuth issuerAuth = new(
            mso, EncodedCoseSign1.FromBytes(new byte[1], BaseMemoryPool.Shared));
        using MdocIssuerSigned issuerSigned = new(nameSpaces, issuerAuth);

        MdocDigestBindingResult result = MdocMsoDigestBindingValidator.Validate(issuerSigned);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(MdocDigestBindingFailureReason.UnsupportedDigestAlgorithm, result.FailureReason);
    }


    private async Task AssertValidatesAsync(string digestAlgorithm)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument signed = await BuildSampleLogical().SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = digestAlgorithm,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            MdocDigestBindingResult result = signed.VerifyDigestBinding();

            Assert.IsTrue(result.IsValid,
                $"Freshly-signed document under {digestAlgorithm} must validate. Got: {result}");
            Assert.HasCount(2, result.ItemResults);
            Assert.IsTrue(result.ItemResults[0].IsValid);
            Assert.IsTrue(result.ItemResults[1].IsValid);
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    private static MdocLogicalDocument BuildSampleLogical() =>
        MdocIssuance.BuildDocument(
            docType: PidDocType,
            claims:
            [
                new() { NameSpace = PidNamespace, ElementIdentifier = "family_name", EncodedElementValue = CborText("Mustermann") },
                new() { NameSpace = PidNamespace, ElementIdentifier = "given_name", EncodedElementValue = CborText("Erika") }
            ],
            generateRandom: DefaultRandomGenerator);


    private static Salt DefaultRandomGenerator() =>
        MdocTestFixtures.ItemRandomSalt();


    //Bit-identical to TestClock.CanonicalEpoch.AddDays(-8) (2026-05-24T12:00:00Z).
    private static readonly DateTimeOffset SampleValiditySigned = TestClock.CanonicalEpoch.AddDays(-8);
    private static readonly DateTimeOffset SampleValidityValidUntil = SampleValiditySigned.AddYears(1);


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: SampleValiditySigned,
            validFrom: SampleValiditySigned,
            validUntil: SampleValidityValidUntil);


    private static CoseKey CoseKeyFromP256Public(PublicKeyMemory publicKey)
    {
        ReadOnlySpan<byte> compressed = publicKey.AsReadOnlySpan();
        byte[] uncompressed = EllipticCurveUtilities.Decompress(compressed, EllipticCurveTypes.P256);
        return new CoseKey(
            kty: CoseKeyTypes.Ec2,
            curve: CoseKeyCurves.P256,
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


    private static byte[] CborBool(bool value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteBoolean(value);

        return writer.Encode();
    }
}

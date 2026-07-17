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
/// End-to-end tests for the M.3 issuer-side signing pipeline. Runs the
/// full sequence:
/// </summary>
/// <list type="number">
/// <item><description><see cref="MdocIssuance.BuildDocument"/> assembles the logical mdoc.</description></item>
/// <item><description><see cref="MdocCborIssuance.SignAsync"/> encodes items, computes the MSO digests, signs as COSE_Sign1.</description></item>
/// <item><description>The wire bytes are emitted via the same <see cref="CoseSerialization.SerializeCoseSign1"/> the signer wrote them with.</description></item>
/// <item><description><see cref="MdocCborIssuerAuthReader.Read"/> parses the wire bytes back into <see cref="MdocIssuerAuth"/>.</description></item>
/// <item><description><see cref="MdocCborIssuerAuthVerifier.VerifyAsync"/> validates the signature against the issuer's public key.</description></item>
/// </list>
/// <remarks>
/// <para>
/// Uses real P-256 / EdDSA / P-384 issuer signing keys from
/// <see cref="TestKeyMaterialProvider"/> per the test-crypto rule. The
/// device key inside the MSO is also a real generated key (we only need
/// the public half; the wallet-side device-signing path lands in M.3b).
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocCborIssuanceEndToEndTests
{
    private const string PidDocType = "eu.europa.ec.eudi.pid.1";
    private const string PidNamespace = "eu.europa.ec.eudi.pid.1";

    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task IssueAndVerifyRoundTripWithP256IssuerKey()
    {
        await RunRoundTripAsync(
            issuerKeys: TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            deviceKeys: TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha256).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task IssueAndVerifyRoundTripWithP384IssuerKey()
    {
        await RunRoundTripAsync(
            issuerKeys: TestKeyMaterialProvider.CreateFreshP384KeyMaterial(),
            deviceKeys: TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha384).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task IssueAndVerifyRoundTripWithEd25519IssuerKey()
    {
        await RunRoundTripAsync(
            issuerKeys: TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial(),
            deviceKeys: TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha256).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task SignAttachesIssuerAuthAndFillsItemWireBytes()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator);
            CoseKey deviceCoseKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey);

            using MdocDocument signed = await logical.SignAsync(
                config: new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = deviceCoseKey
                },
                signingKey: issuerKeys.PrivateKey,
                signaturePool: BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            //IssuerAuth + per-item WireBytes are non-nullable on the signed
            //MdocDocument by construction; what once required runtime
            //IsNotNull guards is now a structural invariant.
            Assert.HasCount(signed.IssuerSigned.NameSpaces.Count, signed.IssuerSigned.IssuerAuth.Mso.ValueDigests);
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyFailsWithWrongIssuerKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> imposterKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator);
            using MdocDocument signed = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            bool isVerified = await signed.VerifyIssuerAuthAsync(
                imposterKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(isVerified, "Verification under a different issuer key must fail.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(imposterKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task SignedItemWireBytesHashToMsoValueDigests()
    {
        //The MSO commits to SHA-256(item.WireBytes) per ISO/IEC 18013-5
        //§9.1.2.5. Re-hashing the item bytes the signer wrote MUST match
        //the digest in the MSO valueDigests map — that's the contract the
        //M.4 binding validator will check against the issuer's signed MSO.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator);
            using MdocDocument signed = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            IReadOnlyDictionary<uint, ReadOnlyMemory<byte>> nsDigests =
                signed.IssuerSigned.IssuerAuth.Mso.ValueDigests[PidNamespace];

            foreach(MdocIssuerSignedItem item in signed.IssuerSigned.NameSpaces[PidNamespace])
            {
                byte[] expected = System.Security.Cryptography.SHA256.HashData(item.WireBytes.Span);
                Assert.IsTrue(
                    nsDigests[item.DigestId].Span.SequenceEqual(expected),
                    $"valueDigests[{PidNamespace}][{item.DigestId}] must equal SHA-256(item.WireBytes).");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task SignVerboseExposesSignedMsoPayload()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            (MdocDocument signed, ReadOnlyMemory<byte> signedMsoPayload) = await MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator).SignVerboseAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using(signed)
            {
                Assert.IsGreaterThan(0, signedMsoPayload.Length, "The signed MSO payload must be exposed.");

                //Verbose captures, it does not reconstruct: the threaded payload must be
                //byte-identical to the COSE_Sign1 payload the signature actually covers.
                using CoseSign1Message message = CoseSerialization.ParseCoseSign1(
                    signed.IssuerSigned.IssuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), BaseMemoryPool.Shared);
                Assert.IsTrue(
                    message.Payload.Span.SequenceEqual(signedMsoPayload.Span),
                    "The signed MSO payload must equal the produced document's COSE_Sign1 payload.");

                //And it must be the Tag 24-wrapped MSO per ISO/IEC 18013-5 §9.1.2.4.
                EncodedCborItem wrapper = EncodedCborItem.Read(
                    new CborReader(signedMsoPayload.ToArray(), CborConformanceMode.Lax));
                MdocMobileSecurityObject mso = MdocCborMsoReader.Read(wrapper.InnerBytes.Span);
                Assert.AreEqual(PidDocType, mso.DocType);
                Assert.HasCount(2, mso.ValueDigests[PidNamespace]);
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyIssuerAuthVerboseExposesParsedMessageAndMso()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument signed = await MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            (bool result, MdocIssuerAuthVerificationContext? context) = await signed.VerifyIssuerAuthVerboseAsync(
                issuerKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsTrue(result, "A correctly signed IssuerAuth must verify.");
                Assert.IsNotNull(context, "A verified IssuerAuth must expose intermediate context.");
                Assert.IsGreaterThan(0, context.Message.Payload.Length, "The parsed Tag 24-wrapped MSO payload must be exposed.");
                Assert.AreSame(signed.IssuerSigned.IssuerAuth.Mso, context.Mso, "The context surfaces the verified IssuerAuth's MSO.");
                Assert.AreEqual(PidDocType, context.Mso.DocType);
                Assert.IsNull(context.TrustResolution, "The direct-key overload leaves the trust resolution null.");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyIssuerAuthVerboseReturnsNullContextWhenSignatureInvalid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> imposterKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument signed = await MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey)
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            (bool result, MdocIssuerAuthVerificationContext? context) = await signed.VerifyIssuerAuthVerboseAsync(
                imposterKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsFalse(result, "Verification under a different issuer key must fail.");
                Assert.IsNull(context, "No context is exposed when the signature is invalid.");
            }
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(imposterKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    /// <summary>
    /// Runs the full issue → sign → (no separate encode step needed: the
    /// signer's IssuerAuth.EncodedCoseSign1 IS the wire form) → parse → verify
    /// loop and asserts each leg holds.
    /// </summary>
    private async Task RunRoundTripAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys,
        string digestAlgorithm)
    {
        try
        {
            //fall through to common body below
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(SampleRandomGenerator);
            CoseKey deviceCoseKey = MdocTestFixtures.CoseKeyFromP256Public(deviceKeys.PublicKey);

            using MdocDocument signed = await logical.SignAsync(
                config: new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = digestAlgorithm,
                    Validity = SampleValidity(),
                    DeviceKey = deviceCoseKey
                },
                signingKey: issuerKeys.PrivateKey,
                signaturePool: BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(signed.IssuerSigned.IssuerAuth);

            //Round-trip the wire bytes through the M.2 reader.
            ReadOnlyMemory<byte> wireBytes = signed.IssuerSigned.IssuerAuth.EncodedCoseSign1.AsReadOnlyMemory();
            MdocIssuerAuth roundTripped = MdocCborIssuerAuthReader.Read(wireBytes.Span, BaseMemoryPool.Shared);

            Assert.AreEqual(signed.IssuerSigned.IssuerAuth.Mso.DocType, roundTripped.Mso.DocType);
            Assert.AreEqual(signed.IssuerSigned.IssuerAuth.Mso.DigestAlgorithm, roundTripped.Mso.DigestAlgorithm);
            Assert.HasCount(
                signed.IssuerSigned.IssuerAuth.Mso.ValueDigests[PidNamespace].Count,
                roundTripped.Mso.ValueDigests[PidNamespace]);

            //Verify the COSE_Sign1 signature under the issuer's public key.
            bool isVerified = await roundTripped.VerifyAsync(
                issuerKeys.PublicKey, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified, $"Round-tripped IssuerAuth signature must verify under {digestAlgorithm}.");
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(issuerKeys);
            MdocTestFixtures.DisposeKeyMaterial(deviceKeys);
        }
    }


    private static Salt SampleRandomGenerator() =>
        MdocTestFixtures.ItemRandomSalt();


    //Bit-identical to TestClock.CanonicalEpoch.AddDays(-8) (2026-05-24T12:00:00Z).
    private static readonly DateTimeOffset SampleValiditySigned = TestClock.CanonicalEpoch.AddDays(-8);
    private static readonly DateTimeOffset SampleValidityValidUntil = SampleValiditySigned.AddYears(1);


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: SampleValiditySigned,
            validFrom: SampleValiditySigned,
            validUntil: SampleValidityValidUntil);
}

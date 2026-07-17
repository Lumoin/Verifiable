using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Tests.TestInfrastructure;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// End-to-end tests for the M.5 IACA trust delegate. Generates a tiny
/// self-issued IACA root + leaf certificate, signs an MSO with the leaf,
/// embeds the chain in the COSE_Sign1 <c>x5chain</c> unprotected header,
/// and verifies through the trust delegate against the IACA root.
/// </summary>
/// <remarks>
/// <para>
/// Uses <see cref="MicrosoftX509Functions.ValidateChain"/> as the
/// underlying chain validator — the same delegate the OAuth/JAR
/// signature-verification path uses.
/// </para>
/// <para>
/// The cert generation uses <see cref="CertificateRequest"/> directly
/// rather than going through the project's key-material providers because
/// the test needs the X.509 chain to be self-consistent (issuer name of the
/// leaf == subject name of the root, leaf signed by the root's private
/// key). Once that chain is built, the leaf's public key is what signs the
/// MSO — passed through the project's signing pipeline as a
/// <see cref="PrivateKeyMemory"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocIacaTrustEndToEndTests
{
    public required TestContext TestContext { get; set; }

    //Bit-identical to TestClock.CanonicalEpoch.AddDays(-7) (2026-05-25T12:00:00Z) —
    //the trust delegate's "now" for chain validation; the certs are valid for a
    //wide window (see CreateSelfSignedCa/CreateLeafCertificate) so this is stable.
    private static readonly DateTimeOffset TrustResolutionValidationTime = TestClock.CanonicalEpoch.AddDays(-7);

    //Family anchor: not a clean single-call TestClock.CanonicalEpoch offset
    //(2026-06-01T12:00:00Z is 7 days 4 hours after this signed instant), so
    //the one-year window anchors itself.
    private static readonly DateTimeOffset SampleValiditySigned = new(2026, 5, 25, 8, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset SampleValidityValidUntil = SampleValiditySigned.AddYears(1);


    [TestMethod]
    public async Task IssuerWithIacaChainVerifiesThroughTrustDelegate()
    {
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        //Build a IACA root + leaf cert. The leaf's signing key is what
        //signs the MSO; the IACA root is what the verifier trusts.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Test IACA Root", rootKey);
        using X509Certificate2 leafCert = CreateLeafCertificate("CN=Test mDL Issuer", leafKey, rootCert, rootKey);

        //Wrap the leaf's private key into the project's PrivateKeyMemory shape.
        using PrivateKeyMemory leafPrivateKey = LoadP256PrivateKey(leafKey);

        //x5chain: leaf first, root next per RFC 9360 §2 convention.
        IReadOnlyList<ReadOnlyMemory<byte>> x5Chain =
        [
            leafCert.RawData,
            rootCert.RawData
        ];

        //Sign the MSO with the leaf key, embedding the chain.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            MdocLogicalDocument logical = MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt());
            using MdocDocument issued = await logical.SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = x5Chain
                },
                leafPrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Build the trust delegate — trust the root cert; verify "now"
            //(the certs are valid for a wide window so this is stable).
            using PkiCertificateMemory rootTrustAnchor = CopyToPkiCertificate(rootCert.RawData);
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                validateChain: MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [rootTrustAnchor],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            //End-to-end: trust resolution + signature verification in one call.
            bool isVerified = await issued.VerifyIssuerAuthAsync(
                trustDelegate, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified, "IACA-rooted IssuerAuth must verify under the trust delegate.");
        }
        finally
        {
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyIssuerAuthVerboseExposesTrustResolutionAndMessage()
    {
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Verbose IACA Root", rootKey);
        using X509Certificate2 leafCert = CreateLeafCertificate("CN=Verbose mDL Issuer", leafKey, rootCert, rootKey);

        using PrivateKeyMemory leafPrivateKey = LoadP256PrivateKey(leafKey);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt()).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = [leafCert.RawData, rootCert.RawData]
                },
                leafPrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using PkiCertificateMemory rootTrustAnchor = CopyToPkiCertificate(rootCert.RawData);
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [rootTrustAnchor],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            (bool result, MdocIssuerAuthVerificationContext? context) = await issued.VerifyIssuerAuthVerboseAsync(
                trustDelegate, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsTrue(result, "An IACA-rooted IssuerAuth must verify through the trust delegate.");
                Assert.IsNotNull(context, "A verified IssuerAuth must expose intermediate context.");
                Assert.IsGreaterThan(0, context.Message.Payload.Length, "The parsed Tag 24-wrapped MSO payload must be exposed.");
                Assert.AreSame(issued.IssuerSigned.IssuerAuth.Mso, context.Mso);
                Assert.IsNotNull(context.TrustResolution, "The trust-resolver overload surfaces the resolution.");
                Assert.IsTrue(context.TrustResolution.IsTrusted);
                Assert.IsNotNull(context.TrustResolution.IssuerVerificationKey, "The successful resolution carries the resolved leaf key.");
            }
        }
        finally
        {
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task VerifyIssuerAuthVerboseReturnsNullContextWhenTrustFails()
    {
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Real IACA Root", rootKey);
        using X509Certificate2 leafCert = CreateLeafCertificate("CN=mDL Issuer", leafKey, rootCert, rootKey);

        //A second, unrelated self-signed CA the trust delegate must reject.
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 imposterRootCert = CreateSelfSignedCa("CN=Imposter Root", imposterRootKey);

        using PrivateKeyMemory leafPrivateKey = LoadP256PrivateKey(leafKey);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt()).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = [leafCert.RawData, rootCert.RawData]
                },
                leafPrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using PkiCertificateMemory imposterAnchor = CopyToPkiCertificate(imposterRootCert.RawData);
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [imposterAnchor],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            (bool result, MdocIssuerAuthVerificationContext? context) = await issued.VerifyIssuerAuthVerboseAsync(
                trustDelegate, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            using(context)
            {
                Assert.IsFalse(result, "An IssuerAuth that builds to an untrusted root must not verify.");
                Assert.IsNull(context, "A failed trust resolution exposes no context.");
            }
        }
        finally
        {
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task TrustResolutionFailsWhenIssuerAuthHasNoX5Chain()
    {
        //Sign without an x5chain — the trust delegate has nothing to walk.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt()).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey)
                    //No X5Chain
                },
                issuerKeys.PrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            //Build a trust delegate against an empty anchor list — irrelevant
            //since the missing header is what should fail.
            //Validation time is irrelevant for this test — the failure
            //fires before chain validation runs.
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            using MdocIacaTrustResolution resolution = await trustDelegate(
                issued.IssuerSigned.IssuerAuth, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(resolution.IsTrusted);
            Assert.AreEqual(MdocIacaTrustFailureReason.X5ChainHeaderMissing, resolution.FailureReason);
        }
        finally
        {
            DisposeKeyMaterial(issuerKeys);
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task TrustResolutionFailsWhenChainBuildsToUntrustedRoot()
    {
        //Sign with a self-issued IACA root, but resolve trust against a
        //different root. The chain validator must reject.
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Real IACA Root", rootKey);
        using X509Certificate2 leafCert = CreateLeafCertificate("CN=mDL Issuer", leafKey, rootCert, rootKey);

        //A second, unrelated self-signed CA the chain must not resolve to.
        using ECDsa imposterRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 imposterRootCert = CreateSelfSignedCa("CN=Imposter Root", imposterRootKey);

        using PrivateKeyMemory leafPrivateKey = LoadP256PrivateKey(leafKey);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt()).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = [leafCert.RawData, rootCert.RawData]
                },
                leafPrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using PkiCertificateMemory imposterAnchor = CopyToPkiCertificate(imposterRootCert.RawData);
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [imposterAnchor],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            using MdocIacaTrustResolution resolution = await trustDelegate(
                issued.IssuerSigned.IssuerAuth, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(resolution.IsTrusted);
            Assert.AreEqual(MdocIacaTrustFailureReason.ChainValidationFailed, resolution.FailureReason);
            Assert.IsNotNull(resolution.FailureMessage);
        }
        finally
        {
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public async Task SingleCertificateX5ChainAcceptedAsSingleBstrForm()
    {
        //RFC 9360 §2 allows a single-cert x5chain to be a bare bstr instead
        //of a one-element array. The signer emits the bstr form; the
        //extractor accepts both.
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Single-Cert Root", rootKey);
        using PrivateKeyMemory rootPrivateKey = LoadP256PrivateKey(rootKey);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            using MdocDocument issued = await MdocTestFixtures.BuildSampleLogicalPid(() => MdocTestFixtures.ItemRandomSalt()).SignAsync(
                new MdocIssuerSigningConfig
                {
                    DigestAlgorithm = MdocMsoWellKnownKeys.DigestAlgorithmSha256,
                    Validity = SampleValidity(),
                    DeviceKey = CoseKeyFromP256Public(deviceKeys.PublicKey),
                    X5Chain = [rootCert.RawData]
                },
                rootPrivateKey,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using PkiCertificateMemory rootAnchor = CopyToPkiCertificate(rootCert.RawData);
            ResolveMdocIssuerKeyDelegate trustDelegate = MdocCborIacaTrustResolver.Create(
                MicrosoftX509Functions.ValidateChainAsync,
                trustAnchors: [rootAnchor],
                validationTime: TrustResolutionValidationTime,
                pool: BaseMemoryPool.Shared);

            bool isVerified = await issued.VerifyIssuerAuthAsync(
                trustDelegate, BaseMemoryPool.Shared, CoseSerialization.ParseCoseSign1, CoseSerialization.BuildSigStructure, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(isVerified,
                "Single-cert x5chain (bare bstr form per RFC 9360 §2) must verify.");
        }
        finally
        {
            DisposeKeyMaterial(deviceKeys);
        }
    }


    [TestMethod]
    public void ExtractorReturnsCertificatesInChainOrder()
    {
        //Direct test of the extractor: feed in a signed-with-x5chain
        //IssuerAuth and assert leaf-first ordering. Independent of any
        //trust validation.
        //Cert-factory carve-out (see class remarks): CertificateRequest needs a framework ECDsa key to mint the chain.
        using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 rootCert = CreateSelfSignedCa("CN=Root", rootKey);
        using X509Certificate2 leafCert = CreateLeafCertificate("CN=Leaf", leafKey, rootCert, rootKey);

        //Construct a COSE_Sign1 with x5chain manually rather than going
        //through full signing — keeps the extractor test focused.
        byte[] coseSign1 = BuildMinimalCoseSign1WithX5Chain(leafCert.RawData, rootCert.RawData);

        IReadOnlyList<PkiCertificateMemory> chain = MdocCborX5ChainExtractor.Extract(
            coseSign1, BaseMemoryPool.Shared);

        try
        {
            Assert.HasCount(2, chain);
            Assert.IsTrue(chain[0].AsReadOnlySpan().SequenceEqual(leafCert.RawData),
                "Leaf certificate must be the first chain entry per RFC 9360 §2.");
            Assert.IsTrue(chain[1].AsReadOnlySpan().SequenceEqual(rootCert.RawData),
                "Root certificate is the second entry.");
        }
        finally
        {
            foreach(PkiCertificateMemory cert in chain)
            {
                cert.Dispose();
            }
        }
    }


    private static MdocValidityInfo SampleValidity() =>
        new(
            signed: SampleValiditySigned,
            validFrom: SampleValiditySigned,
            validUntil: SampleValidityValidUntil);


    //Cert-factory carve-out (see class remarks): mints the chain with CertificateRequest directly.
    private static X509Certificate2 CreateSelfSignedCa(string subjectName, ECDsa key)
    {
        var request = new CertificateRequest(subjectName, key, HashAlgorithmName.SHA256);

        //Basic constraints + key usage for an IACA root.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        return request.CreateSelfSigned(
            notBefore: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
    }


    //Cert-factory carve-out (see class remarks): mints the chain with CertificateRequest directly.
    private static X509Certificate2 CreateLeafCertificate(
        string subjectName,
        ECDsa leafKey,
        X509Certificate2 issuerCert,
        ECDsa issuerKey)
    {
        var request = new CertificateRequest(subjectName, leafKey, HashAlgorithmName.SHA256);

        //Leaf: not a CA, signing-only key usage.
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(
            certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        //Certificate serial number: required argument for CertificateRequest.Create; cert-factory carve-out (see class remarks).
        byte[] serialNumber = RandomNumberGenerator.GetBytes(16);
        return request.Create(
            issuerCert,
            notBefore: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            notAfter: new DateTimeOffset(2029, 1, 1, 0, 0, 0, TimeSpan.Zero),
            serialNumber).CopyWithPrivateKey(leafKey);
    }


    private static PrivateKeyMemory LoadP256PrivateKey(ECDsa key)
    {
        //The private scalar D is the raw form the project's signing
        //pipeline expects. Tag identifies the curve so the registry can
        //resolve the right SignP256 function.
        ECParameters parameters = key.ExportParameters(includePrivateParameters: true);
        byte[] dBytes = parameters.D!;

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(dBytes.Length);
        dBytes.CopyTo(owner.Memory.Span);

        return new PrivateKeyMemory(owner, CryptoTags.P256PrivateKey);
    }


    private static PkiCertificateMemory CopyToPkiCertificate(byte[] derBytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(derBytes.Length);
        derBytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    private static byte[] BuildMinimalCoseSign1WithX5Chain(byte[] leafDer, byte[] rootDer)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag((CborTag)18); //COSE_Sign1

        writer.WriteStartArray(4);

        //Protected header — empty map.
        writer.WriteByteString(new byte[] { 0xA0 });

        //Unprotected header — { 33: [leaf, root] }.
        writer.WriteStartMap(1);
        writer.WriteInt32(MdocCoseHeaderLabels.X5Chain);
        writer.WriteStartArray(2);
        writer.WriteByteString(leafDer);
        writer.WriteByteString(rootDer);
        writer.WriteEndArray();
        writer.WriteEndMap();

        //Payload — empty bstr (we're not testing signature).
        writer.WriteByteString([]);

        //Signature — empty bstr.
        writer.WriteByteString([]);

        writer.WriteEndArray();

        return writer.Encode();
    }


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
}

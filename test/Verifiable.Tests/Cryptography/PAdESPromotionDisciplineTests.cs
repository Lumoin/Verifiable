using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The promotion-discipline template proof for PAdES, adapted from <c>JAdESPromotionDisciplineTests</c>'s own
/// shape to the mint-only carrier-class discipline <see cref="CAdESVerificationResult"/>/<see
/// cref="PAdESSignatureValidationResult"/>/<see cref="PAdESValidationResult"/> share (a private constructor plus
/// non-public static factories, rather than <c>Verified&lt;T&gt;</c>'s own generic wrapper — PAdES composes <see
/// cref="CAdESVerification"/>'s carrier shape unchanged, RP-3). Compile-time forgeability is checked by reflection over
/// every minting surface; runtime forgeability is checked by proving a parsed-but-cryptographically-invalid signature
/// never reaches <see cref="PAdESSignatureStatus.Valid"/> while its decoded (Unverified) facts stay reachable, and the
/// mirror-image success case.
/// </summary>
[TestClass]
internal sealed class PAdESPromotionDisciplineTests
{
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;


    public required TestContext TestContext { get; set; }


    /// <summary><see cref="PAdESSignatureValidationResult"/> has no public constructor -- an external caller cannot wrap arbitrary decoded data into a "valid" result even by direct construction.</summary>
    [TestMethod]
    public void SignatureValidationResultConstructorIsNotPublic()
    {
        AssertNoPublicConstructor(typeof(PAdESSignatureValidationResult));
    }


    /// <summary><see cref="PAdESSignatureValidationResult.Valid"/>/<see cref="PAdESSignatureValidationResult.Failed"/> are the only routes to an instance and both are non-public -- minting one is <see cref="PAdESSignatureValidation"/>'s exclusive responsibility.</summary>
    [TestMethod]
    public void SignatureValidationResultMintingFactoriesAreNotPublic()
    {
        AssertNoPublicStaticFactory(typeof(PAdESSignatureValidationResult), "Valid");
        AssertNoPublicStaticFactory(typeof(PAdESSignatureValidationResult), "Failed");
    }


    /// <summary><see cref="PAdESValidationResult"/> -- the whole-document result -- has no public constructor either.</summary>
    [TestMethod]
    public void ValidationResultConstructorIsNotPublic()
    {
        AssertNoPublicConstructor(typeof(PAdESValidationResult));
    }


    /// <summary><see cref="PAdESValidationResult.Success"/>/<see cref="PAdESValidationResult.Failure"/> are the only routes to an instance and both are non-public.</summary>
    [TestMethod]
    public void ValidationResultMintingFactoriesAreNotPublic()
    {
        AssertNoPublicStaticFactory(typeof(PAdESValidationResult), "Success");
        AssertNoPublicStaticFactory(typeof(PAdESValidationResult), "Failure");
    }


    /// <summary>
    /// The composed <see cref="CAdESVerificationResult"/> (RP-3: PAdES never re-derives cryptographic proof, it
    /// composes the shipped CAdES verification carrier unchanged) carries the identical mint-only shape one layer
    /// down -- checked here too, since a public constructor or factory on the COMPOSED type would let a caller
    /// fabricate the cryptographic outcome <see cref="PAdESSignatureValidationResult.CryptographicResult"/> wraps,
    /// even with every PAdES-side factory locked down.
    /// </summary>
    [TestMethod]
    public void ComposedCAdESVerificationResultConstructorAndFactoriesAreNotPublic()
    {
        AssertNoPublicConstructor(typeof(CAdESVerificationResult));
        AssertNoPublicStaticFactory(typeof(CAdESVerificationResult), "Valid");
        AssertNoPublicStaticFactory(typeof(CAdESVerificationResult), "Failed");
    }


    /// <summary>
    /// Runtime proof: a signature whose bytes parse (a well-formed Signature Dictionary, a well-formed
    /// <c>ByteRange</c>) but whose cryptographic signature does not verify NEVER reaches
    /// <see cref="PAdESSignatureStatus.Valid"/> -- the decoded (Unverified) <see cref="PAdESSignatureValidationResult.SigningTime"/>
    /// stays reachable regardless, exactly the "failures keep decoded facts" guarantee
    /// <see cref="PAdESSignatureValidationResult"/>'s own remarks state.
    /// </summary>
    [TestMethod]
    public async Task ParsedButCryptographicallyInvalidSignatureNeverReachesValid()
    {
        using Scenario scenario = await Scenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tampered = (byte[])scenario.Signed.Bytes.Clone();
        int contentsStart = FindContentsHexStart(tampered);
        tampered[contentsStart + 20] = tampered[contentsStart + 20] == (byte)'0' ? (byte)'1' : (byte)'0';

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        PAdESSignatureValidationResult result = validation.Signatures![0];
        Assert.AreNotEqual(PAdESSignatureStatus.Valid, result.Status, "A tampered Contents value must never promote to Valid -- the RP-4 guarantee this class proves.");
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SigningTime, result.SigningTime, "The Unverified M-entry fact must survive a cryptographic failure.");
        Assert.IsNull(result.SignerCertificate, "Cryptographic facts stay null once verification itself was never reached successfully.");
    }


    /// <summary>The mirror-image invariant: a genuinely valid signature reaches <see cref="PAdESSignatureStatus.Valid"/> and its cryptographic facts (the signer certificate) are reachable only there.</summary>
    [TestMethod]
    public async Task GenuinelyValidSignatureReachesValidWithCryptographicFactsAttached()
    {
        using Scenario scenario = await Scenario.CreateAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using PAdESValidationResult validation = await PAdESSignatureValidation.ValidateAsync(
            scenario.Signed.Bytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(validation.IsSuccess, validation.FailureReason);
        PAdESSignatureValidationResult result = validation.Signatures![0];
        Assert.AreEqual(PAdESSignatureStatus.Valid, result.Status);
        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.SignerCertificate);
        Assert.IsTrue(result.SignerCertificate!.AsReadOnlySpan().SequenceEqual(scenario.SignerCertificate.AsReadOnlySpan()));
    }


    private static void AssertNoPublicConstructor(Type type)
    {
        ConstructorInfo[] constructors = type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.IsGreaterThan(0, constructors.Length, $"{type.Name} must declare at least one constructor.");
        Assert.IsTrue(constructors.All(static c => !c.IsPublic), $"{type.Name}'s constructor must stay non-public -- a public one would let any caller mint a result carrying arbitrary data.");
    }


    private static void AssertNoPublicStaticFactory(Type type, string methodName)
    {
        MethodInfo? factory = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .FirstOrDefault(m => string.Equals(m.Name, methodName, StringComparison.Ordinal));

        Assert.IsNotNull(factory, $"{type.Name}.{methodName} must exist.");
        Assert.IsFalse(factory!.IsPublic, $"{type.Name}.{methodName} must stay non-public -- minting one is the validation surface's exclusive responsibility.");
    }


    private static int FindContentsHexStart(byte[] document)
    {
        string text = System.Text.Encoding.ASCII.GetString(document);

        return text.IndexOf("/Contents <", StringComparison.Ordinal) + "/Contents <".Length;
    }


    /// <summary>A minted PAdES-B-B signature and everything that produced it, disposed together.</summary>
    private sealed class Scenario: IDisposable
    {
        internal required X509ChainTestRingNode Root { get; init; }

        internal required PkiCertificateMemory SignerCertificate { get; init; }

        internal required PrivateKeyMemory SignerPrivateKey { get; init; }

        internal required PAdESSignedDocument Signed { get; init; }


        internal static async ValueTask<Scenario> CreateAsync(System.Threading.CancellationToken cancellationToken)
        {
            var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
            X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
            (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
            (byte[] unsignedDocument, PdfIncrementalUpdateAnchor anchor) = BuildUnsignedBasePdf();

            PAdESSignedDocument signed = await PAdESSignatureCreation.SignAsync(
                new PAdESSigningRequest
                {
                    PriorDocument = unsignedDocument,
                    Anchor = anchor,
                    ContentsCapacityBytes = 4096,
                    SignerCertificate = certificate,
                    SignerPrivateKey = privateKey,
                    SigningTime = SigningTime,
                    Name = "Promotion Discipline Signer"
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            return new Scenario { Root = root, SignerCertificate = certificate, SignerPrivateKey = privateKey, Signed = signed };
        }


        public void Dispose()
        {
            SignerPrivateKey.Dispose();
            SignerCertificate.Dispose();
            Root.Dispose();
        }
    }


    private static (byte[] Bytes, PdfIncrementalUpdateAnchor Anchor) BuildUnsignedBasePdf()
    {
        var writer = new System.Collections.Generic.List<byte>();
        void Ascii(string s) => writer.AddRange(System.Text.Encoding.ASCII.GetBytes(s));

        Ascii("%PDF-1.7\n");
        int obj1Offset = writer.Count;
        Ascii("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        int xrefOffset = writer.Count;
        Ascii("xref\n0 2\n");
        Ascii("0000000000 65535 f \n");
        Ascii($"{obj1Offset:D10} 00000 n \n");
        Ascii("trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n");
        Ascii(xrefOffset.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Ascii("\n%%EOF\n");

        byte[] bytes = [.. writer];
        var anchor = new PdfIncrementalUpdateAnchor
        {
            PriorXrefOffset = xrefOffset,
            PriorObjectCount = 2,
            RootObjectNumber = 1,
            RootGeneration = 0
        };

        return (bytes, anchor);
    }


    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintSigner()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            using ECDsa platformKey = ECDsa.Create(ecParameters);
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

            return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
        }
    }


    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        System.Buffers.IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}

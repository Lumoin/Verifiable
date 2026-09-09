using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.Foundation;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The promotion-discipline template proof for PAdES, adapted from <c>JAdESPromotionDisciplineTests</c>'s own
/// shape to the mint-only carrier-class discipline <see cref="CAdESVerificationResult"/>/<see
/// cref="PAdESSignatureValidationResult"/>/<see cref="PAdESValidationResult"/> share (a private constructor plus
/// non-public static factories, rather than <c>Verified&lt;T&gt;</c>'s own generic wrapper — PAdES composes <see
/// cref="CAdESVerification"/>'s carrier shape unchanged, RP-3). Compile-time forgeability is checked by a source
/// scan over every minting surface's own declaration; runtime forgeability is checked by proving a
/// parsed-but-cryptographically-invalid signature never reaches <see cref="PAdESSignatureStatus.Valid"/> while
/// its decoded (Unverified) facts stay reachable, and the mirror-image success case.
/// </summary>
[TestClass]
internal sealed class PAdESPromotionDisciplineTests
{
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// <see cref="PAdESSignatureValidationResult"/> declares no public constructor and its
    /// <see cref="PAdESSignatureValidationResult.Valid"/>/<see cref="PAdESSignatureValidationResult.Failed"/>
    /// minting factories stay non-public -- an external caller cannot wrap arbitrary decoded data into a
    /// "valid" result even by direct construction; minting one is <see cref="PAdESSignatureValidation"/>'s
    /// exclusive responsibility. Proved as a source scan of the declaring file's own constructor and factory
    /// declaration lines, since the compiler already enforces whatever accessibility the source states.
    /// </summary>
    [TestMethod]
    public void SignatureValidationResultConstructorAndFactoriesAreNotPublic()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertConstructorIsNotPublicInSource(repositoryRoot, PkiPath, "PAdESSignatureValidationResult");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, PkiPath, "Valid");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, PkiPath, "Failed");
    }


    /// <summary>
    /// <see cref="PAdESValidationResult"/> -- the whole-document result -- declares no public constructor, and
    /// its <see cref="PAdESValidationResult.Success"/>/<see cref="PAdESValidationResult.Failure"/> minting
    /// factories stay non-public. Proved as a source scan of the declaring file's own declaration lines.
    /// </summary>
    [TestMethod]
    public void ValidationResultConstructorAndFactoriesAreNotPublic()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertConstructorIsNotPublicInSource(repositoryRoot, PkiPath, "PAdESValidationResult");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, PkiPath, "Success");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, PkiPath, "Failure");
    }


    /// <summary>
    /// The composed <see cref="CAdESVerificationResult"/> (RP-3: PAdES never re-derives cryptographic proof, it
    /// composes the shipped CAdES verification carrier unchanged) carries the identical mint-only shape one layer
    /// down -- checked here too, since a public constructor or factory on the COMPOSED type would let a caller
    /// fabricate the cryptographic outcome <see cref="PAdESSignatureValidationResult.CryptographicResult"/> wraps,
    /// even with every PAdES-side factory locked down. Proved as a source scan of that type's own declaring file.
    /// </summary>
    [TestMethod]
    public void ComposedCAdESVerificationResultConstructorAndFactoriesAreNotPublic()
    {
        string repositoryRoot = SourceHygieneScanner.FindRepositoryRoot();

        AssertConstructorIsNotPublicInSource(repositoryRoot, CAdESVerificationPath, "CAdESVerificationResult");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, CAdESVerificationPath, "Valid");
        AssertStaticFactoryIsNotPublicInSource(repositoryRoot, CAdESVerificationPath, "Failed");
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


    /// <summary>The repository-relative path declaring <see cref="PAdESSignatureValidationResult"/> and <see cref="PAdESValidationResult"/>.</summary>
    private const string PkiPath = "src/Verifiable.Cryptography/Pki/PAdESSignatureValidation.cs";

    /// <summary>The repository-relative path declaring <see cref="CAdESVerificationResult"/>.</summary>
    private const string CAdESVerificationPath = "src/Verifiable.Cryptography/Pki/CAdESVerification.cs";


    /// <summary>
    /// Asserts <paramref name="typeName"/>'s declaring file at <paramref name="relativePath"/> carries a
    /// non-public constructor declaration and no public one -- a source-text check, since the compiler already
    /// enforces whatever accessibility the declaration states.
    /// </summary>
    /// <param name="repositoryRoot">The repository root <paramref name="relativePath"/> is relative to.</param>
    /// <param name="relativePath">The declaring file's repository-relative path.</param>
    /// <param name="typeName">The type whose constructor is checked.</param>
    private static void AssertConstructorIsNotPublicInSource(string repositoryRoot, string relativePath, string typeName)
    {
        string text = File.ReadAllText(Path.Combine(repositoryRoot, relativePath));
        string escapedName = Regex.Escape(typeName);

        Assert.IsFalse(
            Regex.IsMatch(text, $@"(?m)^\s*public\s+{escapedName}\s*\("),
            $"{relativePath}: {typeName} must declare no public constructor -- a public one would let any caller mint a result carrying arbitrary data.");
        Assert.IsTrue(
            Regex.IsMatch(text, $@"(?m)^\s*(?:private|internal|protected)\s+{escapedName}\s*\("),
            $"{relativePath}: {typeName} must declare a non-public constructor.");
    }


    /// <summary>
    /// Asserts the static method named <paramref name="methodName"/> in the file at
    /// <paramref name="relativePath"/> is declared non-public and never also declared public -- a source-text
    /// check of the minting factory's own accessibility modifier.
    /// </summary>
    /// <param name="repositoryRoot">The repository root <paramref name="relativePath"/> is relative to.</param>
    /// <param name="relativePath">The declaring file's repository-relative path.</param>
    /// <param name="methodName">The static factory method's name.</param>
    private static void AssertStaticFactoryIsNotPublicInSource(string repositoryRoot, string relativePath, string methodName)
    {
        string text = File.ReadAllText(Path.Combine(repositoryRoot, relativePath));
        string escapedName = Regex.Escape(methodName);

        Assert.IsFalse(
            Regex.IsMatch(text, $@"(?m)^\s*public\s+static\s+\S.*\b{escapedName}\s*\("),
            $"{relativePath}: {methodName} must stay non-public -- minting one is the validation surface's exclusive responsibility.");
        Assert.IsTrue(
            Regex.IsMatch(text, $@"(?m)^\s*(?:private|internal|protected)\s+static\s+\S.*\b{escapedName}\s*\("),
            $"{relativePath}: {methodName} must exist and stay non-public.");
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

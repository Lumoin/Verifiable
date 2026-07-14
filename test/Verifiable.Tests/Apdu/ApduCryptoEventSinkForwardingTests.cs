using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Coverage for the wave-7 <see cref="CryptoEventSink"/> widening of the APDU/eMRTD explicit-delegate call
/// sites that resolve and invoke a <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/>/
/// <see cref="RecoverableSigningDelegate"/>/<see cref="RecoverableVerificationDelegate"/> directly (there is
/// no <see cref="PrivateKey"/>/<see cref="PublicKey"/> object at these call sites, only raw key bytes or a
/// distinct carrier type). Each forwards the produced <see cref="CryptoEvent"/> through its trailing
/// <c>CryptoEventSink? eventSink</c> parameter where the site exposes one, or to
/// <see cref="CryptographicKeyEvents.DefaultSink"/> (the global stream) at the private verify helpers that
/// do not.
/// </summary>
/// <remarks>
/// Every raw <see cref="ECDsa"/>/<see cref="RSA"/> key this class mints is an independent oracle: it
/// stands in for the chip's or terminal's own key material (ICAO Doc 9303 Active Authentication, BSI
/// TR-03110 Terminal Authentication CVC chains), producing the external wire artifacts whose handling
/// the sink-forwarding assertions observe — never fixture material the project's key providers could
/// substitute without collapsing the exercised delegate resolution onto the library's own signing seams.
/// </remarks>
[TestClass]
internal sealed class ApduCryptoEventSinkForwardingTests
{
    private static readonly byte[] ChipIdentifier = System.Text.Encoding.ASCII.GetBytes("L898902C<3");
    private static readonly byte[] ChipChallenge = Convert.FromHexString("0001020304050607");


    public required TestContext TestContext { get; set; }


    /// <summary>
    /// <see cref="ActiveAuthenticationCardResponder.SignChallengeAsync"/> forwards the
    /// <see cref="SignatureProducedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task ActiveAuthenticationCardResponderSignForwardsToExplicitSink()
    {
        using ECDsa chipKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] chipPrivateKey = chipKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] challenge = Convert.FromHexString("0102030405060708");

        var observed = new List<CryptoEvent>();

        using Signature signature = await ActiveAuthenticationCardResponder.SignChallengeAsync(
            chipPrivateKey, CryptoTags.P256ExchangePublicKey, challenge, BaseMemoryPool.Shared,
            eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsGreaterThan(0, signature.AsReadOnlySpan().Length);
        SignatureProducedEvent produced = Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
        Assert.AreEqual(CryptoAlgorithm.P256, produced.Algorithm);
    }


    /// <summary>
    /// <see cref="RsaActiveAuthenticationCardResponder.SignChallengeAsync"/> — the recoverable-family
    /// (ISO/IEC 9796-2) sign site that completes design item 4's tuple route — forwards the
    /// <see cref="SignatureProducedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task RsaActiveAuthenticationCardResponderSignForwardsToExplicitSink()
    {
        using RSA chipKey = RSA.Create(1024);
        byte[] chipPrivateKey = chipKey.ExportRSAPrivateKey();
        byte[] challenge = Convert.FromHexString("0102030405060708");

        var observed = new List<CryptoEvent>();

        using Signature signature = await RsaActiveAuthenticationCardResponder.SignChallengeAsync(
            chipPrivateKey, challenge, BaseMemoryPool.Shared, eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsGreaterThan(0, signature.AsReadOnlySpan().Length);
        SignatureProducedEvent produced = Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
        Assert.AreEqual(CryptoAlgorithm.RsaIso9796d2, produced.Algorithm);
    }


    /// <summary>
    /// <see cref="TerminalAuthenticationSignature.SignAsync(ReadOnlyMemory{byte}, Tag, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, MemoryPool{byte}, CryptoEventSink?, CancellationToken)"/>
    /// (the raw-bytes overload) forwards the <see cref="SignatureProducedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task TerminalAuthenticationSignatureSignAsyncForwardsToExplicitSink()
    {
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        var observed = new List<CryptoEvent>();

        using Signature signature = await TerminalAuthenticationSignature.SignAsync(
            terminalPrivateKey, CryptoTags.P256ExchangePublicKey, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsGreaterThan(0, signature.AsReadOnlySpan().Length);
        Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
    }


    /// <summary>
    /// <see cref="TerminalAuthenticationSignature.VerifyAsync(EncodedEcPoint, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, ReadOnlyMemory{byte}, MemoryPool{byte}, CryptoEventSink?, CancellationToken)"/>
    /// forwards the <see cref="VerificationCompletedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task TerminalAuthenticationSignatureVerifyAsyncForwardsToExplicitSink()
    {
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);
        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        using EncodedEcPoint terminalPublicKey = EncodedEcPoint.FromBytes(
            UncompressedPoint(terminalKey), CryptoTags.P256ExchangePublicKey, BaseMemoryPool.Shared);

        var observed = new List<CryptoEvent>();

        bool verified = await TerminalAuthenticationSignature.VerifyAsync(
            terminalPublicKey, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verified);
        VerificationCompletedEvent produced = Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
        Assert.AreEqual(VerificationOutcome.Valid, produced.Outcome);
    }


    /// <summary>
    /// <see cref="TerminalAuthenticationSignature.SignWithRsaAsync"/> forwards the
    /// <see cref="SignatureProducedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task TerminalAuthenticationSignatureSignWithRsaAsyncForwardsToExplicitSink()
    {
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        var observed = new List<CryptoEvent>();

        using Signature signature = await TerminalAuthenticationSignature.SignWithRsaAsync(
            terminalKey.ExportRSAPrivateKey(), CvcSignatureScheme.RsaPkcs1Sha256, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsGreaterThan(0, signature.AsReadOnlySpan().Length);
        Assert.ContainsSingle(observed.OfType<SignatureProducedEvent>());
    }


    /// <summary>
    /// <see cref="TerminalAuthenticationSignature.VerifyWithRsaAsync"/> forwards the
    /// <see cref="VerificationCompletedEvent"/> to an explicit sink.
    /// </summary>
    [TestMethod]
    public async Task TerminalAuthenticationSignatureVerifyWithRsaAsyncForwardsToExplicitSink()
    {
        using RSA terminalKey = RSA.Create(2048);
        using ECDsa terminalEphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalEphemeralPublicKey = UncompressedPoint(terminalEphemeralKey);

        byte[] message = SignedMessage(terminalEphemeralPublicKey);
        byte[] signature = terminalKey.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using RsaPublicKey terminalPublicKey = RsaPublicKey.FromBytes(terminalKey.ExportRSAPublicKey(), BaseMemoryPool.Shared);

        var observed = new List<CryptoEvent>();

        bool verified = await TerminalAuthenticationSignature.VerifyWithRsaAsync(
            terminalPublicKey, CvcSignatureScheme.RsaPkcs1Sha256, signature, ChipIdentifier, ChipChallenge, terminalEphemeralPublicKey,
            BaseMemoryPool.Shared, eventSink: observed.Add, cancellationToken: TestContext.CancellationToken);

        Assert.IsTrue(verified);
        VerificationCompletedEvent produced = Assert.ContainsSingle(observed.OfType<VerificationCompletedEvent>());
        Assert.AreEqual(VerificationOutcome.Valid, produced.Outcome);
    }


    /// <summary>
    /// <see cref="CardVerifiableCertificateChain.VerifyAsync"/> (elliptic-curve issuer) has no
    /// <see cref="CryptoEventSink"/> exposed at its public entry point (only the private per-link verify
    /// helper does), so the produced <see cref="VerificationCompletedEvent"/> reaches
    /// <see cref="CryptographicKeyEvents.DefaultSink"/> (the global stream) by default.
    /// </summary>
    [TestMethod]
    public async Task CardVerifiableCertificateChainVerifyEllipticCurveEmitsToGlobalStream()
    {
        var effective = new DateOnly(2024, 1, 1);
        var expiration = new DateOnly(2026, 1, 1);
        var withinValidity = new DateOnly(2025, 1, 1);

        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate cvca = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, "UTCVCA00002", "UTCVCA00002", CardVerifiableCertificateMinter.CvcaRole,
            includeDomainParameters: true, effective, expiration, inheritedCurve: null, BaseMemoryPool.Shared);
        Tag curve = cvca.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, "UTCVCA00002", "UTDVDE00002", CardVerifiableCertificateMinter.DocumentVerifierRole,
            includeDomainParameters: false, effective, expiration, curve, BaseMemoryPool.Shared);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, "UTDVDE00002", "UTISDE00002", CardVerifiableCertificateMinter.TerminalRole,
            includeDomainParameters: false, effective, expiration, curve, BaseMemoryPool.Shared);

        var observer = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyAsync(
                cvca, [documentVerifier, terminal], withinValidity, TestContext.CancellationToken);

            Assert.AreEqual(CvcChainVerificationResult.Valid, result);
        }

        Assert.Contains(
            (VerificationCompletedEvent e) => e.Outcome == VerificationOutcome.Valid,
            observer.Received.OfType<VerificationCompletedEvent>(),
            "CardVerifiableCertificateChain's elliptic-curve verify helper must publish to the global stream by default.");
    }


    /// <summary>The signed message <c>ID_IC || r_IC || Comp(PK_DH,IFD)</c>, mirroring <c>TerminalAuthenticationSignatureTests</c>.</summary>
    private static byte[] SignedMessage(byte[] terminalEphemeralPublicKey)
    {
        int fieldWidth = (terminalEphemeralPublicKey.Length - 1) / 2;
        byte[] message = new byte[ChipIdentifier.Length + ChipChallenge.Length + fieldWidth];
        ChipIdentifier.CopyTo(message, 0);
        ChipChallenge.CopyTo(message, ChipIdentifier.Length);
        Array.Copy(terminalEphemeralPublicKey, 1, message, ChipIdentifier.Length + ChipChallenge.Length, fieldWidth);

        return message;
    }


    /// <summary>The key's public point as an uncompressed SEC1 point (<c>0x04 || X || Y</c>).</summary>
    private static byte[] UncompressedPoint(ECDsa key)
    {
        ECParameters parameters = key.ExportParameters(includePrivateParameters: false);
        byte[] x = parameters.Q.X!;
        byte[] y = parameters.Q.Y!;

        byte[] point = new byte[1 + x.Length + y.Length];
        point[0] = 0x04;
        x.CopyTo(point, 1);
        y.CopyTo(point, 1 + x.Length);

        return point;
    }
}

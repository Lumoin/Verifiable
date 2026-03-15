using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Tests for SECDSA core algorithms: EC math, key generation (Algorithm 1),
/// signing (Algorithm 2), verification (Algorithms 14/15), and Schnorr
/// zero-knowledge proofs (Algorithms 19/20).
/// </summary>
/// <remarks>
/// <para>
/// These tests validate Phase 1 (software-only) of the SECDSA implementation.
/// Phase 2 will introduce TPM-backed keys for the NCH private key u.
/// </para>
/// <para>
/// Test coverage mirrors the paper's propositions:
/// </para>
/// <list type="bullet">
///   <item><description>Proposition 3.1: SECDSA signature is a valid ECDSA signature on combined key u*P.</description></item>
///   <item><description>Proposition 3.2: Security reduces to raw ECDSA (NCH key alone insufficient).</description></item>
///   <item><description>Proposition 3.4: Wrong PIN produces invalid signature.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class SecdsaCoreTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void BasePointMultiplyProducesValidPoint()
    {
        BigInteger scalar = EcMath.RandomScalar();
        EcPoint point = EcMath.BasePointMultiply(scalar);

        Assert.IsTrue(EcMath.IsValidPoint(point), "Scalar multiple of G must be on the curve.");
    }

    [TestMethod]
    public void ScalarMultiplicationIsCommutativeForPublicKeyDerivation()
    {
        BigInteger a = EcMath.RandomScalar();
        BigInteger b = EcMath.RandomScalar();

        EcPoint abG = EcMath.BasePointMultiply(a * b % EcMath.Q);
        EcPoint baG = EcMath.BasePointMultiply(b * a % EcMath.Q);

        Assert.AreEqual(abG, baG, "EC scalar multiplication must be commutative: (a*b)*G == (b*a)*G.");
    }

    [TestMethod]
    public void PublicKeyFromCombinedPrivateMatchesTwoStepDerivation()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();

        EcPoint uG = EcMath.BasePointMultiply(u);
        EcPoint pUG = EcMath.Multiply(uG, p);

        BigInteger combined = u * p % EcMath.Q;
        EcPoint directG = EcMath.BasePointMultiply(combined);

        Assert.AreEqual(pUG, directG, "P*(u*G) must equal (u*P)*G.");
    }

    [TestMethod]
    public void ModularInverseIsCorrect()
    {
        BigInteger scalar = EcMath.RandomScalar();
        BigInteger inverse = EcMath.ModInverse(scalar);

        BigInteger product = scalar * inverse % EcMath.Q;

        Assert.AreEqual(BigInteger.One, product, "scalar * scalar^(-1) mod q must equal 1.");
    }

    [TestMethod]
    public void UncompressedPointEncodingRoundTrips()
    {
        BigInteger scalar = EcMath.RandomScalar();
        EcPoint original = EcMath.BasePointMultiply(scalar);

        byte[] encoded = EcMath.EncodePointUncompressed(original);
        EcPoint decoded = EcMath.DecodePointUncompressed(encoded);

        Assert.AreEqual(original, decoded, "Uncompressed encoding must round-trip correctly.");
        Assert.HasCount(EllipticCurveConstants.P256.UncompressedPointByteCount, encoded,
            "Uncompressed P-256 point must be 65 bytes.");
        Assert.AreEqual(0x04, encoded[0], "Uncompressed point must start with 0x04.");
    }

    [TestMethod]
    public void CompressedPointEncodingProducesCorrectPrefix()
    {
        BigInteger scalar = EcMath.RandomScalar();
        EcPoint point = EcMath.BasePointMultiply(scalar);

        byte[] encoded = EcMath.EncodePointCompressed(point);

        Assert.HasCount(EllipticCurveConstants.P256.CompressedPointByteCount, encoded,
            "Compressed P-256 point must be 33 bytes.");
        Assert.IsTrue(encoded[0] == 0x02 || encoded[0] == 0x03,
            "Compressed point prefix must be 0x02 or 0x03.");
    }

    [TestMethod]
    public void RandomScalarsAreInValidRange()
    {
        for(int i = 0; i < 20; i++)
        {
            BigInteger scalar = EcMath.RandomScalar();
            Assert.IsGreaterThan(BigInteger.Zero, scalar, $"Random scalar {i} must be positive.");
            Assert.IsLessThan(EcMath.Q, scalar, $"Random scalar {i} must be less than q.");
        }
    }

    [TestMethod]
    public void HashToIntegerProducesNonNegativeInteger()
    {
        byte[] hash = SHA256.HashData("Test input."u8);
        BigInteger e = EcMath.HashToInteger(hash);

        Assert.IsGreaterThanOrEqualTo(BigInteger.Zero, e, "Hash integer must be non-negative.");
    }

    [TestMethod]
    public void GenerateKeyPairPublicKeyEqualsSecdsaFormula()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();

        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        EcPoint expected = EcMath.Multiply(EcMath.BasePointMultiply(u), p);
        Assert.AreEqual(expected, keyPair.PublicKey, "SECDSA public key must equal P*(u*G).");
    }

    [TestMethod]
    public void GenerateKeyPairPublicKeyIsOnCurve()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();

        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        Assert.IsTrue(EcMath.IsValidPoint(keyPair.PublicKey), "SECDSA public key must be on the curve.");
    }

    [TestMethod]
    public void SignAndVerifySucceedsWithCorrectKeys()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash = SHA256.HashData("Hello SECDSA."u8);
        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);

        Assert.IsTrue(
            SecdsaAlgorithms.Verify(hash, signature, keyPair.PublicKey),
            "Signature must verify with the corresponding SECDSA public key.");
    }

    [TestMethod]
    public void SecdsaSignatureVerifiesAsStandardEcdsaOnCombinedKey()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();

        BigInteger combinedPrivate = u * p % EcMath.Q;
        EcPoint combinedPublic = EcMath.BasePointMultiply(combinedPrivate);

        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);
        Assert.AreEqual(combinedPublic, keyPair.PublicKey,
            "SECDSA public key must equal (u*P)*G.");

        byte[] hash = SHA256.HashData("Proposition 3.1."u8);
        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);

        Assert.IsTrue(
            SecdsaAlgorithms.Verify(hash, signature, combinedPublic),
            "SECDSA signature must verify as standard ECDSA on combined public key (Proposition 3.1).");
    }

    [TestMethod]
    public void NchKeyAloneCannotProduceValidSignature()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash = SHA256.HashData("Proposition 3.2."u8);
        EcdsaSignature badSignature = SecdsaAlgorithms.Sign(hash, u, u);

        Assert.IsFalse(
            SecdsaAlgorithms.Verify(hash, badSignature, keyPair.PublicKey),
            "Signature produced without the correct PIN key must not verify (Proposition 3.2).");
    }

    [TestMethod]
    public void WrongPinProducesInvalidSignature()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger correctPin = EcMath.RandomScalar();
        BigInteger wrongPin = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, correctPin);

        byte[] hash = SHA256.HashData("Proposition 3.4."u8);
        EcdsaSignature badSignature = SecdsaAlgorithms.Sign(hash, u, wrongPin);

        Assert.IsFalse(
            SecdsaAlgorithms.Verify(hash, badSignature, keyPair.PublicKey),
            "Signature with wrong PIN must not verify (Proposition 3.4).");
    }

    [TestMethod]
    public void WrongMessageHashFailsVerification()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash1 = SHA256.HashData("Original message."u8);
        byte[] hash2 = SHA256.HashData("Tampered message."u8);

        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash1, u, p);

        Assert.IsFalse(
            SecdsaAlgorithms.Verify(hash2, signature, keyPair.PublicKey),
            "Signature must not verify against a different message hash.");
    }

    [TestMethod]
    public void MultipleSignaturesAllVerify()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        for(int i = 0; i < 10; i++)
        {
            byte[] hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"Message {i}."));
            EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);

            Assert.IsTrue(
                SecdsaAlgorithms.Verify(hash, signature, keyPair.PublicKey),
                $"Signature {i} must verify.");
        }
    }

    [TestMethod]
    public void FullFormatConversionPreservesS()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash = SHA256.HashData("Full format test."u8);
        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);
        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(signature, hash, keyPair.PublicKey);

        Assert.IsTrue(EcMath.IsValidPoint(fullSig.RPoint), "R point in full format must be on the curve.");
        Assert.AreEqual(signature.S, fullSig.S, "s value must be preserved in full format.");
    }

    [TestMethod]
    public void FullFormatVerificationSucceeds()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash = SHA256.HashData("Full format verification."u8);
        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);
        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(signature, hash, keyPair.PublicKey);

        Assert.IsTrue(
            SecdsaAlgorithms.VerifyFull(hash, fullSig, keyPair.PublicKey),
            "Full format signature must verify.");
    }

    [TestMethod]
    public void FullFormatRPointXCoordinateMatchesR()
    {
        BigInteger u = EcMath.RandomScalar();
        BigInteger p = EcMath.RandomScalar();
        SecdsaKeyPair keyPair = SecdsaAlgorithms.GenerateKeyPair(u, p);

        byte[] hash = SHA256.HashData("R point check."u8);
        EcdsaSignature signature = SecdsaAlgorithms.Sign(hash, u, p);
        FullEcdsaSignature fullSig = SecdsaAlgorithms.ToFullFormat(signature, hash, keyPair.PublicKey);

        BigInteger xCoord = fullSig.RPoint.X % EcMath.Q;
        Assert.AreEqual(signature.R, xCoord, "x-coordinate of R point mod q must equal r.");
    }

    [TestMethod]
    public void ZkpProofOfPossessionSucceeds()
    {
        BigInteger d = EcMath.RandomScalar();
        EcPoint dPoint = EcMath.BasePointMultiply(d);

        EcPoint[] generators = [EcMath.G];
        EcPoint[] publicKeys = [dPoint];

        SchnorrZkProof proof = SchnorrZkp.Generate(generators, publicKeys, d, ReadOnlySpan<byte>.Empty);
        bool isValid = SchnorrZkp.Verify(proof, generators, publicKeys, ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(isValid, "Proof of possession must verify.");
    }

    [TestMethod]
    public void ZkpDiscreteLogEqualityAcrossTwoGenerators()
    {
        BigInteger d = EcMath.RandomScalar();
        BigInteger h = EcMath.RandomScalar();
        EcPoint hPoint = EcMath.BasePointMultiply(h);

        EcPoint point0 = EcMath.BasePointMultiply(d);
        EcPoint point1 = EcMath.Multiply(hPoint, d);

        EcPoint[] generators = [EcMath.G, hPoint];
        EcPoint[] publicKeys = [point0, point1];

        SchnorrZkProof proof = SchnorrZkp.Generate(generators, publicKeys, d, ReadOnlySpan<byte>.Empty);
        bool isValid = SchnorrZkp.Verify(proof, generators, publicKeys, ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(isValid, "Discrete log equality proof across two generators must verify.");
    }

    [TestMethod]
    public void ZkpRejectsMismatchedDiscreteLogAcrossGenerators()
    {
        BigInteger d1 = EcMath.RandomScalar();
        BigInteger d2 = EcMath.RandomScalar();
        BigInteger h = EcMath.RandomScalar();
        EcPoint hPoint = EcMath.BasePointMultiply(h);

        EcPoint point0 = EcMath.BasePointMultiply(d1);
        EcPoint point1 = EcMath.Multiply(hPoint, d2);

        EcPoint[] generators = [EcMath.G, hPoint];
        EcPoint[] publicKeys = [point0, point1];

        SchnorrZkProof proofWithD1 = SchnorrZkp.Generate(generators, publicKeys, d1, ReadOnlySpan<byte>.Empty);
        SchnorrZkProof proofWithD2 = SchnorrZkp.Generate(generators, publicKeys, d2, ReadOnlySpan<byte>.Empty);

        Assert.IsFalse(
            SchnorrZkp.Verify(proofWithD1, generators, publicKeys, ReadOnlySpan<byte>.Empty),
            "Proof with d1 must fail when public keys use different discrete logs.");
        Assert.IsFalse(
            SchnorrZkp.Verify(proofWithD2, generators, publicKeys, ReadOnlySpan<byte>.Empty),
            "Proof with d2 must fail when public keys use different discrete logs.");
    }

    [TestMethod]
    public void ZkpForBlindingKeyRelationship()
    {
        BigInteger aU = EcMath.RandomScalar();
        BigInteger yScalar = EcMath.RandomScalar();
        EcPoint y = EcMath.BasePointMultiply(yScalar);

        EcPoint gPrime = EcMath.BasePointMultiply(aU);
        EcPoint yPrime = EcMath.Multiply(y, aU);

        EcPoint[] generators = [EcMath.G, y];
        EcPoint[] publicKeys = [gPrime, yPrime];

        SchnorrZkProof proof = SchnorrZkp.Generate(generators, publicKeys, aU, ReadOnlySpan<byte>.Empty);
        bool isValid = SchnorrZkp.Verify(proof, generators, publicKeys, ReadOnlySpan<byte>.Empty);

        Assert.IsTrue(isValid, "Blinding key relationship proof must verify.");
    }

    [TestMethod]
    public void ZkpChallengeBindingChangesProof()
    {
        BigInteger d = EcMath.RandomScalar();
        EcPoint dPoint = EcMath.BasePointMultiply(d);
        EcPoint[] generators = [EcMath.G];
        EcPoint[] publicKeys = [dPoint];

        byte[] binding1 = SHA256.HashData("Context A."u8);
        byte[] binding2 = SHA256.HashData("Context B."u8);

        SchnorrZkProof proof1 = SchnorrZkp.Generate(generators, publicKeys, d, binding1);
        SchnorrZkProof proof2 = SchnorrZkp.Generate(generators, publicKeys, d, binding2);

        Assert.AreNotEqual(proof1.R, proof2.R, "Different challenge bindings must produce different challenge hashes.");
        Assert.IsTrue(SchnorrZkp.Verify(proof1, generators, publicKeys, binding1), "Proof 1 must verify with binding 1.");
        Assert.IsFalse(SchnorrZkp.Verify(proof1, generators, publicKeys, binding2), "Proof 1 must not verify with binding 2.");
    }
}

using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for <see cref="CoseKey"/>'s content-based <see cref="IEquatable{T}"/> implementation: two
/// independently constructed instances over independently allocated buffers with identical COSE_Key
/// parameters must compare equal and report the same hash code, while any single differing parameter
/// must break equality.
/// </summary>
/// <remarks>
/// Every buffer under test is a freshly allocated array, never a shared reference, so a passing
/// positive test proves content equality rather than the reference/alias equality
/// <see cref="ReadOnlyMemory{T}"/>'s own default comparison would give two independent buffers.
/// </remarks>
[TestClass]
internal sealed class CoseKeyEqualityTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Two EC2 <see cref="CoseKey"/> instances built from independently allocated but byte-identical
    /// <c>x</c>/<c>y</c> buffers compare equal, satisfy both equality operators, and report the same
    /// hash code.
    /// </summary>
    [TestMethod]
    public void Ec2KeysWithEqualContentFromIndependentBuffersAreEqual()
    {
        byte[] xBufferA = [1, 2, 3, 4];
        byte[] xBufferB = [1, 2, 3, 4];
        byte[] yBufferA = [5, 6, 7, 8];
        byte[] yBufferB = [5, 6, 7, 8];
        Assert.AreNotSame(xBufferA, xBufferB);
        Assert.AreNotSame(yBufferA, yBufferB);

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: xBufferA, y: yBufferA);
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: xBufferB, y: yBufferB);

        Assert.IsTrue(keyA.Equals(keyB));
        Assert.IsTrue(keyA.Equals((object)keyB));
        Assert.IsTrue(keyA == keyB);
        Assert.IsFalse(keyA != keyB);
        Assert.AreEqual(keyA.GetHashCode(), keyB.GetHashCode());
    }


    /// <summary>A differing <c>kty</c> breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingKtyBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, x: x);
        CoseKey keyB = new(kty: CoseKeyTypes.Okp, x: x);

        Assert.IsFalse(keyA.Equals(keyB));
        Assert.IsFalse(keyA == keyB);
        Assert.IsTrue(keyA != keyB);
    }


    /// <summary>A differing <c>alg</c> breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingAlgBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];
        byte[] y = [5, 6, 7, 8];

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: x, y: y);
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es384, curve: CoseKeyCurves.P256, x: x, y: y);

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>A differing <c>crv</c> breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingCurveBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];
        byte[] y = [5, 6, 7, 8];

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256, x: x, y: y);
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P384, x: x, y: y);

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>A differing <c>x</c> content breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingXContentBreaksEquality()
    {
        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, x: new byte[] { 1, 2, 3, 4 });
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, x: new byte[] { 1, 2, 3, 5 });

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>A differing <c>y</c> content breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingYContentBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, x: x, y: new byte[] { 5, 6, 7, 8 });
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, x: x, y: new byte[] { 5, 6, 7, 9 });

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>
    /// A present <c>y</c> versus an absent <c>y</c> breaks equality — the null-handling half of the
    /// memory-member comparison, distinct from differing non-null content.
    /// </summary>
    [TestMethod]
    public void PresentVersusAbsentYBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];
        byte[] y = [5, 6, 7, 8];

        CoseKey keyWithY = new(kty: CoseKeyTypes.Ec2, x: x, y: y);
        CoseKey keyWithoutY = new(kty: CoseKeyTypes.Ec2, x: x);

        Assert.IsFalse(keyWithY.Equals(keyWithoutY));
        Assert.IsFalse(keyWithoutY.Equals(keyWithY));
    }


    /// <summary>A differing <c>encodedYCompressionSign</c> breaks equality even when every other parameter matches.</summary>
    [TestMethod]
    public void DifferingEncodedYCompressionSignBreaksEquality()
    {
        byte[] x = [1, 2, 3, 4];

        CoseKey keyA = new(kty: CoseKeyTypes.Ec2, x: x, encodedYCompressionSign: true);
        CoseKey keyB = new(kty: CoseKeyTypes.Ec2, x: x, encodedYCompressionSign: false);

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>
    /// Two RSA <see cref="CoseKey"/> instances built from independently allocated but byte-identical
    /// <c>n</c>/<c>e</c> buffers compare equal and report the same hash code.
    /// </summary>
    [TestMethod]
    public void RsaKeysWithEqualContentFromIndependentBuffersAreEqual()
    {
        byte[] modulusA = [0x80, 1, 2, 3];
        byte[] modulusB = [0x80, 1, 2, 3];
        byte[] exponentA = [0x01, 0x00, 0x01];
        byte[] exponentB = [0x01, 0x00, 0x01];
        Assert.AreNotSame(modulusA, modulusB);

        CoseKey keyA = new(kty: CoseKeyTypes.Rsa, n: modulusA, e: exponentA);
        CoseKey keyB = new(kty: CoseKeyTypes.Rsa, n: modulusB, e: exponentB);

        Assert.IsTrue(keyA.Equals(keyB));
        Assert.AreEqual(keyA.GetHashCode(), keyB.GetHashCode());
    }


    /// <summary>A differing <c>n</c> (modulus) content breaks equality even when <c>e</c> matches.</summary>
    [TestMethod]
    public void DifferingModulusBreaksEquality()
    {
        byte[] exponent = [0x01, 0x00, 0x01];

        CoseKey keyA = new(kty: CoseKeyTypes.Rsa, n: new byte[] { 0x80, 1, 2, 3 }, e: exponent);
        CoseKey keyB = new(kty: CoseKeyTypes.Rsa, n: new byte[] { 0x80, 1, 2, 4 }, e: exponent);

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>A differing <c>e</c> (public exponent) content breaks equality even when <c>n</c> matches.</summary>
    [TestMethod]
    public void DifferingExponentBreaksEquality()
    {
        byte[] modulus = [0x80, 1, 2, 3];

        CoseKey keyA = new(kty: CoseKeyTypes.Rsa, n: modulus, e: new byte[] { 0x01, 0x00, 0x01 });
        CoseKey keyB = new(kty: CoseKeyTypes.Rsa, n: modulus, e: new byte[] { 0x03 });

        Assert.IsFalse(keyA.Equals(keyB));
    }


    /// <summary>
    /// <see cref="CoseKey.Equals(CoseKey?)"/> reports <see langword="false"/> against
    /// <see langword="null"/>, the <c>==</c>/<c>!=</c> operators agree, and two <see langword="null"/>
    /// references compare equal — matching this codebase's carrier-equality convention.
    /// </summary>
    [TestMethod]
    public void NullHandlingMatchesCarrierConvention()
    {
        CoseKey key = new(kty: CoseKeyTypes.Ec2, x: new byte[] { 1, 2, 3, 4 });
        CoseKey? nullKeyA = null;
        CoseKey? nullKeyB = null;

        Assert.IsFalse(key.Equals(null));
        Assert.IsFalse(key.Equals((object?)null));
        Assert.IsFalse(key == nullKeyA);
        Assert.IsFalse(nullKeyA == key);
        Assert.IsTrue(key != nullKeyA);
        Assert.IsTrue(nullKeyA == nullKeyB);
    }


    /// <summary><see cref="CoseKey.Equals(object?)"/> reports <see langword="false"/> for a non-<see cref="CoseKey"/> object.</summary>
    [TestMethod]
    public void EqualsObjectReturnsFalseForUnrelatedType()
    {
        CoseKey key = new(kty: CoseKeyTypes.Ec2, x: new byte[] { 1, 2, 3, 4 });

        Assert.IsFalse(key.Equals("not a CoseKey"));
    }
}

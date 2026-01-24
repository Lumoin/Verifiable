using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TpmAlgIdExtensions"/>.
/// </summary>
[TestClass]
public class TpmAlgIdExtensionsTests
{
    [TestMethod]
    public void GetNameReturnsCorrectHashAlgorithmNames()
    {
        Assert.AreEqual("SHA1", TpmAlgIdConstants.TPM_ALG_SHA1.GetName());
        Assert.AreEqual("SHA256", TpmAlgIdConstants.TPM_ALG_SHA256.GetName());
        Assert.AreEqual("SHA384", TpmAlgIdConstants.TPM_ALG_SHA384.GetName());
        Assert.AreEqual("SHA512", TpmAlgIdConstants.TPM_ALG_SHA512.GetName());
        Assert.AreEqual("SM3_256", TpmAlgIdConstants.TPM_ALG_SM3_256.GetName());
        Assert.AreEqual("SHA3_256", TpmAlgIdConstants.TPM_ALG_SHA3_256.GetName());
        Assert.AreEqual("SHA3_384", TpmAlgIdConstants.TPM_ALG_SHA3_384.GetName());
        Assert.AreEqual("SHA3_512", TpmAlgIdConstants.TPM_ALG_SHA3_512.GetName());
    }

    [TestMethod]
    public void GetNameReturnsCorrectAsymmetricAlgorithmNames()
    {
        Assert.AreEqual("RSA", TpmAlgIdConstants.TPM_ALG_RSA.GetName());
        Assert.AreEqual("ECC", TpmAlgIdConstants.TPM_ALG_ECC.GetName());
        Assert.AreEqual("ECDSA", TpmAlgIdConstants.TPM_ALG_ECDSA.GetName());
        Assert.AreEqual("ECDH", TpmAlgIdConstants.TPM_ALG_ECDH.GetName());
    }

    [TestMethod]
    public void GetNameReturnsCorrectSymmetricAlgorithmNames()
    {
        Assert.AreEqual("AES", TpmAlgIdConstants.TPM_ALG_AES.GetName());
        Assert.AreEqual("CAMELLIA", TpmAlgIdConstants.TPM_ALG_CAMELLIA.GetName());
    }

    [TestMethod]
    public void GetNameReturnsCorrectModeNames()
    {
        Assert.AreEqual("CTR", TpmAlgIdConstants.TPM_ALG_CTR.GetName());
        Assert.AreEqual("CBC", TpmAlgIdConstants.TPM_ALG_CBC.GetName());
        Assert.AreEqual("CFB", TpmAlgIdConstants.TPM_ALG_CFB.GetName());
        Assert.AreEqual("ECB", TpmAlgIdConstants.TPM_ALG_ECB.GetName());
        Assert.AreEqual("GCM", TpmAlgIdConstants.TPM_ALG_GCM.GetName());
    }

    [TestMethod]
    public void GetNameReturnsHexForUnknownAlgorithm()
    {
        var unknown = (TpmAlgIdConstants)0x9999;

        Assert.AreEqual("ALG_0x9999", unknown.GetName());
    }

    [TestMethod]
    public void GetDigestSizeReturnsCorrectSizes()
    {
        Assert.AreEqual(20, TpmAlgIdConstants.TPM_ALG_SHA1.GetDigestSize());
        Assert.AreEqual(32, TpmAlgIdConstants.TPM_ALG_SHA256.GetDigestSize());
        Assert.AreEqual(48, TpmAlgIdConstants.TPM_ALG_SHA384.GetDigestSize());
        Assert.AreEqual(64, TpmAlgIdConstants.TPM_ALG_SHA512.GetDigestSize());
        Assert.AreEqual(32, TpmAlgIdConstants.TPM_ALG_SM3_256.GetDigestSize());
        Assert.AreEqual(32, TpmAlgIdConstants.TPM_ALG_SHA3_256.GetDigestSize());
        Assert.AreEqual(48, TpmAlgIdConstants.TPM_ALG_SHA3_384.GetDigestSize());
        Assert.AreEqual(64, TpmAlgIdConstants.TPM_ALG_SHA3_512.GetDigestSize());
    }

    [TestMethod]
    public void GetDigestSizeReturnsNullForNonHashAlgorithms()
    {
        Assert.IsNull(TpmAlgIdConstants.TPM_ALG_RSA.GetDigestSize());
        Assert.IsNull(TpmAlgIdConstants.TPM_ALG_ECC.GetDigestSize());
        Assert.IsNull(TpmAlgIdConstants.TPM_ALG_AES.GetDigestSize());
        Assert.IsNull(TpmAlgIdConstants.TPM_ALG_ECDSA.GetDigestSize());
        Assert.IsNull(TpmAlgIdConstants.TPM_ALG_NULL.GetDigestSize());
    }

    [TestMethod]
    public void IsHashAlgorithmReturnsTrueForHashAlgorithms()
    {
        Assert.IsTrue(TpmAlgIdConstants.TPM_ALG_SHA1.IsHashAlgorithm());
        Assert.IsTrue(TpmAlgIdConstants.TPM_ALG_SHA256.IsHashAlgorithm());
        Assert.IsTrue(TpmAlgIdConstants.TPM_ALG_SHA384.IsHashAlgorithm());
        Assert.IsTrue(TpmAlgIdConstants.TPM_ALG_SHA512.IsHashAlgorithm());
        Assert.IsTrue(TpmAlgIdConstants.TPM_ALG_SHA3_256.IsHashAlgorithm());
    }

    [TestMethod]
    public void IsHashAlgorithmReturnsFalseForNonHashAlgorithms()
    {
        Assert.IsFalse(TpmAlgIdConstants.TPM_ALG_RSA.IsHashAlgorithm());
        Assert.IsFalse(TpmAlgIdConstants.TPM_ALG_ECC.IsHashAlgorithm());
        Assert.IsFalse(TpmAlgIdConstants.TPM_ALG_AES.IsHashAlgorithm());
        Assert.IsFalse(TpmAlgIdConstants.TPM_ALG_ECDSA.IsHashAlgorithm());
        Assert.IsFalse(TpmAlgIdConstants.TPM_ALG_HMAC.IsHashAlgorithm());
    }

    [TestMethod]
    public void GetNameReturnsCorrectPostQuantumAlgorithmNames()
    {
        Assert.AreEqual("MLKEM", TpmAlgIdConstants.TPM_ALG_MLKEM.GetName());
        Assert.AreEqual("MLDSA", TpmAlgIdConstants.TPM_ALG_MLDSA.GetName());
        Assert.AreEqual("HASH_MLDSA", TpmAlgIdConstants.TPM_ALG_HASH_MLDSA.GetName());
    }
}
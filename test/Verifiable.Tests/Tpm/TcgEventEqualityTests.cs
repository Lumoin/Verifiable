using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Tpm.EventLog;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for <see cref="TcgEvent"/>, <see cref="TcgEventDigest"/>, and <see cref="TcgEventLog"/> equality.
/// </summary>
[TestClass]
public class TcgEventEqualityTests
{
    [TestMethod]
    public void TcgEventDigestEqualsWithSameValues()
    {
        byte[] digest = [0x01, 0x02, 0x03, 0x04];
        var digest1 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, digest);
        var digest2 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01, 0x02, 0x03, 0x04]);

        Assert.AreEqual(digest1, digest2);
        Assert.IsTrue(digest1 == digest2);
        Assert.IsFalse(digest1 != digest2);
        Assert.AreEqual(digest1.GetHashCode(), digest2.GetHashCode());
    }

    [TestMethod]
    public void TcgEventDigestNotEqualWithDifferentAlgorithm()
    {
        byte[] digest = [0x01, 0x02, 0x03, 0x04];
        var digest1 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, digest);
        var digest2 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA384, digest);

        Assert.AreNotEqual(digest1, digest2);
        Assert.IsFalse(digest1 == digest2);
        Assert.IsTrue(digest1 != digest2);
    }

    [TestMethod]
    public void TcgEventDigestNotEqualWithDifferentDigest()
    {
        var digest1 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01, 0x02, 0x03, 0x04]);
        var digest2 = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x05, 0x06, 0x07, 0x08]);

        Assert.AreNotEqual(digest1, digest2);
        Assert.IsFalse(digest1 == digest2);
        Assert.IsTrue(digest1 != digest2);
    }

    [TestMethod]
    public void TcgEventDigestNullComparison()
    {
        var digest = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01]);

        Assert.IsFalse(digest == null);
        Assert.IsTrue(digest != null);
        Assert.IsFalse(digest.Equals(null));
    }

    [TestMethod]
    public void TcgEventEqualsWithSameValues()
    {
        var digests1 = new[] { new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01, 0x02]) };
        var digests2 = new[] { new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01, 0x02]) };

        var event1 = new TcgEvent(0, 7, TcgEventType.EV_SEPARATOR, digests1, [0x00, 0x00, 0x00, 0x00]);
        var event2 = new TcgEvent(0, 7, TcgEventType.EV_SEPARATOR, digests2, [0x00, 0x00, 0x00, 0x00]);

        Assert.AreEqual(event1, event2);
        Assert.IsTrue(event1 == event2);
        Assert.IsFalse(event1 != event2);
        Assert.AreEqual(event1.GetHashCode(), event2.GetHashCode());
    }

    [TestMethod]
    public void TcgEventNotEqualWithDifferentPcrIndex()
    {
        var digests = new[] { new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01]) };

        var event1 = new TcgEvent(0, 0, TcgEventType.EV_POST_CODE, digests, []);
        var event2 = new TcgEvent(0, 7, TcgEventType.EV_POST_CODE, digests, []);

        Assert.AreNotEqual(event1, event2);
        Assert.IsFalse(event1 == event2);
    }

    [TestMethod]
    public void TcgEventNotEqualWithDifferentEventType()
    {
        var digests = new[] { new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01]) };

        var event1 = new TcgEvent(0, 0, TcgEventType.EV_POST_CODE, digests, []);
        var event2 = new TcgEvent(0, 0, TcgEventType.EV_SEPARATOR, digests, []);

        Assert.AreNotEqual(event1, event2);
    }

    [TestMethod]
    public void TcgEventNotEqualWithDifferentEventData()
    {
        var digests = new[] { new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0x01]) };

        var event1 = new TcgEvent(0, 0, TcgEventType.EV_POST_CODE, digests, [0x01, 0x02]);
        var event2 = new TcgEvent(0, 0, TcgEventType.EV_POST_CODE, digests, [0x03, 0x04]);

        Assert.AreNotEqual(event1, event2);
    }

    [TestMethod]
    public void TcgEventNullComparison()
    {
        var evt = new TcgEvent(0, 0, TcgEventType.EV_POST_CODE, [], []);

        Assert.IsFalse(evt == null);
        Assert.IsTrue(evt != null);
        Assert.IsFalse(evt.Equals(null));
    }

    [TestMethod]
    public void TcgEventDigestAlgorithmNameReturnsCorrectValue()
    {
        var sha256Digest = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, []);
        var sha384Digest = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA384, []);
        var sha1Digest = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA1, []);

        Assert.AreEqual("SHA256", sha256Digest.AlgorithmName);
        Assert.AreEqual("SHA384", sha384Digest.AlgorithmName);
        Assert.AreEqual("SHA1", sha1Digest.AlgorithmName);
    }

    [TestMethod]
    public void TcgEventDigestHexReturnsCorrectValue()
    {
        var digest = new TcgEventDigest(TpmAlgIdConstants.TPM_ALG_SHA256, [0xDE, 0xAD, 0xBE, 0xEF]);

        Assert.AreEqual("DEADBEEF", digest.DigestHex);
    }

    [TestMethod]
    public void TcgEventTypeNameReturnsCorrectValue()
    {
        var evt = new TcgEvent(0, 7, TcgEventType.EV_EFI_VARIABLE_AUTHORITY, [], []);

        Assert.AreEqual("EV_EFI_VARIABLE_AUTHORITY", evt.EventTypeName);
    }
}
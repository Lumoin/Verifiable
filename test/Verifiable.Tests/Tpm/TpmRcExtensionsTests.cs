using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;


[TestClass]
public class TpmRcExtensionsTests
{
    [TestMethod]
    public void IsFormatOneReturnsFalseForFormatZeroErrors()
    {
        Assert.IsFalse(TpmRcConstants.TPM_RC_SUCCESS.IsFormatOne());
        Assert.IsFalse(TpmRcConstants.TPM_RC_INITIALIZE.IsFormatOne());
        Assert.IsFalse(TpmRcConstants.TPM_RC_FAILURE.IsFormatOne());
        Assert.IsFalse(TpmRcConstants.TPM_RC_LOCKOUT.IsFormatOne());
    }


    [TestMethod]
    public void IsFormatOneReturnsTrueForFormatOneErrors()
    {
        Assert.IsTrue(TpmRcConstants.TPM_RC_VALUE.IsFormatOne());
        Assert.IsTrue(TpmRcConstants.TPM_RC_HASH.IsFormatOne());
        Assert.IsTrue(TpmRcConstants.TPM_RC_SIZE.IsFormatOne());
        Assert.IsTrue(TpmRcConstants.TPM_RC_SIGNATURE.IsFormatOne());
    }


    [TestMethod]
    public void IsWarningReturnsTrueForWarnings()
    {
        Assert.IsTrue(TpmRcConstants.TPM_RC_YIELDED.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_CANCELED.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_TESTING.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_RETRY.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_LOCKOUT.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_NV_RATE.IsWarning());
    }


    [TestMethod]
    public void IsWarningReturnsFalseForErrors()
    {
        Assert.IsFalse(TpmRcConstants.TPM_RC_SUCCESS.IsWarning());
        Assert.IsFalse(TpmRcConstants.TPM_RC_FAILURE.IsWarning());
        Assert.IsFalse(TpmRcConstants.TPM_RC_VALUE.IsWarning());
    }


    [TestMethod]
    public void IsVersion2ReturnsTrueForTpm2Codes()
    {
        Assert.IsTrue(TpmRcConstants.TPM_RC_INITIALIZE.IsVersion2());
        Assert.IsTrue(TpmRcConstants.TPM_RC_VALUE.IsVersion2());
        Assert.IsTrue(TpmRcConstants.TPM_RC_LOCKOUT.IsVersion2());
    }


    [TestMethod]
    public void IsParameterErrorReturnsTrueWhenPBitSet()
    {
        //TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 = 0x084 + 0x040 + 0x100 = 0x1C4.
        var parameterError = (TpmRcConstants)(0x084 + 0x040 + 0x100);
        Assert.IsTrue(parameterError.IsParameterError());
    }


    [TestMethod]
    public void IsParameterErrorReturnsFalseForHandleErrors()
    {
        //TPM_RC_VALUE + TPM_RC_1 (handle, no P bit) = 0x084 + 0x100 = 0x184.
        var handleError = (TpmRcConstants)(0x084 + 0x100);
        Assert.IsFalse(handleError.IsParameterError());
    }


    [TestMethod]
    public void IsHandleErrorReturnsTrueForHandleErrors()
    {
        //TPM_RC_VALUE + TPM_RC_1 (handle 1) = 0x084 + 0x100 = 0x184.
        var handleError = (TpmRcConstants)(0x084 + 0x100);
        Assert.IsTrue(handleError.IsHandleError());
    }


    [TestMethod]
    public void IsHandleErrorReturnsFalseForParameterErrors()
    {
        //TPM_RC_VALUE + TPM_RC_P + TPM_RC_1 = 0x084 + 0x040 + 0x100 = 0x1C4.
        var parameterError = (TpmRcConstants)(0x084 + 0x040 + 0x100);
        Assert.IsFalse(parameterError.IsHandleError());
    }


    [TestMethod]
    public void IsSessionErrorReturnsTrueForSessionErrors()
    {
        //TPM_RC_VALUE + TPM_RC_S + TPM_RC_1 (session 1) = 0x084 + 0x800 + 0x100 = 0x984.
        //But per spec, session uses N = 8-15, so N field has bit 11 set.
        //TPM_RC_VALUE (0x084) + N=8 in bits 11:8 = 0x084 + 0x800 = 0x884.
        var sessionError = (TpmRcConstants)(0x084 + 0x800);
        Assert.IsTrue(sessionError.IsSessionError());
    }


    [TestMethod]
    public void GetParameterNumberReturnsCorrectValue()
    {
        //TPM_RC_VALUE + TPM_RC_P + TPM_RC_2 = 0x084 + 0x040 + 0x200 = 0x2C4.
        var param2Error = (TpmRcConstants)(0x084 + 0x040 + 0x200);
        Assert.AreEqual(2, param2Error.GetParameterNumber());
    }


    [TestMethod]
    public void GetParameterNumberReturnsZeroForNonParameterErrors()
    {
        Assert.AreEqual(0, TpmRcConstants.TPM_RC_FAILURE.GetParameterNumber());
        Assert.AreEqual(0, TpmRcConstants.TPM_RC_LOCKOUT.GetParameterNumber());
    }


    [TestMethod]
    public void GetHandleNumberReturnsCorrectValue()
    {
        //TPM_RC_VALUE + TPM_RC_3 (handle 3) = 0x084 + 0x300 = 0x384.
        var handle3Error = (TpmRcConstants)(0x084 + 0x300);
        Assert.AreEqual(3, handle3Error.GetHandleNumber());
    }


    [TestMethod]
    public void GetSessionNumberReturnsCorrectValue()
    {
        //Session 2: N = 8 + 2 = 10 = 0xA, so N field = 0xA00.
        //TPM_RC_VALUE (0x084) + 0xA00 = 0xA84.
        var session2Error = (TpmRcConstants)(0x084 + 0xA00);
        Assert.AreEqual(2, session2Error.GetSessionNumber());
    }


    [TestMethod]
    public void GetBaseErrorStripsModifiers()
    {
        //TPM_RC_VALUE + TPM_RC_P + TPM_RC_2 = 0x084 + 0x040 + 0x200 = 0x2C4.
        var param2Error = (TpmRcConstants)(0x084 + 0x040 + 0x200);

        //Base error should be TPM_RC_VALUE (0x084) but GetBaseError keeps format bit and clears P.
        //Actually looking at the implementation: it returns value & 0x0BF which is 0x2C4 & 0x0BF = 0x084.
        TpmRcConstants baseError = param2Error.GetBaseError();
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, baseError);
    }


    [TestMethod]
    public void GetBaseErrorReturnsUnmodifiedForFormatZero()
    {
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, TpmRcConstants.TPM_RC_FAILURE.GetBaseError());
        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, TpmRcConstants.TPM_RC_LOCKOUT.GetBaseError());
    }


    [TestMethod]
    public void GetDescriptionReturnsSuccessForSuccessCode()
    {
        string description = TpmRcConstants.TPM_RC_SUCCESS.GetDescription();
        Assert.AreEqual("Success.", description);
    }


    [TestMethod]
    public void GetDescriptionReturnsDescriptiveTextForKnownErrors()
    {
        string description = TpmRcConstants.TPM_RC_FAILURE.GetDescription();
        Assert.Contains("TPM failure", description);
    }


    [TestMethod]
    public void GetDescriptionIncludesParameterContext()
    {
        //TPM_RC_VALUE + TPM_RC_P + TPM_RC_2 = 0x2C4.
        var param2Error = (TpmRcConstants)(0x084 + 0x040 + 0x200);
        string description = param2Error.GetDescription();

        Assert.Contains("parameter 2", description, $"Expected 'parameter 2' in: {description}");
    }


    [TestMethod]
    public void GetDescriptionIncludesHandleContext()
    {
        //TPM_RC_VALUE + TPM_RC_1 (handle 1) = 0x184.
        var handle1Error = (TpmRcConstants)(0x084 + 0x100);
        string description = handle1Error.GetDescription();

        Assert.Contains("handle 1", description, $"Expected 'handle 1' in: {description}");
    }


    [TestMethod]
    public void GetDescriptionIncludesSessionContext()
    {
        //Session 1: N = 8 + 1 = 9 = 0x9, so N field = 0x900.
        //TPM_RC_VALUE (0x084) + 0x900 = 0x984.
        var session1Error = (TpmRcConstants)(0x084 + 0x900);
        string description = session1Error.GetDescription();

        Assert.Contains("session 1", description, $"Expected 'session 1' in: {description}");
    }


    [TestMethod]
    public void GetDescriptionReturnsHexForUnknownCodes()
    {
        //Use a format-zero unknown code (bit 7 clear) so it doesn't get parsed as format-one.
        //0x17F: bit 8 set (version 2.0), error number 0x7F (not a defined error).
        var unknownCode = (TpmRcConstants)0x17F;
        string description = unknownCode.GetDescription();

        Assert.Contains("'0x0000017F'", description, "Expected hex code in description.");
    }


    [TestMethod]
    public void IsVendorSpecificReturnsFalseForStandardCodes()
    {
        Assert.IsFalse(TpmRcConstants.TPM_RC_FAILURE.IsVendorSpecific());
        Assert.IsFalse(TpmRcConstants.TPM_RC_VALUE.IsVendorSpecific());
    }


    [TestMethod]
    public void WarningCodesAreCorrectlyIdentified()
    {
        //All RC_WARN codes should be identified as warnings.
        Assert.IsTrue(TpmRcConstants.TPM_RC_CONTEXT_GAP.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_OBJECT_MEMORY.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_SESSION_MEMORY.IsWarning());
        Assert.IsTrue(TpmRcConstants.TPM_RC_MEMORY.IsWarning());
    }
}
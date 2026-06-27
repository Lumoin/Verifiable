using System;
using Verifiable.Apdu.Eac;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Pins the Terminal Authentication protocol object identifiers (BSI TR-03110-3 Tables 17 and 18) the
/// terminal sends in the MSE:Set AT cryptographic-mechanism reference (DO'80') and the chip checks against
/// the terminal certificate it imported. The value bytes must equal the <c>id-TA-*</c> object identifier the
/// matching CV-certificate public key embeds, so the chip's comparison holds.
/// </summary>
[TestClass]
internal sealed class TerminalAuthenticationObjectIdentifierTests
{
    [TestMethod]
    [DataRow(CvcSignatureScheme.EcdsaSha1, "04007F00070202020201")]
    [DataRow(CvcSignatureScheme.EcdsaSha224, "04007F00070202020202")]
    [DataRow(CvcSignatureScheme.EcdsaSha256, "04007F00070202020203")]
    [DataRow(CvcSignatureScheme.EcdsaSha384, "04007F00070202020204")]
    [DataRow(CvcSignatureScheme.EcdsaSha512, "04007F00070202020205")]
    [DataRow(CvcSignatureScheme.RsaPkcs1Sha1, "04007F00070202020101")]
    [DataRow(CvcSignatureScheme.RsaPkcs1Sha256, "04007F00070202020102")]
    [DataRow(CvcSignatureScheme.RsaPssSha1, "04007F00070202020103")]
    [DataRow(CvcSignatureScheme.RsaPssSha256, "04007F00070202020104")]
    [DataRow(CvcSignatureScheme.RsaPkcs1Sha512, "04007F00070202020105")]
    [DataRow(CvcSignatureScheme.RsaPssSha512, "04007F00070202020106")]
    public void MapsEachSchemeToItsTerminalAuthenticationObjectIdentifier(CvcSignatureScheme scheme, string expectedHex)
    {
        ReadOnlySpan<byte> value = TerminalAuthenticationObjectIdentifier.ValueBytes(scheme);

        Assert.AreEqual(expectedHex, Convert.ToHexString(value), $"The {scheme} object identifier must equal the id-TA-* value bytes the CV certificate embeds.");
    }
}

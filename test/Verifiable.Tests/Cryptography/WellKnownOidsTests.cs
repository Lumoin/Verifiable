using System;
using System.Numerics;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests the <see cref="WellKnownOids"/> dotted/DER converters (which use the framework DER codec) and
/// the <see cref="EllipticCurveUtilities"/> curve recognizers built on them. The hardcoded DER value
/// bytes are validated against the framework encoding of the matching dotted string, and each supported
/// curve is recognised from both its named-curve OID and its explicit field prime.
/// </summary>
[TestClass]
internal sealed class WellKnownOidsTests
{
    /// <summary>One supported curve: its dotted OID, DER value bytes, field prime, and curve-type flag.</summary>
    private sealed record Curve(string DottedOid, byte[] DerValue, byte[] Prime, EllipticCurveTypes Type);


    /// <summary>The supported elliptic curves, paired with the constants this suite cross-checks.</summary>
    private static Curve[] SupportedCurves() =>
    [
        new(WellKnownOids.EcP256, WellKnownOids.EcP256DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.P256.Prime), EllipticCurveTypes.P256),
        new(WellKnownOids.EcP384, WellKnownOids.EcP384DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.P384.Prime), EllipticCurveTypes.P384),
        new(WellKnownOids.EcP521, WellKnownOids.EcP521DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.P521.Prime), EllipticCurveTypes.P521),
        new(WellKnownOids.EcSecp256k1, WellKnownOids.EcSecp256k1DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.Secp256k1.Prime), EllipticCurveTypes.Secp256k1),
        new(WellKnownOids.EcBrainpoolP256r1, WellKnownOids.EcBrainpoolP256r1DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.BrainpoolP256r1.Prime), EllipticCurveTypes.BrainpoolP256r1),
        new(WellKnownOids.EcBrainpoolP320r1, WellKnownOids.EcBrainpoolP320r1DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.BrainpoolP320r1.Prime), EllipticCurveTypes.BrainpoolP320r1),
        new(WellKnownOids.EcBrainpoolP384r1, WellKnownOids.EcBrainpoolP384r1DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.BrainpoolP384r1.Prime), EllipticCurveTypes.BrainpoolP384r1),
        new(WellKnownOids.EcBrainpoolP512r1, WellKnownOids.EcBrainpoolP512r1DerValue.ToArray(), PrimeBytes(EllipticCurveConstants.BrainpoolP512r1.Prime), EllipticCurveTypes.BrainpoolP512r1)
    ];


    [TestMethod]
    public void OidConvertersAgreeWithTheHardcodedDerValues()
    {
        foreach(Curve curve in SupportedCurves())
        {
            Assert.AreEqual(Convert.ToHexString(curve.DerValue), Convert.ToHexString(WellKnownOids.OidToDerValue(curve.DottedOid)),
                $"Encoding {curve.DottedOid} must reproduce its hardcoded DER value bytes.");
            Assert.AreEqual(curve.DottedOid, WellKnownOids.OidFromDerValue(curve.DerValue),
                $"Decoding the DER value bytes must reproduce {curve.DottedOid}.");
        }

        //The id-ecPublicKey key-type OID round-trips too (it is not a curve, so it has no curve type).
        Assert.AreEqual(Convert.ToHexString(WellKnownOids.EcPublicKeyDerValue.ToArray()), Convert.ToHexString(WellKnownOids.OidToDerValue(WellKnownOids.EcPublicKey)),
            "Encoding id-ecPublicKey must reproduce its hardcoded DER value bytes.");
        Assert.AreEqual(WellKnownOids.EcPublicKey, WellKnownOids.OidFromDerValue(WellKnownOids.EcPublicKeyDerValue),
            "Decoding id-ecPublicKey must reproduce its dotted string.");
    }


    [TestMethod]
    public void CurveTypeFromCurveOidRecognisesEverySupportedCurve()
    {
        foreach(Curve curve in SupportedCurves())
        {
            Assert.AreEqual(curve.Type, EllipticCurveUtilities.CurveTypeFromCurveOid(curve.DerValue),
                $"The named-curve OID of {curve.DottedOid} must resolve to {curve.Type}.");
        }

        //A well-formed but non-curve OID (Ed25519) is not a supported curve.
        Assert.AreEqual(EllipticCurveTypes.None, EllipticCurveUtilities.CurveTypeFromCurveOid(WellKnownOids.OidToDerValue(WellKnownOids.Ed25519)),
            "A non-curve OID must resolve to None.");
    }


    [TestMethod]
    public void CurveTypeFromPrimeRecognisesEverySupportedCurve()
    {
        foreach(Curve curve in SupportedCurves())
        {
            Assert.AreEqual(curve.Type, EllipticCurveUtilities.CurveTypeFromPrime(curve.Prime),
                $"The field prime of {curve.DottedOid} must resolve to {curve.Type}.");
        }

        Assert.AreEqual(EllipticCurveTypes.None, EllipticCurveUtilities.CurveTypeFromPrime([0x02]),
            "An unknown prime must resolve to None.");
    }


    /// <summary>The unsigned big-endian magnitude bytes of a curve prime, as a SubjectPublicKeyInfo would carry them.</summary>
    private static byte[] PrimeBytes(BigInteger prime) => prime.ToByteArray(isUnsigned: true, isBigEndian: true);
}

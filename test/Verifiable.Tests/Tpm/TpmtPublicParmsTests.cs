using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The Spec-layer wire behaviour of <c>TPMT_PUBLIC_PARMS</c> (TPM 2.0 Library Part 2, clause 12.2.3.10, Table
/// 234) and of <c>TPMS_SYMCIPHER_PARMS</c> (clause 11.1.9, Table 165), the union arm <c>TPMU_PUBLIC_PARMS</c>
/// gained so a caller can name a symmetric block cipher object on the wire: a write-then-parse round trip for
/// every selector Table 225 admits, the serialized width each selector accounts for, value equality, and the
/// debugger text each structure presents.
/// </summary>
/// <remarks>
/// These are pure structure tests — no simulator, no device, no session. They pin the shape a
/// <c>TPM2_TestParms()</c> caller frames and the shape a TPM unmarshals, independently of whether any
/// particular TPM implements the object type named.
/// </remarks>
[TestClass]
internal sealed class TpmtPublicParmsTests
{
    /// <summary>
    /// "This Table 234 structure is used in TPM2_TestParms() to validate that a set of algorithm parameters is
    /// supported by the TPM" — <c>type</c> is "the algorithm to be tested" and <c>[type]parameters</c> is "the
    /// algorithm details", so a structure written out and read back reproduces both fields for every selector
    /// Table 225 admits.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.2, Table 225</see>.
    /// </summary>
    /// <param name="type">The <c>TPMI_ALG_PUBLIC</c> selector under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_KEYEDHASH)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_ECC)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SYMCIPHER)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLKEM)]
    public void PublicParmsRoundTripThroughTheWireForEverySelectorTable225Admits(TpmAlgIdConstants type)
    {
        TpmtPublicParms original = TpmtPublicParms.Create(type, CreateParametersFor(type));

        byte[] octets = Serialize(original);
        var reader = new TpmReader(octets);
        TpmtPublicParms parsed = TpmtPublicParms.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining, $"Parsing '{type}' must consume exactly the octets WriteTo produced.");
        Assert.AreEqual(type, parsed.Type, "The parsed selector must be the one written.");
        Assert.AreEqual(original.Parameters, parsed.Parameters, $"The parsed union arm for '{type}' must equal the one written.");
        Assert.AreEqual(original, parsed, $"A TPMT_PUBLIC_PARMS for '{type}' must survive a write-then-parse round trip unchanged.");
    }

    /// <summary>
    /// Table 234 has exactly two fields, and only the first has a fixed width: the <c>TPMI_ALG_PUBLIC</c>
    /// selector is a <c>TPM_ALG_ID</c>, two octets, and the rest is whatever the selected
    /// <c>TPMU_PUBLIC_PARMS</c> arm occupies — so the declared size is the selector plus the arm, and it is
    /// exactly what <c>WriteTo</c> fills.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.3.9, Table 233</see>.
    /// </summary>
    /// <param name="type">The <c>TPMI_ALG_PUBLIC</c> selector under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_KEYEDHASH)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_ECC)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SYMCIPHER)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLKEM)]
    public void PublicParmsSerializedSizeIsTheSelectorPlusTheSelectedUnionArm(TpmAlgIdConstants type)
    {
        TpmuPublicParms parameters = CreateParametersFor(type);
        TpmtPublicParms parms = TpmtPublicParms.Create(type, parameters);

        Assert.AreEqual(sizeof(ushort) + parameters.SerializedSize, parms.SerializedSize,
            $"The declared width for '{type}' must be the two-octet selector plus the selected union arm.");

        byte[] octets = new byte[parms.SerializedSize];
        var writer = new TpmWriter(octets);
        parms.WriteTo(ref writer);

        Assert.AreEqual(parms.SerializedSize, writer.Written, $"WriteTo must fill exactly the declared width for '{type}'.");
    }

    /// <summary>
    /// Table 234's two fields are the whole structure, so two structures carrying the same <c>type</c> and the
    /// same <c>[type]parameters</c> are the same value and hash alike.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    [TestMethod]
    public void PublicParmsWithTheSameTypeAndParametersAreEqual()
    {
        TpmtPublicParms first = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA, CreateParametersFor(TpmAlgIdConstants.TPM_ALG_RSA));
        TpmtPublicParms second = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA, CreateParametersFor(TpmAlgIdConstants.TPM_ALG_RSA));

        Assert.AreEqual(first, second, "Two TPMT_PUBLIC_PARMS with the same type and parameters must be equal.");
        Assert.IsTrue(first == second, "The equality operator must agree with Equals.");
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode(), "Equal TPMT_PUBLIC_PARMS must hash alike.");
    }

    /// <summary>
    /// <c>type</c> is "the algorithm to be tested" and it selects the union arm, so two structures differing in
    /// the selector are different values even when both carry a well-formed arm.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    [TestMethod]
    public void PublicParmsDifferingInTheSelectorAreNotEqual()
    {
        TpmtPublicParms rsa = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA, CreateParametersFor(TpmAlgIdConstants.TPM_ALG_RSA));
        TpmtPublicParms ecc = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC, CreateParametersFor(TpmAlgIdConstants.TPM_ALG_ECC));

        Assert.AreNotEqual(rsa, ecc, "An RSA and an ECC TPMT_PUBLIC_PARMS must not be equal.");
        Assert.IsTrue(rsa != ecc, "The inequality operator must agree with Equals.");
    }

    /// <summary>
    /// <c>[type]parameters</c> is "the algorithm details", so two structures sharing a selector but differing in
    /// one detail — here the RSA modulus width — are different values.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.3.4, Table 228</see>.
    /// </summary>
    [TestMethod]
    public void PublicParmsDifferingInOneParameterFieldAreNotEqual()
    {
        TpmtPublicParms narrow = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));
        TpmtPublicParms wide = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(4096, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        Assert.AreNotEqual(narrow, wide, "TPMT_PUBLIC_PARMS differing only in the RSA modulus width must not be equal.");
    }

    /// <summary>
    /// "This Table 165 structure contains the parameters for a symmetric block cipher object" — its single field
    /// <c>sym</c> is a <c>TPMT_SYM_DEF_OBJECT</c>, so the structure written out and read back reproduces the
    /// algorithm, the key size and the mode.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.9, Table 165; clause 11.1.7, Table 163</see>.
    /// </summary>
    [TestMethod]
    public void SymcipherParmsRoundTripTheirSymmetricDefinitionThroughTheWire()
    {
        TpmsSymcipherParms original = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(192, TpmAlgIdConstants.TPM_ALG_CFB));

        byte[] octets = new byte[original.SerializedSize];
        var writer = new TpmWriter(octets);
        original.WriteTo(ref writer);

        var reader = new TpmReader(octets);
        TpmsSymcipherParms parsed = TpmsSymcipherParms.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining, "Parsing must consume exactly the octets WriteTo produced.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, parsed.Sym.Algorithm, "The parsed symmetric algorithm must be the one written.");
        Assert.AreEqual((ushort)192, parsed.Sym.KeyBits, "The parsed key size must be the one written.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_CFB, parsed.Sym.Mode, "The parsed cipher mode must be the one written.");
        Assert.AreEqual(original, parsed, "A TPMS_SYMCIPHER_PARMS must survive a write-then-parse round trip unchanged.");
    }

    /// <summary>
    /// Table 165 defines exactly one field, so the structure occupies precisely what its
    /// <c>TPMT_SYM_DEF_OBJECT</c> occupies — six octets for a keyed algorithm (algorithm, keyBits, mode) and two
    /// for the <c>TPM_ALG_NULL</c> form, whose union arms are empty.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.9, Table 165; clause 11.1.7, Table 163</see>.
    /// </summary>
    [TestMethod]
    public void SymcipherParmsSerializedSizeIsTheirSymmetricDefinitionAlone()
    {
        TpmsSymcipherParms keyed = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB));
        TpmsSymcipherParms none = TpmsSymcipherParms.Create(TpmtSymDefObject.Null);

        Assert.AreEqual(6, keyed.SerializedSize, "An AES-CFB TPMS_SYMCIPHER_PARMS is algorithm, keyBits and mode — six octets.");
        Assert.AreEqual(2, none.SerializedSize, "A TPM_ALG_NULL TPMS_SYMCIPHER_PARMS is the algorithm selector alone — two octets.");
    }

    /// <summary>
    /// Table 165's single field is the whole structure, so two structures carrying the same
    /// <c>TPMT_SYM_DEF_OBJECT</c> are the same value, and differing in any of its three fields makes them
    /// different.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.9, Table 165</see>.
    /// </summary>
    [TestMethod]
    public void SymcipherParmsAreEqualExactlyWhenTheirSymmetricDefinitionsAre()
    {
        TpmsSymcipherParms first = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB));
        TpmsSymcipherParms same = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB));
        TpmsSymcipherParms wider = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(256, TpmAlgIdConstants.TPM_ALG_CFB));

        Assert.AreEqual(first, same, "Two TPMS_SYMCIPHER_PARMS over the same symmetric definition must be equal.");
        Assert.AreEqual(first.GetHashCode(), same.GetHashCode(), "Equal TPMS_SYMCIPHER_PARMS must hash alike.");
        Assert.AreNotEqual(first, wider, "TPMS_SYMCIPHER_PARMS differing in key size must not be equal.");
    }

    /// <summary>
    /// Table 233's <c>symDetail</c> member is selected by <c>TPM_ALG_SYMCIPHER</c>: the factory stamps that
    /// selector and fills the symmetric arm alone, leaving every other arm unoccupied, so a caller can build the
    /// symmetric-cipher combination a TPM may be asked about.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.9, Table 233; clause 11.1.9, Table 165</see>.
    /// </summary>
    [TestMethod]
    public void PublicParmsUnionSymCipherFactorySelectsTheSymmetricArmAlone()
    {
        TpmsSymcipherParms symParms = TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(256, TpmAlgIdConstants.TPM_ALG_CFB));

        TpmuPublicParms union = TpmuPublicParms.SymCipher(symParms);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SYMCIPHER, union.Type, "The factory must stamp the TPM_ALG_SYMCIPHER selector.");
        Assert.AreEqual(symParms, union.SymDetail, "The symmetric arm must carry the parameters supplied.");
        Assert.IsNull(union.RsaDetail, "The RSA arm must stay unoccupied.");
        Assert.IsNull(union.EccDetail, "The ECC arm must stay unoccupied.");
        Assert.IsNull(union.KeyedHashDetail, "The keyed-hash arm must stay unoccupied.");
        Assert.IsNull(union.MlDsaDetail, "The ML-DSA arm must stay unoccupied.");
        Assert.IsNull(union.HashMlDsaDetail, "The pre-hash ML-DSA arm must stay unoccupied.");
        Assert.IsNull(union.MlKemDetail, "The ML-KEM arm must stay unoccupied.");
    }

    /// <summary>
    /// The union's own parser dispatches on the selector, so the <c>TPM_ALG_SYMCIPHER</c> arm written out and
    /// read back under its own selector reproduces the symmetric parameters and compares equal, while a union
    /// differing in that arm compares unequal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.9, Table 233; clause 11.1.9, Table 165</see>.
    /// </summary>
    [TestMethod]
    public void PublicParmsUnionSymCipherArmRoundTripsAndComparesByValue()
    {
        TpmuPublicParms original = TpmuPublicParms.SymCipher(
            TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)));
        TpmuPublicParms other = TpmuPublicParms.SymCipher(
            TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(192, TpmAlgIdConstants.TPM_ALG_CFB)));

        byte[] octets = new byte[original.SerializedSize];
        var writer = new TpmWriter(octets);
        original.WriteTo(ref writer);

        var reader = new TpmReader(octets);
        TpmuPublicParms parsed = TpmuPublicParms.Parse(TpmAlgIdConstants.TPM_ALG_SYMCIPHER, ref reader);

        Assert.AreEqual(0, reader.Remaining, "Parsing the symmetric arm must consume exactly the octets WriteTo produced.");
        Assert.AreEqual(original, parsed, "The parsed symmetric arm must equal the one written.");
        Assert.AreEqual(original.GetHashCode(), parsed.GetHashCode(), "Equal unions must hash alike.");
        Assert.IsTrue(original != other, "Unions whose symmetric arms differ must compare unequal.");
    }

    /// <summary>
    /// Builds the union arm Table 233 pairs with <paramref name="type"/>, using a combination that is well-formed
    /// on the wire for that selector — the input shape a caller frames when asking whether a TPM supports it.
    /// </summary>
    /// <param name="type">The <c>TPMI_ALG_PUBLIC</c> selector to build an arm for.</param>
    /// <returns>The union carrying that selector's arm.</returns>
    private static TpmuPublicParms CreateParametersFor(TpmAlgIdConstants type) => type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => TpmuPublicParms.Rsa(
            TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))),
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => TpmuPublicParms.KeyedHash(
            TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256)),
        TpmAlgIdConstants.TPM_ALG_ECC => TpmuPublicParms.Ecc(
            TpmsEccParms.ForSigning(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))),
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER => TpmuPublicParms.SymCipher(
            TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB))),
        TpmAlgIdConstants.TPM_ALG_MLDSA => TpmuPublicParms.MlDsa(TpmsMlDsaParms.MlDsa65()),
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => TpmuPublicParms.HashMlDsa(TpmsHashMlDsaParms.HashMlDsa65Sha384()),
        _ => TpmuPublicParms.MlKem(TpmsMlKemParms.Create(TpmtSymDefObject.Null, TpmMlKemParameterSet.TPM_MLKEM_768))
    };

    /// <summary>
    /// Writes <paramref name="parms"/> into a buffer sized by its own declared width and returns the octets.
    /// </summary>
    /// <param name="parms">The structure to serialize.</param>
    /// <returns>The wire octets.</returns>
    private static byte[] Serialize(TpmtPublicParms parms)
    {
        byte[] octets = new byte[parms.SerializedSize];
        var writer = new TpmWriter(octets);
        parms.WriteTo(ref writer);

        return octets;
    }
}

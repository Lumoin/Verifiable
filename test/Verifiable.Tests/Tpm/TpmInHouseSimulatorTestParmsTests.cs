using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_TestParms()</c> against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> with the real <see cref="TestParmsInput"/> and response codec), plus a
/// hand-framed wire path for the combinations the host union cannot express.
/// </summary>
/// <remarks>
/// <para>
/// "This command is used to check to see if specific combinations of algorithm parameters are supported." "The
/// TPM will unmarshal the provided TPMT_PUBLIC_PARMS. If the parameters unmarshal correctly, then the TPM will
/// return TPM_RC_SUCCESS, indicating that the parameters are valid for the TPM. The TPM will return the
/// appropriate unmarshaling error if a parameter is not valid." (TPM 2.0 Library Part 3, clause 30.3.1) — so
/// the command IS its unmarshal, and every case below is either a combination this model implements (success,
/// with no state change beyond the command's own clock quantum) or one field this model does not, answered with
/// the response code that field's own interface-type table names.
/// </para>
/// <para>
/// Every refusal names <c>parameters</c>, TPM2_TestParms()'s sole and first parameter (Table 240), so each is
/// asserted parameter-encoded at parameter 1 (TPM 2.0 Library Part 2, clause 6.6.2, Table 15).
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorTestParmsTests
{
    /// <summary>The session hash algorithm the order-of-checks case starts its companion session under.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "TPM2_TestParms() is used to determine if a TPM supports a particular combination of algorithm
    /// parameters" — every RSA modulus width this model implements, crossed with every RSA scheme it implements
    /// and every hash algorithm its schemes admit, unmarshals and answers <c>TPM_RC_SUCCESS</c>. Table 189 lists
    /// four schemes: RSASSA and RSAPSS are the signing schemes, OAEP and RSAES the decryption schemes — OAEP is
    /// also the labeled transport the salted-session path uses. Each carries a <c>hashAlg</c> judged against the
    /// implemented hash set (Table 77), except RSAES: Table 190's <c>rsaes</c> arm is <c>TPMS_EMPTY</c> and
    /// carries none.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.1, clause 30.3; Part 2, clause 11.2.4.1, Table 189; clause 11.2.4.2, Table 190; clause 11.2.4.7, Table 195; clause 9.31, Table 77</see>.
    /// </summary>
    /// <param name="keyBits">The RSA modulus width under test.</param>
    /// <param name="scheme">The RSA scheme under test.</param>
    /// <param name="hashAlg">The scheme's hash algorithm under test.</param>
    [TestMethod]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)2048, TpmAlgIdConstants.TPM_ALG_RSAES, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSASSA, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSAPSS, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA1)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA256)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA384)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_OAEP, TpmAlgIdConstants.TPM_ALG_SHA512)]
    [DataRow((ushort)4096, TpmAlgIdConstants.TPM_ALG_RSAES, TpmAlgIdConstants.TPM_ALG_NULL)]
    public async Task TestParmsAcceptsEveryImplementedRsaSchemeAndHashCombination(ushort keyBits, TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(keyBits, RsaSchemeOf(scheme, hashAlg))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 189 carries the leading <c>+</c> on <c>TPM_ALG_NULL</c>, so a scheme-less RSA key — the
    /// unrestricted shape a caller chooses the scheme for per command — unmarshals with no <c>hashAlg</c> on the
    /// wire at all and answers <c>TPM_RC_SUCCESS</c> at both implemented widths.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.1, Table 189; clause 12.2.3.4, Table 228; Part 3, clause 30.3</see>.
    /// </summary>
    /// <param name="keyBits">The RSA modulus width under test.</param>
    [TestMethod]
    [DataRow((ushort)2048)]
    [DataRow((ushort)4096)]
    public async Task TestParmsAcceptsAnRsaKeyWhoseSchemeIsNull(ushort keyBits)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(keyBits, TpmtRsaScheme.Null)));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// The storage-parent shape of Table 228: a non-NULL <c>symmetric</c> whose algorithm, key size and mode are
    /// each judged in Part 4's field order. AES is the implemented block cipher, CFB the mode a parent object
    /// may carry, and Table 158's <c>TPMI_AES_KEY_BITS</c> row admits {128, 192, 256} — all three unmarshal at
    /// both implemented RSA widths.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.2, Table 158; clause 9.34, Table 80; clause 9.35, Table 81; clause 12.2.3.4, Table 228</see>.
    /// </summary>
    /// <param name="keyBits">The RSA modulus width under test.</param>
    /// <param name="symmetricKeyBits">The AES key size under test.</param>
    [TestMethod]
    [DataRow((ushort)2048, (ushort)128)]
    [DataRow((ushort)2048, (ushort)192)]
    [DataRow((ushort)2048, (ushort)256)]
    [DataRow((ushort)4096, (ushort)128)]
    [DataRow((ushort)4096, (ushort)192)]
    [DataRow((ushort)4096, (ushort)256)]
    public async Task TestParmsAcceptsTheStorageParentSymmetricKeySizesTable158Admits(ushort keyBits, ushort symmetricKeyBits)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForStorage(keyBits, TpmtSymDefObject.Aes(symmetricKeyBits, TpmAlgIdConstants.TPM_ALG_CFB))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 229's four fields for an ECC key: every curve this model implements, crossed with the signing
    /// scheme (ECDSA), the key-exchange scheme (ECDH) and the NULL scheme Table 200's leading <c>+</c> admits,
    /// crossed with a NULL <c>kdf</c> and with the HKDF the key-encapsulation shape carries — each combination
    /// unmarshals and answers <c>TPM_RC_SUCCESS</c>. <c>TestParms</c> carries no <c>TPMA_OBJECT</c>, so the
    /// attribute-conditioned rules an object's creation applies to the same fields play no part here.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.5, Table 229; clause 11.2.5.4, Table 200; clause 11.2.5.5, Table 201; clause 9.36, Table 82</see>.
    /// </summary>
    /// <param name="curve">The curve under test.</param>
    /// <param name="scheme">The ECC scheme under test.</param>
    /// <param name="kdf">The key-derivation function under test.</param>
    [TestMethod]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P384, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_ECDH, TpmAlgIdConstants.TPM_ALG_HKDF)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NIST_P521, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_HKDF)]
    public async Task TestParmsAcceptsEveryImplementedEccCurveSchemeAndKdfCombination(
        TpmEccCurveConstants curve, TpmAlgIdConstants scheme, TpmAlgIdConstants kdf)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(new TpmsEccParms
            {
                Symmetric = TpmtSymDefObject.Null,
                Scheme = EccSchemeOf(scheme, TpmAlgIdConstants.TPM_ALG_SHA256),
                CurveId = curve,
                Kdf = KdfSchemeOf(kdf, TpmAlgIdConstants.TPM_ALG_SHA256)
            }));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 175's registry is HMAC — "the 'signing' scheme" — XOR — "the 'obfuscation' scheme" — and the
    /// <c>TPM_ALG_NULL</c> its leading <c>+</c> admits, which is the sealed data object with no details at all.
    /// The XOR arm carries a <c>kdf</c> that Table 177 marks <c>TPMI_ALG_KDF+</c>, so both an implemented KDF and
    /// the NULL are accepted.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.19, Table 175; clause 11.1.21, Table 177; clause 12.2.3.3, Table 227</see>.
    /// </summary>
    /// <param name="scheme">The keyed-hash scheme under test.</param>
    /// <param name="hashAlg">The scheme's hash algorithm (ignored for the NULL scheme).</param>
    /// <param name="kdf">The XOR scheme's key-derivation function (ignored for the other schemes).</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_XOR, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_XOR, TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_NULL)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL)]
    public async Task TestParmsAcceptsEveryKeyedHashSchemeTable175Admits(TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg, TpmAlgIdConstants kdf)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH, TpmuPublicParms.KeyedHash(KeyedHashParmsOf(scheme, hashAlg, kdf)));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 225 lists seven object types and carries <c>#TPM_RC_TYPE</c> — "response code when a public type is
    /// not supported" — and Table 2 names the same code for "The type parameter of a TPMT_PUBLIC or
    /// TPMT_SENSITIVE has a value that is not supported by the TPM". This model creates RSA, ECC and KEYEDHASH
    /// objects only, so the four registered types it does not implement are each refused with
    /// <c>TPM_RC_TYPE</c> even though their parameters are well-formed on the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.2, Table 225; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    /// <param name="type">The registered but unimplemented object type under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SYMCIPHER)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLKEM)]
    public async Task TestParmsRefusesAnObjectTypeThisTpmDoesNotImplementWithType(TpmAlgIdConstants type)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(type, UnimplementedParametersFor(type));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_TYPE).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPMI_ALG_PUBLIC</c> selector outside Table 225's own seven-member registry is as unsupported as a
    /// registered type the TPM does not implement, and answers the same <c>#TPM_RC_TYPE</c>. No host structure
    /// can express such a selector, so the frame is laid out by hand: the two selector octets alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.2, Table 225; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesASelectorOutsideTable225WithType()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        //A TPM_ALG_ID that names no object type at all.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(simulator, pool, [0x00, 0xFF]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TYPE, 0), responseCode,
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); a TPMI_ALG_PUBLIC selector outside Part 2, clause 12.2.2, Table 225 must answer parameter-encoded TPM_RC_TYPE there.");
    }

    /// <summary>
    /// Table 80's <c>TPMI_ALG_SYM_OBJECT</c> carries <c>#TPM_RC_SYMMETRIC</c>, and Table 2 names the same code
    /// for "a parameter that should be a symmetric algorithm selection does not have a value that is supported
    /// by the TPM". SM4 and CAMELLIA are registered block ciphers this model implements nowhere, so a
    /// storage-parent <c>symmetric</c> naming either is refused before its key size or mode is even considered.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.34, Table 80; clause 11.1.7, Table 163; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    /// <param name="algorithm">The unimplemented block cipher under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SM4)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_CAMELLIA)]
    public async Task TestParmsRefusesASymmetricAlgorithmThisTpmDoesNotImplementWithSymmetric(TpmAlgIdConstants algorithm)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForStorage(2048, new TpmtSymDefObject
            {
                Algorithm = algorithm,
                KeyBits = 128,
                Mode = TpmAlgIdConstants.TPM_ALG_CFB
            })));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SYMMETRIC).ConfigureAwait(false);
    }

    /// <summary>
    /// "This Table 158 interface type defines the supported key sizes for each symmetric algorithm. This type is
    /// used to allow an unmarshaling routine to generate the proper validation code (TPM_RC_VALUE)" — its
    /// <c>TPMI_AES_KEY_BITS</c> row admits {128, 192, 256}, so a 64-bit AES key size is refused with
    /// <c>TPM_RC_VALUE</c>, the code the table itself names.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.2, Table 158; clause 11.1.7, Table 163</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesAnAesKeySizeOutsideTable158WithValue()
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForStorage(2048, TpmtSymDefObject.Aes(64, TpmAlgIdConstants.TPM_ALG_CFB))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_VALUE).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 81's <c>TPMI_ALG_SYM_MODE</c> carries <c>#TPM_RC_MODE</c>, and Table 2 names the same code for "a
    /// parameter that should be a symmetric encryption mode selection does not have a value that is supported by
    /// the TPM". CFB is the only mode a parent object may carry here, so an AES-128 <c>symmetric</c> in counter
    /// mode is refused with <c>TPM_RC_MODE</c> after its algorithm and key size have both passed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.35, Table 81; clause 11.1.7, Table 163; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesASymmetricModeThisTpmDoesNotImplementWithMode()
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForStorage(2048, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CTR))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_MODE).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 189 lists RSASSA, RSAES, RSAPSS and OAEP and carries <c>#TPM_RC_VALUE</c> for a value outside that
    /// set. This profile implements all four members, so an area naming RSAES passes the membership gate.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.1, Table 189; clause 12.2.3.4, Table 228</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAdmitsTheRsaesScheme()
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForUnrestrictedKey(2048, TpmtRsaScheme.RsaEs)));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SUCCESS).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 77's <c>TPMI_ALG_HASH</c> carries <c>#TPM_RC_HASH</c>, and Table 2 names the same code for "a
    /// parameter that should be a hash algorithm selection does not have a value that is supported by the TPM".
    /// SHA3-256 and SM3-256 are registered hash algorithms this model computes nowhere, so an RSA scheme naming
    /// either as its <c>hashAlg</c> is refused with <c>TPM_RC_HASH</c> after the scheme selector itself passed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.31, Table 77; clause 11.1.17, Table 173; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    /// <param name="hashAlg">The unimplemented hash algorithm under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SHA3_256)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SM3_256)]
    public async Task TestParmsRefusesASchemeHashThisTpmDoesNotImplementWithHash(TpmAlgIdConstants hashAlg)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(hashAlg))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_HASH).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 195's <c>TPMI_RSA_KEY_BITS</c> carries the response code for the "error when key size is not
    /// supported", and Table 2 names <c>TPM_RC_VALUE</c> for "a parameter does not have one of its allowed
    /// values". This model implements 2048- and 4096-bit RSA, so 1024 and 3072 are both refused with
    /// <c>TPM_RC_VALUE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.7, Table 195; clause 12.2.3.4, Table 228; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    /// <param name="keyBits">The unimplemented modulus width under test.</param>
    [TestMethod]
    [DataRow((ushort)1024)]
    [DataRow((ushort)3072)]
    public async Task TestParmsRefusesAnRsaKeySizeThisTpmDoesNotImplementWithValue(ushort keyBits)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(keyBits, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_VALUE).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 200's <c>TPMI_ALG_ECC_SCHEME</c> carries <c>#TPM_RC_SCHEME</c>, and Table 2 names the same code for
    /// "a parameter that should be signing or encryption scheme selection does not have a value that is
    /// supported by the TPM". ECSCHNORR and ECDAA are registered ECC schemes this model implements nowhere, so
    /// an ECC parameter set naming either is refused with <c>TPM_RC_SCHEME</c> — a different code from the RSA
    /// scheme's <c>TPM_RC_VALUE</c>, exactly as the two tables differ.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.4, Table 200; clause 12.2.3.5, Table 229; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    /// <param name="scheme">The unimplemented ECC scheme under test.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_ECSCHNORR)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_ECDAA)]
    public async Task TestParmsRefusesAnEccSchemeThisTpmDoesNotImplementWithScheme(TpmAlgIdConstants scheme)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(new TpmsEccParms
            {
                Symmetric = TpmtSymDefObject.Null,
                Scheme = EccSchemeOf(scheme, TpmAlgIdConstants.TPM_ALG_SHA256),
                CurveId = TpmEccCurveConstants.TPM_ECC_NIST_P256,
                Kdf = TpmtKdfScheme.Null
            }));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_SCHEME).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 201's <c>TPMI_ECC_CURVE</c> carries <c>#TPM_RC_CURVE</c>, "error when curve is not supported". This
    /// model implements the three NIST prime curves, so a Barreto-Naehrig curve is refused — and so is
    /// <c>TPM_ECC_NONE</c>, which is a member of Table 201's own registry but of no implemented set, and is
    /// therefore refused exactly like any other unimplemented curve rather than treated as an absent field.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.5, Table 201; clause 12.2.3.5, Table 229</see>.
    /// </summary>
    /// <param name="curve">The unimplemented curve under test.</param>
    [TestMethod]
    [DataRow(TpmEccCurveConstants.TPM_ECC_BN_P256)]
    [DataRow(TpmEccCurveConstants.TPM_ECC_NONE)]
    public async Task TestParmsRefusesAnEccCurveThisTpmDoesNotImplementWithCurve(TpmEccCurveConstants curve)
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(curve, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_CURVE).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 82's <c>TPMI_ALG_KDF</c> carries <c>#TPM_RC_KDF</c>, and Table 2 names the same code for "a
    /// parameter that should be a key derivation scheme (KDF) selection does not have a value that is supported
    /// by the TPM". KDF2 is a registered member of that table this model implements nowhere, so an ECC
    /// parameter set naming it as its <c>kdf</c> is refused with <c>TPM_RC_KDF</c> after the curve has passed.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.36, Table 82; clause 12.2.3.5, Table 229; Part 3, clause 5.8.2, Table 2</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesAKdfThisTpmDoesNotImplementWithKdf()
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(new TpmsEccParms
            {
                Symmetric = TpmtSymDefObject.Null,
                Scheme = TpmtEccScheme.Ecdh(TpmAlgIdConstants.TPM_ALG_SHA256),
                CurveId = TpmEccCurveConstants.TPM_ECC_NIST_P256,
                Kdf = KdfSchemeOf(TpmAlgIdConstants.TPM_ALG_KDF2, TpmAlgIdConstants.TPM_ALG_SHA256)
            }));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_KDF).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 175's <c>TPMI_ALG_KEYEDHASH_SCHEME</c> admits HMAC, XOR and — through its leading <c>+</c> —
    /// <c>TPM_ALG_NULL</c>, and carries <c>#TPM_RC_VALUE</c> for anything else. The host structure refuses to
    /// build such a scheme at all, so the frame is laid out by hand: the KEYEDHASH selector followed by a scheme
    /// selector that names a block cipher.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.19, Table 175; clause 12.2.3.3, Table 227</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesAKeyedHashSchemeOutsideTable175WithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        //type TPM_ALG_KEYEDHASH | scheme TPM_ALG_CAMELLIA, which Table 175 does not list.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(simulator, pool, [0x00, 0x08, 0x00, 0x26]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), responseCode,
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); a keyed-hash scheme selector outside Part 2, clause 11.1.19, Table 175 must answer parameter-encoded TPM_RC_VALUE there.");
    }

    /// <summary>
    /// "Prior to version 1.59, the TPM_ALG_NULL hash algorithm was permitted. This produced a zero-length key.
    /// The TPM_ALG_NULL hashAlg now returns TPM_RC_HASH." — Table 177's own sentence, so an XOR scheme whose
    /// <c>hashAlg</c> is <c>TPM_ALG_NULL</c> is refused with <c>TPM_RC_HASH</c>, not accepted as an absent hash,
    /// even though the same structure's <c>kdf</c> field does admit the NULL.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177; clause 9.31, Table 77</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesTheXorSchemeWithANullHashWithHash()
    {
        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.Xor(
                TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108)));

        await AssertTestParmsAnswersAsync(parms, TpmRcConstants.TPM_RC_HASH).ConfigureAwait(false);
    }

    /// <summary>
    /// Table 2 names <c>TPM_RC_INSUFFICIENT</c> for "the input buffer did not contain enough octets to allow
    /// unmarshaling of the expected data type": a frame cut immediately after the <c>TPMI_ALG_PUBLIC</c>
    /// selector leaves the union arm with nothing at all to read.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesAFrameCutAfterTheSelectorWithInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        //type TPM_ALG_RSA, and then nothing where TPMS_RSA_PARMS should begin.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(simulator, pool, [0x00, 0x01]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), responseCode,
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); a frame with no octets left for the selected union arm must answer parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// The same rule inside a partly-read structure: a frame that carries <c>symmetric</c> and <c>scheme</c> but
    /// stops one octet into <c>keyBits</c> has not enough octets for the expected data type, so it answers
    /// <c>TPM_RC_INSUFFICIENT</c> rather than any of the field-specific codes the earlier fields could have
    /// produced.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; Part 2, clause 12.2.3.4, Table 228</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesAFrameCutInsideTheRsaParametersWithInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        //type TPM_ALG_RSA | symmetric TPM_ALG_NULL | scheme RSASSA, SHA-256 | one octet of keyBits.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(
            simulator, pool, [0x00, 0x01, 0x00, 0x10, 0x00, 0x14, 0x00, 0x0B, 0x08]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), responseCode,
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); a frame cut inside TPMS_RSA_PARMS must answer parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>parameters</c> is the whole parameter area, so an octet following a complete and otherwise acceptable
    /// <c>TPMT_PUBLIC_PARMS</c> makes the command size wrong: Table 2 names <c>TPM_RC_SIZE</c> for "the value of
    /// a size parameter is larger or smaller than allowed".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; clause 30.3, Table 240</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsRefusesATrailingOctetWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        //A complete RSA-2048/RSASSA-SHA256 TPMT_PUBLIC_PARMS, then one octet that belongs to nothing.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(
            simulator, pool, [0x00, 0x01, 0x00, 0x10, 0x00, 0x14, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, responseCode,
            "An octet past the end of TPMT_PUBLIC_PARMS must answer TPM_RC_SIZE.");
    }

    /// <summary>
    /// "TPM2_TestParms() is used to determine if a TPM supports a particular combination of algorithm
    /// parameters" — so a combination it reports as supported must be one an object can actually be created
    /// with: the RSA-2048 RSASSA-SHA256 parameters answer <c>TPM_RC_SUCCESS</c> at <c>TPM2_TestParms()</c> and
    /// the same parameters create a primary key at <c>TPM2_CreatePrimary()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.1, clause 30.3; clause 24.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAndCreatePrimaryAgreeOnTheRsaSigningParameters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateCreationCapableOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(testResult),
            "The RSA-2048 RSASSA-SHA256 parameters must be reported as supported.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: 2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(createResult.IsSuccess,
            $"Parameters TPM2_TestParms reports as supported must create a key: '{createResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = createResult.Value;
        await FlushIfPresentAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// The same agreement on the ECC side: the P-256 ECDSA-SHA256 parameters answer <c>TPM_RC_SUCCESS</c> at
    /// <c>TPM2_TestParms()</c> and create a primary key at <c>TPM2_CreatePrimary()</c>, so the reported support
    /// is the object-creation path's own support and not a separate opinion.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.1, clause 30.3; clause 24.1; Part 2, clause 12.2.3.5, Table 229</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAndCreatePrimaryAgreeOnTheEccSigningParameters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateCreationCapableOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(
                TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(testResult),
            "The ECC P-256 ECDSA-SHA256 parameters must be reported as supported.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(createResult.IsSuccess,
            $"Parameters TPM2_TestParms reports as supported must create a key: '{createResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = createResult.Value;
        await FlushIfPresentAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// The converse of the same interface-type layer: a modulus width Table 195 does not admit here is refused
    /// with <c>TPM_RC_VALUE</c> at <c>TPM2_TestParms()</c>, and a <c>TPM2_CreatePrimary()</c> template naming
    /// that same width is refused with the same underlying <c>TPM_RC_VALUE</c> — the question and the creation
    /// read one set of implemented widths, not two — each parameter-encoded to its OWN command's field position:
    /// <c>parameters</c> is <c>TestParms</c>'s sole parameter (Table 240, index 0) while <c>inPublic</c> is
    /// <c>CreatePrimary</c>'s second parameter (Table 191, index 1), so the two wire codes differ by their N
    /// field even though the base failure is identical.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.7, Table 195; Part 3, clause 30.3, Table 240; clause 24.1, Table 191</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAndCreatePrimaryRefuseAnUnimplementedRsaKeySizeWithTheSameValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateCreationCapableOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(3072, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), AnsweredCode(testResult),
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); a 3072-bit RSA modulus must be refused with parameter-encoded TPM_RC_VALUE there.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: 3072, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 1), AnsweredCode(createResult),
            "Table 191: inPublic is TPM2_CreatePrimary()'s second parameter (index 1); TPM2_CreatePrimary must refuse the 3072-bit modulus with the same underlying TPM_RC_VALUE TPM2_TestParms answered, parameter-encoded to its own field position.");
    }

    /// <summary>
    /// The same converse for Table 189's scheme set, now that this profile implements all four members: RSAES
    /// is admitted with <c>TPM_RC_SUCCESS</c> at <c>TPM2_TestParms()</c>, and a <c>TPM2_CreatePrimary()</c>
    /// template naming it for an unrestricted decryption key (the shape Table 228's own row admits — RSAES,
    /// OAEP, or NULL for a decrypt-SET, restricted-CLEAR key) is admitted with the same code.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.4.1, Table 189; clause 12.2.3.4, Table 228; Part 3, clause 30.3; clause 24.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAndCreatePrimaryAdmitTheRsaesSchemeAlike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateCreationCapableOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA, TpmuPublicParms.Rsa(TpmsRsaParms.ForUnrestrictedKey(2048, TpmtRsaScheme.RsaEs)));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(testResult), "RSAES must be admitted with TPM_RC_SUCCESS.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaDecryptKey(
            TpmRh.TPM_RH_OWNER, password: null, keyBits: 2048, TpmtRsaScheme.RsaEs, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        using CreatePrimaryResponse createResponse = createResult.Value;

        Assert.AreEqual(AnsweredCode(testResult), AnsweredCode(createResult),
            "TPM2_CreatePrimary must admit RSAES with the same code TPM2_TestParms answered.");
    }

    /// <summary>
    /// The same converse for Table 201's curve set: a Barreto-Naehrig curve is refused with
    /// <c>TPM_RC_CURVE</c> at <c>TPM2_TestParms()</c>, and a <c>TPM2_CreatePrimary()</c> template naming it is
    /// refused with the same underlying <c>TPM_RC_CURVE</c> rather than reaching the signing backend — each
    /// parameter-encoded to its OWN command's field position: <c>parameters</c> is <c>TestParms</c>'s sole
    /// parameter (Table 240, index 0) while <c>inPublic</c> is <c>CreatePrimary</c>'s second parameter (Table
    /// 191, index 1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.5.5, Table 201; Part 3, clause 30.3, Table 240; clause 24.1, Table 191</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAndCreatePrimaryRefuseAnUnimplementedCurveWithTheSameCurve()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateCreationCapableOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(
                TpmEccCurveConstants.TPM_ECC_BN_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_CURVE, 0), AnsweredCode(testResult),
            "Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); TPM_ECC_BN_P256 must be refused with parameter-encoded TPM_RC_CURVE there.");

        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_BN_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_CURVE, 1), AnsweredCode(createResult),
            "Table 191: inPublic is TPM2_CreatePrimary()'s second parameter (index 1); TPM2_CreatePrimary must refuse the unimplemented curve with the same underlying TPM_RC_CURVE TPM2_TestParms answered, parameter-encoded to its own field position.");
    }

    /// <summary>
    /// The limit of that agreement, stated rather than hidden: <c>TPM2_TestParms()</c>'s input carries no
    /// <c>TPMA_OBJECT</c>, so it answers only the interface-type question — an HMAC scheme over SHA-1 is a
    /// combination of algorithm parameters this TPM supports, and it says so. Object creation additionally
    /// applies its own attribute-conditioned rules, and a signing keyed-hash key over SHA-1 is refused there
    /// with <c>TPM_RC_HASH</c>. The two answers differ because the questions differ.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.3; clause 12.1; Part 2, clause 12.2.3.10, Table 234; clause 11.1.19, Table 175</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsAcceptsHmacOverSha1WhileASigningKeyedHashKeyOverSha1IsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(
            "tpm-in-house-test-parms-hmac", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_TestParms, TpmResponseCodec.TestParms);

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA1)));

        TpmResult<TestParmsResponse> testResult = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(testResult),
            "HMAC over SHA-1 is a supported combination of algorithm parameters, so TPM2_TestParms must accept it.");

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(
            tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateHmacKeyAsync(
                tpm, registry, pool, parent.ObjectHandle.Value, keyBytes: default, TpmAlgIdConstants.TPM_ALG_SHA1,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), AnsweredCode(createResult),
                "A signing keyed-hash key over SHA-1 must be refused at creation with TPM_RC_HASH, the attribute-conditioned rule TPM2_TestParms does not apply.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Table 240 admits <c>TPM_ST_SESSIONS</c> only when an audit session is present, and this model implements
    /// none; "If a session is not being used for authorization, at least one of decrypt, encrypt, or audit must
    /// be SET. (TPM_RC_ATTRIBUTES)." — so a lone companion session at this zero-handle command is refused with
    /// the session-index-encoded <c>TPM_RC_ATTRIBUTES</c>. The refusal comes from clause 5.5's session-area
    /// checks, which precede clause 5.8's parameter unmarshaling: the parameters here name
    /// <c>TPM_ALG_SYMCIPHER</c>, which would otherwise answer <c>TPM_RC_TYPE</c>, and that code is never
    /// reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5; clause 5.8.2; clause 30.3, Table 240; Part 2, clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsOverAnAttributelessSessionIsRefusedWithAttributesBeforeTheParametersAreJudged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            try
            {
                var input = new TestParmsInput(TpmtPublicParms.Create(
                    TpmAlgIdConstants.TPM_ALG_SYMCIPHER,
                    TpmuPublicParms.SymCipher(TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)))));

                TpmResult<TestParmsResponse> result = await TpmCommandExecutor.ExecuteAsync<TestParmsResponse>(
                    tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), AnsweredCode(result),
                    "A lone session claiming nothing must be refused at the session area, ahead of the parameters, with the session-encoded TPM_RC_ATTRIBUTES.");
            }
            finally
            {
                await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// The over-session parse rents three carriers — a nonce, an hmac and the whole raw parameter area — for a
    /// lone companion claiming neither <c>decrypt</c>, <c>encrypt</c> nor <c>audit</c>, refused at the session
    /// area ahead of any parameter judgment (TPM 2.0 Library Part 3, clause 5.5, step 4.4.2 precedes clause
    /// 5.8): every carrier the parse rented must come back on that refusing path. A plain-form success beside
    /// it, which rents no pooled carrier at all, proves the baseline is undisturbed either way.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.5; clause 30.3, Table 240</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsReturnsItsCarriersAcrossASessionRefusalAndAPlainFormSuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        long baseline;
        long afterRefusal;
        long afterSuccess;

        using(TpmSimulator simulator = CreatePoweredOff())
        {
            await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
            await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
            using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
            TpmResponseRegistry registry = CreateRegistry();

            baseline = trackingPool.OutstandingCount;

            (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(session)
            {
                try
                {
                    var refusedInput = new TestParmsInput(TpmtPublicParms.Create(
                        TpmAlgIdConstants.TPM_ALG_SYMCIPHER,
                        TpmuPublicParms.SymCipher(TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)))));

                    TpmResult<TestParmsResponse> refusal = await TpmCommandExecutor.ExecuteAsync<TestParmsResponse>(
                        tpm, refusedInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), AnsweredCode(refusal),
                        "The session-form refusal under test must actually be refused before its carriers are counted.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
                }
            }

            afterRefusal = trackingPool.OutstandingCount;
            Assert.AreEqual(baseline, afterRefusal,
                "The over-session parse's nonce, hmac and parameter area must all come back on TPM2_TestParms()'s only refusing path.");

            TpmtPublicParms successParms = TpmtPublicParms.Create(
                TpmAlgIdConstants.TPM_ALG_RSA,
                TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));
            TpmResult<TestParmsResponse> success = await TestParmsAsync(tpm, registry, pool, successParms).ConfigureAwait(false);
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(success), "The plain-form success under test must actually succeed.");
            afterSuccess = trackingPool.OutstandingCount;
        }

        Assert.AreEqual(baseline, afterSuccess,
            "TPM2_TestParms()'s plain form carries no pooled carrier at all, so a success must leave the pool balance exactly where it stood.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the TPM must not change a balance a stateless command already left untouched.");
    }

    /// <summary>
    /// A command sent before <c>TPM2_Startup()</c> is answered with <c>TPM_RC_INITIALIZE</c> — the TPM has not
    /// been initialized and no command but <c>TPM2_Startup()</c> is admitted — so
    /// <c>TPM2_TestParms()</c>'s membership ladder is never reached for parameters this model would otherwise
    /// accept.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.2; Part 3, clause 9.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsBeforeStartupReturnsInitialize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = CreatePoweredOff();
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A combination this TPM implements, so nothing but the lifecycle phase can be answering.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(
            simulator, pool, [0x00, 0x08, 0x00, 0x05, 0x00, 0x0B]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, responseCode,
            "Before TPM2_Startup the TPM must answer TPM_RC_INITIALIZE, not judge the parameters.");
        Assert.AreEqual(TpmLifecyclePhase.Initializing, simulator.CurrentPhase);
    }

    /// <summary>
    /// In Failure Mode the TPM answers <c>TPM_RC_FAILURE</c> to every command but the few the mode admits, so
    /// <c>TPM2_TestParms()</c> over a combination this model implements answers <c>TPM_RC_FAILURE</c> rather
    /// than reporting support from a TPM that has failed its self-test.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 12.3; Part 3, clause 30.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsInFailureModeReturnsFailure()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var simulator = new TpmSimulator("tpm-in-house-test-parms-failed",selfTest: TpmSelfTestBehavior.Fails, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        TpmRcConstants selfTestCode = await SubmitSelfTestFramedAsync(simulator, pool).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, selfTestCode, "A failing self-test must enter Failure Mode.");
        Assert.AreEqual(TpmLifecyclePhase.FailureMode, simulator.CurrentPhase);

        //A combination this TPM implements, so nothing but the lifecycle phase can be answering.
        TpmRcConstants responseCode = await SubmitTestParmsFramedAsync(
            simulator, pool, [0x00, 0x08, 0x00, 0x05, 0x00, 0x0B]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, responseCode,
            "In Failure Mode TPM2_TestParms must answer TPM_RC_FAILURE rather than report support.");
    }

    /// <summary>
    /// "The parameters are tested at unmarshal process. We do nothing in command action" — a successful
    /// <c>TPM2_TestParms()</c> changes nothing about the TPM, so a <c>TPM2_ReadClock()</c> taken before and
    /// after differs only by the two commands dispatched between the readings: the <c>TPM2_TestParms()</c> and
    /// the second <c>TPM2_ReadClock()</c> itself.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.3; Part 1, clause 36.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TestParmsChangesNoStateBeyondItsOwnClockQuantum()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmsTimeInfo before = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmtPublicParms parms = TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))));
        TpmResult<TestParmsResponse> result = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, AnsweredCode(result), "The parameters under test must be reported as supported.");

        TpmsTimeInfo after = await ReadClockAsync(tpm, registry, pool).ConfigureAwait(false);

        Assert.AreEqual(before.ClockInfo.Clock + 2ul, after.ClockInfo.Clock,
            "Clock must advance by exactly the two dispatched commands' quanta — TPM2_TestParms performs no action of its own.");
        Assert.AreEqual(before.Time + 2ul, after.Time,
            "Time must advance by exactly the two dispatched commands' quanta.");
        Assert.AreEqual(before.ClockInfo.ResetCount, after.ClockInfo.ResetCount, "TPM2_TestParms must not reset the TPM.");
        Assert.AreEqual(before.ClockInfo.RestartCount, after.ClockInfo.RestartCount, "TPM2_TestParms must not restart the TPM.");
    }

    /// <summary>
    /// Builds the <c>TPMT_RSA_SCHEME</c> Table 189 names for <paramref name="scheme"/>, with
    /// <paramref name="hashAlg"/> as its <c>hashAlg</c> where the scheme carries one.
    /// </summary>
    /// <param name="scheme">The RSA scheme selector.</param>
    /// <param name="hashAlg">The scheme's hash algorithm.</param>
    /// <returns>The RSA scheme structure.</returns>
    private static TpmtRsaScheme RsaSchemeOf(TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg) => scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_RSASSA => TpmtRsaScheme.Rsassa(hashAlg),
        TpmAlgIdConstants.TPM_ALG_RSAPSS => TpmtRsaScheme.RsaPss(hashAlg),
        TpmAlgIdConstants.TPM_ALG_OAEP => TpmtRsaScheme.Oaep(hashAlg),
        TpmAlgIdConstants.TPM_ALG_RSAES => TpmtRsaScheme.RsaEs,
        _ => TpmtRsaScheme.Null
    };

    /// <summary>
    /// Builds the <c>TPMT_ECC_SCHEME</c> Table 200 names for <paramref name="scheme"/>, including the schemes
    /// this model does not implement, which the factories do not offer and the refusal cases need.
    /// </summary>
    /// <param name="scheme">The ECC scheme selector.</param>
    /// <param name="hashAlg">The scheme's hash algorithm.</param>
    /// <returns>The ECC scheme structure.</returns>
    private static TpmtEccScheme EccSchemeOf(TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg) => scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_ECDSA => TpmtEccScheme.Ecdsa(hashAlg),
        TpmAlgIdConstants.TPM_ALG_ECDH => TpmtEccScheme.Ecdh(hashAlg),
        TpmAlgIdConstants.TPM_ALG_NULL => TpmtEccScheme.Null,
        _ => new TpmtEccScheme { Scheme = scheme, HashAlg = hashAlg }
    };

    /// <summary>
    /// Builds the <c>TPMT_KDF_SCHEME</c> Table 82 names for <paramref name="kdf"/>; the NULL selector carries no
    /// hash on the wire.
    /// </summary>
    /// <param name="kdf">The key-derivation function selector.</param>
    /// <param name="hashAlg">The function's hash algorithm.</param>
    /// <returns>The KDF scheme structure.</returns>
    private static TpmtKdfScheme KdfSchemeOf(TpmAlgIdConstants kdf, TpmAlgIdConstants hashAlg) =>
        kdf == TpmAlgIdConstants.TPM_ALG_NULL
            ? TpmtKdfScheme.Null
            : new TpmtKdfScheme { Scheme = kdf, HashAlg = hashAlg };

    /// <summary>
    /// Builds the <c>TPMS_KEYEDHASH_PARMS</c> Table 227 names for <paramref name="scheme"/>: the sealed-data
    /// form for the NULL selector, the HMAC form carrying a hash, and the XOR form carrying a hash and a KDF.
    /// </summary>
    /// <param name="scheme">The keyed-hash scheme selector.</param>
    /// <param name="hashAlg">The scheme's hash algorithm.</param>
    /// <param name="kdf">The XOR scheme's key-derivation function.</param>
    /// <returns>The keyed-hash parameters.</returns>
    private static TpmsKeyedHashParms KeyedHashParmsOf(TpmAlgIdConstants scheme, TpmAlgIdConstants hashAlg, TpmAlgIdConstants kdf) => scheme switch
    {
        TpmAlgIdConstants.TPM_ALG_HMAC => TpmsKeyedHashParms.Hmac(hashAlg),
        TpmAlgIdConstants.TPM_ALG_XOR => TpmsKeyedHashParms.Xor(hashAlg, kdf),
        _ => TpmsKeyedHashParms.SealedData
    };

    /// <summary>
    /// Builds a wire-valid union arm for one of the four object types Table 225 registers and this model does
    /// not implement, so the refusal proved is the type check and not a malformed frame.
    /// </summary>
    /// <param name="type">The registered but unimplemented object type.</param>
    /// <returns>The union carrying that type's arm.</returns>
    private static TpmuPublicParms UnimplementedParametersFor(TpmAlgIdConstants type) => type switch
    {
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER => TpmuPublicParms.SymCipher(
            TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB))),
        TpmAlgIdConstants.TPM_ALG_MLDSA => TpmuPublicParms.MlDsa(TpmsMlDsaParms.MlDsa65()),
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => TpmuPublicParms.HashMlDsa(TpmsHashMlDsaParms.HashMlDsa65Sha384()),
        _ => TpmuPublicParms.MlKem(TpmsMlKemParms.Create(TpmtSymDefObject.Null, TpmMlKemParameterSet.TPM_MLKEM_768))
    };

    /// <summary>
    /// Issues one sessionless <c>TPM2_TestParms()</c> over <paramref name="parms"/> against a freshly created
    /// operational simulator and asserts the response code, the shared body of every matrix case.
    /// </summary>
    /// <param name="parms">The algorithm parameters to validate.</param>
    /// <param name="expected">The unencoded response code the parameters must draw; a non-success value is
    /// parameter-encoded to index 0, since <c>parameters</c> is <c>TPM2_TestParms()</c>'s sole parameter
    /// (TPM 2.0 Library Part 3, clause 30.3, Table 240).</param>
    private async Task AssertTestParmsAnswersAsync(TpmtPublicParms parms, TpmRcConstants expected)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<TestParmsResponse> result = await TestParmsAsync(tpm, registry, pool, parms).ConfigureAwait(false);

        TpmRcConstants expectedOnWire = expected == TpmRcConstants.TPM_RC_SUCCESS
            ? expected
            : HmacKeyHarness.ParameterEncodedRc(expected, 0);

        Assert.AreEqual(expectedOnWire, AnsweredCode(result),
            $"Table 240: parameters is TPM2_TestParms()'s sole parameter (index 0); TPM2_TestParms over '{parms.Type}' parameters must answer parameter-encoded '{expected}'.");
    }

    /// <summary>
    /// The response code a completed exchange carries, whether it succeeded or was refused, so a case can
    /// compare two commands' answers without branching on which of them succeeded. A transport failure is no
    /// answer at all and fails the case outright.
    /// </summary>
    /// <typeparam name="T">The response type.</typeparam>
    /// <param name="result">The completed exchange.</param>
    /// <returns>The response code the TPM answered.</returns>
    private static TpmRcConstants AnsweredCode<T>(TpmResult<T> result)
    {
        Assert.IsFalse(result.IsTransportError, "The exchange must reach the TPM and carry a response code.");

        return result.IsSuccess ? TpmRcConstants.TPM_RC_SUCCESS : result.ResponseCode;
    }

    /// <summary>Issues one sessionless <c>TPM2_TestParms()</c> through the production executor.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parms">The algorithm parameters to validate.</param>
    /// <returns>The raw result, success or refusal.</returns>
    private async Task<TpmResult<TestParmsResponse>> TestParmsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtPublicParms parms)
    {
        var input = new TestParmsInput(parms);

        return await TpmCommandExecutor.ExecuteAsync<TestParmsResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Frames a sessionless <c>TPM2_TestParms()</c> header around <paramref name="body"/> and submits it straight
    /// to the simulator, for the parameter areas no host structure can express.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="body">The parameter area, already laid out.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitTestParmsFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_TestParms);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a hand-framed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Frames a sessionless <c>TPM2_SelfTest()</c> straight to the simulator, the command that drives a
    /// self-test-failing simulator into Failure Mode.
    /// </summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSelfTestFramedAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new SelfTestInput(IsFullTest: false);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer TPM2_SelfTest rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session and composes the host session over it, leaving the session
    /// attributes at their default — <c>continueSession</c> alone, none of decrypt, encrypt or audit.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Issues one <c>TPM2_ReadClock()</c> and returns the parsed current-time snapshot.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The current <c>TPMS_TIME_INFO</c>.</returns>
    private async Task<TpmsTimeInfo> ReadClockAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<ReadClockResponse> result = await TpmCommandExecutor.ExecuteAsync<ReadClockResponse>(
            tpm, new ReadClockInput(), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadClock failed: '{result.ResponseCode}'.");

        ReadClockResponse response = result.Value;

        return response.CurrentTime;
    }

    /// <summary>Flushes <paramref name="handle"/>, ignoring the response so a cleanup path never masks a failure.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient handle to flush.</param>
    private static async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): the base code plus
    /// <c>TPM_RC_S</c> plus <c>TPM_RC_n</c> for the slot, transcribed here so the expectation is computed
    /// independently of the code under test.
    /// </summary>
    /// <param name="baseRc">The unencoded response code.</param>
    /// <param name="sessionIndex">The zero-based session slot.</param>
    /// <returns>The session-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Creates a powered-off simulator needing no asymmetric backend, which TPM2_TestParms never uses.</summary>
    /// <returns>The powered-off simulator.</returns>
    private static TpmSimulator CreatePoweredOff() => new("tpm-in-house-test-parms", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));

    /// <summary>Powers on a backend-free simulator and brings it through <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        TpmSimulator simulator = CreatePoweredOff();
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Powers on a simulator with both asymmetric signing backends wired and brings it operational, for the
    /// cases that put the same parameters to <c>TPM2_CreatePrimary()</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateCreationCapableOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-test-parms-creation",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_TestParms, TpmResponseCodec.TestParms);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadClock, TpmResponseCodec.ReadClock);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}

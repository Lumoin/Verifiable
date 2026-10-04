using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Rows for <see cref="JwsAlgorithmKeyBinding.IsAlgorithmOfKey(string, CryptoAlgorithm)"/>: every pair of an
/// algorithm and a key algorithm the table admits, for each algorithm a key algorithm it refuses, every key
/// algorithm no JWS algorithm is defined over, and the names the table does not name.
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "The
/// library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for
/// the cryptographic operation."
/// </summary>
[TestClass]
internal sealed class JwsAlgorithmKeyBindingTests
{
    /// <summary>Every algorithm the table binds to a key algorithm.</summary>
    private static string[] TableAlgorithms { get; } =
    [
        WellKnownJwaValues.Es256, WellKnownJwaValues.Es384, WellKnownJwaValues.Es512, WellKnownJwaValues.Es256K,
        WellKnownJwaValues.EdDsa, WellKnownJwaValues.Ed25519,
        WellKnownJwaValues.Rs256, WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512,
        WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512,
        WellKnownJwaValues.Esb256, WellKnownJwaValues.Esb320, WellKnownJwaValues.Esb384, WellKnownJwaValues.Esb512,
        WellKnownJwaValues.MlDsa44, WellKnownJwaValues.MlDsa65, WellKnownJwaValues.MlDsa87
    ];


    /// <summary>
    /// Every key algorithm some algorithm of the table binds: the NIST and secp256k1 curves, Ed25519, the two
    /// RSA size tags, the six RSA padding-and-hash tags, the four Brainpool curves an ESB name names and the three
    /// ML-DSA parameter sets.
    /// </summary>
    internal static CryptoAlgorithm[] TableKeyAlgorithms { get; } =
    [
        CryptoAlgorithm.P256, CryptoAlgorithm.P384, CryptoAlgorithm.P521, CryptoAlgorithm.Secp256k1,
        CryptoAlgorithm.Ed25519,
        CryptoAlgorithm.Rsa2048, CryptoAlgorithm.Rsa4096,
        CryptoAlgorithm.RsaSha256, CryptoAlgorithm.RsaSha256Pss, CryptoAlgorithm.RsaSha384,
        CryptoAlgorithm.RsaSha384Pss, CryptoAlgorithm.RsaSha512, CryptoAlgorithm.RsaSha512Pss,
        CryptoAlgorithm.BrainpoolP256r1, CryptoAlgorithm.BrainpoolP320r1, CryptoAlgorithm.BrainpoolP384r1,
        CryptoAlgorithm.BrainpoolP512r1,
        CryptoAlgorithm.MlDsa44, CryptoAlgorithm.MlDsa65, CryptoAlgorithm.MlDsa87
    ];


    /// <summary>
    /// Every predefined key algorithm the table binds to no algorithm, each listed by name:
    /// <see cref="CryptoAlgorithm.Unknown"/>, the BLS12-381 tags, the X25519 key agreement curve, the platform
    /// tag, the ML-KEM key-encapsulation tags, brainpoolP224r1, the symmetric tags, the ISO/IEC 9796-2 RSA tag
    /// and the BLAKE3 hash tag.
    /// </summary>
    internal static CryptoAlgorithm[] UnboundKeyAlgorithms { get; } =
    [
        CryptoAlgorithm.Unknown,
        CryptoAlgorithm.Bls12381G1, CryptoAlgorithm.Bls12381G2, CryptoAlgorithm.Bls12381G1G2,
        CryptoAlgorithm.X25519,
        CryptoAlgorithm.WindowsPlatformEncrypted,
        CryptoAlgorithm.MlKem512, CryptoAlgorithm.MlKem768, CryptoAlgorithm.MlKem1024,
        CryptoAlgorithm.BrainpoolP224r1,
        CryptoAlgorithm.Aes256, CryptoAlgorithm.TripleDes, CryptoAlgorithm.Aes128, CryptoAlgorithm.XChaCha20Poly1305,
        CryptoAlgorithm.RsaIso9796d2,
        CryptoAlgorithm.Blake3
    ];


    /// <summary>Every predefined key algorithm: those the table binds and those it binds to none.</summary>
    private static IEnumerable<CryptoAlgorithm> AllKeyAlgorithms => TableKeyAlgorithms.Concat(UnboundKeyAlgorithms);


    /// <summary>
    /// The rows of <see cref="AlgorithmsBindToTheirKeyAlgorithms"/>: every pair the table admits, answered
    /// <see langword="true"/>; every other pair of an RSA name and an RSA key algorithm, answered
    /// <see langword="false"/>; then for each algorithm a key algorithm of another curve, family or parameter
    /// set, answered <see langword="false"/>.
    /// </summary>
    /// <returns>The algorithm, the key algorithm and whether the table binds them.</returns>
    public static IEnumerable<object[]> BindingRows()
    {
        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.P256, true];
        yield return [WellKnownJwaValues.Es384, CryptoAlgorithm.P384, true];
        yield return [WellKnownJwaValues.Es512, CryptoAlgorithm.P521, true];
        yield return [WellKnownJwaValues.Es256K, CryptoAlgorithm.Secp256k1, true];
        yield return [WellKnownJwaValues.EdDsa, CryptoAlgorithm.Ed25519, true];
        yield return [WellKnownJwaValues.Ed25519, CryptoAlgorithm.Ed25519, true];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.Rsa2048, true];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.Rsa4096, true];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha256, true];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha256Pss, true];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha384, true];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha384Pss, true];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha512, true];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha512Pss, true];
        yield return [WellKnownJwaValues.Esb256, CryptoAlgorithm.BrainpoolP256r1, true];
        yield return [WellKnownJwaValues.Esb320, CryptoAlgorithm.BrainpoolP320r1, true];
        yield return [WellKnownJwaValues.Esb384, CryptoAlgorithm.BrainpoolP384r1, true];
        yield return [WellKnownJwaValues.Esb512, CryptoAlgorithm.BrainpoolP512r1, true];
        yield return [WellKnownJwaValues.MlDsa44, CryptoAlgorithm.MlDsa44, true];
        yield return [WellKnownJwaValues.MlDsa65, CryptoAlgorithm.MlDsa65, true];
        yield return [WellKnownJwaValues.MlDsa87, CryptoAlgorithm.MlDsa87, true];

        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.Rsa2048, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.Rsa2048, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.Rsa2048, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.Rsa2048, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.Rsa2048, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.Rsa4096, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.Rsa4096, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.Rsa4096, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.Rsa4096, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.Rsa4096, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha256, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha256, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha256, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha256, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha256, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha256Pss, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha256Pss, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha256Pss, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha256Pss, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha256Pss, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha384, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha384, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha384, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha384, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha384, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha384Pss, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha384Pss, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha384Pss, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha384Pss, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha384Pss, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha512, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha512, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha512, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha512, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.RsaSha512, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.RsaSha512Pss, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.RsaSha512Pss, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.RsaSha512Pss, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.RsaSha512Pss, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.RsaSha512Pss, false];

        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.BrainpoolP256r1, false];
        yield return [WellKnownJwaValues.Es384, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.Es512, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Es256K, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.EdDsa, CryptoAlgorithm.X25519, false];
        yield return [WellKnownJwaValues.Ed25519, CryptoAlgorithm.X25519, false];
        yield return [WellKnownJwaValues.Rs256, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.Rs384, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Rs512, CryptoAlgorithm.P521, false];
        yield return [WellKnownJwaValues.Ps256, CryptoAlgorithm.Ed25519, false];
        yield return [WellKnownJwaValues.Ps384, CryptoAlgorithm.Secp256k1, false];
        yield return [WellKnownJwaValues.Ps512, CryptoAlgorithm.BrainpoolP512r1, false];
        yield return [WellKnownJwaValues.Esb256, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.Esb320, CryptoAlgorithm.BrainpoolP384r1, false];
        yield return [WellKnownJwaValues.Esb384, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Esb512, CryptoAlgorithm.P521, false];
        yield return [WellKnownJwaValues.MlDsa44, CryptoAlgorithm.MlDsa65, false];
        yield return [WellKnownJwaValues.MlDsa65, CryptoAlgorithm.MlDsa87, false];
        yield return [WellKnownJwaValues.MlDsa87, CryptoAlgorithm.MlDsa44, false];
        yield return [WellKnownJwaValues.None, CryptoAlgorithm.P256, false];
    }


    /// <summary>
    /// The rows of <see cref="AKeyAlgorithmNoJwsAlgorithmIsDefinedOverBindsNone"/>: every algorithm the table
    /// binds.
    /// </summary>
    /// <returns>Each algorithm of the table.</returns>
    public static IEnumerable<object[]> TableAlgorithmRows() => TableAlgorithms.Select(algorithm => new object[] { algorithm });


    /// <summary>
    /// The rows of <see cref="ANameTheTableDoesNotNameBindsNoKeyAlgorithm"/>: <c>none</c>; the three MAC
    /// algorithms; the key-agreement name <c>ECDH-ES</c> as <see cref="WellKnownJwaValues.Ecdha"/> holds it;
    /// the names of RFC 7518 Section 4.1 that <see cref="WellKnownJweAlgorithms"/> holds, of which
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.1">RFC 7518 Section 4.1</see> says: "These
    /// algorithms are used to encrypt the CEK, producing the JWE Encrypted Key, or to use key agreement to agree
    /// upon the CEK.", and the <c>ECDH-1PU</c> names that <see cref="WellKnownJweAlgorithms"/> holds beside them,
    /// which are of another document; an empty value; and four spellings of <c>ES256</c> that are not it (another case, a
    /// trailing space, a trailing NUL and a leading space).
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>: "The
    /// "alg" value is a case-sensitive ASCII string containing a StringOrURI value."
    /// </summary>
    /// <returns>Each name the table binds to no key algorithm.</returns>
    public static IEnumerable<object[]> UnboundNameRows()
    {
        yield return [WellKnownJwaValues.None];
        yield return [WellKnownJwaValues.Hs256];
        yield return [WellKnownJwaValues.Hs384];
        yield return [WellKnownJwaValues.Hs512];
        yield return [WellKnownJwaValues.Ecdha];
        yield return [WellKnownJweAlgorithms.Rsa15];
        yield return [WellKnownJweAlgorithms.RsaOaep];
        yield return [WellKnownJweAlgorithms.RsaOaep256];
        yield return [WellKnownJweAlgorithms.A128Kw];
        yield return [WellKnownJweAlgorithms.A192Kw];
        yield return [WellKnownJweAlgorithms.A256Kw];
        yield return [WellKnownJweAlgorithms.Dir];
        yield return [WellKnownJweAlgorithms.EcdhEsA128Kw];
        yield return [WellKnownJweAlgorithms.EcdhEsA192Kw];
        yield return [WellKnownJweAlgorithms.EcdhEsA256Kw];
        yield return [WellKnownJweAlgorithms.Ecdh1Pu];
        yield return [WellKnownJweAlgorithms.Ecdh1PuA128Kw];
        yield return [WellKnownJweAlgorithms.Ecdh1PuA192Kw];
        yield return [WellKnownJweAlgorithms.Ecdh1PuA256Kw];
        yield return [WellKnownJweAlgorithms.A128GcmKw];
        yield return [WellKnownJweAlgorithms.A192GcmKw];
        yield return [WellKnownJweAlgorithms.A256GcmKw];
        yield return [WellKnownJweAlgorithms.Pbes2Hs256A128Kw];
        yield return [WellKnownJweAlgorithms.Pbes2Hs384A192Kw];
        yield return [WellKnownJweAlgorithms.Pbes2Hs512A256Kw];
        yield return [string.Empty];
        yield return ["es256"];
        yield return ["ES256 "];
        yield return ["ES256\0"];
        yield return [" ES256"];
    }


    /// <summary>
    /// The table answers each row as its pair is defined, holding a declared algorithm to the one operation the
    /// verification its key algorithm selects computes.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "Moreover,
    /// each key MUST be used with exactly one algorithm, and this MUST be checked when the cryptographic
    /// operation is performed."
    /// The pairs are those the definitions give:
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.1">RFC 7518 Section 3.1</see> with
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Section 3.3</see> (<c>RS256</c> to
    /// <c>RS512</c>, RSASSA-PKCS1-v1_5 with SHA-256 to SHA-512),
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Section 3.4</see> (<c>ES256</c> over
    /// P-256, <c>ES384</c> over P-384, <c>ES512</c> over P-521) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Section 3.5</see> (<c>PS256</c> to
    /// <c>PS512</c>, RSASSA-PSS with SHA-256 to SHA-512);
    /// <see href="https://www.rfc-editor.org/rfc/rfc8812#section-3.2">RFC 8812 Section 3.2</see> (<c>ES256K</c>
    /// over secp256k1); <see href="https://www.rfc-editor.org/rfc/rfc8037#section-3.1">RFC 8037 Section 3.1</see>
    /// (<c>EdDSA</c> over the Ed25519 subtype) and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8037#section-3.2">Section 3.2</see> for the X25519 subtype:
    /// "These subtypes MUST NOT be used for signing.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-2.2">RFC 9864 Section 2.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.1">Section 4.1.1</see> (<c>Ed25519</c>
    /// over Ed25519); <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.2.1">RFC 9864 Section
    /// 4.2.1</see> (the COSE registrations <c>ESB256</c> to <c>ESB512</c>, which the library also accepts as
    /// JOSE names, each over the Brainpool curve its registration names). The pairs of <c>ML-DSA-44</c>,
    /// <c>ML-DSA-65</c> and <c>ML-DSA-87</c> rest on the parameter-set names alone, each name over the ML-DSA key
    /// algorithm of the parameter set it spells: <see href="https://csrc.nist.gov/pubs/fips/204/final">FIPS
    /// 204</see> Section 3.3 says "In this document, the abbreviations ML-DSA-44, ML-DSA-65, and ML-DSA-87 are
    /// used to refer to ML-DSA with the parameter choices given in Table 1."; no JOSE registration of these names
    /// is quoted here. An RSA size tag is verified by the
    /// library's providers as RSASSA-PKCS1-v1_5 with SHA-256, so <c>RS256</c> is its one algorithm; a
    /// padding-and-hash tag is the key algorithm of the one name with that padding and hash.
    /// </summary>
    /// <param name="alg">The declared algorithm.</param>
    /// <param name="keyAlgorithm">The algorithm the verifying public key is tagged with.</param>
    /// <param name="isBound">Whether the table binds the pair.</param>
    [TestMethod]
    [DynamicData(nameof(BindingRows))]
    public void AlgorithmsBindToTheirKeyAlgorithms(string alg, CryptoAlgorithm keyAlgorithm, bool isBound)
    {
        Assert.AreEqual(isBound, JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm),
            $"'{alg}' over a {keyAlgorithm} key algorithm.");
    }


    /// <summary>
    /// A key algorithm no JWS algorithm is defined over binds no algorithm of the table: every value of
    /// <see cref="UnboundKeyAlgorithms"/>, among them the X25519 key agreement curve and brainpoolP224r1, the one
    /// of the Brainpool curves the library tags that no ESB registration names.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8037#section-3.2">RFC 8037 Section 3.2</see> on the X25519
    /// and X448 subtypes: "These subtypes MUST NOT be used for signing."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>: "The JWS
    /// Signature value is not valid if the "alg" value does not represent a supported algorithm or if there is
    /// not a key for use with that algorithm associated with the party that digitally signed or MACed the
    /// content."
    /// </summary>
    /// <param name="alg">An algorithm the table binds to some other key algorithm.</param>
    [TestMethod]
    [DynamicData(nameof(TableAlgorithmRows))]
    public void AKeyAlgorithmNoJwsAlgorithmIsDefinedOverBindsNone(string alg)
    {
        foreach(CryptoAlgorithm keyAlgorithm in UnboundKeyAlgorithms)
        {
            Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm), $"'{alg}' over a {keyAlgorithm} key algorithm.");
        }
    }


    /// <summary>
    /// A name the table does not name binds no predefined key algorithm, the three MAC algorithms among them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>: "The JWS
    /// Signature value is not valid if the "alg" value does not represent a supported algorithm or if there is
    /// not a key for use with that algorithm associated with the party that digitally signed or MACed the
    /// content."
    /// </summary>
    /// <param name="alg">The name the table binds to no key algorithm.</param>
    [TestMethod]
    [DynamicData(nameof(UnboundNameRows))]
    public void ANameTheTableDoesNotNameBindsNoKeyAlgorithm(string alg)
    {
        foreach(CryptoAlgorithm keyAlgorithm in AllKeyAlgorithms)
        {
            Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm), $"'{alg}' over a {keyAlgorithm} key algorithm.");
        }
    }


    /// <summary>
    /// <c>Ed448</c> is an algorithm of no predefined key algorithm: the library tags no Ed448 public key, so no
    /// verification it runs computes the operation the name fixes, and <see cref="WellKnownJwaValues"/> holds no
    /// member for it, so the row spells it as the registration does.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-2.2">RFC 9864 Section 2.2</see> defines it and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-4.1.1">Section 4.1.1</see> registers it with the
    /// description "EdDSA using the Ed448 parameter set in Section 5.2 of [RFC8032]".
    /// </summary>
    [TestMethod]
    public void Ed448IsAnAlgorithmOfNoKeyAlgorithm()
    {
        foreach(CryptoAlgorithm keyAlgorithm in AllKeyAlgorithms)
        {
            Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey("Ed448", keyAlgorithm), $"'Ed448' over a {keyAlgorithm} key algorithm.");
        }
    }


    /// <summary>
    /// A null name, a header without <c>alg</c>, is an algorithm of no predefined key algorithm, and the table
    /// answers it without throwing.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1">RFC 7515 Section 4.1.1</see>:
    /// "This Header Parameter MUST be present and MUST be understood and processed by implementations."
    /// </summary>
    [TestMethod]
    public void ANullNameIsAnAlgorithmOfNoKeyAlgorithm()
    {
        foreach(CryptoAlgorithm keyAlgorithm in AllKeyAlgorithms)
        {
            Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(null, keyAlgorithm), $"A null name over a {keyAlgorithm} key algorithm.");
        }
    }


    /// <summary>
    /// Every algorithm of the table binds exactly the key algorithms its rows in <see cref="BindingRows"/> admit,
    /// over every key algorithm the table binds: one key algorithm for each elliptic-curve, Edwards-curve,
    /// Brainpool and ML-DSA algorithm, the two RSA size tags and <see cref="CryptoAlgorithm.RsaSha256"/> for
    /// <c>RS256</c>, and the one padding-and-hash tag for each other RSA algorithm, so the table admits no pair
    /// its rows do not name. The fully-specified <c>Ed25519</c> binds the Ed25519 key algorithm alone, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc9864#section-1">RFC 9864 Section 1</see> calls an identifier
    /// fully specified when it is one of "Those that fully determine the cryptographic operations to be
    /// performed, including any curve, key derivation function (KDF), and hash functions."
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 Section 3.1</see>: "Moreover,
    /// each key MUST be used with exactly one algorithm, and this MUST be checked when the cryptographic
    /// operation is performed."
    /// </summary>
    [TestMethod]
    public void TheTableAdmitsNoPairItsRowsDoNotName()
    {
        HashSet<(string Algorithm, CryptoAlgorithm KeyAlgorithm)> named = [.. BindingRows()
            .Where(row => (bool)row[2])
            .Select(row => ((string)row[0], (CryptoAlgorithm)row[1]))];

        foreach(string algorithm in TableAlgorithms)
        {
            foreach(CryptoAlgorithm keyAlgorithm in TableKeyAlgorithms)
            {
                bool isNamed = named.Contains((algorithm, keyAlgorithm));
                Assert.AreEqual(isNamed, JwsAlgorithmKeyBinding.IsAlgorithmOfKey(algorithm, keyAlgorithm),
                    $"'{algorithm}' over a {keyAlgorithm} key algorithm.");
            }
        }

        Assert.HasCount(21, named);
    }
}

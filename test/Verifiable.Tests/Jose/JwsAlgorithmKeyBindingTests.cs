using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Rows for <see cref="JwsAlgorithmKeyBinding.IsAlgorithmOfKey(string, CryptoAlgorithm)"/>: every
/// algorithm and key pair the table admits, for each algorithm a key it refuses, the keys no JWS
/// algorithm is defined over, and the names the table holds no key for.
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.1">RFC 8725 section 3.1</see>: "The
/// library MUST ensure that the "alg" or "enc" header specifies the same algorithm that is used for
/// the cryptographic operation."
/// </summary>
[TestClass]
internal sealed class JwsAlgorithmKeyBindingTests
{
    /// <summary>The key algorithms of the table's RSA rows: both RSA sizes the library tags.</summary>
    private static CryptoAlgorithm[] RsaKeyAlgorithms { get; } = [CryptoAlgorithm.Rsa2048, CryptoAlgorithm.Rsa4096];


    /// <summary>The six RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms the table binds to an RSA key.</summary>
    private static string[] RsaAlgorithms { get; } =
    [
        WellKnownJwaValues.Rs256, WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512,
        WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512
    ];


    /// <summary>Every algorithm the table binds to a key.</summary>
    private static string[] TableAlgorithms { get; } =
    [
        WellKnownJwaValues.Es256, WellKnownJwaValues.Es384, WellKnownJwaValues.Es512, WellKnownJwaValues.Es256K,
        WellKnownJwaValues.EdDsa,
        WellKnownJwaValues.Rs256, WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512,
        WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512,
        WellKnownJwaValues.Esb256, WellKnownJwaValues.Esb320, WellKnownJwaValues.Esb384, WellKnownJwaValues.Esb512,
        WellKnownJwaValues.MlDsa44, WellKnownJwaValues.MlDsa65, WellKnownJwaValues.MlDsa87
    ];


    /// <summary>Every key algorithm some algorithm of the table binds.</summary>
    private static CryptoAlgorithm[] TableKeyAlgorithms { get; } =
    [
        CryptoAlgorithm.P256, CryptoAlgorithm.P384, CryptoAlgorithm.P521, CryptoAlgorithm.Secp256k1,
        CryptoAlgorithm.Ed25519, CryptoAlgorithm.Rsa2048, CryptoAlgorithm.Rsa4096,
        CryptoAlgorithm.BrainpoolP256r1, CryptoAlgorithm.BrainpoolP320r1, CryptoAlgorithm.BrainpoolP384r1,
        CryptoAlgorithm.BrainpoolP512r1, CryptoAlgorithm.MlDsa44, CryptoAlgorithm.MlDsa65, CryptoAlgorithm.MlDsa87
    ];


    /// <summary>
    /// The rows of <see cref="AlgorithmsBindToTheirKeys"/>: every pair the table admits, answered
    /// <see langword="true"/>, then for each algorithm a key of another curve, family or parameter set,
    /// answered <see langword="false"/>.
    /// </summary>
    /// <returns>The algorithm, the key algorithm and whether the table binds them.</returns>
    public static IEnumerable<object[]> BindingRows()
    {
        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.P256, true];
        yield return [WellKnownJwaValues.Es384, CryptoAlgorithm.P384, true];
        yield return [WellKnownJwaValues.Es512, CryptoAlgorithm.P521, true];
        yield return [WellKnownJwaValues.Es256K, CryptoAlgorithm.Secp256k1, true];
        yield return [WellKnownJwaValues.EdDsa, CryptoAlgorithm.Ed25519, true];
        foreach(string rsaAlgorithm in RsaAlgorithms)
        {
            foreach(CryptoAlgorithm rsaKey in RsaKeyAlgorithms)
            {
                yield return [rsaAlgorithm, rsaKey, true];
            }
        }

        yield return [WellKnownJwaValues.Esb256, CryptoAlgorithm.BrainpoolP256r1, true];
        yield return [WellKnownJwaValues.Esb320, CryptoAlgorithm.BrainpoolP320r1, true];
        yield return [WellKnownJwaValues.Esb384, CryptoAlgorithm.BrainpoolP384r1, true];
        yield return [WellKnownJwaValues.Esb512, CryptoAlgorithm.BrainpoolP512r1, true];
        yield return [WellKnownJwaValues.MlDsa44, CryptoAlgorithm.MlDsa44, true];
        yield return [WellKnownJwaValues.MlDsa65, CryptoAlgorithm.MlDsa65, true];
        yield return [WellKnownJwaValues.MlDsa87, CryptoAlgorithm.MlDsa87, true];

        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Es256, CryptoAlgorithm.BrainpoolP256r1, false];
        yield return [WellKnownJwaValues.Es384, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.Es512, CryptoAlgorithm.P384, false];
        yield return [WellKnownJwaValues.Es256K, CryptoAlgorithm.P256, false];
        yield return [WellKnownJwaValues.EdDsa, CryptoAlgorithm.X25519, false];
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
    /// The rows of <see cref="AKeyNoJwsAlgorithmIsDefinedOverBindsNone"/>: every algorithm the table
    /// binds.
    /// </summary>
    /// <returns>Each algorithm of the table.</returns>
    public static IEnumerable<object[]> TableAlgorithmRows() => TableAlgorithms.Select(algorithm => new object[] { algorithm });


    /// <summary>
    /// The rows of <see cref="ANameTheTableHoldsNoKeyForBindsNone"/>: <c>none</c>, a MAC algorithm, an
    /// encryption algorithm, an empty value and two spellings of <c>ES256</c> that are not it, since
    /// RFC 7515 section 4.1.1 makes "alg" "a case-sensitive ASCII string".
    /// </summary>
    /// <returns>Each name the table binds to no key.</returns>
    public static IEnumerable<object[]> UnboundNameRows()
    {
        yield return [WellKnownJwaValues.None];
        yield return [WellKnownJwaValues.Hs256];
        yield return ["RSA-OAEP"];
        yield return [string.Empty];
        yield return ["es256"];
        yield return ["ES256 "];
    }


    /// <summary>
    /// The table answers each row as its pair is defined: an elliptic-curve, Edwards-curve, Brainpool or
    /// ML-DSA algorithm binds only the key it is defined over, and the RSASSA-PKCS1-v1_5 and RSASSA-PSS
    /// algorithms bind either RSA size and no other key.
    /// </summary>
    /// <param name="alg">The declared algorithm.</param>
    /// <param name="keyAlgorithm">The algorithm the verifying key is tagged with.</param>
    /// <param name="isBound">Whether the table binds the pair.</param>
    [TestMethod]
    [DynamicData(nameof(BindingRows))]
    public void AlgorithmsBindToTheirKeys(string alg, CryptoAlgorithm keyAlgorithm, bool isBound)
    {
        Assert.AreEqual(isBound, JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm),
            $"'{alg}' over a {keyAlgorithm} key.");
    }


    /// <summary>
    /// A key no JWS algorithm is defined over binds no algorithm of the table: an X25519 key-agreement
    /// key and a brainpoolP224r1 key, the one Brainpool curve no ESB algorithm names.
    /// </summary>
    /// <param name="alg">An algorithm the table binds to some other key.</param>
    [TestMethod]
    [DynamicData(nameof(TableAlgorithmRows))]
    public void AKeyNoJwsAlgorithmIsDefinedOverBindsNone(string alg)
    {
        Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, CryptoAlgorithm.X25519), $"'{alg}' over an X25519 key.");
        Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, CryptoAlgorithm.BrainpoolP224r1), $"'{alg}' over a brainpoolP224r1 key.");
    }


    /// <summary>
    /// A name the table holds no key for binds no key of any kind the table knows.
    /// </summary>
    /// <param name="alg">The name the table binds to no key.</param>
    [TestMethod]
    [DynamicData(nameof(UnboundNameRows))]
    public void ANameTheTableHoldsNoKeyForBindsNone(string alg)
    {
        foreach(CryptoAlgorithm keyAlgorithm in TableKeyAlgorithms)
        {
            Assert.IsFalse(JwsAlgorithmKeyBinding.IsAlgorithmOfKey(alg, keyAlgorithm), $"'{alg}' over a {keyAlgorithm} key.");
        }
    }


    /// <summary>
    /// Every algorithm of the table binds exactly the keys its rows in <see cref="BindingRows"/> admit:
    /// one key for each elliptic-curve, Edwards-curve, Brainpool and ML-DSA algorithm and the two RSA
    /// sizes for each RSA algorithm, so the table admits no pair its rows do not name.
    /// </summary>
    [TestMethod]
    public void TheTableAdmitsNoPairItsRowsDoNotName()
    {
        HashSet<(string Algorithm, CryptoAlgorithm Key)> named = [.. BindingRows()
            .Where(row => (bool)row[2])
            .Select(row => ((string)row[0], (CryptoAlgorithm)row[1]))];

        foreach(string algorithm in TableAlgorithms)
        {
            foreach(CryptoAlgorithm keyAlgorithm in TableKeyAlgorithms)
            {
                bool isNamed = named.Contains((algorithm, keyAlgorithm));
                Assert.AreEqual(isNamed, JwsAlgorithmKeyBinding.IsAlgorithmOfKey(algorithm, keyAlgorithm),
                    $"'{algorithm}' over a {keyAlgorithm} key.");
            }
        }

        Assert.HasCount(24, named);
    }
}

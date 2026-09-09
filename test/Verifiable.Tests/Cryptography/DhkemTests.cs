using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for <see cref="Dhkem"/> against
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1's
/// "DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM" base setup vector.
/// </summary>
/// <remarks>
/// <see cref="Dhkem"/> performs no group arithmetic - it consumes an already-computed Diffie-Hellman
/// value. The Diffie-Hellman step (<c>DH(skX, pkY)</c>, RFC 9180 Section 4.1) is therefore driven
/// here with BouncyCastle directly (the same NIST P-256 arithmetic
/// <c>Verifiable.Tests.Tpm.BouncyCastleTpmEccSigningBackend</c> uses for the TPM salted-session
/// suite, transcribed independently rather than shared, so this fixture stays free of any
/// <c>Verifiable.Tpm</c> dependency), so both the Encap and Decap arms of the KEM are exercised
/// through the real elliptic-curve math and not just handed a pre-computed <c>dh</c> constant.
/// </remarks>
[TestClass]
internal sealed class DhkemTests
{
    /// <summary>The MSTest-injected context; supplies <see cref="TestContext.CancellationToken"/> to every async call below.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>RFC 9180, Appendix A.3.1: the recipient's SEC 1 uncompressed public key <c>pkRm</c> (65 octets).</summary>
    private const string PkRm =
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";

    /// <summary>RFC 9180, Appendix A.3.1: the recipient's private scalar <c>skRm</c> (32 octets, unsigned big-endian).</summary>
    private const string SkRm = "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";

    /// <summary>RFC 9180, Appendix A.3.1: the ephemeral sender's private scalar <c>skEm</c> (32 octets, unsigned big-endian).</summary>
    private const string SkEm = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

    /// <summary>
    /// RFC 9180, Appendix A.3.1: <c>enc</c>, the encapsulated key - the ephemeral sender's SEC 1
    /// uncompressed public key <c>pkEm</c> serialized (65 octets). The vector's <c>enc</c> and
    /// <c>pkEm</c> fields are byte-identical, as Section 4.1's <c>Encap</c> requires
    /// (<c>enc = SerializePublicKey(pkE)</c>).
    /// </summary>
    private const string Enc =
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";

    /// <summary>RFC 9180, Appendix A.3.1: the expected 32-octet DHKEM <c>shared_secret</c>.</summary>
    private const string SharedSecret = "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8";

    /// <summary>
    /// Encap side: RFC 9180, Appendix A.3.1. Computes <c>dh = DH(skEm, pkRm)</c> with the ephemeral
    /// sender's private scalar and the recipient's public key (Section 4.1's <c>Encap(pkR)</c>),
    /// binds <c>kem_context = concat(enc, pkRm)</c>, and asserts
    /// <see cref="Dhkem.ExtractAndExpandAsync"/> reproduces the vector's <c>shared_secret</c>
    /// exactly under <see cref="Dhkem.P256HkdfSha256"/>.
    /// </summary>
    [TestMethod]
    public async Task EncapSideReproducesRfc9180AppendixA31SharedSecret()
    {
        byte[] dh = ComputeP256DiffieHellman(Convert.FromHexString(SkEm), Convert.FromHexString(PkRm));
        byte[] kemContext = Concat(Convert.FromHexString(Enc), Convert.FromHexString(PkRm));

        using IMemoryOwner<byte> actual = await Dhkem.ExtractAndExpandAsync(
            Dhkem.P256HkdfSha256.HashAlgorithm, dh, kemContext, Dhkem.P256HkdfSha256.KemId, Dhkem.P256HkdfSha256.NSecret,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SharedSecret, Convert.ToHexStringLower(actual.Memory.Span[..Dhkem.P256HkdfSha256.NSecret]),
            "The encap-side DHKEM derivation must match RFC 9180 Appendix A.3.1's known-answer shared_secret.");
    }

    /// <summary>
    /// Decap side: RFC 9180, Appendix A.3.1. Computes <c>dh = DH(skRm, pkE)</c> with the recipient's
    /// private scalar and the ephemeral sender's public key recovered from <c>enc</c> (Section 4.1's
    /// <c>Decap(enc, skR)</c>), binds the same <c>kem_context = concat(enc, pkRm)</c>, and asserts
    /// <see cref="Dhkem.ExtractAndExpandAsync"/> reproduces the vector's <c>shared_secret</c> -
    /// proving the decap arm's independently-computed <c>dh</c> (via the peer's private key rather
    /// than the encap arm's) still lands on the same DHKEM shared secret.
    /// </summary>
    [TestMethod]
    public async Task DecapSideReproducesRfc9180AppendixA31SharedSecret()
    {
        byte[] dh = ComputeP256DiffieHellman(Convert.FromHexString(SkRm), Convert.FromHexString(Enc));
        byte[] kemContext = Concat(Convert.FromHexString(Enc), Convert.FromHexString(PkRm));

        using IMemoryOwner<byte> actual = await Dhkem.ExtractAndExpandAsync(
            Dhkem.P256HkdfSha256.HashAlgorithm, dh, kemContext, Dhkem.P256HkdfSha256.KemId, Dhkem.P256HkdfSha256.NSecret,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SharedSecret, Convert.ToHexStringLower(actual.Memory.Span[..Dhkem.P256HkdfSha256.NSecret]),
            "The decap-side DHKEM derivation must match RFC 9180 Appendix A.3.1's known-answer shared_secret.");
    }

    /// <summary>
    /// RFC 9180, Section 4.1: <c>suite_id = concat("KEM", I2OSP(kem_id, 2))</c> binds the KEM
    /// identifier into every labeled HKDF call. Re-deriving the Appendix A.3.1 vector's <c>dh</c>/
    /// <c>kem_context</c> under a foreign <c>kem_id</c> (0x0011, DHKEM(P-384, HKDF-SHA384)'s
    /// identifier per Section 7.1, Table 2) must land on a different shared secret than the vector's
    /// own 0x0010 suite - proving <paramref name="kemId"/> genuinely participates in derivation
    /// rather than being cosmetic.
    /// </summary>
    [TestMethod]
    public async Task WrongSuiteIdYieldsDifferentSharedSecret()
    {
        byte[] dh = ComputeP256DiffieHellman(Convert.FromHexString(SkEm), Convert.FromHexString(PkRm));
        byte[] kemContext = Concat(Convert.FromHexString(Enc), Convert.FromHexString(PkRm));

        const ushort foreignKemId = 0x0011;

        using IMemoryOwner<byte> actual = await Dhkem.ExtractAndExpandAsync(
            Dhkem.P256HkdfSha256.HashAlgorithm, dh, kemContext, foreignKemId, Dhkem.P256HkdfSha256.NSecret,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(SharedSecret, Convert.ToHexStringLower(actual.Memory.Span[..Dhkem.P256HkdfSha256.NSecret]),
            "A foreign kem_id must not reproduce the 0x0010 suite's known-answer shared_secret - suite_id must participate in the derivation.");
    }

    /// <summary>
    /// RFC 9180, Section 4: <c>LabeledExpand</c>'s <c>labeled_info</c> begins with
    /// <c>I2OSP(L, 2)</c>, so the requested output length <c>L</c> is folded into every HKDF-Expand
    /// round rather than only truncating the result. Requesting a shorter secret (16 octets) from
    /// the Appendix A.3.1 vector's <c>dh</c>/<c>kem_context</c> must therefore differ from the
    /// leading 16 octets of the vector's 32-octet <c>shared_secret</c>, unlike plain (unlabeled)
    /// HKDF-Expand, where a shorter <c>L</c> is always a strict prefix of a longer one.
    /// </summary>
    [TestMethod]
    public async Task ShorterNSecretIsNotATruncationOfTheLongerSharedSecret()
    {
        byte[] dh = ComputeP256DiffieHellman(Convert.FromHexString(SkEm), Convert.FromHexString(PkRm));
        byte[] kemContext = Concat(Convert.FromHexString(Enc), Convert.FromHexString(PkRm));
        const int shortNSecret = 16;

        using IMemoryOwner<byte> actual = await Dhkem.ExtractAndExpandAsync(
            Dhkem.P256HkdfSha256.HashAlgorithm, dh, kemContext, Dhkem.P256HkdfSha256.KemId, shortNSecret,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        string actualHex = Convert.ToHexStringLower(actual.Memory.Span[..shortNSecret]);
        string truncatedThirtyTwoByteAnswer = SharedSecret[..(shortNSecret * 2)];

        Assert.AreNotEqual(truncatedThirtyTwoByteAnswer, actualHex,
            "L is baked into labeled_info for every HKDF-Expand round, so a shorter requested Nsecret is a fresh derivation, not a prefix of the longer one.");
    }

    /// <summary>
    /// Computes the raw NIST P-256 Diffie-Hellman value <c>dh</c> RFC 9180 Section 4.1's
    /// <c>DH(skX, pkY)</c> names - the affine x-coordinate of <paramref name="privateScalar"/> times
    /// <paramref name="peerPublicPoint"/>, left-padded to the 32-octet field width (Section 4.1:
    /// "the size Ndh of the Diffie-Hellman shared secret is equal to ... the x-coordinate of the
    /// resulting elliptic curve point"). Runs on BouncyCastle so this fixture drives the group
    /// arithmetic independently of any project ECDH backend; <see cref="Dhkem"/> itself performs
    /// none.
    /// </summary>
    /// <param name="privateScalar">The local party's private scalar, unsigned big-endian (32 octets).</param>
    /// <param name="peerPublicPoint">The peer's public point, SEC 1 uncompressed (<c>0x04 || X || Y</c>, 65 octets).</param>
    /// <returns>The 32-octet shared value <c>dh</c>.</returns>
    private static byte[] ComputeP256DiffieHellman(byte[] privateScalar, byte[] peerPublicPoint)
    {
        X9ECParameters parameters = SecNamedCurves.GetByName("secp256r1");
        var domain = new ECDomainParameters(parameters.Curve, parameters.G, parameters.N, parameters.H, parameters.GetSeed());

        var scalar = new BigInteger(1, privateScalar);
        Org.BouncyCastle.Math.EC.ECPoint peer = domain.Curve.DecodePoint(peerPublicPoint);
        Org.BouncyCastle.Math.EC.ECPoint product = peer.Multiply(scalar).Normalize();

        return LeftPad(product.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), 32);
    }

    /// <summary>Left-pads a big-endian value to a fixed width, as SEC 1 coordinate encoding requires.</summary>
    /// <param name="value">The big-endian value. BouncyCastle's unsigned encoding may omit leading zero bytes.</param>
    /// <param name="length">The fixed width to produce.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] LeftPad(byte[] value, int length)
    {
        if(value.Length == length)
        {
            return value;
        }

        byte[] result = new byte[length];
        value.CopyTo(result, length - value.Length);

        return result;
    }

    /// <summary>Concatenates two byte sequences, as RFC 9180's <c>concat(...)</c> notation does when building <c>kem_context</c>.</summary>
    /// <param name="first">The leading sequence.</param>
    /// <param name="second">The trailing sequence.</param>
    /// <returns>A new array holding <paramref name="first"/> followed by <paramref name="second"/>.</returns>
    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);

        return result;
    }
}

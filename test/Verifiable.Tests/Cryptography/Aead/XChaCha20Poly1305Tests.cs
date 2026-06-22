using System;
using Verifiable.BouncyCastle;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Primitive-level known-answer coverage for the XChaCha20-Poly1305 (<c>XC20P</c>) content cipher. The
/// full AEAD is interop-anchored by the DIDComm v2.1 Appendix C.3 example 1 vector (decrypt) and the X25519
/// + XC20P round trip (encrypt), but the HChaCha20 subkey derivation is the one step BouncyCastle 2.6.2 does
/// not provide and is therefore hand-written. This test pins that hand-written core directly to its own
/// known-answer vector so a future edit that only manifests on a different nonce cannot pass unnoticed.
/// </summary>
[TestClass]
internal sealed class XChaCha20Poly1305Tests
{
    /// <summary>
    /// HChaCha20 matches the draft-irtf-cfrg-xchacha-03 §2.2.1 known-answer test vector: from the all-bytes
    /// key <c>00 01 .. 1f</c> and the 16-byte nonce <c>00000009 0000004a 00000000 31415927</c> it derives the
    /// 256-bit subkey <c>82413b42 27b27bfe d30e4250 8a877d73 a0f9e4d5 8a74a853 c12ec413 26d3ecdc</c>. This
    /// independently fixes the ChaCha constants, the 20-round count, the column/diagonal quarter-round order,
    /// the little-endian word loads/stores, and the no-feed-forward output extraction.
    /// </summary>
    [TestMethod]
    public void HChaCha20_MatchesDraftIrtfCfrgXchacha03Section221Vector()
    {
        ReadOnlySpan<byte> key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        ReadOnlySpan<byte> nonce = Convert.FromHexString("000000090000004a0000000031415927");
        Span<byte> subkey = stackalloc byte[32];

        BouncyCastleKeyAgreementFunctions.HChaCha20(key, nonce, subkey);

        Assert.AreEqual(
            "82413B4227B27BFED30E42508A877D73A0F9E4D58A74A853C12EC41326D3ECDC",
            Convert.ToHexString(subkey),
            "HChaCha20 MUST reproduce the draft-irtf-cfrg-xchacha-03 §2.2.1 subkey vector.");
    }
}

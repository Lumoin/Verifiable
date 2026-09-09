using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Known-answer test for <see cref="DhkemEncapsulation.EncapsulateAsync"/> — the host-side DHKEM(P-256,
/// HKDF-SHA256) encapsulation core <c>TPM2_Encapsulate()</c>'s own simulator effect composes over (TPM 2.0
/// Library Part 1, clause 44.4.2) — against
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1's "DHKEM(P-256,
/// HKDF-SHA256), HKDF-SHA256, AES-128-GCM" base setup vector.
/// </summary>
/// <remarks>
/// <see cref="Verifiable.Tests.Cryptography.DhkemTests"/> proves the KDF composition
/// (<see cref="Dhkem.ExtractAndExpandAsync"/>) reproduces the vector's <c>shared_secret</c> from an
/// already-computed <c>dh</c>/<c>kem_context</c> supplied directly by the test. This test proves the layer
/// above it: driving the vector's own ephemeral (<c>skEm</c>, <c>pkEm</c>) through
/// <see cref="DhkemEncapsulation.EncapsulateAsync"/>'s <c>generateKey</c> delegate — the same delegate shape
/// the simulator's own Encapsulate effect and a real <c>TPM2_CreatePrimary()</c> ephemeral draw use —
/// reproduces the vector's <c>enc</c> AND <c>shared_secret</c> from nothing but the recipient's public point
/// <c>pkRm</c>, the same inputs the RFC's own <c>Encap(pkR)</c> takes.
/// </remarks>
[TestClass]
internal sealed class DhkemEncapsulationTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>RFC 9180, Appendix A.3.1: the recipient's SEC 1 uncompressed public key <c>pkRm</c> (65 octets).</summary>
    private const string PkRm =
        "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0";

    /// <summary>RFC 9180, Appendix A.3.1: the ephemeral sender's private scalar <c>skEm</c> (32 octets, unsigned big-endian).</summary>
    private const string SkEm = "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb";

    /// <summary>
    /// RFC 9180, Appendix A.3.1: <c>enc</c> — the encapsulated key, the ephemeral sender's SEC 1 uncompressed
    /// public key <c>pkEm</c> serialized (65 octets). The vector's <c>enc</c> and <c>pkEm</c> fields are
    /// byte-identical, as Section 4.1's <c>Encap</c> requires (<c>enc = SerializePublicKey(pkE)</c>).
    /// </summary>
    private const string PkEm =
        "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4";

    /// <summary>RFC 9180, Appendix A.3.1: the expected 32-octet DHKEM <c>shared_secret</c>.</summary>
    private const string SharedSecret = "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8";

    /// <summary>
    /// Injects RFC 9180 Appendix A.3.1's fixed ephemeral (<c>skEm</c>, <c>pkEm</c>) through
    /// <see cref="DhkemEncapsulation.EncapsulateAsync"/>'s ordinary <c>generateKey</c>/<c>computeSharedSecret</c>
    /// delegate parameters — no test seam in production — and asserts the returned ciphertext and shared
    /// secret reproduce the vector's <c>enc</c> and <c>shared_secret</c> byte-exactly
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Appendix A.3.1).
    /// </summary>
    [TestMethod]
    public async Task EncapsulateAsyncReproducesRfc9180AppendixA31EncAndSharedSecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] recipientPoint = Convert.FromHexString(PkRm);
        TpmEccSigningBackend backend = BouncyCastleTpmEccSigningBackend.Create();

        (Tpm2bSharedSecret sharedSecret, Tpm2bKemCiphertext ciphertext) = await DhkemEncapsulation.EncapsulateAsync(
            recipientPoint, FixedEphemeralKeyAsync, backend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

        using(sharedSecret)
        using(ciphertext)
        {
            Assert.AreEqual(
                PkEm, Convert.ToHexStringLower(ciphertext.Ciphertext),
                "enc must be pkE_serialized — the vector's own ephemeral public key, byte-exactly (Part 1, clause 44.4.2 step 3).");
            Assert.AreEqual(
                SharedSecret, Convert.ToHexStringLower(sharedSecret.AsReadOnlySpan()),
                "The host-side encapsulation core must reproduce RFC 9180 Appendix A.3.1's known-answer shared_secret from the vector ephemeral alone.");
        }
    }

    /// <summary>
    /// "The sender MUST validate the recipient's public key pkR" with partial public-key validation
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see>, Section 7.1.4): a recipient point
    /// whose Y coordinate is corrupted by one octet keeps the SEC 1 shape but is no longer on P-256, and the
    /// encapsulation core refuses it before the ephemeral is ever drawn — no ciphertext, no shared secret.
    /// </summary>
    [TestMethod]
    public async Task EncapsulateAsyncRefusesAnOffCurveRecipientPoint()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] offCurvePoint = Convert.FromHexString(PkRm);
        offCurvePoint[^1] ^= 0x01;
        TpmEccSigningBackend backend = BouncyCastleTpmEccSigningBackend.Create();

        //The refusal fires before the ephemeral is drawn or any carrier is rented, so nothing is returned to
        //dispose; the discard keeps the lambda a single expression.
        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            _ = await DhkemEncapsulation.EncapsulateAsync(
                offCurvePoint, FixedEphemeralKeyAsync, backend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual("recipientPublicPoint", exception.ParamName, "An off-curve recipient point must be refused on the pkR parameter itself.");
    }

    /// <summary>The fixed <c>generateKey</c> delegate standing in for step 1's ephemeral draw: returns RFC 9180 Appendix A.3.1's own (<c>skEm</c>, <c>pkEm</c>) instead of a freshly-generated pair.</summary>
    /// <param name="curve">The requested curve (always P-256 for this delegate's one caller).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token, unused — the fixed key needs no asynchronous work.</param>
    /// <returns>The vector's ephemeral key pair, in pool-owned carriers the caller disposes.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the scalar and point carriers transfers to the returned TpmGeneratedEccKey, which the encapsulation core disposes after the ephemeral has been used.")]
    private static ValueTask<TpmGeneratedEccKey> FixedEphemeralKeyAsync(TpmEccCurveConstants curve, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var privateScalar = new PrivateKeyMemory(RentCopy(Convert.FromHexString(SkEm), pool), CryptoTags.P256PrivateKey);
        EncodedEcPoint publicPoint = EncodedEcPoint.FromBytes(Convert.FromHexString(PkEm), CryptoTags.P256ExchangePublicKey, pool);

        return ValueTask.FromResult(new TpmGeneratedEccKey(privateScalar, publicPoint));
    }

    /// <summary>Rents pool memory of <paramref name="bytes"/>'s length and copies the bytes in.</summary>
    /// <param name="bytes">The source bytes.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The pool-owned buffer holding a copy of <paramref name="bytes"/>.</returns>
    private static IMemoryOwner<byte> RentCopy(byte[] bytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.AsSpan().CopyTo(owner.Memory.Span);

        return owner;
    }
}

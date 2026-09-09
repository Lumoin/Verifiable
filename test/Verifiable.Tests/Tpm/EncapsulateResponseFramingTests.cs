using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="EncapsulateResponse"/> (TPM2_Encapsulate, Table 61): asserts the
/// response's two-TPM2B parameter order — <c>sharedSecret</c> (TPM2B_SHARED_SECRET) then <c>ciphertext</c>
/// (TPM2B_KEM_CIPHERTEXT) — against hand-computed big-endian octets, mirroring
/// <see cref="KemInputFramingTests"/>'s wire-format style for the command side.
/// </summary>
[TestClass]
internal sealed class EncapsulateResponseFramingTests
{
    /// <summary>
    /// A hand-framed Table 61 response — <c>sharedSecret</c>'s TPM2B THEN <c>ciphertext</c>'s TPM2B, in that
    /// order — parses to the expected fields byte-exactly
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10, Table 61).
    /// </summary>
    [TestMethod]
    public void EncapsulateResponseParsesSharedSecretThenCiphertextByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sharedSecretBytes = [0x11, 0x22, 0x33, 0x44];
        byte[] ciphertextBytes = [0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        byte[] wire =
        [
            0x00, 0x04, 0x11, 0x22, 0x33, 0x44,             //sharedSecret: TPM2B_SHARED_SECRET, size 4.
            0x00, 0x06, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,  //ciphertext: TPM2B_KEM_CIPHERTEXT, size 6.
        ];

        var reader = new TpmReader(wire);
        using EncapsulateResponse response = EncapsulateResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The response's two TPM2Bs must account for every octet in the wire frame.");
        Assert.AreSequenceEqual(sharedSecretBytes, response.SharedSecret.AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(ciphertextBytes, response.Ciphertext.Ciphertext.ToArray());
    }

    /// <summary>
    /// Swapping Table 61's parameter order — framing <c>ciphertext</c>'s octets where <c>sharedSecret</c>'s
    /// are expected, and vice versa — must NOT parse to the same fields: with the sizes and payloads
    /// exchanged, the response's <see cref="Tpm2bSharedSecret"/> and <see cref="Tpm2bKemCiphertext"/> come
    /// back holding the OTHER field's length and bytes, pinning that <see cref="EncapsulateResponse.Parse"/>
    /// reads exactly Table 61's declared order rather than merely two TPM2Bs in either order
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10, Table 61).
    /// </summary>
    [TestMethod]
    public void EncapsulateResponseWithSwappedParameterOrderDoesNotParseToTheSameFields()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sharedSecretBytes = [0x11, 0x22, 0x33, 0x44];
        byte[] ciphertextBytes = [0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        byte[] swapped =
        [
            0x00, 0x06, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,  //ciphertext's own bytes framed FIRST, as if it were sharedSecret.
            0x00, 0x04, 0x11, 0x22, 0x33, 0x44,              //sharedSecret's own bytes framed SECOND, as if it were ciphertext.
        ];

        var reader = new TpmReader(swapped);
        using EncapsulateResponse response = EncapsulateResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.AreNotEqual(sharedSecretBytes.Length, response.SharedSecret.Size, "A swapped order reads ciphertext's own length into sharedSecret's size field.");
        Assert.AreSequenceEqual(ciphertextBytes, response.SharedSecret.AsReadOnlySpan().ToArray(), "A swapped order reads ciphertext's own bytes into sharedSecret.");
        Assert.AreSequenceEqual(sharedSecretBytes, response.Ciphertext.Ciphertext.ToArray(), "A swapped order reads sharedSecret's own bytes into ciphertext.");
    }
}

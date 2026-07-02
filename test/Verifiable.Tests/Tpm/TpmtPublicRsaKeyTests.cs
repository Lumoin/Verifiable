using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Covers building a public area for a <em>generated</em> RSA signing key — one carrying its actual public
/// modulus, the <c>outPublic</c> form a TPM returns from <c>TPM2_CreatePrimary</c>, as opposed to the
/// empty-unique <c>inPublic</c> template a caller supplies. This is the structure the in-house simulator frames
/// for an RSA key, so it is pinned by a wire round-trip: build, serialize, parse back, and confirm the modulus
/// survives.
/// </summary>
[TestClass]
internal sealed class TpmtPublicRsaKeyTests
{
    /// <summary>The modulus length in bytes of a 2048-bit RSA key.</summary>
    private const int Rsa2048ModulusLength = 256;

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the RSA modulus storage transfers to the Tpm2bPublic, which is disposed by its using declaration.")]
    public void RsaSigningPublicAreaCarryingAModulusRoundTrips()
    {
        Span<byte> modulus = stackalloc byte[Rsa2048ModulusLength];
        modulus.Fill(0xC4);

        //A 2048-bit modulus is a 256-octet big-endian integer whose top octet has the high bit set.
        modulus[0] = 0xC4;

        TpmaObject attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT;

        using Tpm2bPublic publicArea = Tpm2bPublic.CreateRsaSigningKey(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            keyBits: 2048,
            TpmtRsaScheme.Null,
            modulus,
            BaseMemoryPool.Shared);

        int size = publicArea.GetSerializedSize();
        using IMemoryOwner<byte> buffer = BaseMemoryPool.Shared.Rent(size);
        var writer = new TpmWriter(buffer.Memory.Span);
        publicArea.WriteTo(ref writer);

        var reader = new TpmReader(buffer.Memory.Span[..size]);
        using Tpm2bPublic parsed = Tpm2bPublic.Parse(ref reader, BaseMemoryPool.Shared);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, parsed.PublicArea.Type, "The parsed public area must be an RSA key.");
        Assert.IsFalse(parsed.PublicArea.Unique.IsEmpty, "An outPublic RSA key must carry a modulus, not an empty template.");
        Assert.IsTrue(modulus.SequenceEqual(parsed.PublicArea.Unique.GetRsaModulus()), "The RSA modulus must survive the wire round-trip.");
    }
}

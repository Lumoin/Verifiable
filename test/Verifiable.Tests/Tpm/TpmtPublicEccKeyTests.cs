using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Covers building a public area for a <em>generated</em> ECC signing key — one carrying its actual public
/// point, the <c>outPublic</c> form a TPM returns from <c>TPM2_CreatePrimary</c>, as opposed to the
/// empty-unique <c>inPublic</c> template a caller supplies. This is the structure the in-house simulator must
/// frame, so it is pinned by a wire round-trip: build, serialize, parse back, and confirm the point survives.
/// </summary>
[TestClass]
internal sealed class TpmtPublicEccKeyTests
{
    /// <summary>The P-256 coordinate length in bytes.</summary>
    private const int P256CoordinateLength = 32;

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the ECC point transfers to the Tpm2bPublic, which is disposed by its using declaration.")]
    public void EccSigningPublicAreaCarryingAPointRoundTrips()
    {
        Span<byte> x = stackalloc byte[P256CoordinateLength];
        Span<byte> y = stackalloc byte[P256CoordinateLength];
        x.Fill(0x11);
        y.Fill(0x22);

        TpmaObject attributes =
            TpmaObject.FIXED_TPM |
            TpmaObject.FIXED_PARENT |
            TpmaObject.SENSITIVE_DATA_ORIGIN |
            TpmaObject.USER_WITH_AUTH |
            TpmaObject.SIGN_ENCRYPT;

        using Tpm2bPublic publicArea = Tpm2bPublic.CreateEccSigningKey(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            attributes,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            TpmsEccPoint.Create(x, y, BaseMemoryPool.Shared));

        int size = publicArea.GetSerializedSize();
        using IMemoryOwner<byte> buffer = BaseMemoryPool.Shared.Rent(size);
        var writer = new TpmWriter(buffer.Memory.Span);
        publicArea.WriteTo(ref writer);

        var reader = new TpmReader(buffer.Memory.Span[..size]);
        using Tpm2bPublic parsed = Tpm2bPublic.Parse(ref reader, BaseMemoryPool.Shared);

        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, parsed.PublicArea.Type, "The parsed public area must be an ECC key.");
        Assert.IsNotNull(parsed.PublicArea.Unique.Ecc, "An outPublic ECC key must carry a unique point, not an empty template.");
        Assert.IsTrue(x.SequenceEqual(parsed.PublicArea.Unique.Ecc!.X.AsReadOnlySpan()), "The X coordinate must survive the wire round-trip.");
        Assert.IsTrue(y.SequenceEqual(parsed.PublicArea.Unique.Ecc!.Y.AsReadOnlySpan()), "The Y coordinate must survive the wire round-trip.");
    }
}

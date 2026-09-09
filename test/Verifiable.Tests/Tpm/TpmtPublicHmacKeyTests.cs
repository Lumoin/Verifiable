using System.Buffers;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Covers <see cref="TpmtPublic.CreateHmacKeyTemplate"/>'s public-area framing and
/// <see cref="Tpm2bSensitiveCreate.ForHmacKey"/>'s TPMS_SENSITIVE_CREATE shape — an HMAC key differs from a
/// sealed data object only in its public area's scheme (Table 179's <c>TPM_ALG_HMAC</c> versus
/// <c>TPM_ALG_NULL</c>); the sensitive area the two builders produce is byte-identical.
/// </summary>
[TestClass]
internal sealed class TpmtPublicHmacKeyTests
{
    /// <summary>
    /// <see cref="TpmtPublic.CreateHmacKeyTemplate"/>'s defaults (unrestricted, TPM-generated, userWithAuth SET,
    /// not duplicable, no policy) frame TPMA_OBJECT as fixedTPM | fixedParent | sensitiveDataOrigin |
    /// userWithAuth | signEncrypt, and the parameters as an HMAC scheme naming the supplied hash — the shape
    /// <c>TPM2_HMAC_Start()</c>/<c>TPM2_HMAC()</c> require (Part 3, clauses 17.2 and 15.5: restricted CLEAR).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.3.2, Table 37; clause 12.2.4, Table 235; clause 11.1.23, Table 179</see>.
    /// </summary>
    [TestMethod]
    public void CreateHmacKeyTemplateFramesTheAttributeWordAndKeyedHashParmsByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtPublic template = TpmtPublic.CreateHmacKeyTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        byte[] expected =
        [
            0x00, 0x08, //type: TPM_ALG_KEYEDHASH.
            0x00, 0x0B, //nameAlg: TPM_ALG_SHA256.
            0x00, 0x04, 0x00, 0x72, //objectAttributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | signEncrypt.
            0x00, 0x00, //authPolicy: empty TPM2B_DIGEST.
            0x00, 0x05, 0x00, 0x0B, //parameters: TPMT_KEYEDHASH_SCHEME(scheme=TPM_ALG_HMAC, hashAlg=TPM_ALG_SHA256).
            0x00, 0x00 //unique: empty TPMU_PUBLIC_ID (a template carries no unique).
        ];
        int expectedLength = expected.Length;
        Assert.AreEqual(expectedLength, template.GetSerializedSize());

        using IMemoryOwner<byte> owner = pool.Rent(expectedLength);
        Span<byte> actual = owner.Memory.Span[..expectedLength];
        var writer = new TpmWriter(actual);
        template.WriteTo(ref writer);

        Assert.IsTrue(actual.SequenceEqual(expected), "The template must frame TPMA_OBJECT and the keyedHash parameters byte-exactly.");
    }

    /// <summary>
    /// <see cref="TpmtPublic.CreateHmacKeyTemplate"/> with <c>isRestricted: true</c> sets TPMA_OBJECT.restricted
    /// in addition to the unrestricted defaults, producing a restricted signing key rather than an ordinary
    /// HMAC key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.3.2, Table 37</see>.
    /// </summary>
    [TestMethod]
    public void CreateHmacKeyTemplateWithIsRestrictedSetsTheRestrictedAttributeBit()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmtPublic template = TpmtPublic.CreateHmacKeyTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_SHA256, pool, isRestricted: true);

        byte[] expectedAttributes = [0x00, 0x05, 0x00, 0x72]; //adds RESTRICTED (0x00010000) to the unrestricted 0x00040072.
        using IMemoryOwner<byte> owner = pool.Rent(expectedAttributes.Length);
        Span<byte> actualAttributes = owner.Memory.Span[..expectedAttributes.Length];
        var writer = new TpmWriter(actualAttributes);
        writer.WriteUInt32((uint)template.ObjectAttributes);

        Assert.IsTrue(actualAttributes.SequenceEqual(expectedAttributes), "isRestricted must add RESTRICTED to the unrestricted attribute word.");
    }

    /// <summary>
    /// <see cref="Tpm2bSensitiveCreate.ForHmacKey"/> and <see cref="Tpm2bSensitiveCreate.ForSealedData(System.ReadOnlySpan{byte}, System.ReadOnlySpan{byte}, BaseMemoryPool)"/>
    /// build the identical TPMS_SENSITIVE_CREATE shape for the same key and authorization value — a sealed
    /// secret and an HMAC key differ only in how the public area's scheme interprets the sensitive data, never
    /// in the sensitive area's own framing.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.15, Table 171</see>.
    /// </summary>
    [TestMethod]
    public void ForHmacKeyProducesTheSameBytesAsForSealedData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] key = [0x11, 0x22, 0x33, 0x44];
        byte[] userAuth = [0xAA, 0xBB];

        using Tpm2bSensitiveCreate hmacSensitive = Tpm2bSensitiveCreate.ForHmacKey(key, userAuth, pool);
        using Tpm2bSensitiveCreate sealedSensitive = Tpm2bSensitiveCreate.ForSealedData(key, userAuth, pool);

        int sealedSize = sealedSensitive.SerializedSize;
        Assert.AreEqual(sealedSize, hmacSensitive.SerializedSize);

        using IMemoryOwner<byte> hmacOwner = pool.Rent(hmacSensitive.SerializedSize);
        Span<byte> hmacBytes = hmacOwner.Memory.Span[..hmacSensitive.SerializedSize];
        var hmacWriter = new TpmWriter(hmacBytes);
        hmacSensitive.WriteTo(ref hmacWriter);

        using IMemoryOwner<byte> sealedOwner = pool.Rent(sealedSize);
        Span<byte> sealedBytes = sealedOwner.Memory.Span[..sealedSize];
        var sealedWriter = new TpmWriter(sealedBytes);
        sealedSensitive.WriteTo(ref sealedWriter);

        Assert.IsTrue(sealedBytes.SequenceEqual(hmacBytes), "ForHmacKey and ForSealedData must produce byte-identical TPMS_SENSITIVE_CREATE framing.");
    }
}

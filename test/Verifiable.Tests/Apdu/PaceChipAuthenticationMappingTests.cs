using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the PACE Chip Authentication Mapping cryptography (ICAO Doc 9303 Part 11 §4.4.3.5) against the
/// worked example in Doc 9303 Part 11 Appendix I.1 — the ECDH example over brainpoolP256r1 with AES-128. The
/// example lists only the chip's static public key; the matching static private key is the one the formula
/// <c>CA_IC = s_IC⁻¹ · s_Map,IC mod n</c> fixes from the documented <c>CA_IC</c> and <c>s_Map,IC</c>, and the
/// first assertion confirms it reproduces the documented public key, making the rest a true vector.
/// </summary>
[TestClass]
internal sealed class PaceChipAuthenticationMappingTests
{
    /// <summary>The chip's static Chip Authentication private key s_IC, fixed from the App I.1 CA_IC and s_Map,IC.</summary>
    private const string StaticPrivateKey =
        "86C88A4579CE48135878E6348A734B5D47CE5BC1E54C0E8978687B49FDE2E2C2";

    /// <summary>The chip's static Chip Authentication public key PK_IC (X ‖ Y) from Doc 9303 App I.1.</summary>
    private const string StaticPublicKey =
        "1872709494399E7470A6431BE25E83EEE24FEA568C2ED28DB48E05DB3A610DC8" +
        "84D256A40E35EFCB59BF6753D3A489D28C7A4D973C2DA138A6E7A4A08F68E16F";

    /// <summary>The chip's ephemeral mapping private key s_Map,IC from Doc 9303 App I.1.</summary>
    private const string MappingPrivateKey =
        "9E56A6B59C95D06ECE5CD10F983BB2F4F1943528E577F23881D89D8C3BBEE0AA";

    /// <summary>The chip's mapping public key PK_Map,IC (X ‖ Y) from the Generic Mapping round, Doc 9303 App I.1.</summary>
    private const string MappingPublicKey =
        "A234236AA9B9621E8EFB73B5245C0E09D2576E5277183C1208BDD55280CAE8B3" +
        "04F365713A356E65A451E165ECC9AC0AC46E3771342C8FE5AEDD092685338E23";

    /// <summary>The Chip Authentication Data CA_IC = s_IC⁻¹ · s_Map,IC mod n from Doc 9303 App I.1.</summary>
    private const string ChipAuthenticationDataValue =
        "85DC3FA93D0952BFA82F5FD189EE75BD82F11D1F0B8ED4BF5319AC9B53C426B3";

    /// <summary>The PACE session encryption key KSenc from Doc 9303 App I.1.</summary>
    private const string SessionEncryptionKey = "0A9DA4DB03BDDE39FC5202BC44B2E89E";

    /// <summary>The Encrypted Chip Authentication Data A_IC (DO'8A' value) from Doc 9303 App I.1.</summary>
    private const string EncryptedChipAuthenticationData =
        "1EEA964DAAE372AC990E3EFDE6333353BFC89A6704D93DA8798CF77F5B7A54BD10CBA372B42BE0B9B5F28AA8DE2F4F92";

    /// <summary>The SEC1 uncompressed-point prefix prepended to an X ‖ Y coordinate pair.</summary>
    private const string UncompressedPointPrefix = "04";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task ChipAuthenticationMappingChainMatchesTheAppendixIWorkedExample()
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;

        //The static private key derived for the example must reproduce the documented static public key PK_IC,
        //confirming it is the example's actual chip CA key (the worked example lists only the public half).
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        using EncodedEcPoint staticPublicKey = await multiplyGenerator(
            Convert.FromHexString(StaticPrivateKey), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(UncompressedPointPrefix + StaticPublicKey, Convert.ToHexString(staticPublicKey.AsReadOnlySpan()),
            "The derived static private key must reproduce the Appendix I.1 static public key PK_IC.");

        //CA_IC = s_IC^-1 * s_Map,IC mod n.
        using ChipAuthenticationData chipAuthenticationData = await PaceChipAuthenticationMapping.GenerateAsync(
            Convert.FromHexString(StaticPrivateKey), Convert.FromHexString(MappingPrivateKey), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ChipAuthenticationDataValue, Convert.ToHexString(chipAuthenticationData.AsReadOnlySpan()),
            "CA_IC must equal the Appendix I.1 Chip Authentication Data.");

        //A_IC = E(KSenc, pad(CA_IC)) with IV = E(KSenc, -1).
        using SymmetricKeyMemory encryptionKey = ImportEncryptionKey(SessionEncryptionKey);
        using Ciphertext encrypted = await PaceChipAuthenticationMapping.EncryptAsync(
            chipAuthenticationData, encryptionKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(EncryptedChipAuthenticationData, Convert.ToHexString(encrypted.AsReadOnlySpan()),
            "A_IC must equal the Appendix I.1 Encrypted Chip Authentication Data.");

        //The terminal recovers CA_IC from A_IC.
        using ChipAuthenticationData recovered = await PaceChipAuthenticationMapping.DecryptAsync(
            encrypted.AsReadOnlyMemory(), encryptionKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ChipAuthenticationDataValue, Convert.ToHexString(recovered.AsReadOnlySpan()),
            "Decrypting A_IC must recover the Appendix I.1 CA_IC.");

        //The chip authenticates: PK_Map,IC = CA_IC * PK_IC.
        using EncodedEcPoint mappingPublicKey = EncodedEcPoint.FromBytes(
            Convert.FromHexString(UncompressedPointPrefix + MappingPublicKey), curve, BaseMemoryPool.Shared);
        bool authentic = await PaceChipAuthenticationMapping.VerifyAsync(
            recovered, staticPublicKey, mappingPublicKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(authentic, "The Appendix I.1 chip must authenticate: PK_Map,IC = CA_IC * PK_IC.");
    }


    [TestMethod]
    public async Task ChipAuthenticationMappingRejectsAWrongStaticPublicKey()
    {
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;

        using ChipAuthenticationData chipAuthenticationData = await PaceChipAuthenticationMapping.GenerateAsync(
            Convert.FromHexString(StaticPrivateKey), Convert.FromHexString(MappingPrivateKey), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Verifying against the mapping public key (not the static public key PK_IC) must fail: CA_IC scales only
        //PK_IC back to PK_Map,IC, so a substituted chip key is rejected.
        using EncodedEcPoint mappingPublicKey = EncodedEcPoint.FromBytes(
            Convert.FromHexString(UncompressedPointPrefix + MappingPublicKey), curve, BaseMemoryPool.Shared);
        bool authentic = await PaceChipAuthenticationMapping.VerifyAsync(
            chipAuthenticationData, mappingPublicKey, mappingPublicKey, curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(authentic, "A static public key that is not PK_IC must not authenticate the chip.");
    }


    /// <summary>
    /// Imports raw AES-128 key bytes into a pinned <see cref="SymmetricKeyMemory"/> tagged for AES-128 CBC.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented key buffer transfers to the returned SymmetricKeyMemory, which the caller disposes.")]
    private static SymmetricKeyMemory ImportEncryptionKey(string keyHex)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(keyHex.Length / 2, AllocationKind.Pinned);
        try
        {
            Convert.FromHexString(keyHex).AsSpan().CopyTo(owner.Memory.Span);

            return new SymmetricKeyMemory(owner, CryptoTags.Aes128Cbc);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}

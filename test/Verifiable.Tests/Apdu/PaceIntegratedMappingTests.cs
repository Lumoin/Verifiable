using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the PACE Integrated Mapping cryptography (ICAO Doc 9303 Part 11 §4.4.3.3.2, Appendix B point
/// encoding) against the worked example in Doc 9303 Part 11 Appendix H.1 — the ECDH example over
/// brainpoolP256r1 with AES-128. These vectors are an authoritative conformance oracle for the
/// <see cref="EcMap2PointDelegate"/> point encoding f_G, the <see cref="PaceIntegratedMapping"/> pseudo-random
/// function R(s,t), and the mapped generator the two compose.
/// </summary>
[TestClass]
internal sealed class PaceIntegratedMappingTests
{
    /// <summary>The decrypted nonce s (16 octets) from Doc 9303 App H.1.</summary>
    private const string Nonce =
        "2923BE84E16CD6AE529049F1F1BBE9EB";

    /// <summary>The terminal's additional nonce t (16 octets, the AES-128 key in the PRF) from Doc 9303 App H.1.</summary>
    private const string AdditionalNonce =
        "5DD4CBFC96F5453B130D890A1CDBAE32";

    /// <summary>The brainpoolP256r1 field bit length, sizing the PRF output to n = 3 blocks (48 octets).</summary>
    private const int BrainpoolP256r1FieldBitLength = 256;

    /// <summary>The pseudo-random function output R(s,t) (48 octets) from Doc 9303 App H.1.</summary>
    private const string PseudoRandomOutput =
        "E4447E2DFB3586BAC05DDB00156B57FBB2179A3949294C97254189800C517BAA8DA0FF397ED8C445D3E421E4FEB57322";

    /// <summary>The reduced field element Rp(s,t) = int(R(s,t)) mod p (32 octets) from Doc 9303 App H.1.</summary>
    private const string ReducedFieldElement =
        "A2F8FF2DF50E52C6599F386ADCB595D229F6A167ADE2BE5F2C3296ADD5B7430E";

    /// <summary>The mapped generator Ĝ = f_G(Rp(s,t)) as SEC1 uncompressed (0x04 ‖ X ‖ Y) from Doc 9303 App H.1.</summary>
    private const string MappedGenerator =
        "04" +
        "8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427" +
        "4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD";

    /// <summary>The chip's static-ephemeral private key SK_IC over the mapped generator, from Doc 9303 App H.1.</summary>
    private const string ChipPrivateKey =
        "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";

    /// <summary>The terminal's static-ephemeral private key SK_IFD over the mapped generator, from Doc 9303 App H.1.</summary>
    private const string TerminalPrivateKey =
        "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    /// <summary>The agreed shared secret K (the X-coordinate of SK_IFD · PK_IC), from Doc 9303 App H.1.</summary>
    private const string SharedSecretK =
        "4F150FDE1D4F0E38E95017B891BAE17133A0DF45B0D3E18B60BA7BEAFDC2C713";

    /// <summary>The derived AES-128 session encryption key KSenc, from Doc 9303 App H.1.</summary>
    private const string SessionEncryptionKey = "0D3FEB33251A6370893D62AE8DAAF51B";

    /// <summary>The derived AES-128 session MAC key KSmac, from Doc 9303 App H.1.</summary>
    private const string SessionMacKey = "B01E89E3D9E8719E586B50B4A7506E0B";

    /// <summary>The terminal authentication token T_IFD = MAC(KSmac, PK_IC ‖ OID), from Doc 9303 App H.1.</summary>
    private const string TerminalToken = "450F02B86F6A0909";

    /// <summary>The chip authentication token T_IC = MAC(KSmac, PK_IFD ‖ OID), from Doc 9303 App H.1.</summary>
    private const string ChipToken = "75D4D96E8D5B0308";

    /// <summary>The id-PACE-ECDH-IM-AES-CBC-CMAC-128 OID value bytes (without the outer 0x06 tag), from Doc 9303 App H.1.</summary>
    private const string IntegratedMappingObjectIdentifier = "04007F00070202040402";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task Map2PointMapsPseudoRandomOutputToTheDoc9303AppendixHGenerator()
    {
        EcMap2PointDelegate map2Point = Resolve<EcMap2PointDelegate>();

        using EncodedEcPoint mapped = await map2Point(
            Convert.FromHexString(PseudoRandomOutput), CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(MappedGenerator, Convert.ToHexString(mapped.AsReadOnlySpan()),
            "f_G(R(s,t)) must equal the mapped generator from Doc 9303 Part 11 Appendix H.1.");
    }


    [TestMethod]
    public async Task Map2PointReducesModuloThePrimeBeforeEncoding()
    {
        //Feeding the already-reduced field element Rp(s,t) yields the same generator: the reduction step is
        //idempotent on a value already in [0, p), confirming f_G operates on int(input) mod p.
        EcMap2PointDelegate map2Point = Resolve<EcMap2PointDelegate>();

        using EncodedEcPoint mapped = await map2Point(
            Convert.FromHexString(ReducedFieldElement), CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(MappedGenerator, Convert.ToHexString(mapped.AsReadOnlySpan()),
            "f_G(Rp(s,t)) must equal the same mapped generator as f_G(R(s,t)).");
    }


    [TestMethod]
    public async Task PseudoRandomFunctionReproducesTheDoc9303AppendixHOutput()
    {
        //R(s,t) is the AES-128 cipher cascade of Doc 9303 Figure 2; for brainpoolP256r1 it is n = 3 blocks.
        using IMemoryOwner<byte> pseudoRandom = await PaceIntegratedMapping.ComputePseudoRandomAsync(
            Convert.FromHexString(Nonce), Convert.FromHexString(AdditionalNonce), BrainpoolP256r1FieldBitLength, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(PseudoRandomOutput, Convert.ToHexString(pseudoRandom.Memory.Span),
            "R(s,t) must equal the pseudo-random function output from Doc 9303 Part 11 Appendix H.1.");
    }


    [TestMethod]
    public async Task MapNonceComposesThePseudoRandomFunctionAndPointEncodingToTheAppendixHGenerator()
    {
        //The full Integrated Mapping Ĝ = f_G(R_p(s,t)): the PRF feeds the point encoding, mod-p reduction inside.
        using EncodedEcPoint mapped = await PaceIntegratedMapping.MapNonceAsync(
            Convert.FromHexString(Nonce), Convert.FromHexString(AdditionalNonce), CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(MappedGenerator, Convert.ToHexString(mapped.AsReadOnlySpan()),
            "Ĝ = f_G(R_p(s,t)) must equal the mapped generator from Doc 9303 Part 11 Appendix H.1.");
    }


    [TestMethod]
    public async Task IntegratedMappingChainReproducesTheAppendixHSessionKeysAndTokens()
    {
        //The full Integrated Mapping chain over brainpoolP256r1/AES-128, each step pinned to Doc 9303 Part 11
        //Appendix H.1: map the nonces to Ĝ, take the ephemeral public keys SK·Ĝ, agree the shared secret,
        //derive the AES session keys, and compute the mutual-authentication tokens.
        EcMultiplyPointDelegate multiplyPoint = Resolve<EcMultiplyPointDelegate>();
        Tag curve = CryptoTags.BrainpoolP256r1ExchangePublicKey;

        using EncodedEcPoint mappedGenerator = await PaceIntegratedMapping.MapNonceAsync(
            Convert.FromHexString(Nonce), Convert.FromHexString(AdditionalNonce), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(MappedGenerator, Convert.ToHexString(mappedGenerator.AsReadOnlySpan()),
            "Ĝ must equal the Appendix H.1 mapped generator.");

        //The ephemeral public keys are SK·Ĝ over the mapped generator.
        using EncodedEcPoint chipPublicKey = await multiplyPoint(
            Convert.FromHexString(ChipPrivateKey), mappedGenerator.AsReadOnlyMemory(), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using EncodedEcPoint terminalPublicKey = await multiplyPoint(
            Convert.FromHexString(TerminalPrivateKey), mappedGenerator.AsReadOnlyMemory(), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //The shared secret K is the X-coordinate of SK_IFD · PK_IC (equivalently SK_IC · PK_IFD).
        using SharedSecret sharedSecret = await chipPublicKey.AgreeSharedSecretAsync(
            Convert.FromHexString(TerminalPrivateKey), curve, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SharedSecretK, Convert.ToHexString(sharedSecret.AsReadOnlySpan()),
            "The shared secret K must equal the Appendix H.1 value.");

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await PaceKeyDerivation.DeriveSessionKeysAsync(
            sharedSecret.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        {
            Assert.AreEqual(SessionEncryptionKey, Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                "KSenc must equal the Appendix H.1 KEnc.");
            Assert.AreEqual(SessionMacKey, Convert.ToHexString(macKey.AsReadOnlySpan()),
                "KSmac must equal the Appendix H.1 KMAC.");

            //T_IFD authenticates the chip's ephemeral public key; T_IC authenticates the terminal's.
            using MacValue terminalToken = await macKey.ComputeAuthenticationTokenAsync(
                chipPublicKey, Convert.FromHexString(IntegratedMappingObjectIdentifier), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(TerminalToken, Convert.ToHexString(terminalToken.AsReadOnlySpan()),
                "T_IFD must equal the Appendix H.1 terminal token.");

            using MacValue chipToken = await macKey.ComputeAuthenticationTokenAsync(
                terminalPublicKey, Convert.FromHexString(IntegratedMappingObjectIdentifier), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(ChipToken, Convert.ToHexString(chipToken.AsReadOnlySpan()),
                "T_IC must equal the Appendix H.1 chip token.");
        }
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}

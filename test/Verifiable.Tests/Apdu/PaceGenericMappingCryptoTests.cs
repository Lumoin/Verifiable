using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu.Pace;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the PACE Generic Mapping cryptographic orchestration — nonce mapping, key agreement
/// over the mapped generator, session-key derivation, and the mutual-authentication tokens —
/// against the ICAO Doc 9303 Part 11 Appendix G.1 worked example (brainpoolP256r1, AES-128).
/// </summary>
[TestClass]
internal sealed class PaceGenericMappingCryptoTests
{
    private const string Oid = "04007F00070202040202";
    private const string Nonce = "3F00C4D39D153F2B2A214A078D899B22";
    private const string MappingPrivateIfd = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    private const string KeyAgreementPrivateIfd = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    private const string MappingPublicIc = "04" +
        "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57" +
        "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54";
    private const string MappedGenerator = "04" +
        "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2" +
        "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522";
    private const string KeyAgreementPublicIfd = "04" +
        "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C" +
        "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462";
    private const string KeyAgreementPublicIc = "04" +
        "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB" +
        "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094";
    private const string SharedSecretK = "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925";


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task MapNonceProducesTheMappedGeneratorPerAppendixG1()
    {
        using EncodedEcPoint mapped = await PaceGenericMapping.MapNonceAsync(
            Convert.FromHexString(Nonce), Convert.FromHexString(MappingPrivateIfd), Convert.FromHexString(MappingPublicIc),
            CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(MappedGenerator, Convert.ToHexString(mapped.AsReadOnlySpan()),
            "MapNonce must produce the Appendix G.1 mapped generator.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The session keys are disposed in the finally block.")]
    public async Task AgreesKeysAndComputesTokensPerAppendixG1()
    {
        using SharedSecret sharedSecret = await PaceGenericMapping.AgreeSharedSecretAsync(
            Convert.FromHexString(KeyAgreementPrivateIfd), Convert.FromHexString(KeyAgreementPublicIc),
            CryptoTags.BrainpoolP256r1ExchangePublicKey, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SharedSecretK, Convert.ToHexString(sharedSecret.AsReadOnlySpan()),
            "The agreed shared secret must match Appendix G.1.");

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await PaceKeyDerivation.DeriveSessionKeysAsync(sharedSecret.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            Assert.AreEqual("F5F0E35C0D7161EE6724EE513A0D9A7F", Convert.ToHexString(encryptionKey.AsReadOnlySpan()),
                "KSenc must match Appendix G.1.");
            Assert.AreEqual("FE251C7858B356B24514B3BD5F4297D1", Convert.ToHexString(macKey.AsReadOnlySpan()),
                "KSmac must match Appendix G.1.");

            //T_IFD authenticates the chip's ephemeral public key; T_IC authenticates the terminal's.
            using MacValue terminalToken = await PaceGenericMapping.ComputeAuthenticationTokenAsync(
                macKey, Convert.FromHexString(KeyAgreementPublicIc), Convert.FromHexString(Oid),
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual("C2B0BD78D94BA866", Convert.ToHexString(terminalToken.AsReadOnlySpan()),
                "T_IFD must match Appendix G.1.");

            using MacValue chipToken = await PaceGenericMapping.ComputeAuthenticationTokenAsync(
                macKey, Convert.FromHexString(KeyAgreementPublicIfd), Convert.FromHexString(Oid),
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual("3ABB9674BCE93C08", Convert.ToHexString(chipToken.AsReadOnlySpan()),
                "T_IC must match Appendix G.1.");
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }
}

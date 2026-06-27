using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// The first slice of the TPM + APDU "extra secure" capstone: reading your own passport at home on a
/// TPM-equipped desktop, where the terminal's Basic Access Control session secrets are drawn from the TPM
/// rather than software. It composes the two in-house pushdown-automaton devices — the
/// <see cref="TpmSimulator"/> (TPM side) and the <see cref="CardSimulator"/> (eMRTD card side) — into one
/// flow: the terminal's chip-challenge response RND.IFD and keying material KIFD come from the TPM's RNG
/// (auditable through the <see cref="EntropyConsumedEvent"/> tagged <see cref="EntropySource.Tpm"/>), BAC
/// establishes a Secure Messaging session against the card, and the data groups read back over it.
/// </summary>
/// <remarks>
/// <para>
/// This runs entirely against the in-process simulators (no real TPM or Docker), so it always executes.
/// Richer capstone slices — the terminal's Chip Authentication ephemeral key held inside the TPM (TPM2_ECDH_ZGen
/// so the private key never leaves it), sealing the session keys, and an attested-terminal signature over the
/// read — use the production TPM command path against a real or ms-tpm-20-ref TPM and are gated separately.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmBackedPassportReadTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    /// <summary>The byte length of the Basic Access Control terminal nonce RND.IFD.</summary>
    private const int TerminalNonceLength = 8;

    /// <summary>The byte length of the Basic Access Control terminal keying material KIFD.</summary>
    private const int TerminalKeyingMaterialLength = 16;


    public required TestContext TestContext { get; set; }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The access keys are disposed in the using block; the TPM-drawn nonce and keying material are disposed via using.")]
    public async Task ReadsPassportOverBacWithTpmSourcedTerminalEntropy()
    {
        //The TPM-equipped terminal: an operational in-house TPM exposed as an auditable entropy source.
        using TpmDevice tpm = await CreateOperationalTpmAsync("capstone-tpm").ConfigureAwait(false);
        var entropy = new TpmEntropyProvider(tpm, BaseMemoryPool.Shared, emittedBy: "capstone-tpm");

        //The passport: an in-house eMRTD card holding EF.COM and EF.DG1.
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using var card = new CardSimulator("capstone-passport", [efCom, dataGroup1]);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //The terminal draws its BAC session secrets (RND.IFD, KIFD) from the TPM; the events prove provenance.
        using Nonce terminalNonce = DrawTpmNonce(entropy, TerminalNonceLength, out EntropyConsumedEvent nonceEvent);
        using Nonce terminalKeyingMaterial = DrawTpmNonce(entropy, TerminalKeyingMaterialLength, out EntropyConsumedEvent keyingEvent);

        Assert.AreEqual(EntropySource.Tpm, nonceEvent.Source, "RND.IFD must be drawn from the TPM.");
        Assert.AreEqual(EntropySource.Tpm, keyingEvent.Source, "KIFD must be drawn from the TPM.");

        //The terminal derives the access keys from the MRZ it read optically and runs Basic Access Control,
        //contributing the TPM-sourced RND.IFD and KIFD.
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await BasicAccessControl.DeriveAccessKeysAsync(
            mrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using(encryptionKey)
        using(macKey)
        {
            using SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
                device, encryptionKey, macKey, terminalNonce.AsReadOnlyMemory(), terminalKeyingMaterial.AsReadOnlyMemory(),
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(CardLifecyclePhase.SecureMessaging, card.Phase, "Basic Access Control must establish Secure Messaging.");

            //The same channel that reads a real chip reads the passport over the TPM-seeded session.
            var channel = new SecureMessagingChannel(device, session);

            using ElementaryFile readEfCom = await channel.ReadElementaryFileAsync(efCom.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(efCom.Content), Convert.ToHexString(readEfCom.Content),
                "EF.COM must read back byte-for-byte over the TPM-seeded Secure Messaging session.");

            using ElementaryFile readDataGroup1 = await channel.ReadElementaryFileAsync(dataGroup1.FileIdentifier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(Convert.ToHexString(dataGroup1.Content), Convert.ToHexString(readDataGroup1.Content),
                "EF.DG1 must read back byte-for-byte over the TPM-seeded Secure Messaging session.");
        }
    }


    [TestMethod]
    public async Task TpmEntropyHealthIsAssessedHealthyBeforeReading()
    {
        //An "extra secure" terminal assesses the TPM RNG health (TPM2_SelfTest) before trusting its output
        //for session key material — a degraded source surfaces rather than silently weakening the session.
        using TpmDevice tpm = await CreateOperationalTpmAsync("capstone-tpm-health").ConfigureAwait(false);
        var entropy = new TpmEntropyProvider(tpm, BaseMemoryPool.Shared, emittedBy: "capstone-tpm-health");

        (EntropyHealthObservation observation, _) = await entropy.AssessHealthAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(EntropySource.Tpm, observation.Source);
        Assert.AreEqual(EntropyOutcome.Healthy, observation.Outcome, "A passing TPM self-test must report the entropy source healthy.");
        Assert.IsTrue(observation.IsHealthy);
    }


    /// <summary>
    /// Draws a TPM nonce and surfaces the accompanying provenance event (which must be present and tagged
    /// <see cref="EntropySource.Tpm"/>).
    /// </summary>
    private static Nonce DrawTpmNonce(TpmEntropyProvider entropy, int byteLength, out EntropyConsumedEvent consumed)
    {
        (Nonce nonce, CryptoEvent? evt) = entropy.GenerateNonce(byteLength, Tag.Create((typeof(Purpose), Purpose.Nonce)), BaseMemoryPool.Shared);
        consumed = evt as EntropyConsumedEvent
            ?? throw new InvalidOperationException("A TPM entropy draw must emit an EntropyConsumedEvent.");

        return nonce;
    }


    /// <summary>
    /// Brings up an in-house TPM simulator, drives it to the operational phase, and exposes it as a device.
    /// </summary>
    private async Task<TpmDevice> CreateOperationalTpmAsync(string tpmId)
    {
        var simulator = new TpmSimulator(tpmId, TpmSelfTestBehavior.Passes);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using IMemoryOwner<byte> command = FrameSessionlessCommand(new StartupInput(TpmSuConstants.TPM_SU_CLEAR), BaseMemoryPool.Shared, out int length);
        TpmResult<TpmResponse> startup = await simulator.SubmitAsync(command.Memory[..length], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        startup.Value.Dispose();

        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase, "The TPM must reach the operational phase before drawing entropy.");

        return TpmDevice.Create(simulator.SubmitAsync);
    }


    /// <summary>
    /// Frames a sessionless TPM command (header, handles, parameters) into a rented buffer.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented command buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> FrameSessionlessCommand<TInput>(TInput input, MemoryPool<byte> pool, out int length)
        where TInput: ITpmCommandInput
    {
        length = TpmHeader.HeaderSize + input.GetSerializedSize();
        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
            header.WriteTo(ref writer);
            input.WriteHandles(ref writer);
            input.WriteParameters(ref writer);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }
}

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Mrz;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Foundation.Automata;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// A behavioural eMRTD card simulator built on a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>.
/// Unlike <see cref="VirtualCard"/>, which replays recorded bytes by content hash, this models card
/// behaviour and computes responses from state, so a terminal driving the real read or access-control flow
/// against it behaves as it would against a personalised contactless IC.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TransceiveAsync"/> has the <see cref="TransceiveDelegate"/> shape, so the simulator plugs
/// straight into <see cref="ApduDevice.Create(TransceiveDelegate, ApduPlatform, Action?)"/> — the same way
/// the TPM simulator plugs into its device — and the card's command/response traffic is observable through
/// the device's <see cref="System.IObservable{T}"/> of <see cref="ApduExchange"/>. The card's own internal
/// transitions are observable at the state level through <see cref="Subscribe"/>, which yields a
/// <see cref="TraceEntry{TState, TInput}"/> per step.
/// </para>
/// <para>
/// <strong>Scope.</strong> The card models the plaintext read path (SELECT, READ BINARY), GET CHALLENGE, and
/// both eMRTD access protocols. Basic Access Control: on EXTERNAL AUTHENTICATE the card verifies the
/// terminal's token against the access keys derived from its own EF.DG1 MRZ and the chip nonce it issued,
/// answers with its token, and establishes a 3DES <see cref="SecureMessagingCardSession"/>. PACE with Generic
/// Mapping: MSE:Set AT selects the mechanism, then the four chained GENERAL AUTHENTICATE rounds (encrypted
/// nonce, nonce mapping, key agreement, mutual authentication) establish an AES session. Once a session is
/// established, subsequent commands are routed through it (Secure Messaging) and plaintext access to protected
/// files is refused. Chip Authentication and INTERNAL AUTHENTICATE follow.
/// </para>
/// <para>
/// The card is a stateful device: it owns the issued challenge RND.IC, the PACE exchange's intermediate
/// values, and the established Secure Messaging session, so it is <see cref="IDisposable"/> (the caller
/// disposes it). The elementary files are <em>borrowed</em> — the producer that minted them retains ownership
/// and disposes them. Commands are processed serially, as a physical card does; the simulator is not safe for
/// concurrent calls.
/// </para>
/// </remarks>
/// <seealso cref="VirtualCard"/>
/// <seealso cref="ApduDevice"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CardSimulator: IObservable<TraceEntry<CardSimulatorState, CardSimulatorInput>>, IDisposable
{
    /// <summary>The SELECT P1 value selecting an elementary file by its file identifier (ISO/IEC 7816-4).</summary>
    private const byte SelectByFileIdentifier = 0x02;

    /// <summary>The SELECT P2 value requesting no response data (return no FCI), the eMRTD form.</summary>
    private const byte SelectNoResponseData = 0x0C;

    /// <summary>The READ BINARY P1 bit that marks a short-EF-identifier reference (not modelled in this slice).</summary>
    private const byte ReadBinaryShortEfBit = 0x80;

    /// <summary>The ISO/IEC 7816-4 class-byte bits that mark a command as Secure Messaging with a protected header.</summary>
    private const byte SecureMessagingClassBits = 0x0C;

    /// <summary>The GENERAL AUTHENTICATE instruction byte PACE uses (Doc 9303 §4.4.4); the even variant, distinct from the BER-TLV <see cref="InstructionCode.GeneralAuthenticate"/> (0x87).</summary>
    private const byte GeneralAuthenticateInstruction = 0x86;

    /// <summary>P1 of MSE:Set AT — set the authentication template for verification/computation.</summary>
    private const byte SetAuthenticationTemplateP1 = 0xC1;

    /// <summary>P2 of MSE:Set AT — the Authentication Template (AT) tag, selecting the PACE mechanism.</summary>
    private const byte SetAuthenticationTemplateP2 = 0xA4;

    /// <summary>P1 of MSE:Set KAT — set a Key Agreement Template for computation (EACv1 Chip Authentication).</summary>
    private const byte SetKeyAgreementTemplateP1 = 0x41;

    /// <summary>P2 of MSE:Set KAT — the Key Agreement Template (KAT) tag.</summary>
    private const byte SetKeyAgreementTemplateP2 = 0xA6;

    /// <summary>P1 of MSE:Set DST — set the Digital Signature Template naming the Terminal Authentication verification key.</summary>
    private const byte SetDigitalSignatureTemplateP1 = 0x81;

    /// <summary>P2 of MSE:Set DST — the Digital Signature Template (DST) tag.</summary>
    private const byte SetDigitalSignatureTemplateP2 = 0xB6;

    /// <summary>P1 of PSO:Verify Certificate — the data field carries the certificate to verify.</summary>
    private const byte VerifyCertificateP1 = 0x00;

    /// <summary>P2 of PSO:Verify Certificate — verify a self-descriptive certificate (ISO/IEC 7816-8).</summary>
    private const byte VerifyCertificateP2 = 0xBE;

    /// <summary>BER-TLV tag for the public-key reference in MSE:Set DST (DO'83').</summary>
    private const byte PublicKeyReferenceTag = 0x83;

    /// <summary>BER-TLV tag (two bytes) of the outer card-verifiable certificate object (<c>7F21</c>), which wraps the presented body and signature for parsing.</summary>
    private const int CardVerifiableCertificateTag = 0x7F21;

    /// <summary>BER-TLV tag for the terminal's ephemeral public key in MSE:Set KAT (DO'91').</summary>
    private const byte EphemeralPublicKeyTag = 0x91;

    /// <summary>BER-TLV tag for the chip's private-key reference in MSE:Set KAT (DO'84').</summary>
    private const byte PrivateKeyReferenceTag = 0x84;

    /// <summary>BER-TLV tag for a GENERAL AUTHENTICATE dynamic authentication data object.</summary>
    private const byte DynamicAuthenticationDataTag = 0x7C;

    /// <summary>Context tag of the cryptographic-mechanism reference (the PACE OID) in the MSE:Set AT data field (DO'80').</summary>
    private const byte CryptographicMechanismReferenceTag = 0x80;

    /// <summary>Context tag of the encrypted nonce inside the GENERAL AUTHENTICATE response (DO'80').</summary>
    private const byte EncryptedNonceTag = 0x80;

    /// <summary>Context tag of the chip's mapping public key inside the GENERAL AUTHENTICATE response (DO'82').</summary>
    private const byte ChipMappingDataTag = 0x82;

    /// <summary>Context tag of the chip's ephemeral public key inside the GENERAL AUTHENTICATE response (DO'84').</summary>
    private const byte ChipEphemeralKeyTag = 0x84;

    /// <summary>Context tag of the chip's authentication token inside the GENERAL AUTHENTICATE response (DO'86').</summary>
    private const byte ChipTokenTag = 0x86;

    /// <summary>Context tag of the Encrypted Chip Authentication Data inside the round-4 response under Chip Authentication Mapping (DO'8A').</summary>
    private const byte EncryptedChipAuthenticationDataTag = 0x8A;

    /// <summary>The PACE nonce length in bytes (one AES-128 block) for the AES-128 profile.</summary>
    private const int PaceNonceLengthBytes = 16;

    /// <summary>The length in octets of an elementary file identifier.</summary>
    private const int FileIdentifierLength = 2;

    /// <summary>The number of octets a zero short Le field requests.</summary>
    private const int MaxShortExpectedLength = 256;

    /// <summary>The length in octets of the chip keying material KIC the card contributes to the BAC session seed.</summary>
    private const int ChipKeyingMaterialLength = 16;

    /// <summary>The live automaton holding this card's state of record.</summary>
    private PushdownAutomaton<CardSimulatorState, CardSimulatorInput, CardStackSymbol> Automaton { get; }

    /// <summary>The time source threaded to the effectful runner for trace timestamps.</summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>The card's RNG backend, drawn on for nonces such as RND.IC and the keying material KIC.</summary>
    private FillEntropyDelegate Rng { get; }

    /// <summary>The curve the card's PACE (and Chip Authentication) elliptic-curve operations run over, from personalisation; <see langword="null"/> when the card supports no EC access protocol.</summary>
    private Tag? PaceCurve { get; }

    /// <summary>The chip nonce RND.IC issued by the most recent GET CHALLENGE, owned by the card; <see langword="null"/> when none is outstanding.</summary>
    private IMemoryOwner<byte>? IssuedChallenge { get; set; }

    /// <summary>The number of valid octets in <see cref="IssuedChallenge"/>.</summary>
    private int IssuedChallengeLength { get; set; }

    /// <summary>The Secure Messaging session established by an access protocol (and re-keyed by Chip Authentication), owned by the card; <see langword="null"/> until established.</summary>
    private SecureMessagingCardSession? SecureMessagingSession { get; set; }

    /// <summary>The re-keyed Secure Messaging session a Chip Authentication built, awaiting activation once the MSE:Set KAT response is framed under the prior session; <see langword="null"/> when none is pending. Owned by the card.</summary>
    private SecureMessagingCardSession? PendingSecureMessagingSession { get; set; }

    /// <summary>The chip's static Chip Authentication private keys, paired with their DG14 key identifier (borrowed, not owned).</summary>
    private List<ChipAuthenticationKey> ChipAuthenticationKeys { get; }

    /// <summary>The chip's Active Authentication private key matching its EF.DG15 public key (borrowed, not owned); <see langword="null"/> when the card supports no Active Authentication.</summary>
    private ActiveAuthenticationKey? ActiveAuthenticationKey { get; }

    /// <summary>The chip's static Chip Authentication private key for PACE Chip Authentication Mapping, on the PACE curve (borrowed, not owned); <see langword="null"/> when the card supports no CAM.</summary>
    private ChipAuthenticationKey? PaceChipAuthenticationKey { get; }

    /// <summary>The trusted Country Verifying Certification Authority certificate Terminal Authentication verifies the presented chain against (borrowed, not owned); <see langword="null"/> when the card supports no Terminal Authentication.</summary>
    private CardVerifiableCertificate? TerminalAuthenticationTrustAnchor { get; }

    /// <summary>The chip's current date for Terminal Authentication validity, advanced to the most recent effective date it has verified (a clockless chip's view of "now"); only certificates expired relative to it are rejected.</summary>
    private DateOnly TerminalAuthenticationCurrentDate { get; set; }

    /// <summary>The certificate holder reference MSE:Set DST named as the verifier of the next PSO:Verify Certificate; <see langword="null"/> when none is selected.</summary>
    private string? DigitalSignatureTemplateReference { get; set; }

    /// <summary>The terminal certificate holder reference MSE:Set AT selected for the EXTERNAL AUTHENTICATE, pinning which imported key the Terminal Authentication signature is verified against; <see langword="null"/> when none is selected.</summary>
    private string? SelectedTerminalAuthenticationReference { get; set; }

    /// <summary>The most recently imported Terminal Authentication certificate (the Document Verifier, then the terminal), owned by the card; <see langword="null"/> until one is imported.</summary>
    private CardVerifiableCertificate? ImportedTerminalCertificate { get; set; }

    /// <summary>The effective Inspection System read authorization accumulated across the certificate chain as it is verified — the bitwise AND of each certificate's Certificate Holder Authorization Template, re-seeded from the trusted Country Verifying Certification Authority when a fresh chain begins (BSI TR-03110-3 §2.7). Granted to the terminal once its EXTERNAL AUTHENTICATE succeeds; <see cref="InspectionSystemAccess.None"/> until a chain is presented.</summary>
    private InspectionSystemAccess AccumulatedReadAccess { get; set; }

    /// <summary>The terminal's ephemeral public key PK_DH,IFD captured at the MSE:Set KAT of Chip Authentication, owned by the card; <see langword="null"/> until Chip Authentication runs. <c>Comp()</c> of it binds the Terminal Authentication signature to the session-establishing key.</summary>
    private EncodedEcPoint? TerminalChipAuthenticationEphemeralKey { get; set; }

    /// <summary>The chip's own PACE ephemeral public key, retained when PACE rather than Basic Access Control established the session, owned by the card; <see langword="null"/> when access was Basic Access Control (or no session is established). When present it marks PACE as the access protocol, and <c>Comp()</c> of it is the chip identifier ID_IC a subsequent Terminal Authentication signs (BSI TR-03110-3 §A.2.2.3).</summary>
    private EncodedEcPoint? PaceAccessChipEphemeralPublicKey { get; set; }

    /// <summary>The PACE protocol OID selected by MSE:Set AT, owned by the card; <see langword="null"/> when no PACE exchange is in progress. Retained for the round-4 authentication tokens.</summary>
    private IMemoryOwner<byte>? SelectedPaceObjectIdentifier { get; set; }

    /// <summary>The number of valid octets in <see cref="SelectedPaceObjectIdentifier"/>.</summary>
    private int SelectedPaceObjectIdentifierLength { get; set; }

    /// <summary>The PACE nonce s drawn in the encrypted-nonce round, owned by the card; <see langword="null"/> when none is outstanding. Retained for the mapping round.</summary>
    private IMemoryOwner<byte>? PaceNonce { get; set; }

    /// <summary>The number of valid octets in <see cref="PaceNonce"/>.</summary>
    private int PaceNonceLength { get; set; }

    /// <summary>The chip's mapping private key s_Map,IC from the nonce-mapping round, owned by the card; <see langword="null"/> when none is outstanding. Retained so Chip Authentication Mapping can blind the static key with it in round 4.</summary>
    private IMemoryOwner<byte>? PaceMappingPrivateKey { get; set; }

    /// <summary>The number of valid octets in <see cref="PaceMappingPrivateKey"/>.</summary>
    private int PaceMappingPrivateKeyLength { get; set; }

    /// <summary>The mapped generator Ĝ from the PACE nonce-mapping round, owned by the card; <see langword="null"/> when none is outstanding. Retained for the key-agreement round.</summary>
    private EncodedEcPoint? PaceMappedGenerator { get; set; }

    /// <summary>The chip's PACE ephemeral public key from the key-agreement round, owned by the card; <see langword="null"/> when none is outstanding. Retained so the round-4 token verification authenticates it.</summary>
    private EncodedEcPoint? PaceChipEphemeralPublicKey { get; set; }

    /// <summary>The terminal's PACE ephemeral public key from the key-agreement round, owned by the card; <see langword="null"/> when none is outstanding. Retained so the chip's round-4 token authenticates it.</summary>
    private EncodedEcPoint? PaceTerminalEphemeralPublicKey { get; set; }

    /// <summary>The PACE session encryption key KSenc derived in the key-agreement round, owned by the card; <see langword="null"/> until derived. Transferred to the Secure Messaging session at round 4.</summary>
    private SymmetricKeyMemory? PaceEncryptionKey { get; set; }

    /// <summary>The PACE session MAC key KSmac derived in the key-agreement round, owned by the card; <see langword="null"/> until derived. Used for the round-4 tokens, then transferred to the Secure Messaging session.</summary>
    private SymmetricKeyMemory? PaceMacKey { get; set; }

    /// <summary>The counter backing the deterministic RNG default; advances once per drawn block.</summary>
    private ulong RngCounter { get; set; }

    private bool disposed;


    /// <summary>
    /// Creates a card simulator personalised with a set of elementary files.
    /// </summary>
    /// <param name="cardId">A stable identifier for this simulated card; also the automaton's run identifier.</param>
    /// <param name="files">The elementary files the card serves (for example EF.COM, the data groups, EF.SOD). Borrowed — the caller retains ownership and disposes them; the last file registered for a given identifier wins.</param>
    /// <param name="rng">
    /// The random-number backend the card draws its nonces from. The simulator models the card's own RNG,
    /// not the application entropy source, so the default is a deterministic counter stream seeded per
    /// instance — reproducible for replay yet distinct across draws. Tests inject a fixed pattern; the
    /// delegate must fill the entire destination span.
    /// </param>
    /// <param name="timeProvider">The time source for trace timestamps. Defaults to <see cref="System.TimeProvider.System"/>.</param>
    /// <param name="paceCurve">
    /// A tag carrying the curve the card's PACE elliptic-curve operations run over, part of the card's
    /// personalisation. Required for the PACE mapping and key-agreement rounds; the encrypted-nonce round and
    /// Basic Access Control do not need it, so it defaults to <see langword="null"/>. Chip Authentication
    /// takes its curve from EF.DG14, not from this.
    /// </param>
    /// <param name="chipAuthenticationKeys">
    /// The chip's static Chip Authentication private keys (the personalisation secrets matching the EF.DG14
    /// public keys), each paired with its DG14 key identifier. Required for the Chip Authentication MSE:Set KAT
    /// responder; defaults to none. Borrowed — the caller retains ownership and disposes them.
    /// </param>
    /// <param name="activeAuthenticationKey">
    /// The chip's Active Authentication private key (the personalisation secret matching the EF.DG15 public
    /// key). Required for the INTERNAL AUTHENTICATE responder; defaults to <see langword="null"/>. Borrowed —
    /// the caller retains ownership and disposes it.
    /// </param>
    /// <param name="paceChipAuthenticationKey">
    /// The chip's static Chip Authentication private key on the PACE curve, for PACE Chip Authentication
    /// Mapping (the secret the chip blinds with its mapping private key in round 4). Required only when a
    /// PACE-CAM mechanism is selected; defaults to <see langword="null"/>. Borrowed — the caller retains
    /// ownership and disposes it.
    /// </param>
    /// <param name="terminalAuthenticationTrustAnchor">
    /// The trusted Country Verifying Certification Authority certificate the chip verifies the presented
    /// Terminal Authentication certificate chain against. Required for the MSE:Set DST and PSO:Verify
    /// Certificate responders; defaults to <see langword="null"/>. Borrowed — the caller retains ownership
    /// and disposes it.
    /// </param>
    /// <param name="terminalAuthenticationDate">
    /// The initial current date the chip checks Terminal Authentication certificate validity against. Like a
    /// real clockless chip, the simulator advances this to the most recent effective date of a certificate it
    /// verifies, so a chain whose certificates are issued in sequence is accepted; only certificates expired
    /// relative to the advancing current date are rejected. Defaults to <see langword="null"/>, which starts
    /// from the trust anchor's effective date.
    /// </param>
    public CardSimulator(
        string cardId,
        IEnumerable<ElementaryFile> files,
        FillEntropyDelegate? rng = null,
        TimeProvider? timeProvider = null,
        Tag? paceCurve = null,
        IEnumerable<ChipAuthenticationKey>? chipAuthenticationKeys = null,
        ActiveAuthenticationKey? activeAuthenticationKey = null,
        ChipAuthenticationKey? paceChipAuthenticationKey = null,
        CardVerifiableCertificate? terminalAuthenticationTrustAnchor = null,
        DateOnly? terminalAuthenticationDate = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cardId);
        ArgumentNullException.ThrowIfNull(files);

        TimeProvider = timeProvider ?? TimeProvider.System;
        Rng = rng ?? FillDeterministic;
        PaceCurve = paceCurve;
        ActiveAuthenticationKey = activeAuthenticationKey;
        PaceChipAuthenticationKey = paceChipAuthenticationKey;
        TerminalAuthenticationTrustAnchor = terminalAuthenticationTrustAnchor;
        TerminalAuthenticationCurrentDate = terminalAuthenticationDate ?? terminalAuthenticationTrustAnchor?.EffectiveDate ?? default;

        var chipAuthenticationKeyList = new List<ChipAuthenticationKey>();
        if(chipAuthenticationKeys is not null)
        {
            foreach(ChipAuthenticationKey key in chipAuthenticationKeys)
            {
                ArgumentNullException.ThrowIfNull(key);
                chipAuthenticationKeyList.Add(key);
            }
        }

        ChipAuthenticationKeys = chipAuthenticationKeyList;

        ImmutableDictionary<ushort, ElementaryFile>.Builder builder = ImmutableDictionary.CreateBuilder<ushort, ElementaryFile>();
        foreach(ElementaryFile file in files)
        {
            ArgumentNullException.ThrowIfNull(file);
            builder[file.FileIdentifier] = file;
        }

        Automaton = new PushdownAutomaton<CardSimulatorState, CardSimulatorInput, CardStackSymbol>(
            runId: cardId,
            initialState: CardSimulatorState.Operational(cardId, builder.ToImmutable()),
            initialStackSymbol: CardStackSymbol.Application,
            transition: CardCommandTransitions.Create(),
            acceptPredicate: static state => state.Phase is CardLifecyclePhase.Operational or CardLifecyclePhase.SecureMessaging,
            timeProvider: TimeProvider);
    }


    /// <summary>
    /// Gets the currently selected elementary file identifier, or <see langword="null"/> when none is selected.
    /// </summary>
    public ushort? SelectedFile => Automaton.CurrentState.SelectedFile;

    /// <summary>
    /// Gets the card's current operational phase.
    /// </summary>
    public CardLifecyclePhase Phase => Automaton.CurrentState.Phase;


    /// <inheritdoc />
    public IDisposable Subscribe(IObserver<TraceEntry<CardSimulatorState, CardSimulatorInput>> observer) =>
        Automaton.Subscribe(observer);


    /// <summary>
    /// Processes a command APDU and produces its response. Has the <see cref="TransceiveDelegate"/> shape.
    /// </summary>
    /// <param name="commandApdu">The command APDU bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The response. The caller owns the returned response and must dispose it.</returns>
    public async ValueTask<ApduResult<ApduResponse>> TransceiveAsync(ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        bool secureMessagingProtected = commandApdu.Length > 0 && (commandApdu.Span[0] & SecureMessagingClassBits) == SecureMessagingClassBits;

        //Once Basic Access Control establishes Secure Messaging the card accepts only protected commands;
        //before then there is no session to unwrap a protected command, so it is refused.
        if(Phase == CardLifecyclePhase.SecureMessaging && SecureMessagingSession is not null)
        {
            return secureMessagingProtected
                ? await SecureTransceiveAsync(commandApdu, SecureMessagingSession, pool, cancellationToken).ConfigureAwait(false)
                : SerializeResponse(new StatusOnlyResponse(StatusWord.SecurityNotSatisfied), pool);
        }

        if(secureMessagingProtected)
        {
            return SerializeResponse(new StatusOnlyResponse(StatusWord.SecurityNotSatisfied), pool);
        }

        return await PlaintextTransceiveAsync(commandApdu, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a plaintext command: parses it, drives the effectful loop, and frames the response.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of the rented buffer and is owned by the returned ApduResult, which the caller disposes.")]
    private async ValueTask<ApduResult<ApduResponse>> PlaintextTransceiveAsync(ReadOnlyMemory<byte> commandApdu, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        //A structurally malformed command is framed directly without stepping the automaton, so it leaves
        //no trace entry and does not disturb the card state.
        if(!TryParseCommand(commandApdu, out CardSimulatorInput? input, out StatusWord malformedStatus))
        {
            return SerializeResponse(new StatusOnlyResponse(malformedStatus), pool);
        }

        await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);

        CardResponseIntent intent = Automaton.CurrentState.ResponseIntent ?? new StatusOnlyResponse(StatusWord.NoPreciseDiagnosis);

        return SerializeResponse(intent, pool);
    }


    /// <summary>
    /// Dispatches a Secure-Messaging-protected command: unprotects it through the session, dispatches the
    /// recovered inner command, and protects the response — the card side of <see cref="SecureMessagingChannel"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of the rented buffer and is owned by the returned ApduResult, which the caller disposes.")]
    private async ValueTask<ApduResult<ApduResponse>> SecureTransceiveAsync(
        ReadOnlyMemory<byte> protectedCommand, SecureMessagingCardSession session, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Secure Messaging requires a BaseMemoryPool for pinned, zeroized buffers.");
        }

        SecureMessagingCommand inner;
        try
        {
            inner = await session.UnprotectCommandAsync(protectedCommand, basePool, cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //The command MAC did not verify: the command is tampered or the session desynchronized.
            return SerializeResponse(new StatusOnlyResponse(StatusWord.SecurityNotSatisfied), pool);
        }

        using(inner)
        {
            (IMemoryOwner<byte>? ownedData, ReadOnlyMemory<byte> responseData, StatusWord statusWord) =
                await DispatchInnerCommandAsync(inner, pool, cancellationToken).ConfigureAwait(false);
            try
            {
                using ProtectedResponseApdu protectedResponse = await session.ProtectResponseAsync(responseData, statusWord, basePool, cancellationToken).ConfigureAwait(false);

                ApduResult<ApduResponse> framed = WrapResponse(protectedResponse.AsReadOnlySpan(), pool);

                //Chip Authentication re-keys mid-session: a session it built during dispatch becomes active only
                //now, after its MSE:Set KAT acknowledgement was framed under the prior (still-current) session.
                ActivatePendingSecureMessagingSession();

                return framed;
            }
            finally
            {
                //An Active Authentication signature is the only owned Secure-Messaging response data; it is
                //released once protected (a borrowed file window leaves this null).
                ownedData?.Dispose();
            }
        }
    }


    /// <summary>
    /// Reconstructs the recovered inner command into a plaintext APDU, dispatches it, and returns the
    /// plaintext response data and status word to be protected.
    /// </summary>
    private async ValueTask<(IMemoryOwner<byte>? OwnedData, ReadOnlyMemory<byte> Data, StatusWord StatusWord)> DispatchInnerCommandAsync(
        SecureMessagingCommand inner, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> innerCommand = ReconstructInnerCommand(inner, pool, out int length);
        if(!TryParseCommand(innerCommand.Memory[..length], out CardSimulatorInput? input, out StatusWord malformedStatus))
        {
            return (null, ReadOnlyMemory<byte>.Empty, malformedStatus);
        }

        await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);

        CardResponseIntent intent = Automaton.CurrentState.ResponseIntent ?? new StatusOnlyResponse(StatusWord.NoPreciseDiagnosis);

        return ExtractResponse(intent);
    }


    /// <summary>
    /// Reassembles the plaintext command APDU bytes (<c>header [Lc data] [Le]</c>) from a recovered inner command.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it.")]
    private static IMemoryOwner<byte> ReconstructInnerCommand(SecureMessagingCommand inner, MemoryPool<byte> pool, out int length)
    {
        ReadOnlySpan<byte> data = inner.Data;
        bool hasData = data.Length > 0;
        bool hasExpectedLength = inner.ExpectedResponseLength.HasValue;
        //Lc is a single byte for up to 255 data bytes; a larger inner command (a long RSA certificate or
        //signature in Terminal Authentication) needs an extended Lc — a 0x00 marker then a two-byte length
        //(ISO/IEC 7816-4 §5.1). The commands that carry an extended Lc here are Case 3 (no Le), so the
        //extended-Lc and Le encodings never coexist.
        int lengthFieldSize = !hasData ? 0 : data.Length <= ApduConstants.MaxShortCommandData ? 1 : 3;
        int total = ApduConstants.CommandHeaderSize + lengthFieldSize + data.Length + (hasExpectedLength ? 1 : 0);

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> span = owner.Memory.Span;
            span[0] = inner.Cla;
            span[1] = inner.Instruction;
            span[2] = inner.Parameter1;
            span[3] = inner.Parameter2;
            int offset = ApduConstants.CommandHeaderSize;
            if(hasData)
            {
                if(data.Length <= ApduConstants.MaxShortCommandData)
                {
                    span[offset++] = (byte)data.Length;
                }
                else
                {
                    span[offset++] = 0x00;
                    span[offset++] = (byte)(data.Length >> 8);
                    span[offset++] = (byte)data.Length;
                }

                data.CopyTo(span[offset..]);
                offset += data.Length;
            }

            if(hasExpectedLength)
            {
                span[offset] = (byte)(inner.ExpectedResponseLength!.Value == MaxShortExpectedLength ? 0 : inner.ExpectedResponseLength.Value);
            }

            length = total;

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Extracts the plaintext response data and status word from a response intent. A response that carries
    /// owned data over Secure Messaging (an Active Authentication signature) returns its buffer for the caller
    /// to dispose once the response is protected; intents that never carry Secure-Messaging data release their
    /// buffers here (a defensive path).
    /// </summary>
    private static (IMemoryOwner<byte>? OwnedData, ReadOnlyMemory<byte> Data, StatusWord StatusWord) ExtractResponse(CardResponseIntent intent)
    {
        switch(intent)
        {
            case BinaryReadResponse read:
                return (null, read.Data, read.StatusWord);
            case ActiveAuthenticationResponse activeAuthentication:
                //INTERNAL AUTHENTICATE runs over Secure Messaging too; the signature is the protected response
                //data, so its buffer is handed back to be disposed after protection rather than released here.
                return (activeAuthentication.Signature, activeAuthentication.Signature.Memory[..activeAuthentication.Length], activeAuthentication.StatusWord);
            case ChallengeResponse challenge:
                //GET CHALLENGE runs over Secure Messaging during Terminal Authentication; the issued challenge
                //r_IC is the protected response data, so its buffer is handed back to be disposed after protection.
                return (challenge.Challenge, challenge.Challenge.Memory[..challenge.Length], challenge.StatusWord);
            case BacAuthenticateResponse authenticate:
                authenticate.Token.Dispose();

                return (null, ReadOnlyMemory<byte>.Empty, authenticate.StatusWord);
            case DynamicAuthenticationDataResponse dynamicAuthentication:
                //PACE rounds run in the clear, so this is a defensive release of an owned buffer that should
                //never reach the Secure-Messaging-wrapped dispatch path.
                dynamicAuthentication.Data.Dispose();

                return (null, ReadOnlyMemory<byte>.Empty, dynamicAuthentication.StatusWord);
            default:
                return (null, ReadOnlyMemory<byte>.Empty, intent.StatusWord);
        }
    }


    /// <summary>
    /// Wraps already-framed response bytes (here, a protected response APDU) into an <see cref="ApduResponse"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of the rented buffer and is owned by the returned ApduResult, which the caller disposes.")]
    private static ApduResult<ApduResponse> WrapResponse(ReadOnlySpan<byte> responseBytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(responseBytes.Length);
        try
        {
            responseBytes.CopyTo(owner.Memory.Span);
            var response = new ApduResponse(owner, responseBytes.Length);

            return ApduResult<ApduResponse>.Success(response, response.StatusWord);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Drives the automaton through the effectful loop: step, execute any action the new state declares
    /// (drawing card entropy, running the BAC crypto), feed the result back, repeat until no action remains.
    /// </summary>
    private async ValueTask RunWithEffectsAsync(CardSimulatorInput input, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<CardSimulatorState, CardSimulatorInput, MemoryPool<byte>>(
            Automaton.CurrentState,
            Automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: ExecuteActionAsync,
            actionContext: pool,
            TimeProvider,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Executes the effectful work a transition declared and returns the input to feed back.
    /// </summary>
    private async ValueTask<CardSimulatorInput> ExecuteActionAsync(PdaAction action, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        action switch
        {
            CardRngAction rngAction => GenerateChallenge(rngAction, pool),
            BacAuthenticateAction bacAction => await AuthenticateAsync(bacAction, pool, cancellationToken).ConfigureAwait(false),
            PaceSelectMechanismAction selectMechanism => SelectPaceMechanism(selectMechanism, pool),
            PaceEncryptNonceAction => await EncryptPaceNonceAsync(pool, cancellationToken).ConfigureAwait(false),
            PaceMapAction mapAction => await MapPaceNonceAsync(mapAction, pool, cancellationToken).ConfigureAwait(false),
            PaceAgreeAction agreeAction => await AgreePaceKeysAsync(agreeAction, pool, cancellationToken).ConfigureAwait(false),
            PaceAuthenticateAction authenticateAction => await AuthenticatePaceAsync(authenticateAction, pool, cancellationToken).ConfigureAwait(false),
            ChipAuthenticateAction chipAuthenticateAction => await ChipAuthenticateAsync(chipAuthenticateAction, pool, cancellationToken).ConfigureAwait(false),
            ActiveAuthenticateAction activeAuthenticateAction => await ActiveAuthenticateAsync(activeAuthenticateAction, pool, cancellationToken).ConfigureAwait(false),
            SetDigitalSignatureTemplateAction setDigitalSignatureTemplateAction => SetDigitalSignatureTemplate(setDigitalSignatureTemplateAction),
            VerifyCertificateAction verifyCertificateAction => await VerifyPresentedCertificateAsync(verifyCertificateAction, pool, cancellationToken).ConfigureAwait(false),
            SetTerminalAuthenticationTemplateAction setTerminalAuthenticationTemplateAction => SetTerminalAuthenticationTemplate(setTerminalAuthenticationTemplateAction),
            TerminalAuthenticateAction terminalAuthenticateAction => await VerifyTerminalSignatureAsync(terminalAuthenticateAction, pool, cancellationToken).ConfigureAwait(false),
            _ => throw new NotSupportedException($"No executor is registered for action '{action.GetType().Name}'.")
        };


    /// <summary>
    /// Draws the requested number of octets for GET CHALLENGE, returns them for framing, and retains a copy
    /// as the issued chip nonce RND.IC the Basic Access Control mutual authentication consumes.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned CardEntropyGenerated, then to the ChallengeResponse intent, and is released by SerializeResponse after framing.")]
    private CardEntropyGenerated GenerateChallenge(CardRngAction action, MemoryPool<byte> pool)
    {
        //Rent at least one octet so a zero-length request still yields a valid (empty) buffer.
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(action.ByteCount, 1));
        try
        {
            Rng(owner.Memory.Span[..action.ByteCount]);
        }
        catch
        {
            owner.Dispose();

            throw;
        }

        RetainIssuedChallenge(owner.Memory.Span[..action.ByteCount], pool);

        return new CardEntropyGenerated(owner, action.ByteCount);
    }


    /// <summary>
    /// Runs the Basic Access Control mutual authentication: derives the access keys from the card's own DG1
    /// MRZ, verifies the terminal token against the issued RND.IC, establishes the Secure Messaging session,
    /// and returns the card's response token.
    /// </summary>
    private async ValueTask<CardSimulatorInput> AuthenticateAsync(BacAuthenticateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Basic Access Control requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(IssuedChallenge is null || !Automaton.CurrentState.Files.TryGetValue(DataGroup1.FileIdentifier, out ElementaryFile? dataGroup1File))
        {
            //No outstanding challenge, or no EF.DG1 to derive the access key from.
            return new BacAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        MachineReadableZone mrz = DataGroup1.Parse(dataGroup1File.Content).MachineReadableZone;
        string mrzInformation = BasicAccessControl.BuildMrzInformation(mrz.DocumentNumber, mrz.DateOfBirth, mrz.DateOfExpiry);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) =
            await BasicAccessControl.DeriveAccessKeysAsync(mrzInformation, basePool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> chipKeyingMaterial = basePool.Rent(ChipKeyingMaterialLength, AllocationKind.Pinned);
        try
        {
            Rng(chipKeyingMaterial.Memory.Span[..ChipKeyingMaterialLength]);

            (IMemoryOwner<byte> responseToken, SecureMessagingCardSession session) = await BasicAccessControlCardResponder.EstablishSessionAsync(
                encryptionKey, macKey, IssuedChallenge.Memory[..IssuedChallengeLength], chipKeyingMaterial.Memory[..ChipKeyingMaterialLength],
                action.TerminalToken, basePool, cancellationToken).ConfigureAwait(false);

            //The challenge is single-use; the new session replaces any prior one.
            ConsumeIssuedChallenge();
            SecureMessagingSession?.Dispose();
            SecureMessagingSession = session;

            return new BacAuthenticationCompleted(responseToken, action.TerminalToken.Length);
        }
        catch(Exception exception) when(exception is InvalidOperationException or ArgumentException)
        {
            //A failed MAC, an unechoed nonce, or a malformed token: the challenge is consumed and the
            //terminal is refused.
            ConsumeIssuedChallenge();

            return new BacAuthenticationFailed(StatusWord.AuthenticationFailed);
        }
        finally
        {
            encryptionKey.Dispose();
            macKey.Dispose();
        }
    }


    /// <summary>
    /// Captures the PACE mechanism MSE:Set AT selected — the protocol OID, retained for the round-4
    /// authentication tokens — abandoning any half-finished PACE exchange first.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented OID buffer transfers to device state, disposed by ResetPaceExchange or Dispose; the catch disposes it on a failure path.")]
    private PaceMechanismSelected SelectPaceMechanism(PaceSelectMechanismAction action, MemoryPool<byte> pool)
    {
        //A fresh MSE:Set AT abandons any half-finished PACE exchange.
        ResetPaceExchange();

        ReadOnlySpan<byte> objectIdentifier = action.ObjectIdentifier.Span;
        IMemoryOwner<byte> retained = pool.Rent(Math.Max(objectIdentifier.Length, 1));
        try
        {
            objectIdentifier.CopyTo(retained.Memory.Span);
            SelectedPaceObjectIdentifier = retained;
            SelectedPaceObjectIdentifierLength = objectIdentifier.Length;

            return new PaceMechanismSelected();
        }
        catch
        {
            retained.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Runs the PACE encrypted-nonce round: derives the password key from the card's own DG1 MRZ, draws and
    /// encrypts the nonce, retains the nonce for the mapping round, and wraps the cryptogram for the terminal.
    /// </summary>
    private async ValueTask<CardSimulatorInput> EncryptPaceNonceAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("PACE requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(!Automaton.CurrentState.Files.TryGetValue(DataGroup1.FileIdentifier, out ElementaryFile? dataGroup1File))
        {
            throw new InvalidOperationException("PACE requires the card to hold EF.DG1 to derive its password.");
        }

        MachineReadableZone mrz = DataGroup1.Parse(dataGroup1File.Content).MachineReadableZone;
        string mrzInformation = BasicAccessControl.BuildMrzInformation(mrz.DocumentNumber, mrz.DateOfBirth, mrz.DateOfExpiry);

        (IMemoryOwner<byte> encryptedNonce, IMemoryOwner<byte> nonce) = await PaceCardResponder.EncryptNonceAsync(
            mrzInformation, Rng, basePool, cancellationToken).ConfigureAwait(false);
        try
        {
            //Retain the nonce s for the mapping round, replacing any prior one.
            PaceNonce?.Dispose();
            PaceNonce = nonce;
            PaceNonceLength = PaceNonceLengthBytes;

            IMemoryOwner<byte> response = WrapDynamicAuthenticationData(EncryptedNonceTag, encryptedNonce.Memory.Span[..PaceNonceLengthBytes], basePool, out int responseLength);

            return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: false);
        }
        finally
        {
            encryptedNonce.Dispose();
        }
    }


    /// <summary>
    /// Runs the PACE nonce-mapping round, dispatching to the mechanism the selected OID names: Generic Mapping
    /// (a mapping key-pair exchange) or Integrated Mapping (a direct map of the terminal's nonce t).
    /// </summary>
    private async ValueTask<CardSimulatorInput> MapPaceNonceAsync(PaceMapAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("PACE requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(PaceCurve is not Tag curve || PaceNonce is null || SelectedPaceObjectIdentifier is null)
        {
            //No curve to map over, no nonce (the encrypted-nonce round has not run), or no selected mechanism.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
        }

        PaceMappingType mappingType;
        try
        {
            mappingType = PaceObjectIdentifier.GetMappingType(SelectedPaceObjectIdentifier.Memory.Span[..SelectedPaceObjectIdentifierLength]);
        }
        catch(ArgumentException)
        {
            //The selected OID does not name a supported mapping: abandon the exchange.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
        }

        return mappingType == PaceMappingType.IntegratedMapping
            ? await MapPaceNonceWithIntegratedMappingAsync(action, curve, basePool, cancellationToken).ConfigureAwait(false)
            : await MapPaceNonceWithGenericMappingAsync(action, curve, basePool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Runs the Generic Mapping nonce round: generates a fresh chip mapping key pair, maps the nonce to the
    /// ephemeral generator <c>Ĝ = s·G + H</c>, retains it (and the mapping private key, which Chip
    /// Authentication Mapping needs in round 4), and answers with the chip's mapping public key (DO'82').
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The mapped generator and mapping private key transfer to device state (disposed by ResetPaceExchange or Dispose); the mapping public key is disposed in the finally; the response buffer transfers to the returned input.")]
    private async ValueTask<CardSimulatorInput> MapPaceNonceWithGenericMappingAsync(PaceMapAction action, Tag curve, BaseMemoryPool basePool, CancellationToken cancellationToken)
    {
        (EncodedEcPoint mappingPublicKey, EncodedEcPoint mappedGenerator, IMemoryOwner<byte> mappingPrivateKey) = await PaceCardResponder.MapAsync(
            PaceNonce!.Memory[..PaceNonceLength], action.TerminalMappingData, curve, Rng, basePool, cancellationToken).ConfigureAwait(false);
        try
        {
            ConsumeNonceAndRetainMappedGenerator(mappedGenerator);
            RetainMappingPrivateKey(mappingPrivateKey);

            IMemoryOwner<byte> response = WrapDynamicAuthenticationData(ChipMappingDataTag, mappingPublicKey.AsReadOnlySpan(), basePool, out int responseLength);

            return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: false);
        }
        finally
        {
            mappingPublicKey.Dispose();
        }
    }


    /// <summary>
    /// Runs the Integrated Mapping nonce round: maps the nonce to the ephemeral generator
    /// <c>Ĝ = f_G(R_p(s,t))</c> directly from the terminal's nonce t, retains it, and answers with an empty
    /// DO'82' (Doc 9303 §4.4.5.2.2 — the chip sends no mapping public key under Integrated Mapping).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The mapped generator transfers to device state (disposed by ResetPaceExchange or Dispose); the response buffer transfers to the returned input.")]
    private async ValueTask<CardSimulatorInput> MapPaceNonceWithIntegratedMappingAsync(PaceMapAction action, Tag curve, BaseMemoryPool basePool, CancellationToken cancellationToken)
    {
        EncodedEcPoint mappedGenerator = await PaceIntegratedMapping.MapNonceAsync(
            PaceNonce!.Memory[..PaceNonceLength], action.TerminalMappingData, curve, basePool, cancellationToken).ConfigureAwait(false);

        ConsumeNonceAndRetainMappedGenerator(mappedGenerator);

        IMemoryOwner<byte> response = WrapDynamicAuthenticationData(ChipMappingDataTag, ReadOnlySpan<byte>.Empty, basePool, out int responseLength);

        return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: false);
    }


    /// <summary>
    /// Consumes the PACE nonce, which the mapping has used, and retains the mapped generator as device state for
    /// the key-agreement round.
    /// </summary>
    private void ConsumeNonceAndRetainMappedGenerator(EncodedEcPoint mappedGenerator)
    {
        PaceNonce?.Dispose();
        PaceNonce = null;
        PaceNonceLength = 0;
        PaceMappedGenerator?.Dispose();
        PaceMappedGenerator = mappedGenerator;
    }


    /// <summary>
    /// Retains the chip's mapping private key s_Map,IC as device state for Chip Authentication Mapping, which
    /// blinds the static key with it in round 4.
    /// </summary>
    private void RetainMappingPrivateKey(IMemoryOwner<byte> mappingPrivateKey)
    {
        PaceMappingPrivateKey?.Dispose();
        PaceMappingPrivateKey = mappingPrivateKey;
        PaceMappingPrivateKeyLength = mappingPrivateKey.Memory.Length;
    }


    /// <summary>
    /// Runs the PACE key-agreement round: agrees the shared secret over the mapped generator with a fresh chip
    /// ephemeral key pair, derives and retains the AES session keys, retains both ephemeral public keys for the
    /// token round, and wraps the chip's ephemeral public key for the terminal.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The ephemeral public key and the session keys transfer to device state (disposed by ResetPaceExchange, the Secure Messaging session, or Dispose); the response buffer transfers to the returned input.")]
    private async ValueTask<CardSimulatorInput> AgreePaceKeysAsync(PaceAgreeAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("PACE requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(PaceCurve is not Tag curve || PaceMappedGenerator is null)
        {
            //No curve, or the mapping round has not run: abandon the exchange.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
        }

        (EncodedEcPoint ephemeralPublicKey, SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await PaceCardResponder.AgreeAsync(
            PaceMappedGenerator.AsReadOnlyMemory(), action.TerminalEphemeralPublicKey, curve, Rng, basePool, cancellationToken).ConfigureAwait(false);

        //Retain the agreement results as device state before anything else can throw.
        PaceChipEphemeralPublicKey?.Dispose();
        PaceChipEphemeralPublicKey = ephemeralPublicKey;
        PaceEncryptionKey?.Dispose();
        PaceEncryptionKey = encryptionKey;
        PaceMacKey?.Dispose();
        PaceMacKey = macKey;

        //The mapped generator is consumed by the agreement.
        PaceMappedGenerator.Dispose();
        PaceMappedGenerator = null;

        //Retain the terminal's ephemeral public key so the chip's round-4 token authenticates it.
        PaceTerminalEphemeralPublicKey?.Dispose();
        PaceTerminalEphemeralPublicKey = EncodedEcPoint.FromBytes(action.TerminalEphemeralPublicKey.Span, curve, basePool);

        IMemoryOwner<byte> response = WrapDynamicAuthenticationData(ChipEphemeralKeyTag, ephemeralPublicKey.AsReadOnlySpan(), basePool, out int responseLength);

        return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: false);
    }


    /// <summary>
    /// Runs the PACE mutual-authentication round: verifies the terminal's token, establishes the AES Secure
    /// Messaging session on success, and wraps the chip's token for the terminal.
    /// </summary>
    private async ValueTask<CardSimulatorInput> AuthenticatePaceAsync(PaceAuthenticateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("PACE requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(PaceMacKey is null || PaceChipEphemeralPublicKey is null || PaceTerminalEphemeralPublicKey is null || SelectedPaceObjectIdentifier is null)
        {
            //The key-agreement round has not run, or no mechanism was selected: abandon the exchange.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
        }

        MacValue chipToken;
        try
        {
            chipToken = await PaceCardResponder.AuthenticateAsync(
                PaceMacKey, action.TerminalToken,
                PaceChipEphemeralPublicKey, PaceTerminalEphemeralPublicKey,
                SelectedPaceObjectIdentifier.Memory[..SelectedPaceObjectIdentifierLength], basePool, cancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException)
        {
            //The terminal's token T_IFD did not verify: abandon the exchange.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.AuthenticationFailed);
        }

        using(chipToken)
        {
            PaceMappingType mappingType;
            try
            {
                mappingType = PaceObjectIdentifier.GetMappingType(SelectedPaceObjectIdentifier.Memory.Span[..SelectedPaceObjectIdentifierLength]);
            }
            catch(ArgumentException)
            {
                //The selected OID does not name a supported mapping: abandon the exchange.
                ResetPaceExchange();

                return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
            }

            if(mappingType == PaceMappingType.ChipAuthenticationMapping)
            {
                return await AuthenticatePaceWithChipAuthenticationMappingAsync(chipToken, basePool, cancellationToken).ConfigureAwait(false);
            }

            //Generic and Integrated Mapping: the agreed keys become the AES Secure Messaging session (SSC=0),
            //and the response carries only the chip token.
            EstablishPaceSecureMessagingSession(basePool);

            IMemoryOwner<byte> response = WrapDynamicAuthenticationData(ChipTokenTag, chipToken.AsReadOnlySpan(), basePool, out int responseLength);

            return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: true);
        }
    }


    /// <summary>
    /// Completes the round-4 mutual authentication under Chip Authentication Mapping: derives the Chip
    /// Authentication Data from the static key and the retained mapping private key, encrypts it under KSenc,
    /// establishes the Secure Messaging session, and answers with the chip token (DO'86') alongside the
    /// Encrypted Chip Authentication Data (DO'8A').
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The response buffer transfers to the returned input; the CA data and its ciphertext are disposed by their using declarations.")]
    private async ValueTask<CardSimulatorInput> AuthenticatePaceWithChipAuthenticationMappingAsync(MacValue chipToken, BaseMemoryPool basePool, CancellationToken cancellationToken)
    {
        if(PaceCurve is not Tag curve || PaceChipAuthenticationKey is null || PaceMappingPrivateKey is null || PaceEncryptionKey is null)
        {
            //CAM was selected but the static key, the retained mapping private key, or the session key is missing.
            ResetPaceExchange();

            return new PaceExchangeFailed(StatusWord.ConditionsNotSatisfied);
        }

        //Compute the Encrypted Chip Authentication Data while KSenc is still held (the session establishment transfers it away).
        using ChipAuthenticationData chipAuthenticationData = await PaceChipAuthenticationMapping.GenerateAsync(
            PaceChipAuthenticationKey.AsReadOnlyMemory(), PaceMappingPrivateKey.Memory[..PaceMappingPrivateKeyLength], curve, basePool, cancellationToken).ConfigureAwait(false);
        using Ciphertext encryptedChipAuthenticationData = await PaceChipAuthenticationMapping.EncryptAsync(
            chipAuthenticationData, PaceEncryptionKey, basePool, cancellationToken).ConfigureAwait(false);

        EstablishPaceSecureMessagingSession(basePool);

        IMemoryOwner<byte> response = WrapDynamicAuthenticationDataPair(
            ChipTokenTag, chipToken.AsReadOnlySpan(),
            EncryptedChipAuthenticationDataTag, encryptedChipAuthenticationData.AsReadOnlySpan(),
            basePool, out int responseLength);

        return new PaceRoundCompleted(response, responseLength, EstablishesSecureMessaging: true);
    }


    /// <summary>
    /// Builds the AES Secure Messaging session from the agreed PACE keys, transferring their ownership to the
    /// session, then releases the remaining PACE exchange state.
    /// </summary>
    private void EstablishPaceSecureMessagingSession(BaseMemoryPool pool)
    {
        SymmetricKeyMemory encryptionKey = PaceEncryptionKey ?? throw new InvalidOperationException("The PACE session encryption key is not available.");
        SymmetricKeyMemory macKey = PaceMacKey ?? throw new InvalidOperationException("The PACE session MAC key is not available.");

        //The keys transfer to the session; clear the PACE references so ResetPaceExchange does not double-dispose them.
        PaceEncryptionKey = null;
        PaceMacKey = null;

        Span<byte> initialSendSequenceCounter = stackalloc byte[SecureMessagingProfile.Aes128.BlockSize];
        initialSendSequenceCounter.Clear();

        SecureMessagingCardSession session;
        try
        {
            session = new SecureMessagingCardSession(encryptionKey, macKey, initialSendSequenceCounter, SecureMessagingProfile.Aes128, pool);
        }
        catch
        {
            encryptionKey.Dispose();
            macKey.Dispose();

            throw;
        }

        //Retain the chip's PACE ephemeral public key before the round state is released: after PACE the chip
        //identifier ID_IC a later Terminal Authentication signs is Comp() of this key, not the MRZ document
        //number, and its presence marks PACE as the access protocol (BSI TR-03110-3 §A.2.2.3).
        if(PaceChipEphemeralPublicKey is not null)
        {
            PaceAccessChipEphemeralPublicKey?.Dispose();
            PaceAccessChipEphemeralPublicKey = EncodedEcPoint.FromBytes(PaceChipEphemeralPublicKey.AsReadOnlySpan(), PaceChipEphemeralPublicKey.Tag, pool);
        }

        //The new session replaces any prior one; the remaining PACE intermediates are released.
        SecureMessagingSession?.Dispose();
        SecureMessagingSession = session;
        ResetPaceExchange();
    }


    /// <summary>
    /// Runs EACv1 Chip Authentication: agrees the static–ephemeral ECDH secret between the card's static
    /// DG14 key (selected by the MSE:Set KAT key identifier) and the terminal's ephemeral key, then builds
    /// the re-keyed session — held pending until the acknowledgement is framed under the prior session.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The re-keyed session transfers to device state (PendingSecureMessagingSession), disposed by ActivatePendingSecureMessagingSession or Dispose; EstablishSessionAsync disposes its keys on its own failure path.")]
    private async ValueTask<CardSimulatorInput> ChipAuthenticateAsync(ChipAuthenticateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Chip Authentication requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(!Automaton.CurrentState.Files.TryGetValue(DataGroup14.FileIdentifier, out ElementaryFile? dataGroup14File))
        {
            //The card holds no EF.DG14 to authenticate against.
            return new ChipAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        ChipAuthenticationKey? chipKey = MatchChipAuthenticationKey(action.KeyId);
        if(chipKey is null)
        {
            //The card holds no Chip Authentication private key for the requested key identifier.
            return new ChipAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        try
        {
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), basePool);
            ChipAuthenticationPublicKeyInfo? publicKeyInfo = MatchPublicKeyInfo(dataGroup14, action.KeyId);
            ChipAuthenticationInfo? info = MatchInfo(dataGroup14, action.KeyId);
            if(publicKeyInfo is null || info is null)
            {
                return new ChipAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
            }

            SecureMessagingCardSession session = await ChipAuthenticationCardResponder.EstablishSessionAsync(
                chipKey.AsReadOnlyMemory(), action.TerminalEphemeralPublicKey, publicKeyInfo.PublicKey.Tag, info.Cipher, basePool, cancellationToken).ConfigureAwait(false);

            //The re-keyed session takes effect only after the MSE:Set KAT response is framed under the prior one.
            PendingSecureMessagingSession?.Dispose();
            PendingSecureMessagingSession = session;

            //Retain the terminal's ephemeral public key PK_DH,IFD: Terminal Authentication binds its signature
            //to Comp() of this session-establishing key.
            TerminalChipAuthenticationEphemeralKey?.Dispose();
            TerminalChipAuthenticationEphemeralKey = EncodedEcPoint.FromBytes(
                action.TerminalEphemeralPublicKey.Span, publicKeyInfo.PublicKey.Tag, basePool);

            return new ChipAuthenticationCompleted();
        }
        catch(Exception exception) when(exception is InvalidOperationException or ArgumentException or NotSupportedException)
        {
            //A malformed DG14, an unsupported curve or cipher, or a bad key: refuse without dropping the session.
            return new ChipAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }
    }


    /// <summary>
    /// Runs Active Authentication: reads the key type from the card's own EF.DG15 and signs the terminal's
    /// INTERNAL AUTHENTICATE challenge with the chip's Active Authentication private key — ECDSA over the
    /// curve EF.DG15 announces, or ISO/IEC 9796-2 message recovery for an RSA key.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented signature buffer transfers to the returned ActiveAuthenticationSigned, then to the ActiveAuthenticationResponse intent, and is released after framing; the catch disposes it on failure.")]
    private async ValueTask<CardSimulatorInput> ActiveAuthenticateAsync(ActiveAuthenticateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Active Authentication requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(ActiveAuthenticationKey is null || !Automaton.CurrentState.Files.TryGetValue(DataGroup15.FileIdentifier, out ElementaryFile? dataGroup15File))
        {
            //No Active Authentication key, or no EF.DG15 to read the key type from: the card cannot authenticate.
            return new ActiveAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        try
        {
            using DataGroup15 dataGroup15 = DataGroup15.Parse(dataGroup15File.AsReadOnlySpan(), basePool);

            //Both Active Authentication key types are modelled: an RSA key signs ISO/IEC 9796-2 with message
            //recovery; an elliptic-curve key signs ECDSA over the curve the chip's own EF.DG15 announces.
            using Signature signature = dataGroup15.KeyType == ActiveAuthenticationKeyType.Rsa
                ? await RsaActiveAuthenticationCardResponder.SignChallengeAsync(
                    ActiveAuthenticationKey.AsReadOnlyMemory(), action.Challenge, basePool, cancellationToken).ConfigureAwait(false)
                : await ActiveAuthenticationCardResponder.SignChallengeAsync(
                    ActiveAuthenticationKey.AsReadOnlyMemory(), dataGroup15.EllipticCurvePublicKey.Tag, action.Challenge, basePool, cancellationToken).ConfigureAwait(false);

            //The signature is public; copy it out of the responder's buffer so the (disposed-here) Signature
            //carrier does not outlive framing, mirroring the GET CHALLENGE data-response path.
            IMemoryOwner<byte> owner = basePool.Rent(signature.Length);
            try
            {
                signature.AsReadOnlySpan().CopyTo(owner.Memory.Span);

                return new ActiveAuthenticationSigned(owner, signature.Length);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }
        catch(Exception exception) when(exception is InvalidOperationException or ArgumentException or NotSupportedException)
        {
            //A malformed DG15, an unsupported curve, or a bad key: the terminal is refused.
            return new ActiveAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }
    }


    /// <summary>
    /// Records the Terminal Authentication MSE:Set DST public-key reference, validating that a certificate
    /// with that holder reference is available — the trusted Country Verifying Certification Authority or a
    /// previously imported certificate — to verify the next presented certificate against.
    /// </summary>
    private TerminalAuthenticationStepCompleted SetDigitalSignatureTemplate(SetDigitalSignatureTemplateAction action)
    {
        if(TerminalAuthenticationTrustAnchor is null)
        {
            //The card holds no trust anchor, so it supports no Terminal Authentication.
            return new TerminalAuthenticationStepCompleted(StatusWord.ConditionsNotSatisfied);
        }

        string reference = Encoding.ASCII.GetString(action.PublicKeyReference.Span);
        if(ResolveVerifier(reference) is null)
        {
            //The named key is neither the trusted CVCA nor a previously imported certificate.
            return new TerminalAuthenticationStepCompleted(StatusWord.ReferencedDataNotFound);
        }

        DigitalSignatureTemplateReference = reference;

        return new TerminalAuthenticationStepCompleted(StatusWord.Success);
    }


    /// <summary>
    /// Verifies a presented card-verifiable certificate against the public key the preceding MSE:Set DST
    /// selected (one chain-verification step), and imports it on success so it can verify the next
    /// certificate — and, for the terminal certificate, carry the public key EXTERNAL AUTHENTICATE checks
    /// the Terminal Authentication signature against.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The parsed certificate is disposed on a verification failure and transferred to device state (ImportedTerminalCertificate, disposed by Dispose) on success.")]
    private async ValueTask<CardSimulatorInput> VerifyPresentedCertificateAsync(VerifyCertificateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Terminal Authentication requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        if(TerminalAuthenticationTrustAnchor is null || DigitalSignatureTemplateReference is null)
        {
            //No trust anchor, or no MSE:Set DST selected a verifying key first.
            return new TerminalAuthenticationStepCompleted(StatusWord.ConditionsNotSatisfied);
        }

        CardVerifiableCertificate? issuer = ResolveVerifier(DigitalSignatureTemplateReference);
        if(issuer is null)
        {
            //The selected verifying key is gone (no MSE:Set DST, or it named a key the chip does not hold).
            return new TerminalAuthenticationStepCompleted(StatusWord.ConditionsNotSatisfied);
        }

        CardVerifiableCertificate certificate;
        try
        {
            //An elliptic-curve issuer supplies the curve a domain-parameter-less subject inherits; an RSA issuer
            //supplies none (an RSA subject carries no curve), so the inherited curve is its point tag or null.
            using IMemoryOwner<byte> wrapped = WrapCertificate(action.CertificateContent.Span, basePool, out int wrappedLength);
            certificate = CardVerifiableCertificate.Parse(wrapped.Memory.Span[..wrappedLength], basePool, issuer.PublicKey.EllipticCurvePoint?.Tag);
        }
        catch(Exception exception) when(exception is InvalidOperationException or ArgumentException)
        {
            return new TerminalAuthenticationStepCompleted(StatusWord.WrongData);
        }

        //A clockless chip has no "now": it checks each certificate against the most recent effective date it
        //has verified, so a certificate issued after the chip's current date is not "not yet valid" — only one
        //expired relative to that advancing date is rejected (Doc 9303 Part 11 §7.1, BSI TR-03110-2).
        DateOnly referenceDate = TerminalAuthenticationCurrentDate >= certificate.EffectiveDate
            ? TerminalAuthenticationCurrentDate
            : certificate.EffectiveDate;
        CvcChainVerificationResult result = await CardVerifiableCertificateChain.VerifyOneAsync(
            issuer, certificate, referenceDate, cancellationToken).ConfigureAwait(false);
        if(result != CvcChainVerificationResult.Valid)
        {
            certificate.Dispose();

            return new TerminalAuthenticationStepCompleted(MapVerificationResult(result));
        }

        //Accumulate the effective authorization (BSI TR-03110-3 §2.7): the bitwise AND of the relative
        //authorizations along the chain. A certificate verified directly against the trusted CVCA begins a
        //fresh chain, so the accumulator is re-seeded from the CVCA and this certificate; a later certificate
        //ANDs into the running value. The chip retains only the most recent certificate, so it accumulates as
        //it verifies rather than recomputing from a stored chain.
        AccumulatedReadAccess = ReferenceEquals(issuer, TerminalAuthenticationTrustAnchor)
            ? issuer.Chat.InspectionSystemReadAccess & certificate.Chat.InspectionSystemReadAccess
            : AccumulatedReadAccess & certificate.Chat.InspectionSystemReadAccess;

        //Import the verified certificate: it becomes the verifier the next MSE:Set DST may select, and the
        //terminal certificate ending the chain carries the public key EXTERNAL AUTHENTICATE will check.
        ImportedTerminalCertificate?.Dispose();
        ImportedTerminalCertificate = certificate;
        DigitalSignatureTemplateReference = null;

        //Advance the chip's current date to this certificate's effective date.
        TerminalAuthenticationCurrentDate = referenceDate;

        return new TerminalAuthenticationStepCompleted(StatusWord.Success);
    }


    /// <summary>
    /// Resolves the certificate whose holder reference an MSE:Set DST named — the trusted Country Verifying
    /// Certification Authority or the most recently imported certificate — or <see langword="null"/> when none matches.
    /// </summary>
    private CardVerifiableCertificate? ResolveVerifier(string reference)
    {
        if(TerminalAuthenticationTrustAnchor is not null
            && string.Equals(reference, TerminalAuthenticationTrustAnchor.CertificateHolderReference, StringComparison.Ordinal))
        {
            return TerminalAuthenticationTrustAnchor;
        }

        if(ImportedTerminalCertificate is not null
            && string.Equals(reference, ImportedTerminalCertificate.CertificateHolderReference, StringComparison.Ordinal))
        {
            return ImportedTerminalCertificate;
        }

        return null;
    }


    /// <summary>
    /// Maps a single-step chain-verification result to the status word PSO:Verify Certificate returns: a bad
    /// signature is an authentication failure, a malformed validity is wrong data, and every other linkage,
    /// role, or date failure is a conditions-of-use violation.
    /// </summary>
    private static StatusWord MapVerificationResult(CvcChainVerificationResult result) => result switch
    {
        CvcChainVerificationResult.InvalidSignature => StatusWord.AuthenticationFailed,
        CvcChainVerificationResult.MalformedValidity => StatusWord.WrongData,
        _ => StatusWord.ConditionsNotSatisfied
    };


    /// <summary>
    /// Wraps a presented certificate's content (its body and signature) in the outer card-verifiable
    /// certificate object (<c>7F21</c>) so it can be parsed, since PSO:Verify Certificate carries the content
    /// without the outer tag and length.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    private static IMemoryOwner<byte> WrapCertificate(ReadOnlySpan<byte> content, MemoryPool<byte> pool, out int length)
    {
        int total = 2 + BerLengthSize(content.Length) + content.Length;

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> span = owner.Memory.Span;
            span[0] = (byte)(CardVerifiableCertificateTag >> 8);
            span[1] = (byte)(CardVerifiableCertificateTag & 0xFF);
            int offset = 2 + WriteBerLength(content.Length, span[2..]);
            content.CopyTo(span[offset..]);
            length = total;

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Selects the imported terminal certificate's key for the EXTERNAL AUTHENTICATE, validating that a
    /// terminal-role certificate with the named holder reference has been imported.
    /// </summary>
    private TerminalAuthenticationTemplateSet SetTerminalAuthenticationTemplate(SetTerminalAuthenticationTemplateAction action)
    {
        string reference = Encoding.ASCII.GetString(action.TerminalReference.Span);
        if(ImportedTerminalCertificate is null
            || ImportedTerminalCertificate.Chat.Role != CertificateRole.Terminal
            || !string.Equals(reference, ImportedTerminalCertificate.CertificateHolderReference, StringComparison.Ordinal))
        {
            return new TerminalAuthenticationTemplateSet(StatusWord.ConditionsNotSatisfied);
        }

        //The named Terminal Authentication protocol (DO'80') must match the imported terminal key's scheme.
        if(!action.ObjectIdentifier.Span.SequenceEqual(TerminalAuthenticationObjectIdentifier.ValueBytes(ImportedTerminalCertificate.PublicKey.SignatureScheme)))
        {
            return new TerminalAuthenticationTemplateSet(StatusWord.ConditionsNotSatisfied);
        }

        //Pin the selected terminal reference so EXTERNAL AUTHENTICATE verifies against exactly this key, even
        //if a further certificate is imported before it.
        SelectedTerminalAuthenticationReference = reference;

        return new TerminalAuthenticationTemplateSet(StatusWord.Success);
    }


    /// <summary>
    /// Verifies the terminal's EXTERNAL AUTHENTICATE signature s_IFD against the imported terminal
    /// certificate's public key. The signed message is <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c>: the chip
    /// identifier, the challenge it issued in GET CHALLENGE, and the terminal's ephemeral key it retained from
    /// Chip Authentication. The chip identifier <c>ID_IC</c> is <c>Comp()</c> of the chip's retained PACE
    /// ephemeral public key when PACE established the session, or the MRZ document number from the card's own
    /// EF.DG1 after Basic Access Control (BSI TR-03110-3 §A.2.2.3). The challenge is single-use.
    /// </summary>
    private async ValueTask<CardSimulatorInput> VerifyTerminalSignatureAsync(TerminalAuthenticateAction action, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        if(pool is not BaseMemoryPool basePool)
        {
            throw new InvalidOperationException("Terminal Authentication requires a BaseMemoryPool for pinned, zeroized key material.");
        }

        //Verify against exactly the terminal key MSE:Set AT pinned, re-asserting its role, so a certificate
        //imported after the selection cannot swap the key the signature is checked against.
        CardVerifiableCertificate? terminalCertificate = ImportedTerminalCertificate;
        if(terminalCertificate is null
            || terminalCertificate.Chat.Role != CertificateRole.Terminal
            || !string.Equals(terminalCertificate.CertificateHolderReference, SelectedTerminalAuthenticationReference, StringComparison.Ordinal)
            || IssuedChallenge is null
            || TerminalChipAuthenticationEphemeralKey is null
            || !Automaton.CurrentState.Files.TryGetValue(DataGroup1.FileIdentifier, out ElementaryFile? dataGroup1File))
        {
            //A missing or swapped terminal key, missing challenge, retained ephemeral key, or EF.DG1: refused.
            ConsumeIssuedChallenge();
            SelectedTerminalAuthenticationReference = null;

            return new TerminalAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        //The terminal key is elliptic-curve or RSA, per the imported certificate's public-key object identifier.
        CardVerifiableCertificatePublicKey terminalPublicKey = terminalCertificate.PublicKey;

        bool verified;
        try
        {
            //ID_IC after PACE is Comp() of the chip's retained PACE ephemeral public key (a view into it); after
            //Basic Access Control it is the MRZ document number built from the card's own EF.DG1.
            ReadOnlyMemory<byte> chipIdentifier;
            IMemoryOwner<byte>? basicAccessControlIdentifier = null;
            if(PaceAccessChipEphemeralPublicKey is not null)
            {
                chipIdentifier = TerminalAuthenticationSignature.Compress(PaceAccessChipEphemeralPublicKey);
            }
            else
            {
                MachineReadableZone mrz = DataGroup1.Parse(dataGroup1File.Content).MachineReadableZone;
                basicAccessControlIdentifier = BuildChipIdentifier(mrz, basePool, out int chipIdentifierLength);
                chipIdentifier = basicAccessControlIdentifier.Memory[..chipIdentifierLength];
            }

            using(basicAccessControlIdentifier)
            {
                verified = terminalPublicKey.IsEllipticCurve
                    ? await TerminalAuthenticationSignature.VerifyAsync(
                        terminalPublicKey.EllipticCurvePoint!, action.Signature, chipIdentifier,
                        IssuedChallenge.Memory[..IssuedChallengeLength], TerminalChipAuthenticationEphemeralKey.AsReadOnlyMemory(),
                        basePool, cancellationToken).ConfigureAwait(false)
                    : await TerminalAuthenticationSignature.VerifyWithRsaAsync(
                        terminalPublicKey.RsaKey!, terminalPublicKey.SignatureScheme, action.Signature, chipIdentifier,
                        IssuedChallenge.Memory[..IssuedChallengeLength], TerminalChipAuthenticationEphemeralKey.AsReadOnlyMemory(),
                        basePool, cancellationToken).ConfigureAwait(false);
            }
        }
        catch(Exception exception) when(exception is InvalidOperationException or ArgumentException)
        {
            //A malformed EF.DG1 or chip-identifier failure: the terminal is refused.
            ConsumeIssuedChallenge();
            SelectedTerminalAuthenticationReference = null;

            return new TerminalAuthenticationFailed(StatusWord.ConditionsNotSatisfied);
        }

        //The challenge and the pinned terminal selection are single-use, consumed whether or not the signature verified.
        ConsumeIssuedChallenge();
        SelectedTerminalAuthenticationReference = null;

        return verified
            ? new TerminalAuthenticationCompleted(AccumulatedReadAccess)
            : new TerminalAuthenticationFailed(StatusWord.AuthenticationFailed);
    }


    /// <summary>
    /// Builds the Basic Access Control chip identifier ID_IC into a pooled buffer: the MRZ document number
    /// from the card's own EF.DG1, including its check digit (Doc 9303 Part 11 §7.1.2), as ASCII.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, which disposes it via a using declaration.")]
    private static IMemoryOwner<byte> BuildChipIdentifier(MachineReadableZone mrz, MemoryPool<byte> pool, out int length)
    {
        string identifier = TerminalAuthentication.ChipIdentifierForBasicAccessControl(mrz.DocumentNumber);
        length = Encoding.ASCII.GetByteCount(identifier);

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            Encoding.ASCII.GetBytes(identifier, owner.Memory.Span[..length]);

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Selects the card's Chip Authentication private key matching the MSE:Set KAT key identifier, or the
    /// single key when none was given.
    /// </summary>
    private ChipAuthenticationKey? MatchChipAuthenticationKey(int? keyId)
    {
        foreach(ChipAuthenticationKey key in ChipAuthenticationKeys)
        {
            if(key.KeyId == keyId)
            {
                return key;
            }
        }

        return keyId is null && ChipAuthenticationKeys.Count == 1 ? ChipAuthenticationKeys[0] : null;
    }


    /// <summary>
    /// Selects the DG14 public-key info matching the key identifier, or the single one when none was given.
    /// </summary>
    private static ChipAuthenticationPublicKeyInfo? MatchPublicKeyInfo(DataGroup14 dataGroup14, int? keyId)
    {
        IReadOnlyList<ChipAuthenticationPublicKeyInfo> infos = dataGroup14.ChipAuthenticationPublicKeyInfos;
        foreach(ChipAuthenticationPublicKeyInfo info in infos)
        {
            if(info.KeyId == keyId)
            {
                return info;
            }
        }

        return keyId is null && infos.Count == 1 ? infos[0] : null;
    }


    /// <summary>
    /// Selects the DG14 Chip Authentication info matching the key identifier, or the single one when none was given.
    /// </summary>
    private static ChipAuthenticationInfo? MatchInfo(DataGroup14 dataGroup14, int? keyId)
    {
        IReadOnlyList<ChipAuthenticationInfo> infos = dataGroup14.ChipAuthenticationInfos;
        foreach(ChipAuthenticationInfo info in infos)
        {
            if(info.KeyId == keyId)
            {
                return info;
            }
        }

        return keyId is null && infos.Count == 1 ? infos[0] : null;
    }


    /// <summary>
    /// Activates a Secure Messaging session a Chip Authentication built, replacing the prior session once its
    /// MSE:Set KAT acknowledgement has been framed under that prior session.
    /// </summary>
    private void ActivatePendingSecureMessagingSession()
    {
        if(PendingSecureMessagingSession is null)
        {
            return;
        }

        SecureMessagingSession?.Dispose();
        SecureMessagingSession = PendingSecureMessagingSession;
        PendingSecureMessagingSession = null;
    }


    /// <summary>
    /// Wraps a value in a GENERAL AUTHENTICATE dynamic authentication data object — <c>7C ‖ {tag ‖ value}</c>
    /// — sizing the BER-TLV lengths for any curve's point or token. Used for every PACE round response.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, then to the PaceRoundCompleted input.")]
    private static IMemoryOwner<byte> WrapDynamicAuthenticationData(byte innerTag, ReadOnlySpan<byte> value, MemoryPool<byte> pool, out int length)
    {
        int innerObjectLength = 1 + BerLengthSize(value.Length) + value.Length;
        int total = 1 + BerLengthSize(innerObjectLength) + innerObjectLength;

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> span = owner.Memory.Span;
            int offset = 0;

            span[offset++] = DynamicAuthenticationDataTag;
            offset += WriteBerLength(innerObjectLength, span[offset..]);
            span[offset++] = innerTag;
            offset += WriteBerLength(value.Length, span[offset..]);
            value.CopyTo(span[offset..]);
            length = total;

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Wraps two values in a GENERAL AUTHENTICATE dynamic authentication data object —
    /// <c>7C ‖ {firstTag ‖ firstValue} ‖ {secondTag ‖ secondValue}</c> — the round-4 response under Chip
    /// Authentication Mapping, which carries the chip token (DO'86') and the Encrypted Chip Authentication Data (DO'8A').
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the caller, then to the PaceRoundCompleted input.")]
    private static IMemoryOwner<byte> WrapDynamicAuthenticationDataPair(
        byte firstTag, ReadOnlySpan<byte> firstValue, byte secondTag, ReadOnlySpan<byte> secondValue, MemoryPool<byte> pool, out int length)
    {
        int firstObjectLength = 1 + BerLengthSize(firstValue.Length) + firstValue.Length;
        int secondObjectLength = 1 + BerLengthSize(secondValue.Length) + secondValue.Length;
        int innerLength = firstObjectLength + secondObjectLength;
        int total = 1 + BerLengthSize(innerLength) + innerLength;

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            Span<byte> span = owner.Memory.Span;
            int offset = 0;

            span[offset++] = DynamicAuthenticationDataTag;
            offset += WriteBerLength(innerLength, span[offset..]);
            span[offset++] = firstTag;
            offset += WriteBerLength(firstValue.Length, span[offset..]);
            firstValue.CopyTo(span[offset..]);
            offset += firstValue.Length;
            span[offset++] = secondTag;
            offset += WriteBerLength(secondValue.Length, span[offset..]);
            secondValue.CopyTo(span[offset..]);
            length = total;

            return owner;
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Releases and clears all PACE exchange state (the selected mechanism, the nonce, the mapping private key,
    /// the mapped generator, the ephemeral public keys, and the session keys), leaving any established Secure
    /// Messaging session intact.
    /// </summary>
    private void ResetPaceExchange()
    {
        SelectedPaceObjectIdentifier?.Dispose();
        SelectedPaceObjectIdentifier = null;
        SelectedPaceObjectIdentifierLength = 0;
        PaceNonce?.Dispose();
        PaceNonce = null;
        PaceNonceLength = 0;
        PaceMappingPrivateKey?.Dispose();
        PaceMappingPrivateKey = null;
        PaceMappingPrivateKeyLength = 0;
        PaceMappedGenerator?.Dispose();
        PaceMappedGenerator = null;
        PaceChipEphemeralPublicKey?.Dispose();
        PaceChipEphemeralPublicKey = null;
        PaceTerminalEphemeralPublicKey?.Dispose();
        PaceTerminalEphemeralPublicKey = null;
        PaceEncryptionKey?.Dispose();
        PaceEncryptionKey = null;
        PaceMacKey?.Dispose();
        PaceMacKey = null;
    }


    /// <summary>
    /// The number of bytes a BER-TLV definite length field occupies for <paramref name="length"/>.
    /// </summary>
    private static int BerLengthSize(int length) =>
        length <= 0x7F ? 1 : length <= 0xFF ? 2 : 3;


    /// <summary>
    /// Writes a BER-TLV definite length field for <paramref name="length"/> into <paramref name="destination"/>,
    /// returning the number of bytes written.
    /// </summary>
    private static int WriteBerLength(int length, Span<byte> destination)
    {
        if(length <= 0x7F)
        {
            destination[0] = (byte)length;

            return 1;
        }

        if(length <= 0xFF)
        {
            destination[0] = 0x81;
            destination[1] = (byte)length;

            return 2;
        }

        destination[0] = 0x82;
        destination[1] = (byte)(length >> 8);
        destination[2] = (byte)length;

        return 3;
    }


    /// <summary>
    /// Retains a copy of the issued challenge RND.IC as device state, disposing any prior one.
    /// </summary>
    private void RetainIssuedChallenge(ReadOnlySpan<byte> challenge, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> retained = pool.Rent(challenge.Length);
        challenge.CopyTo(retained.Memory.Span);

        IssuedChallenge?.Dispose();
        IssuedChallenge = retained;
        IssuedChallengeLength = challenge.Length;
    }


    /// <summary>
    /// Disposes and clears the retained challenge once it has been consumed.
    /// </summary>
    private void ConsumeIssuedChallenge()
    {
        IssuedChallenge?.Dispose();
        IssuedChallenge = null;
        IssuedChallengeLength = 0;
    }


    /// <summary>
    /// The default deterministic RNG backend: a per-instance counter stream. Reproducible across runs yet
    /// advancing across draws, so successive nonces differ. Not a real entropy source — the card's RNG is
    /// part of the device model, not the application entropy provider.
    /// </summary>
    private void FillDeterministic(Span<byte> destination)
    {
        Span<byte> block = stackalloc byte[sizeof(ulong)];
        for(int i = 0; i < destination.Length; i += sizeof(ulong))
        {
            BinaryPrimitives.WriteUInt64LittleEndian(block, RngCounter);
            RngCounter++;

            int take = Math.Min(sizeof(ulong), destination.Length - i);
            block[..take].CopyTo(destination[i..(i + take)]);
        }
    }


    /// <summary>
    /// Bridges the runner's value-threaded step to the live automaton (one live automaton per simulated card
    /// holds the state of record).
    /// </summary>
    private async ValueTask<(CardSimulatorState State, int StepCount)> StepCoreAsync(
        CardSimulatorState currentState, int currentStepCount, CardSimulatorInput input, TimeProvider time, CancellationToken cancellationToken)
    {
        _ = await Automaton.StepAsync(input, cancellationToken).ConfigureAwait(false);

        return (Automaton.CurrentState, Automaton.StepCount);
    }


    /// <summary>
    /// Parses a command APDU into the automaton input, or reports the status word for a malformed command.
    /// </summary>
    private static bool TryParseCommand(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        if(command.Length < ApduConstants.CommandHeaderSize)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        byte instruction = command[1];
        byte p1 = command[2];
        byte p2 = command[3];

        if(instruction == InstructionCode.Select.Code)
        {
            return TryParseSelect(command, p1, p2, out input, out malformedStatus);
        }

        if(instruction == InstructionCode.ReadBinary.Code)
        {
            return TryParseReadBinary(command, p1, p2, out input);
        }

        if(instruction == InstructionCode.GetChallenge.Code)
        {
            return TryParseGetChallenge(command, out input);
        }

        if(instruction == InstructionCode.ExternalAuthenticate.Code)
        {
            return TryParseExternalAuthenticate(commandApdu, out input, out malformedStatus);
        }

        if(instruction == InstructionCode.ManageSecurityEnvironment.Code)
        {
            return TryParseManageSecurityEnvironment(commandApdu, p1, p2, out input, out malformedStatus);
        }

        if(instruction == InstructionCode.PerformSecurityOperation.Code)
        {
            return TryParsePerformSecurityOperation(commandApdu, p1, p2, out input, out malformedStatus);
        }

        if(instruction == GeneralAuthenticateInstruction)
        {
            return TryParseGeneralAuthenticate(commandApdu, out input, out malformedStatus);
        }

        if(instruction == InstructionCode.InternalAuthenticate.Code)
        {
            return TryParseInternalAuthenticate(commandApdu, out input, out malformedStatus);
        }

        input = new UnsupportedCommandReceived(instruction);

        return true;
    }


    /// <summary>
    /// Parses an INTERNAL AUTHENTICATE (Case 4 short); the data field is the Active Authentication challenge
    /// RND.IFD, carried as a view into the command APDU.
    /// </summary>
    private static bool TryParseInternalAuthenticate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength == 0 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        input = new ActiveAuthenticateRequested(commandApdu.Slice(dataStart, contentLength));

        return true;
    }


    /// <summary>
    /// Parses a MANAGE SECURITY ENVIRONMENT by template: MSE:Set AT (P1=C1, P2=A4) selects the PACE
    /// mechanism, MSE:Set KAT (P1=41, P2=A6) carries the terminal's ephemeral key for Chip Authentication.
    /// </summary>
    private static bool TryParseManageSecurityEnvironment(ReadOnlyMemory<byte> commandApdu, byte p1, byte p2, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        if(p1 == SetAuthenticationTemplateP1 && p2 == SetAuthenticationTemplateP2)
        {
            return TryParseSetAuthenticationTemplate(commandApdu, out input, out malformedStatus);
        }

        if(p1 == SetKeyAgreementTemplateP1 && p2 == SetKeyAgreementTemplateP2)
        {
            return TryParseSetKeyAgreementTemplate(commandApdu, out input, out malformedStatus);
        }

        if(p1 == SetDigitalSignatureTemplateP1 && p2 == SetDigitalSignatureTemplateP2)
        {
            return TryParseSetDigitalSignatureTemplate(commandApdu, out input, out malformedStatus);
        }

        if(p1 == SetDigitalSignatureTemplateP1 && p2 == SetAuthenticationTemplateP2)
        {
            return TryParseSetTerminalAuthenticationTemplate(commandApdu, out input, out malformedStatus);
        }

        input = null;
        malformedStatus = StatusWord.IncorrectP1P2;

        return false;
    }


    /// <summary>
    /// Parses an MSE:Set AT for Terminal Authentication (P1 <c>0x81</c>, distinct from PACE's P1 <c>0xC1</c>):
    /// the terminal certificate holder reference DO'83' naming the key for the EXTERNAL AUTHENTICATE.
    /// </summary>
    private static bool TryParseSetTerminalAuthenticationTemplate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength < 2 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        //The first data object is the cryptographic-mechanism reference DO'80' (the TA protocol OID).
        ReadOnlySpan<byte> data = command.Slice(dataStart, contentLength);
        if(data[0] != CryptographicMechanismReferenceTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        int offset = 1;
        if(!TryReadBerLength(data, ref offset, out int objectIdentifierLength) || offset + objectIdentifierLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        ReadOnlyMemory<byte> objectIdentifier = commandApdu.Slice(dataStart + offset, objectIdentifierLength);
        offset += objectIdentifierLength;

        //The second data object is the terminal public-key reference DO'83' (the holder reference).
        if(offset >= data.Length || data[offset++] != PublicKeyReferenceTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        if(!TryReadBerLength(data, ref offset, out int referenceLength) || offset + referenceLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        input = new SetTerminalAuthenticationTemplateRequested(objectIdentifier, commandApdu.Slice(dataStart + offset, referenceLength));

        return true;
    }


    /// <summary>
    /// Parses an MSE:Set DST for Terminal Authentication: the public-key reference DO'83' naming the key the
    /// next PSO:Verify Certificate is checked against.
    /// </summary>
    private static bool TryParseSetDigitalSignatureTemplate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength < 2 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        //The data object must be the public-key reference DO'83'.
        ReadOnlySpan<byte> data = command.Slice(dataStart, contentLength);
        if(data[0] != PublicKeyReferenceTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        int offset = 1;
        if(!TryReadBerLength(data, ref offset, out int referenceLength) || offset + referenceLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        input = new SetDigitalSignatureTemplateRequested(commandApdu.Slice(dataStart + offset, referenceLength));

        return true;
    }


    /// <summary>
    /// Parses a PSO:Verify Certificate (Case 3): the data field carries the presented certificate's content
    /// (its body and signature data objects) for Terminal Authentication, and may exceed the short-Lc limit for
    /// a certificate with an RSA subject key.
    /// </summary>
    private static bool TryParsePerformSecurityOperation(ReadOnlyMemory<byte> commandApdu, byte p1, byte p2, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        if(p1 != VerifyCertificateP1 || p2 != VerifyCertificateP2)
        {
            malformedStatus = StatusWord.IncorrectP1P2;

            return false;
        }

        //A terminal certificate with an RSA subject key exceeds 255 bytes, so PSO:Verify Certificate may carry
        //an extended Lc once unprotected from the Secure Messaging session.
        if(!TryReadCommandDataField(commandApdu.Span, out int dataStart, out int contentLength, out malformedStatus))
        {
            return false;
        }

        input = new VerifyCertificateRequested(commandApdu.Slice(dataStart, contentLength));

        return true;
    }


    /// <summary>
    /// Parses an MSE:Set AT selecting the PACE mechanism, reading the cryptographic-mechanism reference
    /// DO'80' to capture the protocol OID (the password reference DO'83' is not modelled).
    /// </summary>
    private static bool TryParseSetAuthenticationTemplate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength < 2 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        //The first data object must be the cryptographic-mechanism reference DO'80' carrying the PACE OID.
        ReadOnlySpan<byte> data = command.Slice(dataStart, contentLength);
        if(data[0] != CryptographicMechanismReferenceTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        int offset = 1;
        if(!TryReadBerLength(data, ref offset, out int objectIdentifierLength) || offset + objectIdentifierLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        input = new ManageSecurityEnvironmentRequested(commandApdu.Slice(dataStart + offset, objectIdentifierLength));

        return true;
    }


    /// <summary>
    /// Parses an MSE:Set KAT for EACv1 Chip Authentication: the terminal's ephemeral public key DO'91' and
    /// the optional chip key-identifier DO'84'.
    /// </summary>
    private static bool TryParseSetKeyAgreementTemplate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength < 2 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        //The first data object must be the terminal's ephemeral public key DO'91'.
        ReadOnlySpan<byte> data = command.Slice(dataStart, contentLength);
        if(data[0] != EphemeralPublicKeyTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        int offset = 1;
        if(!TryReadBerLength(data, ref offset, out int publicKeyLength) || offset + publicKeyLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        ReadOnlyMemory<byte> ephemeralPublicKey = commandApdu.Slice(dataStart + offset, publicKeyLength);
        offset += publicKeyLength;

        //An optional DO'84' carries the chip key identifier when EF.DG14 offers more than one key.
        int? keyId = null;
        if(offset < data.Length)
        {
            if(data[offset++] != PrivateKeyReferenceTag)
            {
                malformedStatus = StatusWord.WrongData;

                return false;
            }

            if(!TryReadBerLength(data, ref offset, out int keyIdLength) || keyIdLength < 1 || offset + keyIdLength > data.Length)
            {
                malformedStatus = StatusWord.WrongLength;

                return false;
            }

            int value = 0;
            for(int i = 0; i < keyIdLength; i++)
            {
                value = (value << 8) | data[offset + i];
            }

            keyId = value;
        }

        input = new ChipAuthenticationKeyAgreementRequested(ephemeralPublicKey, keyId);

        return true;
    }


    /// <summary>
    /// Parses a GENERAL AUTHENTICATE, reading the dynamic authentication data object (tag 7C) and its single
    /// inner object: the context tag selects the round (0 when the object is empty, the encrypted-nonce round)
    /// and the value carries the terminal's contribution for that round.
    /// </summary>
    private static bool TryParseGeneralAuthenticate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        ReadOnlySpan<byte> command = commandApdu.Span;
        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength < 2 || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        ReadOnlySpan<byte> data = command.Slice(dataStart, contentLength);
        if(data[0] != DynamicAuthenticationDataTag)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        int offset = 1;
        if(!TryReadBerLength(data, ref offset, out int objectLength) || offset + objectLength > data.Length)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        //An empty dynamic authentication data object is the encrypted-nonce round (no inner value).
        if(objectLength == 0)
        {
            input = new GeneralAuthenticateRequested(0, ReadOnlyMemory<byte>.Empty);

            return true;
        }

        int objectEnd = offset + objectLength;
        byte innerTag = data[offset++];
        if(!TryReadBerLength(data, ref offset, out int innerLength) || offset + innerLength > objectEnd)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        input = new GeneralAuthenticateRequested(innerTag, commandApdu.Slice(dataStart + offset, innerLength));

        return true;
    }


    /// <summary>
    /// Reads a BER-TLV definite length field (short form or 0x81 / 0x82 long form) from <paramref name="data"/>
    /// at <paramref name="offset"/>, advancing it, and reports failure rather than throwing on a malformed field.
    /// </summary>
    private static bool TryReadBerLength(ReadOnlySpan<byte> data, ref int offset, out int length)
    {
        length = 0;
        if(offset >= data.Length)
        {
            return false;
        }

        byte first = data[offset++];
        if(first <= 0x7F)
        {
            length = first;

            return true;
        }

        if(first == 0x81)
        {
            if(offset >= data.Length)
            {
                return false;
            }

            length = data[offset++];

            return true;
        }

        if(first == 0x82)
        {
            if(offset + 1 >= data.Length)
            {
                return false;
            }

            length = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            return true;
        }

        return false;
    }


    /// <summary>
    /// Parses a SELECT of an elementary file by identifier (P1=02, P2=0C, two-octet data field).
    /// </summary>
    private static bool TryParseSelect(ReadOnlySpan<byte> command, byte p1, byte p2, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        if(p1 != SelectByFileIdentifier || p2 != SelectNoResponseData)
        {
            malformedStatus = StatusWord.IncorrectP1P2;

            return false;
        }

        int dataStart = ApduConstants.CommandHeaderSize + 1;
        if(command.Length < dataStart)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int contentLength = command[ApduConstants.CommandHeaderSize];
        if(contentLength != FileIdentifierLength || command.Length < dataStart + contentLength)
        {
            malformedStatus = StatusWord.WrongData;

            return false;
        }

        ushort fileIdentifier = (ushort)((command[dataStart] << 8) | command[dataStart + 1]);
        input = new SelectElementaryFileRequested(fileIdentifier);

        return true;
    }


    /// <summary>
    /// Parses a READ BINARY with a 15-bit offset in P1-P2 and a short expected-length field.
    /// </summary>
    private static bool TryParseReadBinary(ReadOnlySpan<byte> command, byte p1, byte p2, [NotNullWhen(true)] out CardSimulatorInput? input)
    {
        //The short-EF-identifier reference (high bit of P1 set) is not modelled in this slice; it is
        //dispatched as an unsupported command so the rejection appears in the trace.
        if((p1 & ReadBinaryShortEfBit) != 0)
        {
            input = new UnsupportedCommandReceived(InstructionCode.ReadBinary.Code);

            return true;
        }

        int offset = ((p1 & 0x7F) << 8) | p2;

        //Short Case 2 carries the expected length in the single octet after the header; a zero field (or
        //an absent one) means the maximum short length.
        int expectedLength = command.Length > ApduConstants.CommandHeaderSize ? command[ApduConstants.CommandHeaderSize] : 0;
        int length = expectedLength == 0 ? MaxShortExpectedLength : expectedLength;

        input = new ReadBinaryRequested(offset, length);

        return true;
    }


    /// <summary>
    /// Parses a GET CHALLENGE (Case 2 short); the expected-length octet is the number of challenge bytes requested.
    /// </summary>
    private static bool TryParseGetChallenge(ReadOnlySpan<byte> command, [NotNullWhen(true)] out CardSimulatorInput? input)
    {
        int expectedLength = command.Length > ApduConstants.CommandHeaderSize ? command[ApduConstants.CommandHeaderSize] : 0;
        int length = expectedLength == 0 ? MaxShortExpectedLength : expectedLength;

        input = new GetChallengeRequested(length);

        return true;
    }


    /// <summary>
    /// Parses an EXTERNAL AUTHENTICATE; the data field is the Basic Access Control terminal token
    /// <c>EIFD || MIFD</c> or the Terminal Authentication signature (which may exceed the short-Lc limit for an
    /// RSA terminal key), carried as a view into the command APDU.
    /// </summary>
    private static bool TryParseExternalAuthenticate(ReadOnlyMemory<byte> commandApdu, [NotNullWhen(true)] out CardSimulatorInput? input, out StatusWord malformedStatus)
    {
        input = null;
        malformedStatus = StatusWord.Success;

        //An RSA terminal's EXTERNAL AUTHENTICATE signature is a full modulus wide (256 bytes for a 2048-bit
        //key), so it may carry an extended Lc once unprotected from the Secure Messaging session.
        if(!TryReadCommandDataField(commandApdu.Span, out int dataStart, out int contentLength, out malformedStatus))
        {
            return false;
        }

        input = new ExternalAuthenticateRequested(commandApdu.Slice(dataStart, contentLength));

        return true;
    }


    /// <summary>
    /// Reads a command's data-field length (Lc) and the offset at which its data begins: a single byte for up
    /// to 255 data bytes, or a <c>0x00</c> marker then a two-byte length for an extended command carrying more
    /// (ISO/IEC 7816-4 §5.1). Used by the parsers of commands that always carry data and may exceed the short
    /// limit (PSO:Verify Certificate and EXTERNAL AUTHENTICATE with RSA Terminal Authentication keys). Reports
    /// a wrong-length status when the field is absent, declares zero data, or declares more data than the
    /// command holds.
    /// </summary>
    private static bool TryReadCommandDataField(ReadOnlySpan<byte> command, out int dataStart, out int contentLength, out StatusWord malformedStatus)
    {
        dataStart = 0;
        contentLength = 0;
        malformedStatus = StatusWord.Success;

        int lengthOffset = ApduConstants.CommandHeaderSize;
        if(command.Length < lengthOffset + 1)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        int declared = command[lengthOffset];
        if(declared == 0x00 && command.Length >= lengthOffset + 3)
        {
            //The 0x00 marker introduces the extended two-byte Lc; a command reaching here always carries data,
            //so a leading 0x00 is unambiguously the extended form rather than an empty short body.
            declared = (command[lengthOffset + 1] << 8) | command[lengthOffset + 2];
            dataStart = lengthOffset + 3;
        }
        else
        {
            dataStart = lengthOffset + 1;
        }

        if(declared == 0 || command.Length < dataStart + declared)
        {
            malformedStatus = StatusWord.WrongLength;

            return false;
        }

        contentLength = declared;

        return true;
    }


    /// <summary>
    /// Frames a response intent as response-APDU bytes — the data field, if any, followed by the status word.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of the rented buffer and is owned by the returned ApduResult, which the caller disposes.")]
    private static ApduResult<ApduResponse> SerializeResponse(CardResponseIntent intent, MemoryPool<byte> pool)
    {
        //A ChallengeResponse / BacAuthenticateResponse owns the pooled buffer the action executor produced;
        //release it in the finally once its octets are copied into the wire response.
        IMemoryOwner<byte>? ownedBuffer = intent switch
        {
            ChallengeResponse challenge => challenge.Challenge,
            BacAuthenticateResponse authenticate => authenticate.Token,
            DynamicAuthenticationDataResponse dynamicAuthentication => dynamicAuthentication.Data,
            ActiveAuthenticationResponse activeAuthentication => activeAuthentication.Signature,
            _ => null
        };
        try
        {
            ReadOnlySpan<byte> data = intent switch
            {
                BinaryReadResponse read => read.Data.Span,
                ChallengeResponse challenge => challenge.Challenge.Memory.Span[..challenge.Length],
                BacAuthenticateResponse authenticate => authenticate.Token.Memory.Span[..authenticate.Length],
                DynamicAuthenticationDataResponse dynamicAuthentication => dynamicAuthentication.Data.Memory.Span[..dynamicAuthentication.Length],
                ActiveAuthenticationResponse activeAuthentication => activeAuthentication.Signature.Memory.Span[..activeAuthentication.Length],
                _ => ReadOnlySpan<byte>.Empty
            };
            StatusWord statusWord = intent.StatusWord;
            int total = data.Length + ApduConstants.StatusWordSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                Span<byte> span = owner.Memory.Span;
                data.CopyTo(span);
                span[data.Length] = statusWord.Sw1;
                span[data.Length + 1] = statusWord.Sw2;

                var response = new ApduResponse(owner, total);

                return ApduResult<ApduResponse>.Success(response, statusWord);
            }
            catch
            {
                owner.Dispose();

                throw;
            }
        }
        finally
        {
            ownedBuffer?.Dispose();
        }
    }


    /// <inheritdoc />
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        IssuedChallenge?.Dispose();
        SecureMessagingSession?.Dispose();
        PendingSecureMessagingSession?.Dispose();
        ImportedTerminalCertificate?.Dispose();
        TerminalChipAuthenticationEphemeralKey?.Dispose();
        PaceAccessChipEphemeralPublicKey?.Dispose();
        ResetPaceExchange();
    }


    private string DebuggerDisplay =>
        $"CardSimulator({Automaton.RunId}, {Automaton.CurrentState.Phase}, {Automaton.CurrentState.Files.Count} files)";
}

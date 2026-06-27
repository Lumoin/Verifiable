using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Foundation.Automata;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// The transition function (δ) of the eMRTD card simulator: a pure mapping from (state, command) to the
/// next state and stack action, mirroring the structure of the TPM simulator's transition function.
/// </summary>
/// <remarks>
/// <para>
/// The function performs no I/O, reads no time, and uses no randomness — the only buffer-touching work
/// (parsing commands, framing responses) happens in <see cref="CardSimulator"/>. This slice serves the
/// plaintext read path: SELECT chooses the current elementary file, and READ BINARY returns octets from
/// it. Access-control gating (refusing protected files until BAC/PACE has established Secure Messaging)
/// is layered in here when those responders are added, the way the TPM simulator gates on its lifecycle
/// phase. The automaton never halts in this slice — a transition is defined for every input — so a
/// returned <see langword="null"/> would signal a genuinely unexpected input.
/// </para>
/// </remarks>
public static class CardCommandTransitions
{
    /// <summary>The READ BINARY 15-bit offset's upper bound — the largest offset expressible in P1-P2 with the short-EF bit clear.</summary>
    private const int MaxOffset = 0x7FFF;

    /// <summary>Context tag of the terminal's mapping public key in a PACE GENERAL AUTHENTICATE (DO'81', the nonce-mapping round).</summary>
    private const byte TerminalMappingDataTag = 0x81;

    /// <summary>Context tag of the terminal's ephemeral public key in a PACE GENERAL AUTHENTICATE (DO'83', the key-agreement round).</summary>
    private const byte TerminalEphemeralKeyTag = 0x83;

    /// <summary>Context tag of the terminal's authentication token in a PACE GENERAL AUTHENTICATE (DO'85', the mutual-authentication round).</summary>
    private const byte TerminalTokenTag = 0x85;


    /// <summary>
    /// Creates the transition delegate for an eMRTD card automaton.
    /// </summary>
    /// <returns>The transition function.</returns>
    public static TransitionDelegate<CardSimulatorState, CardSimulatorInput, CardStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            //The action fold-backs (the RNG result, the BAC outcome) are internal to the effect loop: they
            //carry a disposable buffer that must always be consumed into a response intent, so they are
            //neither cancellation-gated nor NextAction-reset. Every externally-supplied command honours
            //cancellation and starts from a cleared NextAction (DispatchCommand).
            TransitionResult<CardSimulatorState, CardStackSymbol>? result = input switch
            {
                CardEntropyGenerated generated => OnEntropyGenerated(state, generated),
                BacAuthenticationCompleted completed => OnBacAuthenticationCompleted(state, completed),
                BacAuthenticationFailed failed => OnBacAuthenticationFailed(state, failed),
                PaceMechanismSelected => OnPaceMechanismSelected(state),
                PaceRoundCompleted completed => OnPaceRoundCompleted(state, completed),
                PaceExchangeFailed failed => OnPaceExchangeFailed(state, failed),
                ChipAuthenticationCompleted => OnChipAuthenticationCompleted(state),
                ChipAuthenticationFailed failed => OnChipAuthenticationFailed(state, failed),
                ActiveAuthenticationSigned signed => OnActiveAuthenticationSigned(state, signed),
                ActiveAuthenticationFailed failed => OnActiveAuthenticationFailed(state, failed),
                TerminalAuthenticationStepCompleted completed => OnTerminalAuthenticationStepCompleted(state, completed),
                TerminalAuthenticationTemplateSet templateSet => OnTerminalAuthenticationTemplateSet(state, templateSet),
                TerminalAuthenticationCompleted completed => OnTerminalAuthenticationCompleted(state, completed),
                TerminalAuthenticationFailed failed => OnTerminalAuthenticationFailed(state, failed),
                _ => DispatchCommand(state, input, cancellationToken)
            };

            return ValueTask.FromResult<TransitionResult<CardSimulatorState, CardStackSymbol>?>(result);
        };


    /// <summary>
    /// Dispatches an externally-supplied command: honours cancellation and starts from a cleared NextAction.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> DispatchCommand(CardSimulatorState state, CardSimulatorInput input, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        CardSimulatorState ready = state with { NextAction = NullAction.Instance };

        return input switch
        {
            SelectElementaryFileRequested select => OnSelectElementaryFile(ready, select.FileIdentifier),
            ReadBinaryRequested read => OnReadBinary(ready, read.Offset, read.Length),
            GetChallengeRequested challenge => OnGetChallenge(ready, challenge.Length),
            ExternalAuthenticateRequested authenticate => OnExternalAuthenticate(ready, authenticate.TerminalToken),
            ManageSecurityEnvironmentRequested manageSecurityEnvironment => OnManageSecurityEnvironment(ready, manageSecurityEnvironment.ObjectIdentifier),
            GeneralAuthenticateRequested generalAuthenticate => OnGeneralAuthenticate(ready, generalAuthenticate.InnerTag, generalAuthenticate.InnerValue),
            ChipAuthenticationKeyAgreementRequested chipAuthentication => OnChipAuthenticate(ready, chipAuthentication.TerminalEphemeralPublicKey, chipAuthentication.KeyId),
            ActiveAuthenticateRequested activeAuthentication => OnActiveAuthenticate(ready, activeAuthentication.Challenge),
            SetDigitalSignatureTemplateRequested setDigitalSignatureTemplate => OnSetDigitalSignatureTemplate(ready, setDigitalSignatureTemplate.PublicKeyReference),
            VerifyCertificateRequested verifyCertificate => OnVerifyCertificate(ready, verifyCertificate.CertificateContent),
            SetTerminalAuthenticationTemplateRequested setTerminalAuthenticationTemplate => OnSetTerminalAuthenticationTemplate(ready, setTerminalAuthenticationTemplate.ObjectIdentifier, setTerminalAuthenticationTemplate.TerminalReference),
            UnsupportedCommandReceived unsupported => OnUnsupportedCommand(ready, unsupported.Instruction),
            _ => throw new InvalidOperationException($"Input '{input.GetType().Name}' has no dispatch handler.")
        };
    }


    /// <summary>
    /// Selects an elementary file by identifier, making it the current EF when it exists.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnSelectElementaryFile(CardSimulatorState state, ushort fileIdentifier)
    {
        if(!state.Files.ContainsKey(fileIdentifier))
        {
            //Selecting a file the card does not hold leaves the current EF unchanged (ISO/IEC 7816-4).
            return Reject(state, StatusWord.FileNotFound, $"Select:NotFound:0x{fileIdentifier:X4}");
        }

        return Transition(
            state with
            {
                SelectedFile = fileIdentifier,
                ResponseIntent = new StatusOnlyResponse(StatusWord.Success)
            },
            $"Select:0x{fileIdentifier:X4}");
    }


    /// <summary>
    /// Reads octets from the current elementary file at the given offset.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnReadBinary(CardSimulatorState state, int offset, int length)
    {
        //A READ BINARY without a current EF is refused (ISO/IEC 7816-4, 6986).
        if(state.SelectedFile is not ushort selected)
        {
            return Reject(state, StatusWord.NoCurrentElementaryFile, "ReadBinary:NoCurrentEf");
        }

        //The sensitive data groups EF.DG3 (fingerprints) and EF.DG4 (iris) are released only to a terminal
        //whose completed Terminal Authentication granted the matching effective authorization bit (BSI
        //TR-03110-3 §2.7); until then the chip refuses the read with a security-status error (6982).
        InspectionSystemAccess required = RequiredReadAccess(selected);
        if(required != InspectionSystemAccess.None && (state.GrantedReadAccess & required) != required)
        {
            return Reject(state, StatusWord.SecurityNotSatisfied, $"ReadBinary:AccessDenied:0x{selected:X4}");
        }

        ElementaryFile file = state.Files[selected];

        //An offset at or beyond the end of the file has no octets to return (6B00).
        if(offset > MaxOffset || offset >= file.Length)
        {
            return Reject(state, StatusWord.WrongP1P2, $"ReadBinary:OffsetOutOfRange:{offset}");
        }

        //Return as much as was requested but never past the end of the file; a short read still
        //succeeds with 9000, the way a real IC returns only the octets that remain.
        int available = file.Length - offset;
        int readLength = Math.Min(length, available);
        ReadOnlyMemory<byte> window = file.AsReadOnlyMemory().Slice(offset, readLength);

        return Transition(
            state with { ResponseIntent = new BinaryReadResponse(StatusWord.Success, window) },
            $"ReadBinary:{offset}+{readLength}");
    }


    /// <summary>
    /// The effective-authorization bit a READ BINARY of the given file requires: EF.DG3 (fingerprints) needs
    /// the fingerprint bit, EF.DG4 (iris) the iris bit; every other file is freely readable once the access
    /// protocol has established the session, so it requires <see cref="InspectionSystemAccess.None"/>.
    /// </summary>
    private static InspectionSystemAccess RequiredReadAccess(ushort fileIdentifier) => fileIdentifier switch
    {
        DataGroup3.FileIdentifier => InspectionSystemAccess.ReadDataGroup3Fingerprint,
        DataGroup4.FileIdentifier => InspectionSystemAccess.ReadDataGroup4Iris,
        _ => InspectionSystemAccess.None
    };


    /// <summary>
    /// Declares the RNG action a GET CHALLENGE needs: the effectful loop fills a pooled buffer and feeds it
    /// back as <see cref="CardEntropyGenerated"/>, which <see cref="OnEntropyGenerated"/> frames.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnGetChallenge(CardSimulatorState state, int length) =>
        Transition(
            state with
            {
                NextAction = new CardRngAction(length),
                ResponseIntent = null
            },
            "GetChallenge:Requested");


    /// <summary>
    /// Frames the GET CHALLENGE response from the generated octets and moves to <see cref="CardLifecyclePhase.ChallengeIssued"/>.
    /// The issued chip nonce RND.IC itself is retained by <see cref="CardSimulator"/> as device state (a
    /// tracked carrier) for the Basic Access Control mutual authentication.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnEntropyGenerated(CardSimulatorState state, CardEntropyGenerated generated)
    {
        //Over Secure Messaging, GET CHALLENGE serves Terminal Authentication: the session phase must persist so
        //subsequent protected commands keep routing through it, and the issued challenge advances the Terminal
        //Authentication stage once MSE:Set AT has selected the terminal key.
        if(state.Phase == CardLifecyclePhase.SecureMessaging)
        {
            TerminalAuthenticationStage stage = state.TerminalAuthenticationStage == TerminalAuthenticationStage.TerminalKeySelected
                ? TerminalAuthenticationStage.ChallengeIssued
                : state.TerminalAuthenticationStage;

            return Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    TerminalAuthenticationStage = stage,
                    ResponseIntent = new ChallengeResponse(StatusWord.Success, generated.Bytes, generated.Length)
                },
                "GetChallenge:Generated");
        }

        //In the clear, GET CHALLENGE begins the Basic Access Control mutual authentication.
        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = CardLifecyclePhase.ChallengeIssued,
                ResponseIntent = new ChallengeResponse(StatusWord.Success, generated.Bytes, generated.Length)
            },
            "GetChallenge:Generated");
    }


    /// <summary>
    /// Routes an EXTERNAL AUTHENTICATE by context: the Basic Access Control mutual authentication when a
    /// plaintext challenge is outstanding (the <see cref="CardLifecyclePhase.ChallengeIssued"/> phase), or the
    /// Terminal Authentication signature when one is expected over the Secure Messaging session (the terminal
    /// key selected and the challenge issued); otherwise it is refused (ISO/IEC 7816-4, 6985).
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnExternalAuthenticate(CardSimulatorState state, System.ReadOnlyMemory<byte> terminalToken)
    {
        if(state.Phase == CardLifecyclePhase.ChallengeIssued)
        {
            return Transition(
                state with
                {
                    NextAction = new BacAuthenticateAction(terminalToken),
                    ResponseIntent = null
                },
                "ExternalAuthenticate:BasicAccessControl");
        }

        if(state.Phase == CardLifecyclePhase.SecureMessaging && state.TerminalAuthenticationStage == TerminalAuthenticationStage.ChallengeIssued)
        {
            return Transition(
                state with
                {
                    NextAction = new TerminalAuthenticateAction(terminalToken),
                    ResponseIntent = null
                },
                "ExternalAuthenticate:TerminalAuthentication");
        }

        return Reject(state, StatusWord.ConditionsNotSatisfied, "ExternalAuthenticate:NoChallenge");
    }


    /// <summary>
    /// Frames the card's EXTERNAL AUTHENTICATE response and records that Secure Messaging is established. The
    /// session itself is held by <see cref="CardSimulator"/> as device state.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnBacAuthenticationCompleted(CardSimulatorState state, BacAuthenticationCompleted completed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = CardLifecyclePhase.SecureMessaging,
                ResponseIntent = new BacAuthenticateResponse(StatusWord.Success, completed.ResponseToken, completed.Length)
            },
            "ExternalAuthenticate:Completed");


    /// <summary>
    /// Frames a failed EXTERNAL AUTHENTICATE: the outstanding challenge is consumed, so the card returns to
    /// <see cref="CardLifecyclePhase.Operational"/>.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnBacAuthenticationFailed(CardSimulatorState state, BacAuthenticationFailed failed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = CardLifecyclePhase.Operational,
                ResponseIntent = new StatusOnlyResponse(failed.StatusWord)
            },
            "ExternalAuthenticate:Failed");


    /// <summary>
    /// Declares the work MSE:Set AT needs: the effectful loop captures the selected PACE mechanism (OID) as
    /// device state and feeds <see cref="PaceMechanismSelected"/> back, which enters the PACE phase.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnManageSecurityEnvironment(CardSimulatorState state, ReadOnlyMemory<byte> objectIdentifier) =>
        Transition(
            state with
            {
                NextAction = new PaceSelectMechanismAction(objectIdentifier),
                ResponseIntent = null
            },
            "ManageSecurityEnvironment:SetPace");


    /// <summary>
    /// Enters the PACE phase once the mechanism has been captured, beginning the GENERAL AUTHENTICATE rounds.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnPaceMechanismSelected(CardSimulatorState state) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = CardLifecyclePhase.Pace,
                ResponseIntent = new StatusOnlyResponse(StatusWord.Success)
            },
            "ManageSecurityEnvironment:MechanismSelected");


    /// <summary>
    /// Dispatches a PACE GENERAL AUTHENTICATE round once the mechanism is selected, by the inner data object's
    /// context tag: the encrypted-nonce round (an empty object), the nonce mapping (DO'81'), the key agreement
    /// (DO'83'), or the mutual authentication (DO'85'). The effectful loop runs each round's crypto; ordering
    /// prerequisites (a round arriving before the one it depends on) are enforced there against device state.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnGeneralAuthenticate(CardSimulatorState state, byte innerTag, ReadOnlyMemory<byte> innerValue)
    {
        if(state.Phase != CardLifecyclePhase.Pace)
        {
            return Reject(state, StatusWord.ConditionsNotSatisfied, "GeneralAuthenticate:NoPace");
        }

        CardAction? action = innerTag switch
        {
            0 => new PaceEncryptNonceAction(),
            TerminalMappingDataTag => new PaceMapAction(innerValue),
            TerminalEphemeralKeyTag => new PaceAgreeAction(innerValue),
            TerminalTokenTag => new PaceAuthenticateAction(innerValue),
            _ => null
        };

        if(action is null)
        {
            return Reject(state, StatusWord.WrongData, $"GeneralAuthenticate:UnknownRound:0x{innerTag:X2}");
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            $"GeneralAuthenticate:Round:0x{innerTag:X2}");
    }


    /// <summary>
    /// Frames a successful PACE round's response. The round-4 mutual authentication also records that the AES
    /// Secure Messaging session is established; the session and the round's intermediate values are held by
    /// <see cref="CardSimulator"/> as device state.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnPaceRoundCompleted(CardSimulatorState state, PaceRoundCompleted completed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = completed.EstablishesSecureMessaging ? CardLifecyclePhase.SecureMessaging : state.Phase,
                ResponseIntent = new DynamicAuthenticationDataResponse(StatusWord.Success, completed.ResponseData, completed.Length)
            },
            completed.EstablishesSecureMessaging ? "GeneralAuthenticate:SecureMessagingEstablished" : "GeneralAuthenticate:RoundCompleted");


    /// <summary>
    /// Frames a failed PACE round: the exchange is abandoned and the card returns to
    /// <see cref="CardLifecyclePhase.Operational"/> (the intermediate values are released by the effect loop).
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnPaceExchangeFailed(CardSimulatorState state, PaceExchangeFailed failed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                Phase = CardLifecyclePhase.Operational,
                ResponseIntent = new StatusOnlyResponse(failed.StatusWord)
            },
            "GeneralAuthenticate:Failed");


    /// <summary>
    /// Dispatches an MSE:Set KAT (EACv1 Chip Authentication) once Secure Messaging is established. The
    /// effectful loop agrees the static–ephemeral ECDH secret and builds the re-keyed session; a Set KAT
    /// outside Secure Messaging is refused (Chip Authentication runs over the access-protocol session).
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnChipAuthenticate(CardSimulatorState state, ReadOnlyMemory<byte> terminalEphemeralPublicKey, int? keyId)
    {
        if(state.Phase != CardLifecyclePhase.SecureMessaging)
        {
            return Reject(state, StatusWord.ConditionsNotSatisfied, "ChipAuthenticate:NoSecureMessaging");
        }

        return Transition(
            state with
            {
                NextAction = new ChipAuthenticateAction(terminalEphemeralPublicKey, keyId),
                ResponseIntent = null
            },
            "ChipAuthenticate:Requested");
    }


    /// <summary>
    /// Frames the MSE:Set KAT acknowledgement (<c>9000</c>). The re-keyed Secure Messaging session is held by
    /// <see cref="CardSimulator"/> and activated once this response is framed under the prior session.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnChipAuthenticationCompleted(CardSimulatorState state) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new StatusOnlyResponse(StatusWord.Success)
            },
            "ChipAuthenticate:Completed");


    /// <summary>
    /// Frames a rejected MSE:Set KAT: the established Secure Messaging session is left intact (Chip
    /// Authentication is implicit, so a failure simply returns an error status word).
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnChipAuthenticationFailed(CardSimulatorState state, ChipAuthenticationFailed failed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new StatusOnlyResponse(failed.StatusWord)
            },
            "ChipAuthenticate:Failed");


    /// <summary>
    /// Declares the Active Authentication signing work an INTERNAL AUTHENTICATE needs. The plaintext-versus-
    /// Secure-Messaging routing is enforced by <see cref="CardSimulator"/> before the command reaches here, so
    /// the signing itself is phase-agnostic: the effectful loop reads the curve from the card's own EF.DG15,
    /// signs, and feeds the outcome back.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnActiveAuthenticate(CardSimulatorState state, ReadOnlyMemory<byte> challenge) =>
        Transition(
            state with
            {
                NextAction = new ActiveAuthenticateAction(challenge),
                ResponseIntent = null
            },
            "ActiveAuthenticate:Requested");


    /// <summary>
    /// Frames the INTERNAL AUTHENTICATE response from the chip's signature over the challenge. The signature
    /// buffer is held by <see cref="CardSimulator"/> and disposed after framing.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnActiveAuthenticationSigned(CardSimulatorState state, ActiveAuthenticationSigned signed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new ActiveAuthenticationResponse(StatusWord.Success, signed.Signature, signed.Length)
            },
            "ActiveAuthenticate:Signed");


    /// <summary>
    /// Frames a rejected INTERNAL AUTHENTICATE (no Active Authentication key, no EF.DG15, or an unsupported
    /// curve); the card state is otherwise unchanged.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnActiveAuthenticationFailed(CardSimulatorState state, ActiveAuthenticationFailed failed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new StatusOnlyResponse(failed.StatusWord)
            },
            "ActiveAuthenticate:Failed");


    /// <summary>
    /// Dispatches a Terminal Authentication MSE:Set DST once Secure Messaging is established: the effectful
    /// loop validates the named public key is available and selects it for the next certificate verification.
    /// MSE:Set DST runs over the access-protocol session, so it is refused outside Secure Messaging.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnSetDigitalSignatureTemplate(CardSimulatorState state, ReadOnlyMemory<byte> publicKeyReference)
    {
        if(state.Phase != CardLifecyclePhase.SecureMessaging)
        {
            return Reject(state, StatusWord.ConditionsNotSatisfied, "SetDigitalSignatureTemplate:NoSecureMessaging");
        }

        return Transition(
            state with
            {
                NextAction = new SetDigitalSignatureTemplateAction(publicKeyReference),
                ResponseIntent = null
            },
            "SetDigitalSignatureTemplate:Requested");
    }


    /// <summary>
    /// Dispatches a Terminal Authentication PSO:Verify Certificate once Secure Messaging is established: the
    /// effectful loop verifies the presented certificate against the selected public key and imports it on
    /// success. Verifying a certificate outside Secure Messaging is refused.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnVerifyCertificate(CardSimulatorState state, ReadOnlyMemory<byte> certificateContent)
    {
        if(state.Phase != CardLifecyclePhase.SecureMessaging)
        {
            return Reject(state, StatusWord.ConditionsNotSatisfied, "VerifyCertificate:NoSecureMessaging");
        }

        return Transition(
            state with
            {
                NextAction = new VerifyCertificateAction(certificateContent),
                ResponseIntent = null
            },
            "VerifyCertificate:Requested");
    }


    /// <summary>
    /// Frames a Terminal Authentication certificate-chain step (MSE:Set DST or PSO:Verify Certificate). The
    /// established Secure Messaging session is left intact; any imported certificate is held by
    /// <see cref="CardSimulator"/> as device state.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnTerminalAuthenticationStepCompleted(CardSimulatorState state, TerminalAuthenticationStepCompleted completed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new StatusOnlyResponse(completed.StatusWord)
            },
            "TerminalAuthentication:StepCompleted");


    /// <summary>
    /// Dispatches a Terminal Authentication MSE:Set AT once Secure Messaging is established: the effectful loop
    /// validates the named terminal certificate is imported and selects its key for EXTERNAL AUTHENTICATE.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnSetTerminalAuthenticationTemplate(CardSimulatorState state, ReadOnlyMemory<byte> objectIdentifier, ReadOnlyMemory<byte> terminalReference)
    {
        if(state.Phase != CardLifecyclePhase.SecureMessaging)
        {
            return Reject(state, StatusWord.ConditionsNotSatisfied, "SetTerminalAuthenticationTemplate:NoSecureMessaging");
        }

        return Transition(
            state with
            {
                NextAction = new SetTerminalAuthenticationTemplateAction(objectIdentifier, terminalReference),
                ResponseIntent = null
            },
            "SetTerminalAuthenticationTemplate:Requested");
    }


    /// <summary>
    /// Frames an MSE:Set AT for Terminal Authentication. On success the chip arms the EXTERNAL AUTHENTICATE —
    /// the next GET CHALLENGE issues the Terminal Authentication challenge; on failure the stage is unchanged.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnTerminalAuthenticationTemplateSet(CardSimulatorState state, TerminalAuthenticationTemplateSet templateSet) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                TerminalAuthenticationStage = templateSet.StatusWord.IsSuccess
                    ? TerminalAuthenticationStage.TerminalKeySelected
                    : state.TerminalAuthenticationStage,
                ResponseIntent = new StatusOnlyResponse(templateSet.StatusWord)
            },
            "SetTerminalAuthenticationTemplate:Set");


    /// <summary>
    /// Frames a successful Terminal Authentication EXTERNAL AUTHENTICATE (<c>9000</c>) and ends the exchange,
    /// returning the Terminal Authentication stage to <see cref="TerminalAuthenticationStage.None"/> and
    /// granting the now-authenticated terminal the effective sensitive-data read access for EF.DG3/EF.DG4.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnTerminalAuthenticationCompleted(CardSimulatorState state, TerminalAuthenticationCompleted completed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                TerminalAuthenticationStage = TerminalAuthenticationStage.None,
                GrantedReadAccess = completed.GrantedReadAccess,
                ResponseIntent = new StatusOnlyResponse(StatusWord.Success)
            },
            "TerminalAuthenticate:Completed");


    /// <summary>
    /// Frames a rejected Terminal Authentication EXTERNAL AUTHENTICATE: the exchange ends, any previously
    /// granted sensitive-data read access is revoked, and the established Secure Messaging session is left intact.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnTerminalAuthenticationFailed(CardSimulatorState state, TerminalAuthenticationFailed failed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                TerminalAuthenticationStage = TerminalAuthenticationStage.None,
                GrantedReadAccess = InspectionSystemAccess.None,
                ResponseIntent = new StatusOnlyResponse(failed.StatusWord)
            },
            "TerminalAuthenticate:Failed");


    /// <summary>
    /// Rejects a command whose instruction this slice does not model.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> OnUnsupportedCommand(CardSimulatorState state, byte instruction) =>
        Reject(state, StatusWord.InstructionNotSupported, $"Unsupported:0x{instruction:X2}");


    /// <summary>
    /// Produces a status-only rejection that leaves the card state otherwise unchanged.
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> Reject(CardSimulatorState state, StatusWord statusWord, string label) =>
        Transition(state with { ResponseIntent = new StatusOnlyResponse(statusWord) }, label);


    /// <summary>
    /// Builds a transition that leaves the stack unchanged (this slice uses only the sentinel).
    /// </summary>
    private static TransitionResult<CardSimulatorState, CardStackSymbol> Transition(CardSimulatorState nextState, string label) =>
        new(nextState, StackAction<CardStackSymbol>.None, label);
}

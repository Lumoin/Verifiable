using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Apdu.Eac;
using Verifiable.Foundation.Automata;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// The complete state of the eMRTD card simulator's pushdown automaton: the operational phase, the
/// elementary files the card holds, the currently selected file, and the logical response produced by the
/// command just processed.
/// </summary>
/// <remarks>
/// <para>
/// This is the single operational record carried by one <c>PushdownAutomaton</c> per simulated card,
/// mirroring the TPM simulator's state record. The file store is the card's personalised Logical Data
/// Structure (EF.COM, the data groups, EF.SOD), keyed by file identifier; <see cref="SelectedFile"/> is
/// the volatile "current EF" a READ BINARY reads from. Access-control state (a Secure Messaging session
/// after BAC/PACE, the Chip Authentication outcome) is added as further fields when those responders are
/// modelled.
/// </para>
/// <para>
/// The files are <em>borrowed</em>: <see cref="CardSimulator"/> takes them as already-minted carriers and
/// does not dispose them, so the record stays a pure value and the producer that minted the files retains
/// ownership. <see cref="ResponseIntent"/> carries a window into one of them on the READ BINARY path,
/// which is copied out before the command returns.
/// </para>
/// </remarks>
/// <param name="CardId">The stable identifier of this simulated card; also the automaton's run identifier.</param>
/// <param name="Phase">The current operational phase.</param>
/// <param name="Files">The elementary files the card serves, keyed by file identifier (borrowed, not owned).</param>
/// <param name="SelectedFile">The currently selected elementary file identifier, or <see langword="null"/> when none is selected.</param>
/// <param name="IssuedChallenge">The chip nonce RND.IC the most recent GET CHALLENGE issued, or empty when none is outstanding. A public nonce held as model state (mirroring the TPM simulator's authValue handling); consumed by the Basic Access Control mutual authentication.</param>
/// <param name="NextAction">The effectful action the runner must execute next; <see cref="NullAction.Instance"/> when none.</param>
/// <param name="ResponseIntent">The logical response produced by the last command, or <see langword="null"/> before the first command.</param>
/// <param name="TerminalAuthenticationStage">The progress of a Terminal Authentication exchange within the Secure Messaging phase, gating the GET CHALLENGE and EXTERNAL AUTHENTICATE that follow the certificate-chain presentation.</param>
/// <param name="GrantedReadAccess">The effective Inspection System read authorization a completed Terminal Authentication granted the terminal (BSI TR-03110-3 §2.7), gating READ BINARY of the sensitive data groups EF.DG3 and EF.DG4. <see cref="InspectionSystemAccess.None"/> until a Terminal Authentication completes; reset to it on a failed one.</param>
[DebuggerDisplay("Card={CardId}, Phase={Phase}, Selected={SelectedFile}, Files={Files.Count}, NextAction={NextAction}")]
public sealed record CardSimulatorState(
    string CardId,
    CardLifecyclePhase Phase,
    ImmutableDictionary<ushort, ElementaryFile> Files,
    ushort? SelectedFile,
    ReadOnlyMemory<byte> IssuedChallenge,
    PdaAction NextAction,
    CardResponseIntent? ResponseIntent,
    TerminalAuthenticationStage TerminalAuthenticationStage = TerminalAuthenticationStage.None,
    InspectionSystemAccess GrantedReadAccess = InspectionSystemAccess.None)
{
    /// <summary>
    /// Creates the initial state of a personalised card: operational, no file selected yet, holding the
    /// given elementary files.
    /// </summary>
    /// <param name="cardId">The stable identifier of this simulated card.</param>
    /// <param name="files">The elementary files the card serves, keyed by file identifier (borrowed, not owned).</param>
    /// <returns>An operational state.</returns>
    public static CardSimulatorState Operational(string cardId, ImmutableDictionary<ushort, ElementaryFile> files) =>
        new(cardId, CardLifecyclePhase.Operational, files, null, ReadOnlyMemory<byte>.Empty, NullAction.Instance, null);
}

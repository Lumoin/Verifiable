using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Creates the initial state from a <c>create</c> operation's data. Async to support
/// remote trust anchor verification (e.g., EBSI registry lookup, EUDIW trusted list check).
/// </summary>
/// <remarks>
/// <para>
/// Corresponds to the <c>create()</c> function in the
/// <see href="https://identity.foundation/did-registration/#create">DIF DID Registration specification</see>
/// and the Create operation in
/// <see href="https://www.w3.org/TR/did-core/#method-operations">W3C DID Core section 8.2</see>.
/// </para>
/// </remarks>
/// <typeparam name="TState">The type of state derived from replaying operations.</typeparam>
/// <param name="operationData">The data payload of the create operation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The initial state on success, or a descriptive error string on failure.</returns>
public delegate ValueTask<Result<TState, string>> ApplyCreateDelegate<TState>(
    ReadOnlyMemory<byte> operationData,
    CancellationToken cancellationToken);

/// <summary>
/// Applies an <c>update</c> operation to an existing state. Async to support external
/// validation before accepting the state transition (e.g., revocation status checks
/// via Token Status List, governance authority confirmation).
/// </summary>
/// <remarks>
/// <para>
/// Corresponds to the <c>update()</c> function in the
/// <see href="https://identity.foundation/did-registration/#update">DIF DID Registration specification</see>.
/// The <c>didDocumentOperation</c> field supports <c>setDidDocument</c>, <c>addToDidDocument</c>,
/// and <c>removeFromDidDocument</c>.
/// </para>
/// </remarks>
/// <typeparam name="TState">The type of state derived from replaying operations.</typeparam>
/// <param name="currentState">The state before the update.</param>
/// <param name="operationData">The data payload of the update operation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The updated state on success, or a descriptive error string on failure.</returns>
public delegate ValueTask<Result<TState, string>> ApplyUpdateDelegate<TState>(
    TState currentState,
    ReadOnlyMemory<byte> operationData,
    CancellationToken cancellationToken);

/// <summary>
/// Applies a <c>deactivate</c> operation, producing a terminal state. Async to support
/// deactivation flows requiring governance authority confirmation or ledger-anchored
/// finality.
/// </summary>
/// <remarks>
/// <para>
/// Corresponds to the <c>deactivate()</c> function in the
/// <see href="https://identity.foundation/did-registration/#deactivate">DIF DID Registration specification</see>.
/// </para>
/// </remarks>
/// <typeparam name="TState">The type of state derived from replaying operations.</typeparam>
/// <param name="currentState">The state before deactivation.</param>
/// <param name="operationData">The data payload of the deactivate operation.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The deactivated state on success, or a descriptive error string on failure.</returns>
public delegate ValueTask<Result<TState, string>> ApplyDeactivateDelegate<TState>(
    TState currentState,
    ReadOnlyMemory<byte> operationData,
    CancellationToken cancellationToken);

/// <summary>
/// Validates a single operation's proof (signature, witness proofs) against the state
/// that was current at the time of the operation. Async to support proof verification
/// against remote hardware security modules, TPM 2.0, or wallet secure cryptographic devices.
/// </summary>
/// <typeparam name="TState">The type of state derived from replaying operations.</typeparam>
/// <param name="currentState">
/// The state at the point in the log just before this operation. For the first
/// operation, this is <c>default</c>.
/// </param>
/// <param name="operationData">The complete operation including proof.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The unchanged state on success if the proof is valid, or a descriptive error string on failure.
/// </returns>
public delegate ValueTask<Result<TState, string>> ValidateProofDelegate<TState>(
    TState? currentState,
    ReadOnlyMemory<byte> operationData,
    CancellationToken cancellationToken);

/// <summary>
/// Groups the delegates needed to replay lifecycle operations from a log and derive
/// the current state. Each delegate can be tested independently (parameters in,
/// result out) and composed freely — e.g., did:webvh can reuse a did:cel-compatible
/// <see cref="ApplyCreate"/> while providing its own governance-aware <see cref="ValidateProof"/>.
/// </summary>
/// <remarks>
/// <para>
/// All delegates are <see cref="ValueTask"/>-returning. Synchronous implementations
/// (in-memory signature verification, local proof checking) return
/// <see cref="ValueTask.FromResult{TResult}"/> with zero allocation. Async implementations
/// (remote hardware security modules, TPM 2.0, ledger confirmation) use the full async path.
/// </para>
/// <para>
/// The operations (<c>create</c>, <c>update</c>, <c>deactivate</c>) correspond to the
/// <see href="https://www.w3.org/TR/did-core/#method-operations">W3C DID Core method operations</see>
/// and the <see href="https://identity.foundation/did-registration/">DIF DID Registration specification's</see>
/// <c>create()</c>, <c>update()</c>, and <c>deactivate()</c> functions. This grouping
/// is not limited to DID lifecycle — any append-only log with create/update/deactivate
/// semantics (credential status, consent records, certificate lifecycle) can use the same delegates.
/// </para>
/// </remarks>
/// <typeparam name="TState">The type of state derived from replaying operations.</typeparam>
/// <param name="ApplyCreate">Delegate that creates the initial state from a <c>create</c> operation.</param>
/// <param name="ApplyUpdate">Delegate that applies an <c>update</c> operation to an existing state.</param>
/// <param name="ApplyDeactivate">Delegate that applies a <c>deactivate</c> operation, producing a terminal state.</param>
/// <param name="ValidateProof">Delegate that validates an operation's proof against the current state.</param>
public sealed record OperationRules<TState>(
    ApplyCreateDelegate<TState> ApplyCreate,
    ApplyUpdateDelegate<TState> ApplyUpdate,
    ApplyDeactivateDelegate<TState> ApplyDeactivate,
    ValidateProofDelegate<TState> ValidateProof);

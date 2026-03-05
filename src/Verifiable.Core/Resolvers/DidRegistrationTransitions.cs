using System;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Automata;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// PDA states for a DID registration flow. Each state carries the data accumulated so far.
/// </summary>
public abstract record RegistrationFlowState;

/// <summary>
/// The flow has been initiated with a method and optional DID document.
/// </summary>
/// <param name="Method">The DID method name.</param>
/// <param name="Document">The initial DID document, if provided.</param>
public sealed record RegistrationInitiated(string Method, DidDocument? Document) : RegistrationFlowState;

/// <summary>
/// The registrar requires the client to sign a payload before continuing.
/// </summary>
/// <param name="Request">The signing request to present to the client.</param>
/// <param name="PendingState">The state to resume with once the signature is provided.</param>
public sealed record AwaitingSignature(SigningRequest Request, RegistrationFlowState PendingState) : RegistrationFlowState;

/// <summary>
/// The registrar is waiting for an asynchronous backend operation to complete.
/// </summary>
/// <param name="JobId">The job identifier for polling.</param>
public sealed record AwaitingConfirmation(string JobId) : RegistrationFlowState;

/// <summary>
/// The registration completed successfully.
/// </summary>
/// <param name="Did">The created/updated DID.</param>
/// <param name="Document">The resulting DID document.</param>
public sealed record RegistrationCompleted(string Did, DidDocument? Document) : RegistrationFlowState;

/// <summary>
/// The registration failed.
/// </summary>
/// <param name="Error">The error description.</param>
public sealed record RegistrationFailed(string Error) : RegistrationFlowState;

/// <summary>
/// PDA inputs for a DID registration flow.
/// </summary>
public abstract record RegistrationInput;

/// <summary>
/// Begin a create operation.
/// </summary>
/// <param name="Method">The DID method to use.</param>
/// <param name="Document">An optional initial DID document.</param>
public sealed record BeginCreate(string Method, DidDocument? Document) : RegistrationInput;

/// <summary>
/// Begin an update operation.
/// </summary>
/// <param name="Did">The DID to update.</param>
/// <param name="Document">The updated DID document.</param>
public sealed record BeginUpdate(string Did, DidDocument? Document) : RegistrationInput;

/// <summary>
/// Begin a deactivate operation.
/// </summary>
/// <param name="Did">The DID to deactivate.</param>
public sealed record BeginDeactivate(string Did) : RegistrationInput;

/// <summary>
/// The client provides a signing response after an <see cref="AwaitingSignature"/> state.
/// </summary>
/// <param name="Response">The signing response from the client.</param>
public sealed record ProvideSignature(SigningResponse Response) : RegistrationInput;

/// <summary>
/// The backend confirms that an asynchronous operation completed.
/// </summary>
/// <param name="Did">The resulting DID.</param>
/// <param name="Document">The resulting DID document.</param>
public sealed record ConfirmCompletion(string Did, DidDocument? Document) : RegistrationInput;

/// <summary>
/// An error occurred during the registration flow.
/// </summary>
/// <param name="Error">The error description.</param>
public sealed record RegistrationError(string Error) : RegistrationInput;

/// <summary>
/// Provides the transition function and factory methods for creating DID registration
/// PDA instances.
/// </summary>
/// <remarks>
/// <para>
/// The registration flow follows the
/// <see href="https://identity.foundation/did-registration/">DIF DID Registration specification</see>:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>create(method, options, secret, didDocument)</c> initiates via <see cref="BeginCreate"/>.
///   </description></item>
///   <item><description>
///     <c>update(did, options, secret, didDocumentOperation, didDocument)</c> initiates via <see cref="BeginUpdate"/>.
///   </description></item>
///   <item><description>
///     <c>deactivate(did, options, secret)</c> initiates via <see cref="BeginDeactivate"/>.
///   </description></item>
/// </list>
/// <para>
/// In client-managed secret mode, the PDA transitions to <see cref="AwaitingSignature"/>
/// and the caller feeds the <see cref="ProvideSignature"/> input when the client completes signing.
/// For asynchronous backends, the PDA transitions to <see cref="AwaitingConfirmation"/>
/// and the caller feeds <see cref="ConfirmCompletion"/> when polling succeeds.
/// </para>
/// </remarks>
public static class DidRegistrationTransitions
{
    /// <summary>
    /// The stack sentinel symbol for registration flows.
    /// </summary>
    public const string Sentinel = "RegistrationFrame";

    /// <summary>
    /// The stack symbol pushed when entering client-managed signing.
    /// </summary>
    public const string SigningFrame = "SigningFrame";

    /// <summary>
    /// Creates the transition function for DID registration flows.
    /// The <paramref name="methodHandler"/> delegate performs the method-specific work
    /// (key generation, ledger anchoring, log entry creation) and returns the resulting
    /// registration state.
    /// </summary>
    /// <param name="methodHandler">
    /// A delegate that receives the registration flow state and produces the next state.
    /// This is where method-specific logic lives — the PDA handles the state machine,
    /// the handler handles the DID method.
    /// </param>
    /// <returns>A transition delegate suitable for <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>.</returns>
    public static TransitionDelegate<RegistrationFlowState, RegistrationInput, string> Create(
        Func<RegistrationFlowState, RegistrationInput, CancellationToken, ValueTask<RegistrationFlowState>> methodHandler)
    {
        ArgumentNullException.ThrowIfNull(methodHandler);

        return async (state, input, stackTop, cancellationToken) => (state, input) switch
        {
            //Begin operations: delegate to the method handler.
            (RegistrationInitiated or null, BeginCreate or BeginUpdate or BeginDeactivate) =>
                await HandleMethodOperation(state, input, methodHandler, cancellationToken).ConfigureAwait(false),

            //Client provides a signature: pop the signing frame and delegate to handler.
            (AwaitingSignature awaiting, ProvideSignature sig) when stackTop == SigningFrame =>
                new TransitionResult<RegistrationFlowState, string>(
                    await methodHandler(awaiting, sig, cancellationToken).ConfigureAwait(false),
                    StackAction<string>.Pop,
                    "SignatureProvided"),

            //Backend confirms completion.
            (AwaitingConfirmation, ConfirmCompletion confirm) =>
                new TransitionResult<RegistrationFlowState, string>(
                    new RegistrationCompleted(confirm.Did, confirm.Document),
                    StackAction<string>.None,
                    "Confirmed"),

            //Error at any point.
            (_, RegistrationError err) =>
                new TransitionResult<RegistrationFlowState, string>(
                    new RegistrationFailed(err.Error),
                    StackAction<string>.None,
                    "Failed"),

            _ => null
        };
    }

    private static async ValueTask<TransitionResult<RegistrationFlowState, string>?> HandleMethodOperation(
        RegistrationFlowState? currentState,
        RegistrationInput input,
        Func<RegistrationFlowState, RegistrationInput, CancellationToken, ValueTask<RegistrationFlowState>> methodHandler,
        CancellationToken cancellationToken)
    {
        //Initialize state from the input.
        RegistrationFlowState initiated = input switch
        {
            BeginCreate create => new RegistrationInitiated(create.Method, create.Document),
            BeginUpdate update => new RegistrationInitiated("", update.Document),
            BeginDeactivate deactivate => new RegistrationInitiated("", null),
            _ => throw new InvalidOperationException($"Unexpected input type: {input.GetType().Name}.")
        };

        string label = input switch
        {
            BeginCreate => "BeginCreate",
            BeginUpdate => "BeginUpdate",
            BeginDeactivate => "BeginDeactivate",
            _ => "BeginOperation"
        };

        var result = await methodHandler(initiated, input, cancellationToken).ConfigureAwait(false);

        //Method handler decides the next state. If it requires signing, push a frame.
        return result switch
        {
            AwaitingSignature => new TransitionResult<RegistrationFlowState, string>(
                result, StackAction<string>.Push(SigningFrame), label),

            AwaitingConfirmation => new TransitionResult<RegistrationFlowState, string>(
                result, StackAction<string>.None, label),

            RegistrationCompleted => new TransitionResult<RegistrationFlowState, string>(
                result, StackAction<string>.None, label),

            RegistrationFailed => new TransitionResult<RegistrationFlowState, string>(
                result, StackAction<string>.None, label),

            _ => new TransitionResult<RegistrationFlowState, string>(
                result, StackAction<string>.None, label)
        };
    }

    /// <summary>
    /// Creates a PDA configured for a DID registration flow.
    /// </summary>
    /// <param name="runId">The execution/session identifier.</param>
    /// <param name="methodHandler">The method-specific handler.</param>
    /// <param name="timeProvider">Optional time provider for trace timestamps.</param>
    /// <returns>A configured PDA ready to process registration inputs.</returns>
    public static PushdownAutomaton<RegistrationFlowState, RegistrationInput, string> CreateAutomaton(
        string runId,
        Func<RegistrationFlowState, RegistrationInput, CancellationToken, ValueTask<RegistrationFlowState>> methodHandler,
        TimeProvider? timeProvider = null)
    {
        return new PushdownAutomaton<RegistrationFlowState, RegistrationInput, string>(
            runId,
            new RegistrationInitiated("", null),
            Sentinel,
            Create(methodHandler),
            state => state is RegistrationCompleted,
            timeProvider);
    }
}

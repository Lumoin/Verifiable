using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.Model.Common
{
    /// <summary>
    /// Marker interface for all builder types in the Verifiable library.
    /// This provides a common type that can be used for builder collections and constraints.
    /// </summary>
    public interface IBuilder { }


    /// <summary>
    /// Serves as a unified, general-purpose builder for constructing various types in the Verifiable library.
    /// This builder implements a fold/aggregate pattern with fluent interface, applying a sequence of
    /// transformation functions to an initial state through repeated application.
    /// </summary>
    /// <typeparam name="TResult">The type of the object being built. Must have a parameterless constructor.</typeparam>
    /// <typeparam name="TState">The type of the state object passed between build actions to maintain context.</typeparam>
    /// <typeparam name="TBuilder">The specific type of the builder implementing this base class, enabling fluent interfaces.</typeparam>
    /// <remarks>
    /// <para>
    /// <strong>Architectural Role</strong>
    /// </para>
    /// <para>
    /// The Verifiable library uses two complementary patterns for object construction:
    /// </para>
    /// <code>
    /// +------------------------------------------------------------------+
    /// |                    Delegate-Based Pattern                        |
    /// |              (Foundation - "Parameters In, Parameters Out")      |
    /// +------------------------------------------------------------------+
    /// | - Pure functions with explicit parameters.                       |
    /// | - No hidden state, maximum flexibility.                          |
    /// | - Caller provides all dependencies explicitly.                   |
    /// | - Used by: Jws.SignAsync, Jose.VerifyAsync, crypto operations.  |
    /// +------------------------------------------------------------------+
    ///                              |
    ///                    Builds on top of
    ///                              |
    ///                              v
    /// +------------------------------------------------------------------+
    /// |                    Builder Pattern                               |
    /// |              (Convenience - Captured State + Transformations)    |
    /// +------------------------------------------------------------------+
    /// | - Captures "non-moving parts" (signing config, context, etc.).  |
    /// | - Applies transformations in sequence (fold/aggregate).         |
    /// | - Varying parts provided at BuildAsync time.                    |
    /// | - Used by: CredentialBuilder, KeyDidBuilder, WebDidBuilder.     |
    /// +------------------------------------------------------------------+
    /// </code>
    /// <para>
    /// The builder pattern is a convenience layer that captures configuration and orchestrates
    /// the underlying delegate-based operations. Builders hold state that remains constant across
    /// multiple builds (like signing keys, cryptosuites, or fragment generators), while the
    /// <c>BuildAsync</c> method accepts parameters that vary per invocation (like subject claims
    /// or issuer information).
    /// </para>
    /// <para>
    /// <strong>Fold/Aggregate Pattern</strong>
    /// </para>
    /// <para>
    /// This builder operates using a fold/aggregate pattern, where transformation functions are applied
    /// sequentially to an initial state (seed value) of type <typeparamref name="TResult"/>. Each
    /// transformation receives the accumulated result from the previous step and produces a new
    /// accumulated result, implementing the classic fold operation:
    /// </para>
    /// <code>
    /// fold(f, seed, [T1, T2, ..., Tn]) = Tn(...T2(T1(seed))...)
    /// </code>
    /// <para>
    /// The repeated application of transformations allows for incremental construction of complex objects
    /// while maintaining immutability principles and enabling method chaining. Each transformation function receives:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The current accumulated state of the object being built.</description></item>
    /// <item><description>A reference to the builder instance for additional context.</description></item>
    /// <item><description>Optional state information that persists across all transformation steps.</description></item>
    /// <item><description>A cancellation token for cooperative cancellation.</description></item>
    /// </list>
    /// <para>
    /// The builder supports two initialization modes for the fold operation:
    /// </para>
    /// <list type="number">
    /// <item><description>Starting from a default-constructed instance of <typeparamref name="TResult"/>.</description></item>
    /// <item><description>Starting from a pre-configured seed instance.</description></item>
    /// </list>
    /// <para>
    /// <strong>Testability and Formal Properties</strong>
    /// </para>
    /// <para>
    /// A configured builder is a "program" stored as data - a list of transformation functions that can be
    /// inspected, passed around, and reused. This reification enables both formal reasoning and exhaustive testing.
    /// </para>
    /// <para>
    /// The fold pattern has properties amenable to formal verification:
    /// </para>
    /// <code>
    /// Invariant Preservation Theorem:
    /// 
    /// Given:
    ///   - Seed satisfies invariant I.
    ///   - Each transformation Ti preserves I (if input satisfies I, output satisfies I).
    /// Then:
    ///   - Final result satisfies I.
    /// 
    /// This is the loop invariant principle applied to the transformation pipeline.
    /// </code>
    /// <para>
    /// Practical testing strategies enabled by this pattern:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Isolation testing:</strong> Each transformation can be unit tested independently.
    /// Given a specific input state, verify it produces the correct output state.
    /// </description></item>
    /// <item><description>
    /// <strong>Property-based testing:</strong> Using tools like CsCheck, generate arbitrary valid
    /// inputs and verify that invariants hold across all generated cases.
    /// </description></item>
    /// <item><description>
    /// <strong>Composition testing:</strong> If transformations T1 and T2 are individually correct
    /// and invariant-preserving, their composition (T1 then T2) is also correct.
    /// </description></item>
    /// <item><description>
    /// <strong>Determinism verification:</strong> Same builder configuration plus same inputs must
    /// produce identical outputs. No hidden state mutations occur elsewhere.
    /// </description></item>
    /// </list>
    /// <para>
    /// Properties that can be formally proven or exhaustively tested include:
    /// </para>
    /// <list type="bullet">
    /// <item><description>Type preservation (each transformation returns <typeparamref name="TResult"/>).</description></item>
    /// <item><description>Invariant preservation (e.g., "credential always has context after transformation 1").</description></item>
    /// <item><description>Idempotence of specific transformations where applicable.</description></item>
    /// <item><description>Commutativity of independent transformations (order independence).</description></item>
    /// </list>
    /// <para>
    /// <strong>Extensibility</strong>
    /// </para>
    /// <para>
    /// Users extend builders by calling <see cref="With"/> to add transformations. The builder does not
    /// need advance knowledge of what transformations will be added - it applies them in sequence. This
    /// follows the open/closed principle: open for extension (add transformations), closed for modification
    /// (the fold mechanism is fixed). Complex domain-specific construction logic can be captured once and
    /// reused across the application.
    /// </para>
    /// <para>
    /// <strong>When to Use Each Pattern</strong>
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <strong>Delegate pattern:</strong> When you need maximum control, are integrating with
    /// existing infrastructure, or when configuration varies significantly per call.
    /// </description></item>
    /// <item><description>
    /// <strong>Builder pattern:</strong> When you have stable configuration reused across multiple
    /// builds, want a fluent API, or are composing complex multi-step construction.
    /// </description></item>
    /// </list>
    /// <para>
    /// All transformations are asynchronous, returning <see cref="ValueTask{TResult}"/>. This enables
    /// transformations that require I/O operations such as cryptographic signing, key resolution,
    /// or external service calls while maintaining efficient execution for synchronous operations.
    /// </para>
    /// <para>
    /// Verifiable library provides preconfigured builders for various objects such as DID documents,
    /// verification methods, and cryptographic keys. These builders are designed to be extensible
    /// while providing sensible defaults through the repeated application of transformation functions.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// // Builder captures stable configuration.
    /// var builder = new CredentialBuilder()
    ///     .WithDataIntegritySigning(privateKey, verificationMethodId, cryptosuite, ...);
    ///
    /// // BuildAsync receives varying parameters.
    /// var credential1 = await builder.BuildAsync(issuer, subject1, cancellationToken);
    /// var credential2 = await builder.BuildAsync(issuer, subject2, cancellationToken);
    ///
    /// // Compare to delegate pattern where everything is explicit.
    /// var jws = await Jws.SignAsync(header, payload, signingFunction, encoder, pool, cancellationToken);
    /// </code>
    /// </example>
    public class Builder<TResult, TState, TBuilder>: IBuilder
        where TBuilder : Builder<TResult, TState, TBuilder>
        where TResult : new()
    {
        /// <summary>
        /// The list of transformation actions that will be applied in order during the build process.
        /// Each action transforms the current state of the object being built.
        /// </summary>
        /// <remarks>
        /// Actions are applied in the order they were added using <see cref="With"/>.
        /// Each action receives the current object state, the builder instance, optional state information,
        /// and a cancellation token.
        /// </remarks>
        protected List<Func<TResult, TBuilder, TState?, CancellationToken, ValueTask<TResult>>> WithActions { get; private set; } = [];


        /// <summary>
        /// Initializes a new instance of the <see cref="Builder{TResult, TState, TBuilder}"/> class.
        /// Creates an empty builder with no transformation actions.
        /// </summary>
        public Builder() { }


        /// <summary>
        /// Adds a transformation function to the fold/aggregate pipeline.
        /// The transformation will be applied during the build process in the order it was added,
        /// following the fold pattern of repeated application to accumulate the final result.
        /// </summary>
        /// <param name="actionAsync">
        /// An asynchronous function that transforms the current state of the object being built.
        /// The function receives the current object, the builder instance, optional state information,
        /// and a cancellation token. It must return a <see cref="ValueTask{TResult}"/> containing
        /// the transformed object (which may be the same instance or a new one).
        /// </param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="actionAsync"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// Transformation functions are applied in the order they are added, implementing a left-fold operation
        /// where each function receives the accumulated result from the previous transformation. Each function
        /// should be pure and deterministic to ensure predictable results from the repeated application pattern.
        /// </para>
        /// <para>
        /// For synchronous transformations, return the result using <c>ValueTask.FromResult(obj)</c> or
        /// rely on the implicit conversion from <typeparamref name="TResult"/> to <see cref="ValueTask{TResult}"/>.
        /// </para>
        /// <para>
        /// Transformations should check <see cref="CancellationToken.IsCancellationRequested"/> and call
        /// <see cref="CancellationToken.ThrowIfCancellationRequested"/> for long-running operations.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// // Asynchronous transformation with signing.
        /// builder.With(async (credential, builder, state, cancellationToken) =>
        /// {
        ///     var proof = await CreateProofAsync(credential, state.PrivateKey, cancellationToken);
        ///     credential.AddProof(proof);
        ///     return credential;
        /// });
        ///
        /// // Synchronous transformation.
        /// builder.With((didDoc, builder, state, cancellationToken) =>
        /// {
        ///     didDoc.Id = new KeyDidMethod($"did:key:{state.EncodedKey}");
        ///     return ValueTask.FromResult(didDoc);
        /// });
        /// </code>
        /// </example>
        public TBuilder With(Func<TResult, TBuilder, TState?, CancellationToken, ValueTask<TResult>> actionAsync)
        {
            ArgumentNullException.ThrowIfNull(actionAsync, nameof(actionAsync));

            WithActions.Add(actionAsync);
            return (TBuilder)this;
        }


        /// <summary>
        /// Adds a transformation function that does not require cancellation token access.
        /// This is a convenience overload for simple transformations.
        /// </summary>
        /// <param name="actionAsync">
        /// An asynchronous function that transforms the current state of the object being built.
        /// </param>
        /// <returns>The builder instance to enable method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="actionAsync"/> is null.</exception>
        public TBuilder With(Func<TResult, TBuilder, TState?, ValueTask<TResult>> actionAsync)
        {
            ArgumentNullException.ThrowIfNull(actionAsync, nameof(actionAsync));

            return With((result, builder, state, _) => actionAsync(result, builder, state));
        }


        /// <summary>
        /// Executes the fold/aggregate operation by applying all registered transformation functions
        /// to a default-constructed initial state in sequence.
        /// </summary>
        /// <typeparam name="TParam">The type of the parameter used to generate the build state.</typeparam>
        /// <param name="param">The parameter passed to the pre-build action to generate the build state.</param>
        /// <param name="preBuildActionAsync">
        /// An asynchronous function that generates the build state from the input parameter and builder instance.
        /// This state will be passed to all transformation actions during the build process.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="preBuildActionAsync"/> is null.</exception>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        /// <remarks>
        /// <para>
        /// This method executes the complete fold operation: it first invokes the pre-build action to create
        /// the build state, then applies each registered transformation function in sequence to the
        /// default-constructed seed value.
        /// </para>
        /// <para>
        /// The cancellation token is passed to both the pre-build action and all transformation functions,
        /// enabling cooperative cancellation at any point in the build process.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// var credential = await builder.BuildAsync(
        ///     (publicKey, cryptoSuite),
        ///     async (param, builder, ct) => new BuildState
        ///     {
        ///         PublicKey = param.publicKey,
        ///         Suite = param.cryptoSuite
        ///     },
        ///     cancellationToken);
        /// </code>
        /// </example>
        public virtual async ValueTask<TResult> BuildAsync<TParam>(
            TParam param,
            Func<TParam, TBuilder, CancellationToken, ValueTask<TState>> preBuildActionAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            TState buildInvariant = await preBuildActionAsync(param, (TBuilder)this, cancellationToken);
            TResult result = new();

            foreach(Func<TResult, TBuilder, TState?, CancellationToken, ValueTask<TResult>> actionAsync in WithActions)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = await actionAsync(result, (TBuilder)this, buildInvariant, cancellationToken);
            }

            return result;
        }


        /// <summary>
        /// Executes the fold/aggregate operation with a pre-build action that does not require cancellation.
        /// This is a convenience overload for simpler scenarios.
        /// </summary>
        /// <typeparam name="TParam">The type of the parameter used to generate the build state.</typeparam>
        /// <param name="param">The parameter passed to the pre-build action to generate the build state.</param>
        /// <param name="preBuildActionAsync">
        /// An asynchronous function that generates the build state from the input parameter and builder instance.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        public virtual ValueTask<TResult> BuildAsync<TParam>(
            TParam param,
            Func<TParam, TBuilder, ValueTask<TState>> preBuildActionAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            return BuildAsync(
                param,
                (p, b, _) => preBuildActionAsync(p, b),
                cancellationToken);
        }


        /// <summary>
        /// Builds the target object by applying all registered transformation actions to a pre-configured seed instance.
        /// </summary>
        /// <typeparam name="TSeedParam">The type of the parameter used to generate both the seed and the build state.</typeparam>
        /// <param name="seedGeneratorAsync">
        /// An asynchronous function that creates the initial seed instance from the provided parameter.
        /// This seed serves as the starting point for all transformation actions.
        /// </param>
        /// <param name="seedGeneratorParameter">The parameter passed to both the seed generator and pre-build action.</param>
        /// <param name="preBuildActionAsync">
        /// An asynchronous function that generates the build state from the input parameter and builder instance.
        /// This state will be passed to all transformation actions during the build process.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="seedGeneratorAsync"/> or <paramref name="preBuildActionAsync"/> is null.
        /// </exception>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        /// <remarks>
        /// This method is useful when you need to start with a pre-configured instance rather than
        /// a default-constructed one. The seed instance is created first, then all registered
        /// transformation actions are applied to it in order.
        /// </remarks>
        /// <example>
        /// <code>
        /// var didDocument = await builder.BuildAsync(
        ///     async (param, ct) =>
        ///     {
        ///         var doc = new DidDocument();
        ///         doc.AddDefaultContext();
        ///         return doc;
        ///     },
        ///     (publicKey, cryptoSuite),
        ///     async (param, builder, ct) => new BuildState { /* ... */ },
        ///     cancellationToken);
        /// </code>
        /// </example>
        public virtual async ValueTask<TResult> BuildAsync<TSeedParam>(
            Func<TSeedParam, CancellationToken, ValueTask<TResult>> seedGeneratorAsync,
            TSeedParam seedGeneratorParameter,
            Func<TSeedParam, TBuilder, CancellationToken, ValueTask<TState>> preBuildActionAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(seedGeneratorAsync, nameof(seedGeneratorAsync));
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            TState buildInvariant = await preBuildActionAsync(seedGeneratorParameter, (TBuilder)this, cancellationToken);
            TResult seed = await seedGeneratorAsync(seedGeneratorParameter, cancellationToken);

            foreach(Func<TResult, TBuilder, TState?, CancellationToken, ValueTask<TResult>> actionAsync in WithActions)
            {
                cancellationToken.ThrowIfCancellationRequested();
                seed = await actionAsync(seed, (TBuilder)this, buildInvariant, cancellationToken);
            }

            return seed;
        }


        /// <summary>
        /// Builds the target object with seed generator and pre-build action that do not require cancellation.
        /// This is a convenience overload for simpler scenarios.
        /// </summary>
        /// <typeparam name="TSeedParam">The type of the parameter used to generate both the seed and the build state.</typeparam>
        /// <param name="seedGeneratorAsync">
        /// An asynchronous function that creates the initial seed instance from the provided parameter.
        /// </param>
        /// <param name="seedGeneratorParameter">The parameter passed to both the seed generator and pre-build action.</param>
        /// <param name="preBuildActionAsync">
        /// An asynchronous function that generates the build state from the input parameter and builder instance.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        public virtual ValueTask<TResult> BuildAsync<TSeedParam>(
            Func<TSeedParam, ValueTask<TResult>> seedGeneratorAsync,
            TSeedParam seedGeneratorParameter,
            Func<TSeedParam, TBuilder, ValueTask<TState>> preBuildActionAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(seedGeneratorAsync, nameof(seedGeneratorAsync));
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            return BuildAsync(
                (p, _) => seedGeneratorAsync(p),
                seedGeneratorParameter,
                (p, b, _) => preBuildActionAsync(p, b),
                cancellationToken);
        }


        /// <summary>
        /// Applies an accumulator function over a sequence, using the provided seed as the initial accumulator value
        /// and passing build state to each iteration.
        /// </summary>
        /// <typeparam name="TSource">The type of the elements of <paramref name="source"/>.</typeparam>
        /// <typeparam name="TAccumulate">The type of the accumulator value.</typeparam>
        /// <param name="source">The sequence to aggregate over.</param>
        /// <param name="seed">The initial accumulator value.</param>
        /// <param name="buildInvariant">The build state to pass to each iteration of the accumulator function.</param>
        /// <param name="funcAsync">
        /// An asynchronous accumulator function to be invoked on each element, receiving the current accumulator value,
        /// the current element, and the build state.
        /// </param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TAccumulate}"/> containing the final accumulator value.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="source"/> or <paramref name="funcAsync"/> is null.
        /// </exception>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        /// <remarks>
        /// This is a stateful version of the standard LINQ Aggregate method, allowing build state
        /// to be passed to each iteration. Useful for complex transformations that need access
        /// to builder context.
        /// </remarks>
        protected static async ValueTask<TAccumulate> AggregateAsync<TSource, TAccumulate>(
            IEnumerable<TSource> source,
            TAccumulate seed,
            TState buildInvariant,
            Func<TAccumulate, TSource, TState, CancellationToken, ValueTask<TAccumulate>> funcAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));
            ArgumentNullException.ThrowIfNull(funcAsync, nameof(funcAsync));

            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = await funcAsync(result, element, buildInvariant, cancellationToken);
            }

            return result;
        }


        /// <summary>
        /// Applies an accumulator function over a sequence, using the provided seed as the initial accumulator value.
        /// This is a convenience overload for simple aggregations that don't need build state.
        /// </summary>
        /// <typeparam name="TSource">The type of the elements of <paramref name="source"/>.</typeparam>
        /// <typeparam name="TAccumulate">The type of the accumulator value.</typeparam>
        /// <param name="source">The sequence to aggregate over.</param>
        /// <param name="seed">The initial accumulator value.</param>
        /// <param name="funcAsync">An asynchronous accumulator function to be invoked on each element.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A <see cref="ValueTask{TAccumulate}"/> containing the final accumulator value.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="source"/> or <paramref name="funcAsync"/> is null.
        /// </exception>
        /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
        /// <remarks>
        /// This is a standard aggregation method provided for convenience when build state is not needed.
        /// </remarks>
        protected static async ValueTask<TAccumulate> AggregateAsync<TSource, TAccumulate>(
            IEnumerable<TSource> source,
            TAccumulate seed,
            Func<TAccumulate, TSource, CancellationToken, ValueTask<TAccumulate>> funcAsync,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));
            ArgumentNullException.ThrowIfNull(funcAsync, nameof(funcAsync));

            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                cancellationToken.ThrowIfCancellationRequested();
                result = await funcAsync(result, element, cancellationToken);
            }

            return result;
        }
    }
}
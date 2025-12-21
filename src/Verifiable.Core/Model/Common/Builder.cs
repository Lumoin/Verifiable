using System;
using System.Collections.Generic;
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
    /// This builder operates using a fold/aggregate pattern, where transformation functions are applied sequentially
    /// to an initial state (seed value) of type <typeparamref name="TResult"/>. Each transformation receives the
    /// accumulated result from the previous step and produces a new accumulated result, implementing the classic
    /// fold operation: <c>fold(f, seed, [x1, x2, ..., xn]) = f(...f(f(seed, x1), x2)..., xn)</c>
    /// </para>
    /// <para>
    /// The repeated application of transformations allows for incremental construction of complex objects
    /// while maintaining immutability principles and enabling method chaining. Each transformation function receives:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The current accumulated state of the object being built.</description></item>
    /// <item><description>A reference to the builder instance for additional context.</description></item>
    /// <item><description>Optional state information that persists across all transformation steps.</description></item>
    /// </list>
    /// <para>
    /// The builder supports two initialization modes for the fold operation:
    /// </para>
    /// <list type="number">
    /// <item><description>Starting from a default-constructed instance of <typeparamref name="TResult"/>.</description></item>
    /// <item><description>Starting from a pre-configured seed instance.</description></item>
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
    /// var builder = new CustomBuilder()
    ///     .With(async (obj, builder, state) => {
    ///         obj.Property1 = "value1";
    ///         return obj;
    ///     })
    ///     .With(async (obj, builder, state) => {
    ///         obj.Property2 = await FetchValueAsync(state?.Id);
    ///         return obj;
    ///     });
    ///
    /// var result = await builder.BuildAsync(inputParam, async (param, b) => new MyState { Id = param.Value });
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
        /// Each action receives the current object state, the builder instance, and optional state information.
        /// </remarks>
        protected List<Func<TResult, TBuilder, TState?, ValueTask<TResult>>> WithActions { get; private set; } = [];


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
        /// The function receives the current object, the builder instance, and optional state information.
        /// It must return a <see cref="ValueTask{TResult}"/> containing the transformed object
        /// (which may be the same instance or a new one).
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
        /// </remarks>
        /// <example>
        /// <code>
        /// // Asynchronous transformation with signing.
        /// builder.With(async (credential, builder, state) => {
        ///     var proof = await CreateProofAsync(credential, state.PrivateKey);
        ///     credential.AddProof(proof);
        ///     return credential;
        /// });
        ///
        /// // Synchronous transformation.
        /// builder.With((didDoc, builder, state) => {
        ///     didDoc.Id = new KeyDidMethod($"did:key:{state.EncodedKey}");
        ///     return ValueTask.FromResult(didDoc);
        /// });
        /// </code>
        /// </example>
        public TBuilder With(Func<TResult, TBuilder, TState?, ValueTask<TResult>> actionAsync)
        {
            ArgumentNullException.ThrowIfNull(actionAsync, nameof(actionAsync));

            WithActions.Add(actionAsync);
            return (TBuilder)this;
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
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="preBuildActionAsync"/> is null.</exception>
        /// <remarks>
        /// This method implements a left-fold operation: it creates a new instance of <typeparamref name="TResult"/>
        /// as the initial seed, then applies each registered transformation function in sequence. Each transformation
        /// receives the accumulated result from the previous step, implementing the mathematical fold operation
        /// <c>fold(f, seed, [t1, t2, ..., tn]) = tn(...t2(t1(seed))...)</c> where ti are the transformation functions.
        /// </remarks>
        /// <example>
        /// <code>
        /// var didDocument = await builder.BuildAsync(
        ///     (publicKey, cryptoSuite),
        ///     async (param, builder) => new BuildState
        ///     {
        ///         EncodedKey = EncodeKey(param.publicKey),
        ///         PublicKey = param.publicKey,
        ///         Suite = param.cryptoSuite
        ///     }
        /// );
        /// </code>
        /// </example>
        public virtual async ValueTask<TResult> BuildAsync<TParam>(TParam param, Func<TParam, TBuilder, ValueTask<TState>> preBuildActionAsync)
        {
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            TState buildInvariant = await preBuildActionAsync(param, (TBuilder)this);
            TResult result = new();

            foreach(Func<TResult, TBuilder, TState?, ValueTask<TResult>> actionAsync in WithActions)
            {
                result = await actionAsync(result, (TBuilder)this, buildInvariant);
            }

            return result;
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
        /// <returns>A <see cref="ValueTask{TResult}"/> containing the fully constructed object.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="seedGeneratorAsync"/> or <paramref name="preBuildActionAsync"/> is null.
        /// </exception>
        /// <remarks>
        /// This method is useful when you need to start with a pre-configured instance rather than
        /// a default-constructed one. The seed instance is created first, then all registered
        /// transformation actions are applied to it in order.
        /// </remarks>
        /// <example>
        /// <code>
        /// var didDocument = await builder.BuildAsync(
        ///     async param => {
        ///         var doc = new DidDocument();
        ///         doc.AddDefaultContext();
        ///         return doc;
        ///     },
        ///     (publicKey, cryptoSuite),
        ///     async (param, builder) => new BuildState { /* ... */ }
        /// );
        /// </code>
        /// </example>
        public virtual async ValueTask<TResult> BuildAsync<TSeedParam>(
            Func<TSeedParam, ValueTask<TResult>> seedGeneratorAsync,
            TSeedParam seedGeneratorParameter,
            Func<TSeedParam, TBuilder, ValueTask<TState>> preBuildActionAsync)
        {
            ArgumentNullException.ThrowIfNull(seedGeneratorAsync, nameof(seedGeneratorAsync));
            ArgumentNullException.ThrowIfNull(preBuildActionAsync, nameof(preBuildActionAsync));

            TState buildInvariant = await preBuildActionAsync(seedGeneratorParameter, (TBuilder)this);
            TResult seed = await seedGeneratorAsync(seedGeneratorParameter);

            foreach(Func<TResult, TBuilder, TState?, ValueTask<TResult>> actionAsync in WithActions)
            {
                seed = await actionAsync(seed, (TBuilder)this, buildInvariant);
            }

            return seed;
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
        /// <returns>A <see cref="ValueTask{TAccumulate}"/> containing the final accumulator value.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="source"/> or <paramref name="funcAsync"/> is null.
        /// </exception>
        /// <remarks>
        /// This is a stateful version of the standard LINQ Aggregate method, allowing build state
        /// to be passed to each iteration. Useful for complex transformations that need access
        /// to builder context.
        /// </remarks>
        protected static async ValueTask<TAccumulate> AggregateAsync<TSource, TAccumulate>(
            IEnumerable<TSource> source,
            TAccumulate seed,
            TState buildInvariant,
            Func<TAccumulate, TSource, TState, ValueTask<TAccumulate>> funcAsync)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));
            ArgumentNullException.ThrowIfNull(funcAsync, nameof(funcAsync));

            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                result = await funcAsync(result, element, buildInvariant);
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
        /// <returns>A <see cref="ValueTask{TAccumulate}"/> containing the final accumulator value.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="source"/> or <paramref name="funcAsync"/> is null.
        /// </exception>
        /// <remarks>
        /// This is a standard aggregation method provided for convenience when build state is not needed.
        /// </remarks>
        protected static async ValueTask<TAccumulate> AggregateAsync<TSource, TAccumulate>(
            IEnumerable<TSource> source,
            TAccumulate seed,
            Func<TAccumulate, TSource, ValueTask<TAccumulate>> funcAsync)
        {
            ArgumentNullException.ThrowIfNull(source, nameof(source));
            ArgumentNullException.ThrowIfNull(funcAsync, nameof(funcAsync));

            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                result = await funcAsync(result, element);
            }

            return result;
        }
    }
}
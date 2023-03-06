using System;
using System.Collections.Generic;


namespace Verifiable.Core.Builders
{
    public interface IBuilder { }

    /// <summary>
    /// <para>Serves as a unified, general-purpose builder for constructing various types in the Verifiable library.</para>
    /// 
    /// <para>This builder operates by applying a series of functions to a seed value of type <typeparamref name="TResult"/>, in the order they were added.
    /// It also allows for the passing of state between build actions with <typeparamref name="TState"/>, and exposes the builder itself to the functions.</para>
    /// </summary>
    /// <typeparam name="TResult">The type of the object being built.</typeparam>
    /// <typeparam name="TState">The type of the state object passed between build actions.</typeparam>
    /// <typeparam name="TBuilder">The specific type of the builder.</typeparam>
    /// <remarks>
    /// Verifiable library provides preconfigured builders for various objects. These builders are designed to be extensible.
    /// </remarks>
    public class Builder<TResult, TState, TBuilder>: IBuilder where TBuilder: Builder<TResult, TState, TBuilder> where TResult: new()
    {
        /// <summary>
        /// The list of actions, applied in order [0..n).
        /// </summary>
        protected List<Func<TResult, TBuilder, TState?, TResult>> WithActions { get; private set; } = new();

        public Builder() { }

        public TBuilder With(Func<TResult, TBuilder, TState?, TResult> action)
        {
            WithActions.Add(action);
            return (TBuilder)this;
        }


        public virtual TResult Build<TParam>(TParam param, Func<TParam, TBuilder, TState> preBuildAction)
        {
            TState buildInvariant = preBuildAction(param, (TBuilder)this);
            TResult result = new();
            foreach(Func<TResult, TBuilder, TState?, TResult> action in WithActions)
            {
                result = action(result, (TBuilder)this, buildInvariant);
            }

            return result;
        }


        public virtual TResult Build<TSeedParam>(Func<TSeedParam, TResult> seedGenerator, TSeedParam seedGeneratorParameter, Func<TSeedParam, TBuilder, TState> preBuildAction)
        {
            ArgumentNullException.ThrowIfNull(nameof(seedGenerator));

            TState buildInvariant = preBuildAction(seedGeneratorParameter, (TBuilder)this);

            TResult seed = seedGenerator(seedGeneratorParameter);
            foreach(Func<TResult, TBuilder, TState?, TResult> action in WithActions)
            {
                seed = action(seed, (TBuilder)this, buildInvariant);
            }

            return seed;
        }


        protected static TAccumulate Aggregate<TSource, TAccumulate>(IEnumerable<TSource> source, TAccumulate seed, TState buildInvariant, Func<TAccumulate, TSource, TState, TAccumulate> func)
        {
            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                result = func(result, element, buildInvariant);
            }

            return result;
        }


        protected static TAccumulate Aggregate<TSource, TAccumulate>(IEnumerable<TSource> source, TAccumulate seed, Func<TAccumulate, TSource, TAccumulate> func)
        {
            TAccumulate result = seed;
            foreach(TSource element in source)
            {
                result = func(result, element);
            }

            return result;
        }
    }
}

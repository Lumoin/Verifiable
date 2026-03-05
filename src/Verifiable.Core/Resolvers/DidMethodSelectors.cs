using System;
using System.Collections.Generic;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Factory methods for creating <see cref="SelectMethodResolverDelegate"/> and
/// <see cref="SelectMethodDereferencerDelegate"/> implementations backed by a
/// dictionary of (DID method prefix, delegate) registrations.
/// </summary>
/// <remarks>
/// <para>
/// Registrations use the full DID method prefix constant as the key — for example
/// <c>WellKnownDidMethodPrefixes.WebDidMethodPrefix</c>. The factory trims the leading
/// <c>"did:"</c> internally so that dispatch uses only the method name segment.
/// </para>
/// <para>
/// All delegate arguments must be static method groups. Closures capture context by
/// reference, which conflicts with the library requirement that all state flows through
/// parameters.
/// </para>
/// </remarks>
public static class DidMethodSelectors
{
    private const string DidSchemePrefix = "did:";

    /// <summary>
    /// Creates a resolver selector from one or more (prefix, delegate) registrations.
    /// </summary>
    /// <param name="resolvers">
    /// Pairs of full DID method prefix (e.g., <c>"did:web"</c>) and the corresponding
    /// <see cref="DidMethodResolverDelegate"/>, passed as static method groups.
    /// </param>
    /// <returns>A <see cref="SelectMethodResolverDelegate"/> that dispatches by method name segment.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="resolvers"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when any prefix does not start with <c>"did:"</c> or any delegate is null.
    /// </exception>
    public static SelectMethodResolverDelegate FromResolvers(
        params (string Prefix, DidMethodResolverDelegate Resolver)[] resolvers)
    {
        ArgumentNullException.ThrowIfNull(resolvers);

        var lookup = new Dictionary<string, DidMethodResolverDelegate>(resolvers.Length, StringComparer.Ordinal);
        foreach(var (prefix, resolver) in resolvers)
        {
            ValidatePrefix(prefix);

            if(resolver is null)
            {
                throw new ArgumentException(
                    $"The resolver delegate for prefix '{prefix}' is null.",
                    nameof(resolvers));
            }

            lookup[prefix[DidSchemePrefix.Length..]] = resolver;
        }

        return methodName => lookup.TryGetValue(methodName, out var found) ? found : null;
    }

    /// <summary>
    /// Creates a dereferencer selector from one or more (prefix, delegate) registrations.
    /// </summary>
    /// <param name="dereferencers">
    /// Pairs of full DID method prefix (e.g., <c>"did:web"</c>) and the corresponding
    /// <see cref="DidMethodDereferencerDelegate"/>, passed as static method groups.
    /// </param>
    /// <returns>A <see cref="SelectMethodDereferencerDelegate"/> that dispatches by method name segment.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="dereferencers"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when any prefix does not start with <c>"did:"</c> or any delegate is null.
    /// </exception>
    public static SelectMethodDereferencerDelegate FromDereferencers(
        params (string Prefix, DidMethodDereferencerDelegate Dereferencer)[] dereferencers)
    {
        ArgumentNullException.ThrowIfNull(dereferencers);

        var lookup = new Dictionary<string, DidMethodDereferencerDelegate>(dereferencers.Length, StringComparer.Ordinal);
        foreach(var (prefix, dereferencer) in dereferencers)
        {
            ValidatePrefix(prefix);

            if(dereferencer is null)
            {
                throw new ArgumentException(
                    $"The dereferencer delegate for prefix '{prefix}' is null.",
                    nameof(dereferencers));
            }

            lookup[prefix[DidSchemePrefix.Length..]] = dereferencer;
        }

        return methodName => lookup.TryGetValue(methodName, out var found) ? found : null;
    }

    /// <summary>
    /// A dereferencer selector that always returns <see langword="null"/>, meaning all
    /// dereferencing falls back to resolution then fragment matching.
    /// </summary>
    public static SelectMethodDereferencerDelegate None { get; } = _ => null;

    private static void ValidatePrefix(string prefix)
    {
        if(!prefix.StartsWith(DidSchemePrefix, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The prefix '{prefix}' is not a valid DID method prefix. It must start with '{DidSchemePrefix}'.");
        }
    }
}
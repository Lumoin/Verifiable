using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.OAuth.StatusList;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The in-memory <see cref="ResolveVerifiedStatusListTokenDelegate"/> stub every verifier-seat test
/// wires when it stands in for "whatever a deployment fetched and verified"
/// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
/// Status List, Section 8.3</see> steps 2–3): hand back a caller-supplied <see cref="StatusListType"/>
/// as an already-resolved, already-verified <see cref="StatusListToken"/>, with no HTTP fetch and no
/// signature check. The wire-form JWT/CWT Status List Token fixtures
/// (<see cref="StatusListTokenJwtFixtures"/>, <see cref="StatusListTokenCwtFixtures"/>) serve the
/// distinct real-wire-serialization scope; this fixture is the plain resolver stub every in-process
/// gate test shares instead.
/// </summary>
internal static class StatusListFixtures
{
    /// <summary>
    /// The <see cref="StatusListResolutionContext"/> a gate call carries, built from the reference alone
    /// or with the Referenced Token's verified issuer facts alongside it.
    /// </summary>
    /// <param name="reference">The credential's <c>status_list</c> reference.</param>
    /// <param name="referencedTokenIssuer">The Referenced Token's verified <c>iss</c>, when the test supplies one.</param>
    /// <param name="referencedTokenIssuerKey">The key the Referenced Token's issuer signature verified under, when the test supplies one.</param>
    /// <returns>The context.</returns>
    public static StatusListResolutionContext ContextFor(
        StatusListReference reference,
        string? referencedTokenIssuer = null,
        PublicKeyMemory? referencedTokenIssuerKey = null) =>
        new()
        {
            Reference = reference,
            ReferencedTokenIssuer = referencedTokenIssuer,
            ReferencedTokenIssuerKey = referencedTokenIssuerKey
        };


    /// <summary>
    /// <see cref="ContextFor(StatusListReference, string?, PublicKeyMemory?)"/> over an index and URI pair,
    /// the shape a test that only exercises the reference half writes.
    /// </summary>
    /// <param name="index">The zero-based index within the Status List.</param>
    /// <param name="uri">The Status List Token's URI.</param>
    /// <returns>The context.</returns>
    public static StatusListResolutionContext ContextFor(int index, string uri) =>
        ContextFor(new StatusListReference(index, uri));


    /// <summary>
    /// A resolver that answers every request with <paramref name="statusList"/> as the verified Status
    /// List Token for <paramref name="subject"/>, regardless of the reference the gate resolves for.
    /// </summary>
    /// <param name="subject">The token's subject claim, compared against the credential's reference URI by TSL §8.3 step 4.a.</param>
    /// <param name="statusList">The list whose entry the gate reads at the credential's index.</param>
    /// <param name="timeProvider">The clock the token's <c>iat</c> is read from.</param>
    /// <returns>The resolver a host is built with.</returns>
    public static ResolveVerifiedStatusListTokenDelegate ResolverFor(
        string subject, StatusListType statusList, TimeProvider timeProvider) =>
        (context, cancellationToken) =>
        {
            DateTimeOffset resolvedAt = timeProvider.GetUtcNow();

            //statusList is shared across every call this resolver answers, so the resolution does not
            //own it — the test's own `using` disposes it once.
            return ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
            {
                Token = new StatusListToken(subject, resolvedAt, statusList),
                ResolvedAt = resolvedAt,
                IsTokenOwned = false
            });
        };


    /// <summary>
    /// A resolver that answers every request with <paramref name="token"/>, already resolved at
    /// <paramref name="resolvedAt"/> — the shape a test driving <see cref="CredentialStatusGate.CheckAsync"/>
    /// directly against a hand-built token needs, without a subject/list/clock triple.
    /// </summary>
    /// <param name="token">The already-verified Status List Token to hand back.</param>
    /// <param name="resolvedAt">The instant this resolution reports itself as made at.</param>
    /// <returns>The resolver a test is built with.</returns>
    public static ResolveVerifiedStatusListTokenDelegate ResolverFor(StatusListToken token, DateTimeOffset resolvedAt) =>
        (context, cancellationToken) => ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
        {
            Token = token,
            ResolvedAt = resolvedAt,
            IsTokenOwned = false
        });


    /// <summary>
    /// <see cref="ResolverFor(string, StatusListType, TimeProvider)"/>, additionally counting every
    /// invocation — the shape a test proving the status procedure was (or was not) reached needs, since
    /// TSL §8.3's step 2 ("Resolve the Status List Token from the provided URI") runs only when a status
    /// claim exists to resolve for.
    /// </summary>
    /// <param name="subject">The token's subject claim, compared against the credential's reference URI by TSL §8.3 step 4.a.</param>
    /// <param name="statusList">The list whose entry the gate reads at the credential's index.</param>
    /// <param name="timeProvider">The clock the token's <c>iat</c> and resolution instant are read from.</param>
    /// <returns>The resolver, plus a delegate reading its current invocation count.</returns>
    public static (ResolveVerifiedStatusListTokenDelegate Resolver, Func<int> InvocationCount) CountingResolverFor(
        string subject, StatusListType statusList, TimeProvider timeProvider)
    {
        int invocations = 0;

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
        {
            invocations++;

            DateTimeOffset resolvedAt = timeProvider.GetUtcNow();

            return ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
            {
                Token = new StatusListToken(subject, resolvedAt, statusList),
                ResolvedAt = resolvedAt,
                IsTokenOwned = false
            });
        };

        return (resolver, () => invocations);
    }


    /// <summary>
    /// Wraps <paramref name="inner"/> so every <see cref="StatusListResolutionContext"/> it is handed is
    /// recorded before it answers — the shape a test proving what the verifier seat tells the resolution
    /// about the Referenced Token needs, since the context is the only channel those facts travel on.
    /// </summary>
    /// <param name="inner">The resolver whose answers are passed through unchanged.</param>
    /// <returns>The recording resolver and the live list of contexts it has been handed, in call order.</returns>
    public static (ResolveVerifiedStatusListTokenDelegate Resolve, IReadOnlyList<StatusListResolutionContext> Contexts)
        RecordingResolverFor(ResolveVerifiedStatusListTokenDelegate inner)
    {
        List<StatusListResolutionContext> contexts = [];

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
        {
            contexts.Add(context);

            return inner(context, cancellationToken);
        };

        return (resolver, contexts);
    }


    /// <summary>
    /// Wraps <paramref name="inner"/> so every <see cref="StatusListKeyResolutionContext"/> it is handed is
    /// recorded before it answers — the key-resolution half of
    /// <see cref="RecordingResolverFor(ResolveVerifiedStatusListTokenDelegate)"/>, and what a test asserting
    /// which facts reach the Status List Token's key decision reads.
    /// </summary>
    /// <param name="inner">The key resolution whose answers are passed through unchanged.</param>
    /// <returns>The recording key resolution and the live list of contexts it has been handed, in call order.</returns>
    public static (ResolveStatusListIssuerKeyDelegate Resolve, IReadOnlyList<StatusListKeyResolutionContext> Contexts)
        RecordingKeyResolverFor(ResolveStatusListIssuerKeyDelegate inner)
    {
        List<StatusListKeyResolutionContext> contexts = [];

        ResolveStatusListIssuerKeyDelegate resolver = (context, cancellationToken) =>
        {
            contexts.Add(context);

            return inner(context, cancellationToken);
        };

        return (resolver, contexts);
    }


    /// <summary>
    /// A key resolution's answer that the verification releases: a copy of <paramref name="source"/> rented
    /// from <paramref name="pool"/>, so the pool's own accounting is the evidence that the release happened.
    /// This is the answer a resolver that mints a key per call gives.
    /// </summary>
    /// <param name="source">The key whose bytes and tag the copy carries.</param>
    /// <param name="pool">The pool the copy's buffer is rented from.</param>
    /// <returns>The owned resolution.</returns>
    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "The copy's ownership transfers to the returned ResolvedStatusListIssuerKey, whose IsKeyOwned is true, so its own Dispose releases the copy — the release this factory exists to make observable on the supplied pool.")]
    public static ResolvedStatusListIssuerKey OwnedKeyOver(PublicKeyMemory source, BaseMemoryPool pool) =>
        ResolvedStatusListIssuerKey.Owned(CopyOver(source, pool));


    /// <summary>
    /// A key resolution's answer that the verification only reads: a copy of <paramref name="source"/> rented
    /// from <paramref name="pool"/>, which the caller — standing in for the key set a real resolver keeps
    /// alive itself — owns and must dispose. The pool's outstanding rentals are what prove the verification
    /// left it alone.
    /// </summary>
    /// <param name="source">The key whose bytes and tag the copy carries.</param>
    /// <param name="pool">The pool the copy's buffer is rented from.</param>
    /// <returns>The borrowed resolution.</returns>
    [SuppressMessage(
        "Reliability",
        "CA2000:Dispose objects before losing scope",
        Justification = "The copy's ownership transfers to the caller, which stands in for the key set a real resolver keeps alive itself; a borrowed resolution deliberately never releases it, so the caller disposes the returned Key once its assertions are made.")]
    public static ResolvedStatusListIssuerKey BorrowedKeyOver(PublicKeyMemory source, BaseMemoryPool pool) =>
        ResolvedStatusListIssuerKey.Borrowed(CopyOver(source, pool));


    /// <summary>
    /// Copies a public key into a buffer rented from <paramref name="pool"/>, so the copy is an independently
    /// disposable carrier whose release that pool alone accounts for.
    /// </summary>
    /// <param name="source">The key to copy.</param>
    /// <param name="pool">The pool the copy's buffer is rented from.</param>
    /// <returns>The copy, carrying <paramref name="source"/>'s own tag.</returns>
    private static PublicKeyMemory CopyOver(PublicKeyMemory source, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> bytes = source.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, source.Tag);
    }
}

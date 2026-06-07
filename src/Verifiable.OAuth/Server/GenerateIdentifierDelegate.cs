using Verifiable.Core;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Generates an identifier for a stated purpose. Threaded onto
/// <see cref="AuthorizationServerIntegration.GenerateIdentifierAsync"/>
/// so deployments control identifier generation centrally — for audit
/// emission, event-sourced replay, deployment-specific identifier
/// formats (ULID, KSUID, …), or any other dispatch the deployment
/// requires.
/// </summary>
/// <remarks>
/// <para>
/// The library default
/// (<see cref="Pipeline.DefaultIdentifierGenerator.GenerateAsync"/>)
/// returns <c>Guid.CreateVersion7(timeProvider.GetUtcNow()).ToString("N")</c>
/// regardless of purpose — a 32-character hex string with the v7 GUID's
/// 48-bit Unix-milliseconds prefix sorting lexicographically by
/// creation time. Replacing this delegate is how deployments thread
/// audit-log emission, replay-deterministic identifier injection, or
/// purpose-specific format selection.
/// </para>
/// <para>
/// Distinct from the entropy-generation surface in
/// <see cref="Verifiable.Cryptography"/> (<c>FillEntropyDelegate</c>) —
/// cryptographic nonces and CSRF state values route through that
/// delegate, not this one. <see cref="IdentifierPurpose"/> values
/// identify wire and correlation identifiers; nonce / state generation
/// is a separate semantic class with its own delegate.
/// </para>
/// </remarks>
/// <param name="purpose">The purpose the identifier is generated for.</param>
/// <param name="context">The per-request context. May be <see langword="null"/> for callers that don't have a request context handy (e.g. wallet-side flow construction); the default implementation tolerates null.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The generated identifier as a string. Format is purpose- and deployment-dependent.</returns>
public delegate ValueTask<string> GenerateIdentifierDelegate(
    IdentifierPurpose purpose,
    ExchangeContext? context,
    CancellationToken cancellationToken);

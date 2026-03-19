using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Selects which <see cref="KeyId"/> the authorization server should sign with
/// at a specific call site, given the tenant's registration, the protocol
/// <see cref="KeyUsageContext"/> the call represents, and the per-request
/// context bag.
/// </summary>
/// <param name="registration">
/// The tenant's <see cref="ClientRegistration"/>, carrying the structured
/// <see cref="ClientRegistration.SigningKeys"/> indexed by usage context.
/// </param>
/// <param name="usage">
/// The protocol role of the signing operation — token issuance, JAR signing,
/// credential issuance, etc. Identifies which of the registration's signing
/// key sets is being asked about.
/// </param>
/// <param name="context">
/// The full per-request context bag populated by the ASP.NET skin or calling
/// surface. Carries caller identity, tenant metadata, region, billing tier,
/// or any other signal the application uses to make signing decisions.
/// </param>
/// <param name="cancellationToken">Cancellation token for the selection operation.</param>
/// <returns>
/// The <see cref="KeyId"/> to sign with. Implementations are expected to
/// return a key present in the registration's
/// <see cref="SigningKeySet.Current"/> list for the given
/// <paramref name="usage"/>; returning an identifier not in that list
/// indicates misconfiguration.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Default behaviour</strong>
/// </para>
/// <para>
/// When <see cref="AuthorizationServerOptions.SelectSigningKey"/> is
/// <see langword="null"/>, the library uses the first entry in
/// <c>registration.SigningKeys[usage].Current</c>. This covers the common
/// single-key-per-usage case without requiring applications to write a delegate.
/// </para>
/// <para>
/// <strong>Per-caller binding</strong>
/// </para>
/// <para>
/// Applications that bind signing keys to individual callers — for security,
/// auditability, or isolation — implement this delegate to read the caller's
/// identity from <paramref name="context"/> (populated upstream by the ASP.NET
/// skin from JWT claims, headers, mTLS certificate, etc.) and return the
/// caller-specific <see cref="KeyId"/>.
/// </para>
/// <para>
/// <strong>Algorithm-specific selection</strong>
/// </para>
/// <para>
/// For algorithm-agile tenants with multiple entries in <c>Current</c> covering
/// different algorithms, implementations select the matching algorithm based on
/// what the protocol call demands (for example, an <c>alg</c> parameter echoed
/// from the request, or a tenant default). The selection picks from
/// <c>Current</c>; the library retrieves the selected key's material via
/// <see cref="AuthorizationServerOptions.SigningKeyResolver"/>.
/// </para>
/// </remarks>
public delegate ValueTask<KeyId> SelectSigningKeyDelegate(
    ClientRegistration registration,
    KeyUsageContext usage,
    IReadOnlyDictionary<string, object> context,
    CancellationToken cancellationToken);

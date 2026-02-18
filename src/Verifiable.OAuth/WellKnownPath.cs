using System;
using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// Describes how a well-known URI is computed from a base identifier.
/// </summary>
/// <remarks>
/// <para>
/// Different specifications use different strategies for constructing well-known URIs:
/// </para>
/// <list type="bullet">
///   <item><description>Suffix-based: append a fixed path after <c>/.well-known/</c> (OAuth AS metadata, OpenID Configuration).</description></item>
///   <item><description>Identifier-derived: compute a full URL from a structured identifier (DID Web, WebFinger).</description></item>
/// </list>
/// <para>
/// This type captures the computation rule as a pure function. It does not perform
/// any network operations. Consumers call <see cref="ComputeUri"/> to get the URL
/// and then fetch it using their own HTTP infrastructure.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownPath[{Name}]")]
public sealed class WellKnownPath
{
    /// <summary>
    /// Gets the human-readable name identifying this well-known path.
    /// </summary>
    /// <remarks>
    /// Typically the IANA-registered well-known URI suffix, such as
    /// <c>oauth-authorization-server</c> or <c>openid-configuration</c>.
    /// </remarks>
    public string Name { get; }

    /// <summary>
    /// Gets the specification or RFC that defines this well-known path.
    /// </summary>
    public string SpecificationReference { get; }

    /// <summary>
    /// Gets the function that computes the well-known URI from a base identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The input is the base identifier, which varies by methodology:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>For OAuth AS metadata: the issuer URL (e.g., <c>https://example.com</c>).</description></item>
    ///   <item><description>For OpenID Federation: the entity identifier URL.</description></item>
    ///   <item><description>For DID Web: the DID string (e.g., <c>did:web:example.com:users:alice</c>).</description></item>
    /// </list>
    /// <para>
    /// The output is the fully resolved HTTPS URL to fetch the metadata document.
    /// </para>
    /// </remarks>
    public Func<string, Uri> ComputeUri { get; }

    /// <summary>
    /// Creates a new well-known path definition.
    /// </summary>
    /// <param name="name">The name identifying this well-known path.</param>
    /// <param name="specificationReference">The specification that defines it.</param>
    /// <param name="computeUri">The function that computes the full URI from a base identifier.</param>
    public WellKnownPath(string name, string specificationReference, Func<string, Uri> computeUri)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(specificationReference);
        ArgumentNullException.ThrowIfNull(computeUri);

        Name = name;
        SpecificationReference = specificationReference;
        ComputeUri = computeUri;
    }
}
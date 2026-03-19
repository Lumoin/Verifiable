using System;
using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Carries the encrypted direct_post.jwt received from the authorization response sender.
/// Transitions from <see cref="JarServed"/> to <see cref="ResponseReceived"/>.
/// This input arrives at the second DB persistence point.
/// </summary>
/// <remarks>
/// HAIP 1.0 requires the authorization response to be encrypted as a JWE using ECDH-ES
/// key agreement with the verifier's ephemeral P-256 public key, as defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>.
/// </remarks>
/// <param name="EncryptedResponseJwt">The raw JWE compact serialization from the direct_post.jwt request body.</param>
/// <param name="ReceivedAt">The UTC instant the POST was received.</param>
[DebuggerDisplay("ResponsePosted ReceivedAt={ReceivedAt}")]
public sealed record ResponsePosted(
    string EncryptedResponseJwt,
    DateTimeOffset ReceivedAt): OAuthFlowInput;

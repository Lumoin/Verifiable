using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWS in compact form: three Base64Url-encoded
/// segments separated by dots, with a parsed header containing <c>alg</c>
/// but not <c>enc</c>.
/// </summary>
/// <remarks>
/// <para>
/// Carries the parsed-but-unverified <see cref="UnverifiedJwsMessage"/>
/// produced by <see cref="JwsParsing.ParseCompact"/>. The classifier has
/// confirmed the structural shape; the cryptographic signature has not been
/// verified.
/// </para>
/// <para>
/// <strong>Trust state.</strong>
/// Reading <see cref="UnverifiedJwsSignature.ClaimedAlgorithm"/> or any
/// header parameter from <see cref="Message"/> before signature verification
/// is reading attacker-controlled data. The verifier is responsible for
/// resolving the verification key from its own state (key registry,
/// federation chain, JWKS endpoint) and rejecting tokens whose claimed
/// algorithm does not match the resolved key.
/// </para>
/// <para>
/// <strong>Ownership.</strong>
/// <see cref="Message"/> is <see cref="System.IDisposable"/>. The classifier
/// transfers ownership when it produces this shape; the consumer is
/// responsible for disposing <see cref="Message"/> when done. In dispatch
/// pipelines the matcher and handler coordinate disposal across the
/// matcher-to-handler boundary.
/// </para>
/// </remarks>
/// <param name="Message">
/// The parsed-but-unverified JWS message, carrying the protected header,
/// signature bytes, and payload.
/// </param>
[DebuggerDisplay("JwsShape Alg={Message.Signatures[0].ClaimedAlgorithm,nq}")]
public sealed record JwsShape(UnverifiedJwsMessage Message): JoseTokenShape;

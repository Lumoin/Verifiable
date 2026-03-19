using System.Diagnostics;

namespace Verifiable.JCose;

/// <summary>
/// A token classified as a JWE in compact form: five Base64Url-encoded
/// segments separated by dots, with a parsed protected header containing
/// both <c>alg</c> and <c>enc</c>.
/// </summary>
/// <remarks>
/// <para>
/// Carries the typed <see cref="UnverifiedCompactJwe"/> wrapper, which
/// pairs the original wire string with the parsed-but-unauthenticated
/// header. Consumers that intend to decrypt the JWE call
/// <see cref="JweParsing.ParseCompact"/> with
/// <see cref="UnverifiedCompactJwe.Value"/> and the algorithm and
/// content-encryption identifiers they accept as policy.
/// </para>
/// <para>
/// <strong>Trust state.</strong>
/// <see cref="UnverifiedCompactJwe.Header"/> is parsed but unauthenticated.
/// The header is only authenticated when AEAD decryption succeeds — the
/// encoded header is the AAD, and tag verification binds it. Consumers may
/// inspect the unauthenticated header for fast-fail policy checks (rejecting
/// unsupported algorithms before invoking
/// <see cref="JweParsing.ParseCompact"/>) but must treat any conclusions
/// drawn from it as unverified until decryption succeeds.
/// </para>
/// </remarks>
/// <param name="Token">
/// The typed compact-form JWE wrapper, carrying both the wire string and
/// the parsed header. See <see cref="UnverifiedCompactJwe"/> for the trust-
/// state semantics.
/// </param>
[DebuggerDisplay("JweShape Header={Token.Header.Count}")]
public sealed record JweShape(UnverifiedCompactJwe Token): JoseTokenShape;

using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Per-call inputs to
/// <see cref="Oid4VpWalletClient{TCredential}.PresentJarAsync"/>.
/// </summary>
/// <typeparam name="TCredential">
/// The application-supplied credential type. For SD-JWT VC use
/// <see cref="SdJwtVcCredential"/> or a derived type.
/// </typeparam>
[DebuggerDisplay("PresentJarOptions")]
public sealed record PresentJarOptions<TCredential>
{
    /// <summary>The compact JAR received at the <c>request_uri</c>.</summary>
    public required string CompactJar { get; init; }

    /// <summary>
    /// The <c>request_uri</c> the JAR was fetched from. Carried through the
    /// Wallet PDA's initial state for traceability and same-device redirect
    /// matching.
    /// </summary>
    public required Uri RequestUri { get; init; }

    /// <summary>
    /// The Verifier <c>client_id</c> the wallet expects to see in the JAR. Used
    /// for mix-up attack defence — the Wallet PDA rejects JARs whose
    /// <c>client_id</c> claim does not match. The wallet caller obtains this
    /// from the QR code or deep link payload alongside the <c>request_uri</c>.
    /// </summary>
    public required string ExpectedVerifierClientId { get; init; }

    /// <summary>
    /// The Verifier's JAR-signing public key. Used to verify the JAR signature
    /// before any claim is read.
    /// </summary>
    public required PublicKeyMemory VerifierSigningPublicKey { get; init; }

    /// <summary>
    /// The holder's signing key. Used to sign the KB-JWT bound to the
    /// presentation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>.
    /// The matching public key must appear in the SD-JWT VC's <c>cnf</c> claim.
    /// </summary>
    public required PrivateKeyMemory HolderKey { get; init; }

    /// <summary>
    /// Optional stable identifier for this presentation flow. When
    /// <see langword="null"/>, the wallet client generates a fresh GUID.
    /// </summary>
    public string? FlowId { get; init; }

    /// <summary>
    /// Optional disclosure selection delegate. When <see langword="null"/>, the
    /// wallet client reveals every disclosure the credential carries.
    /// </summary>
    public DisclosureSelectionDelegate<TCredential>? DisclosureSelection { get; init; }
}

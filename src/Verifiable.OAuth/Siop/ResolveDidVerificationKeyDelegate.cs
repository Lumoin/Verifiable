using Verifiable.Cryptography;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Resolves the verification key for a Self-Issued ID Token whose Subject Syntax Type is
/// Decentralized Identifier, per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.1">SIOPv2 §11.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The application provides the implementation based on the DID methods it supports: it
/// MUST obtain the DID Document by resolving <paramref name="did"/> using DID Resolution
/// as defined by the DID Method specification, and — because the
/// <c>verificationMethod</c> property may contain multiple public key sets — it MUST
/// select the public key identified by <paramref name="keyId"/>, the <c>kid</c> from the
/// JOSE header of the signed ID Token. Returning a key from any other source breaks the
/// §11.1 sub-to-key binding.
/// </para>
/// <para>
/// Resolving by <paramref name="did"/> is what discharges the §11.1 requirement that the
/// <c>sub</c> claim value equals the <c>id</c> property of the DID Document — the
/// validator passes the <c>sub</c> claim as <paramref name="did"/>.
/// </para>
/// <para>
/// The caller takes ownership of the returned key and disposes it after signature
/// verification.
/// </para>
/// </remarks>
/// <param name="did">The DID to resolve — the <c>sub</c> claim of the ID Token.</param>
/// <param name="keyId">
/// The <c>kid</c> from the ID Token's JOSE header identifying the verification method,
/// or <see langword="null"/> when the header carries none.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The verification key from the resolved DID Document, or <see langword="null"/> when
/// the DID cannot be resolved, the method is unsupported, or no verification method
/// matches <paramref name="keyId"/>.
/// </returns>
public delegate ValueTask<PublicKeyMemory?> ResolveDidVerificationKeyDelegate(
    string did,
    string? keyId,
    CancellationToken cancellationToken);

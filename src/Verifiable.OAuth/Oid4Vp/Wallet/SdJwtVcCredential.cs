using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// A wallet-held SD-JWT Verifiable Credential in its compact wire form,
/// suitable as input to <see cref="Oid4VpWalletClient{TCredential}.PresentJarAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Carries the compact SD-JWT serialisation as the Wallet stores it after
/// issuance — issuer-signed JWT, all disclosures, no KB-JWT. The KB-JWT is
/// computed per presentation and appended at presentation time, so the stored
/// credential is reusable across presentations to different Verifiers.
/// </para>
/// <para>
/// Applications that want to attach extra wallet-side context (storage IDs,
/// freshness markers, etc.) derive from this record. The wallet client reads
/// only <see cref="CompactSdJwt"/>; subtypes pass through unchanged.
/// </para>
/// </remarks>
/// <param name="CompactSdJwt">
/// The compact SD-JWT serialisation: issuer JWS, all disclosures separated by
/// <c>~</c>, with trailing tilde and no KB-JWT.
/// </param>
[DebuggerDisplay("SdJwtVcCredential")]
public record SdJwtVcCredential(string CompactSdJwt);

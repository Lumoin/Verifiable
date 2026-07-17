using System;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The vendor-burned-in enterprise attestation material a <see cref="CtapAuthenticatorState"/> is
/// seeded with at construction: the presence of this record on the state IS "enterprise attestation
/// capable" (<see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/> derives from it —
/// there is no second stored capability flag).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-feature-descriptions-enterp-attstn">
/// CTAP 2.3, section 7.1: Enterprise Attestation</see>, snapshot line 8251: "The expectation is that
/// enterprises will work directly with their authenticator vendor(s) in order to source their
/// enterprise attestation capable authenticators" — this record models exactly that out-of-band
/// provisioning event, not a runtime CTAP command (no CTAP command anywhere in this feature sets any
/// of these four members; they exist before the authenticator's first command is ever processed).
/// <see cref="AttestationKey"/> is SECRET pooled custody, owned by this record and disposed alongside
/// it, following the <c>CtapCredentialRecord.CredentialKey</c>/<c>LargeBlobKey</c> custody precedent —
/// never exposed as a raw byte array. <see cref="X5c"/> is public certificate material, pooled anyway
/// per this codebase's uniform no-naked-bytes rule, reusing <see cref="PkiCertificateMemory"/> exactly
/// as the RP-side <c>PackedAttestation.VerifyCertifiedAsync</c> consumer already does for its own
/// <c>x5c</c> parameter — the same wire concept, opposite end. <see cref="PreConfiguredRpIds"/> is the
/// snapshot line 8256 "non-updateable... pre-configured RP ID list... 'burned into' the authenticator
/// by the vendor": constructor-fixed like <see cref="CtapAuthenticatorState.Aaguid"/>, with NO
/// replaceable/settable shape — unlike <see cref="CtapAuthenticatorState.MinPinLengthRpIds"/>, no CTAP
/// subcommand anywhere in this feature ever mutates it at runtime.
/// </remarks>
/// <param name="AttestationKey">
/// The seeded enterprise attestation private key, bound with its own signing delegate exactly as
/// <c>CtapCredentialRecord.CredentialKey</c> is — signing over <c>authData ‖ clientDataHash</c> is the
/// certified-mint's own concern (CTAP 2.3 line 8250's "may include uniquely identifying information");
/// this key is NEVER the credential key a <c>authenticatorMakeCredential</c> call mints. Owned by this
/// record; disposed by <see cref="Dispose"/>.
/// </param>
/// <param name="X5c">
/// The seeded attestation certificate chain, leaf-first, as DER-encoded entries — the bytes an
/// enterprise-attested mint's <c>attStmt</c> emits verbatim under the <c>x5c</c> key. Opaque to this
/// library: never parsed or minted in <c>src/**</c>, only carried and disposed. Owned by this record;
/// disposed by <see cref="Dispose"/>.
/// </param>
/// <param name="Algorithm">
/// The COSE algorithm identifier <see cref="AttestationKey"/> signs with, mirroring
/// <c>CtapCredentialRecord.Algorithm</c>'s own COSE-alg-id shape.
/// </param>
/// <param name="PreConfiguredRpIds">
/// The vendor's non-updateable pre-configured RP ID list (snapshot line 8256) — the set an
/// <c>enterpriseAttestation</c> value of <c>1</c> checks a request's <c>rp.id</c> against (CTAP 2.3
/// line 3341-3345). Constructor-fixed, immutable for the simulator's whole lifetime; no CTAP
/// subcommand in this feature ever replaces or extends it (trap 8).
/// </param>
public sealed record CtapEnterpriseAttestationProvisioning(
    PrivateKey AttestationKey,
    IReadOnlyList<PkiCertificateMemory> X5c,
    int Algorithm,
    IReadOnlyList<string> PreConfiguredRpIds): IDisposable
{
    /// <summary>
    /// Releases <see cref="AttestationKey"/> and every entry of <see cref="X5c"/> this record owns.
    /// </summary>
    public void Dispose()
    {
        AttestationKey.Dispose();

        foreach(PkiCertificateMemory certificate in X5c)
        {
            certificate.Dispose();
        }
    }
}

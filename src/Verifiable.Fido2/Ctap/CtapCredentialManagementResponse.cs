using System;
using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorCredentialManagement</c> response structure this library models: every member
/// this authenticator ever emits, all Optional and defaulted <see langword="null"/> — the
/// <see cref="CtapClientPinResponse"/> template.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>, the response structure table
/// (lines 7026-7081). <see cref="CredProtect"/> (<c>0x0A</c>) carries the credential's REAL persisted
/// <c>CtapCredentialRecord.CredProtectLevel</c> (R11). <see cref="LargeBlobKey"/> (<c>0x0B</c>) carries
/// the credential's REAL stored <c>CtapCredentialRecord.LargeBlobKey</c>, if any — "the contents, if
/// any, of the stored largeBlobKey" (lines 7312/7341, wavelb R8). <c>thirdPartyPayment</c> (<c>0x0C</c>)
/// carries NO field here: this authenticator models no third-party payment extension, so emitting it
/// would be a wire overclaim (<see cref="WellKnownCtapCredentialManagementResponseKeys"/> still models
/// its integer key, for wire completeness). <c>deleteCredential</c>/<c>updateUserInformation</c> produce
/// no response instance at all (a bare <c>CTAP2_OK</c>) — see
/// <c>Authenticator.Automata.CredentialManagementResponseReady</c>'s own nullable <c>Response</c>.
/// </remarks>
/// <param name="ExistingResidentCredentialsCount">
/// Optional (<c>0x01</c>). The total number of discoverable credentials existing on the authenticator,
/// reported by <c>getCredsMetadata</c>.
/// </param>
/// <param name="MaxPossibleRemainingResidentCredentialsCount">
/// Optional (<c>0x02</c>). The estimated number of additional discoverable credentials that can still be
/// created, reported by <c>getCredsMetadata</c>.
/// </param>
/// <param name="Rp">Optional (<c>0x03</c>). The relying party entity an RP-enumeration step reports.</param>
/// <param name="RpIdHash">Optional (<c>0x04</c>). The RP ID SHA-256 hash paired with <see cref="Rp"/>, computed fresh.</param>
/// <param name="TotalRps">Optional (<c>0x05</c>). The total number of RPs holding a discoverable credential, reported once by <c>enumerateRPsBegin</c>.</param>
/// <param name="User">Optional (<c>0x06</c>). The user entity a credential-enumeration step reports.</param>
/// <param name="CredentialId">Optional (<c>0x07</c>). The credential descriptor a credential-enumeration step reports.</param>
/// <param name="PublicKey">Optional (<c>0x08</c>). The credential's public key in COSE_Key form — the R11 stored value, reused unchanged.</param>
/// <param name="TotalCredentials">Optional (<c>0x09</c>). The total number of credentials for the enumerated RP, reported once by <c>enumerateCredentialsBegin</c>.</param>
/// <param name="CredProtect">
/// Optional (<c>0x0A</c>). The enumerated credential's persisted <c>credProtect</c> level (CTAP 2.3
/// §12.1) — the R11 stored value, reused unchanged from <c>CtapCredentialRecord.CredProtectLevel</c>.
/// </param>
/// <param name="LargeBlobKey">
/// Optional (<c>0x0B</c>). The enumerated credential's stored <c>largeBlobKey</c> (CTAP 2.3 §12.3, lines
/// 7312/7341: "the contents, if any, of the stored largeBlobKey"), reused unchanged from
/// <c>CtapCredentialRecord.LargeBlobKey</c> — <see langword="null"/> when the credential carries none.
/// </param>
[DebuggerDisplay("CtapCredentialManagementResponse(Rp={Rp}, TotalRps={TotalRps}, TotalCredentials={TotalCredentials})")]
public sealed record CtapCredentialManagementResponse(
    int? ExistingResidentCredentialsCount = null,
    int? MaxPossibleRemainingResidentCredentialsCount = null,
    CtapPublicKeyCredentialRpEntity? Rp = null,
    ReadOnlyMemory<byte>? RpIdHash = null,
    int? TotalRps = null,
    CtapPublicKeyCredentialUserEntity? User = null,
    PublicKeyCredentialDescriptor? CredentialId = null,
    CoseKey? PublicKey = null,
    int? TotalCredentials = null,
    int? CredProtect = null,
    ReadOnlyMemory<byte>? LargeBlobKey = null);

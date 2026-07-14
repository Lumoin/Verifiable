using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>user</c> parameter of an <c>authenticatorMakeCredential</c> request, and the optional
/// <c>user</c> member of an <c>authenticatorGetAssertion</c> response: the user account a credential is
/// associated with, as the CTAP wire actually requires it.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>, the <c>user</c> parameter
/// (<c>0x03</c>): "an RP-specific user account identifier of type byte string, (optionally) a user name
/// of type text string, (optionally) a user display name of type text string." The icon member
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses">
/// [WebAuthn-2] removed</see> is not modeled. This differs from
/// <see cref="PublicKeyCredentialUserEntity"/>, the options-creation dictionary's own <c>user</c> member,
/// where <c>name</c> and <c>displayName</c> are required dictionary members — CTAP's own request/response
/// tables relax both to optional, "for privacy reasons for single-factor scenarios where only user
/// presence is required".
/// </para>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// section 6.2</see>'s response table additionally requires: identifiable fields (<c>name</c>,
/// <c>displayName</c>) MUST NOT be returned if user verification was not performed, and at least
/// <see cref="Id"/> is mandatory when a discoverable credential is asserted with <c>allowList</c>
/// omitted — both are handler-level obligations this codec-layer type does not itself enforce.
/// </para>
/// <para>
/// <see cref="Id"/> is owned by whichever caller constructs this instance (a request reader renting
/// fresh pooled memory, or an authenticator handler borrowing from its credential store); this type does
/// not dispose it, mirroring <see cref="PublicKeyCredentialUserEntity"/>'s own borrowing convention.
/// </para>
/// </remarks>
/// <param name="Id">The user handle identifying the user account. Required on the wire.</param>
/// <param name="Name">An optional user name, for display. <see langword="null"/> when omitted.</param>
/// <param name="DisplayName">
/// An optional user display name, for display. <see langword="null"/> when omitted.
/// </param>
[DebuggerDisplay("CtapPublicKeyCredentialUserEntity(Id={Id}, Name={Name}, DisplayName={DisplayName})")]
public sealed record CtapPublicKeyCredentialUserEntity(UserHandle Id, string? Name = null, string? DisplayName = null);

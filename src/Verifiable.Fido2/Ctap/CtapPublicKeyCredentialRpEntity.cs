using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>rp</c> parameter of an <c>authenticatorMakeCredential</c> request: the relying party the new
/// credential will be associated with, as the CTAP wire actually requires it.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>, the <c>rp</c> parameter (<c>0x02</c>):
/// "It contains the relying party identifier (rp.id) of type text string, (optionally) a human-friendly
/// RP name of type text string." This differs from <see cref="PublicKeyCredentialRpEntity"/>, the
/// options-creation dictionary's own <c>rp</c> member, where <c>id</c> is optional (defaulted by the
/// client to the origin's effective domain before the request is ever built) and <c>name</c> is a
/// required dictionary member — by the time a request reaches the wire, the client has already resolved
/// the effective <c>rp.id</c>, so CTAP's own table requires it and relaxes <c>name</c> to optional
/// instead.
/// </para>
/// </remarks>
/// <param name="Id">The relying party identifier the credential is scoped to. Required on the wire.</param>
/// <param name="Name">
/// An optional human-friendly relying party name, intended only for display. <see langword="null"/>
/// when omitted.
/// </param>
[DebuggerDisplay("CtapPublicKeyCredentialRpEntity(Id={Id}, Name={Name})")]
public sealed record CtapPublicKeyCredentialRpEntity(string Id, string? Name = null);

using System;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// One fingerprint template provisioned by a <see cref="CtapAuthenticatorSimulator"/>'s
/// <c>authenticatorBioEnrollment</c> enrollment flow, persisted inside
/// <see cref="CtapAuthenticatorState.BioEnrollmentTemplatesByTemplateId"/> and addressed later by
/// <c>enumerateEnrollments</c>/<c>setFriendlyName</c>/<c>removeEnrollment</c>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the <c>TemplateInfo</c> definition
/// (snapshot lines 6534-6549): <see cref="TemplateId"/> mirrors that table's own Required
/// <c>templateId</c> field; <see cref="FriendlyName"/> mirrors its Optional <c>templateFriendlyName</c>
/// field, <see langword="null"/> until <c>setFriendlyName</c> assigns one (§6.7.7's own body text never
/// names a default). Structurally sibling to (not derived from) <see cref="CtapCredentialRecord"/> — R6.
/// </remarks>
/// <param name="TemplateId">
/// The template's identifier, minted by <c>enrollBegin</c> (CTAP 2.3 §6.7.4 step 8). Owned by this
/// record.
/// </param>
/// <param name="FriendlyName">The template's human-readable name, or <see langword="null"/> when never set.</param>
public sealed record CtapBioEnrollmentTemplateRecord(
    BioEnrollmentTemplateId TemplateId,
    string? FriendlyName): IDisposable
{
    /// <summary>
    /// Releases the template identifier this record owns — the record-disposal discipline
    /// <see cref="CtapAuthenticatorState.FactoryReset"/> already applies to <see cref="CtapCredentialRecord"/>.
    /// </summary>
    public void Dispose()
    {
        TemplateId.Dispose();
    }
}

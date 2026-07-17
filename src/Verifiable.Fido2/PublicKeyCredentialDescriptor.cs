using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// Identifies one existing credential, for the <c>excludeCredentials</c>/<c>allowCredentials</c>
/// options members.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-credential-descriptor">W3C Web
/// Authentication Level 3, section 5.8.3: Credential Descriptor (dictionary
/// <c>PublicKeyCredentialDescriptor</c>)</see>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Id"/> is borrowed from whichever
/// <see cref="Fido2CredentialRecord"/> this descriptor projects (rows 4270/4277/4285 — <see
/// cref="Fido2RegistrationOptionsBuilder"/>/<see cref="Fido2AssertionOptionsBuilder"/> mirror the
/// record's own <c>Type</c>/<c>Id</c>/<c>Transports</c> verbatim, they do not copy the credential
/// identifier into a fresh buffer). The enclosing options document does not own or dispose it; the
/// relying party's own credential store retains that responsibility for as long as the record it
/// loaded stays alive, exactly as <see cref="Fido2CredentialRecord"/>'s own remarks describe for a
/// verifier borrowing the record.
/// </para>
/// </remarks>
[DebuggerDisplay("PublicKeyCredentialDescriptor(Type={Type}, Id={Id})")]
public sealed record PublicKeyCredentialDescriptor
{
    /// <summary>
    /// The credential type, per <see cref="WellKnownPublicKeyCredentialTypes"/>. Row 4270: SHOULD
    /// mirror the credential record's own <c>type</c> item.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// The credential identifier. Row 4277: SHOULD mirror the credential record's own <c>id</c> item.
    /// Borrowed, not owned — see the type-level ownership remarks.
    /// </summary>
    public required CredentialId Id { get; init; }

    /// <summary>
    /// The transports the credential is believed to support, or <see langword="null"/> when no
    /// transport hint is given. Row 4285: SHOULD mirror the credential record's own
    /// <c>transports</c> item whenever possible (row 3906, for <c>allowCredentials</c>).
    /// </summary>
    public IReadOnlyList<string>? Transports { get; init; }
}

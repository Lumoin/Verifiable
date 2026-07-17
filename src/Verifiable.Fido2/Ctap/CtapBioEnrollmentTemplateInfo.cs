using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// One entry of <c>authenticatorBioEnrollment</c>'s <c>templateInfos</c> (<c>0x07</c>) response array.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the <c>TemplateInfo</c> definition
/// (snapshot lines 6534-6553): <see cref="TemplateId"/> is the table's sole Required field;
/// <see cref="TemplateFriendlyName"/> is Optional (<see langword="null"/> until <c>setFriendlyName</c>
/// assigns one).
/// </remarks>
/// <param name="TemplateId">Required (<c>0x01</c>). The enrolled template's identifier.</param>
/// <param name="TemplateFriendlyName">Optional (<c>0x02</c>). The template's human-readable name, or <see langword="null"/> when never set.</param>
[DebuggerDisplay("CtapBioEnrollmentTemplateInfo(TemplateFriendlyName={TemplateFriendlyName})")]
public sealed record CtapBioEnrollmentTemplateInfo(
    ReadOnlyMemory<byte> TemplateId,
    string? TemplateFriendlyName = null);

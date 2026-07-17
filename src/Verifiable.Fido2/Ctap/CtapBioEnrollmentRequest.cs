using System;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorBioEnrollment</c> request structure.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. SIX top-level members, every one
/// Optional (snapshot lines 6386-6417) — mandatory-ness is a per-subcommand DISPATCH decision, not a
/// property of this decoded model. Mirrors <see cref="CtapCredentialManagementRequest"/>'s custody
/// shape: <see cref="SubCommandParams"/> carries the RAW, still-CBOR-encoded <c>subCommandParams</c>
/// map bytes AS RECEIVED (a slice of the request buffer, never re-encoded) — preserved because the
/// platform-side <c>pinUvAuthParam</c> verify message for every gated subcommand covers these EXACT
/// bytes, not a re-serialization of the decoded fields below. <see cref="TemplateId"/>/
/// <see cref="TemplateFriendlyName"/>/<see cref="TimeoutMilliseconds"/> are <see cref="SubCommandParams"/>'s
/// own three members, decoded for convenience (<see langword="null"/> when <see cref="SubCommandParams"/>
/// is absent or the individual member itself was omitted).
/// </remarks>
/// <param name="Modality">Optional (<c>0x01</c>). The requested modality, the only legal value being <see cref="WellKnownCtapBioEnrollmentModalities.Fingerprint"/>.</param>
/// <param name="SubCommand">Optional (<c>0x02</c>). The requested action, one of <see cref="WellKnownCtapBioEnrollmentSubCommands"/>.</param>
/// <param name="SubCommandParams">
/// Optional (<c>0x03</c>). The RAW, still-CBOR-encoded <c>subCommandParams</c> map bytes as received —
/// <see langword="null"/> when the member was omitted entirely.
/// </param>
/// <param name="TemplateId">Decoded from <see cref="SubCommandParams"/>'s member <c>0x01</c>. <see langword="null"/> when absent.</param>
/// <param name="TemplateFriendlyName">Decoded from <see cref="SubCommandParams"/>'s member <c>0x02</c>. <see langword="null"/> when absent.</param>
/// <param name="TimeoutMilliseconds">Decoded from <see cref="SubCommandParams"/>'s member <c>0x03</c>. <see langword="null"/> when absent.</param>
/// <param name="PinUvAuthProtocol">Optional (<c>0x04</c>). The PIN/UV auth protocol version the platform selected.</param>
/// <param name="PinUvAuthParam">
/// Optional (<c>0x05</c>). The output of calling <c>authenticate</c> on the subcommand-specific verify
/// message; <see langword="null"/> when omitted.
/// </param>
/// <param name="GetModality">
/// Optional (<c>0x06</c>). Requests the token-free bio-modality read (§6.7.2); when present-true, WINS
/// over any accompanying <see cref="SubCommand"/> — a documented posture over the spec's own silence on
/// the mixed-member case.
/// </param>
[DebuggerDisplay("CtapBioEnrollmentRequest(SubCommand={SubCommand}, GetModality={GetModality})")]
public sealed record CtapBioEnrollmentRequest(
    int? Modality = null,
    int? SubCommand = null,
    ReadOnlyMemory<byte>? SubCommandParams = null,
    ReadOnlyMemory<byte>? TemplateId = null,
    string? TemplateFriendlyName = null,
    int? TimeoutMilliseconds = null,
    int? PinUvAuthProtocol = null,
    ReadOnlyMemory<byte>? PinUvAuthParam = null,
    bool? GetModality = null);

using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// The <c>authenticatorBioEnrollment</c> response structure this library models: every member the spec
/// defines, all Optional and defaulted <see langword="null"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>, the response structure table
/// (snapshot lines 6484-6533). <see cref="TemplateInfos"/> (<c>0x07</c>) is a CBOR ARRAY of
/// <see cref="CtapBioEnrollmentTemplateInfo"/> maps — this codebase's first repeated-nested-map CTAP
/// response member. <c>cancelCurrentEnrollment</c> produces no response instance at all (a bare
/// <c>CTAP2_OK</c>) — see <c>Authenticator.Automata.BioEnrollmentResponseReady</c>'s own nullable
/// <c>Response</c>.
/// </remarks>
/// <param name="Modality">Optional (<c>0x01</c>). The user verification modality — value 1 for fingerprint, reported by the <c>getModality</c> flow.</param>
/// <param name="FingerprintKind">Optional (<c>0x02</c>). 1 for a touch sensor, 2 for a swipe sensor, reported by <c>getFingerprintSensorInfo</c>.</param>
/// <param name="MaxCaptureSamplesRequiredForEnroll">Optional (<c>0x03</c>). The maximum good samples one enrollment needs, reported by <c>getFingerprintSensorInfo</c> and <c>enrollBegin</c>.</param>
/// <param name="TemplateId">Optional (<c>0x04</c>). The enrollment's template identifier, reported by <c>enrollBegin</c>.</param>
/// <param name="LastEnrollSampleStatus">Optional (<c>0x05</c>). The most recent capture's outcome, one of <see cref="WellKnownCtapLastEnrollSampleStatuses"/>.</param>
/// <param name="RemainingSamples">Optional (<c>0x06</c>). The number of further good samples an in-progress enrollment still needs.</param>
/// <param name="TemplateInfos">Optional (<c>0x07</c>). Every provisioned template, reported by <c>enumerateEnrollments</c>.</param>
/// <param name="MaxTemplateFriendlyName">Optional (<c>0x08</c>). The maximum accepted friendly-name byte length, reported by <c>getFingerprintSensorInfo</c>.</param>
[DebuggerDisplay("CtapBioEnrollmentResponse(Modality={Modality}, LastEnrollSampleStatus={LastEnrollSampleStatus})")]
public sealed record CtapBioEnrollmentResponse(
    int? Modality = null,
    int? FingerprintKind = null,
    int? MaxCaptureSamplesRequiredForEnroll = null,
    ReadOnlyMemory<byte>? TemplateId = null,
    int? LastEnrollSampleStatus = null,
    int? RemainingSamples = null,
    IReadOnlyList<CtapBioEnrollmentTemplateInfo>? TemplateInfos = null,
    int? MaxTemplateFriendlyName = null);

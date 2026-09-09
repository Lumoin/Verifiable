using Verifiable.Core.Model.Mdoc;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// The CBOR/COSE serialization seams <see cref="MdocVpTokenVerification.VerifyAsync"/>
/// needs, bundled so the OID4VP executor can be constructed with mdoc support as one
/// cohesive parameter rather than eight loose delegates.
/// </summary>
/// <remarks>
/// <para>
/// Verifiable.OAuth carries no serialization dependency (the layering rule enforced by
/// BannedSymbols.Serialization). Every member here is a delegate the application wires to
/// a concrete implementation in <c>Verifiable.Cbor.Mdoc</c> / <c>Verifiable.JCose</c> at
/// composition time — the same seam pattern the SD-JWT path's
/// <see cref="ParseSdJwtTokenDelegate"/> / <see cref="ComputeSdJwtHashInputDelegate"/> use.
/// Pass an instance to
/// <see cref="Verifiable.OAuth.Oid4Vp.HaipOid4VpVerifierExecutor.Create"/> to enable
/// <c>mso_mdoc</c> VP-token verification; leave it <see langword="null"/> for
/// SD-JWT-only deployments.
/// </para>
/// </remarks>
public sealed record MdocVpVerificationSeams
{
    /// <summary>Resolves the issuer verification key from the IssuerAuth (typically an IACA x5chain resolver). Wired to e.g. <c>MdocCborIacaTrustResolver</c>.</summary>
    public required ResolveMdocIssuerKeyDelegate ResolveIssuerKey { get; init; }

    /// <summary>
    /// Parses the DeviceResponse wire bytes. Wired to <c>MdocCborDeviceResponseReader.Read</c> — see
    /// <see cref="ParseMdocDeviceResponseDelegate"/>'s remarks for the <see cref="FormatException"/>
    /// contract that method carries at its public boundary.
    /// </summary>
    public required ParseMdocDeviceResponseDelegate ParseDeviceResponse { get; init; }

    /// <summary>Encodes the OID4VP SessionTranscript. Wired to <c>Oid4VpMdocSessionTranscriptEncoder.Encode</c>.</summary>
    public required EncodeMdocSessionTranscriptDelegate EncodeSessionTranscript { get; init; }

    /// <summary>Decodes a CBOR element value to a string. Wired over <c>CborValueConverter.ReadValue</c>.</summary>
    public required DecodeMdocElementValueDelegate DecodeElementValue { get; init; }

    /// <summary>Parses the issuer-auth COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1</c>.</summary>
    public required ParseCoseSign1Delegate ParseCoseSign1 { get; init; }

    /// <summary>Parses the nil-payload device COSE_Sign1. Wired to <c>CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</summary>
    public required ParseCoseSign1Delegate ParseCoseSign1AllowingNilPayload { get; init; }

    /// <summary>Reconstructs the DeviceAuthenticationBytes. Wired to <c>MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</summary>
    public required EncodeDeviceAuthenticationBytesDelegate EncodeDeviceAuthenticationBytes { get; init; }

    /// <summary>Builds the COSE Sig_structure. Wired to <c>CoseSerialization.BuildSigStructure</c>.</summary>
    public required BuildSigStructureDelegate BuildSigStructure { get; init; }

    /// <summary>
    /// Optional: resolves the OID4VP 1.0 §6.1.1 trust evidence from the IssuerAuth x5chain so the
    /// verifier can enforce a DCQL <c>trusted_authorities</c> entry against an <c>mso_mdoc</c>
    /// credential. Wired to e.g. <c>MdocCborTrustedAuthorityEvidence.Create</c>. When
    /// <see langword="null"/> the mdoc path surfaces no trust evidence, so a
    /// <c>trusted_authorities</c> constraint on an <c>mso_mdoc</c> query fails closed
    /// (<see cref="Verifiable.Core.Dcql.DcqlFailureReasons.TrustedAuthorityEvidenceAbsent"/>).
    /// </summary>
    public ExtractMdocTrustedAuthorityEvidenceDelegate? ExtractTrustedAuthorityEvidence { get; init; }
}

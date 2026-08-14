using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for the pooled carriers a preservation-protocol message's payloads ride
/// in, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see> clause 5.
/// </summary>
/// <remarks>
/// Each tag carries a <see cref="PreservationPayloadKind"/> discriminator together with the encoding its octets
/// really are. Every payload here is <see cref="EncodingScheme.Raw"/>: the protocol carries a preservation object
/// as base64-encoded binary or as nested markup and says nothing about what is inside it, so the octets are
/// whatever the submitter handed over — this library neither encodes nor re-encodes them. The pattern mirrors
/// <see cref="EArkTags"/> and <see cref="AsicTags"/>, which do the same job for package and container octets.
/// </remarks>
public static class PreservationTags
{
    /// <summary>Tag for the octets one preservation object carries (clause 5.4.5).</summary>
    public static Tag PreservationObject { get; } =
        Tag.Create(PreservationPayloadKind.PreservationObject).With(EncodingScheme.Raw);

    /// <summary>Tag for the octets one preservation evidence carries (clause 5.4.4).</summary>
    public static Tag PreservationEvidence { get; } =
        Tag.Create(PreservationPayloadKind.PreservationEvidence).With(EncodingScheme.Raw);

    /// <summary>Tag for the octets of one sub-component this document defines only by reference (clauses 5.3.1 and 5.4.7).</summary>
    public static Tag OpaqueElement { get; } =
        Tag.Create(PreservationPayloadKind.OpaqueElement).With(EncodingScheme.Raw);

    /// <summary>Tag for the octets of one container-manifest <c>Extension</c> element carrying a payload of clause 5.5.</summary>
    public static Tag AsicExtension { get; } =
        Tag.Create(PreservationPayloadKind.AsicExtension).With(EncodingScheme.Raw);
}

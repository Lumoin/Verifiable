using System;
using System.Buffers;
using System.Formats.Asn1;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Splices a <see cref="CmsSignedData"/>'s own <c>certificates</c> field byte-for-byte, independent of
/// <see cref="ManagedCmsVerification"/> and <see cref="BouncyCastleCmsFunctions"/> — the fixtures under
/// test never produced this input. Every entry is written verbatim as a complete <c>CertificateChoices</c>
/// TLV (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2">RFC 5652 §10.2.2</see>), so a
/// caller supplies a genuine untagged <c>Certificate</c>, a tagged alternative, or deliberately broken
/// bytes, and the field is rebuilt with exactly the entries given (or omitted entirely when none are
/// given). The structure's signature does not cover <c>certificates</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.4">RFC 5652 §5.4</see>: only the
/// encapsulated content and, when present, the signed attributes feed the message digest calculation), so
/// splicing this field leaves the signature verifiable.
/// </summary>
/// <remarks>
/// Independently duplicated, and generalised from <see cref="CmsSignedData"/>'s
/// <see cref="PkiCertificateMemory"/>-carried counterpart shape, from the identically-shaped private
/// helpers <c>TimestampTokenEmbeddedMaterialTests.RebuildTokenWithCertificatesField</c> and
/// <c>CBAdESLevelValidationNegativeTests.RebuildTokenWithCertificatesField</c> — those two splice a
/// time-stamp token's <see cref="PkiCertificateMemory"/> wire carrier; this one operates on the
/// <see cref="CmsSignedData"/> carrier the CMS verification backends consume directly, for tests that call
/// <see cref="ManagedCmsVerification"/>/<see cref="BouncyCastleCmsFunctions"/> without going through a
/// time-stamp token. Both carriers wrap the identical
/// <c>ContentInfo { contentType id-signedData, content [0] EXPLICIT SignedData }</c> envelope, so the same
/// splice logic applies unchanged.
/// </remarks>
internal static class CmsCertificatesFieldSpliceTestFactory
{
    /// <summary>
    /// Decomposes an already-signed <see cref="CmsSignedData"/> and rebuilds it with its <c>certificates</c>
    /// field's <c>SET OF CertificateChoices</c> content replaced verbatim by <paramref name="certificateEntries"/>
    /// (each already a complete TLV), or with the field omitted entirely when none are supplied.
    /// </summary>
    /// <param name="signedData">The already-signed carrier.</param>
    /// <param name="certificateEntries">The raw TLV bytes of every <c>CertificateChoices</c> entry the rebuilt field carries, in order; empty to omit the field entirely.</param>
    /// <returns>The doctored carrier; the caller disposes it.</returns>
    public static CmsSignedData RebuildWithCertificatesField(CmsSignedData signedData, params ReadOnlyMemory<byte>[] certificateEntries)
    {
        ArgumentNullException.ThrowIfNull(signedData);

        var outer = new AsnReader(signedData.AsReadOnlySpan().ToArray(), AsnEncodingRules.DER);
        AsnReader contentInfo = outer.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader parsedSignedData = explicitContent.ReadSequence();

        ReadOnlyMemory<byte> version = parsedSignedData.ReadEncodedValue();
        ReadOnlyMemory<byte> digestAlgorithms = parsedSignedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = parsedSignedData.ReadEncodedValue();

        if(parsedSignedData.HasData && parsedSignedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            //The carrier's own certificates field, discarded: the rebuilt field below replaces it entirely with
            //certificateEntries (or omits it) rather than preserving it.
            _ = parsedSignedData.ReadEncodedValue();
        }

        ReadOnlyMemory<byte> signerInfos = parsedSignedData.ReadEncodedValue();
        parsedSignedData.ThrowIfNotEmpty();

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);
            using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteEncodedValue(version.Span);
                    writer.WriteEncodedValue(digestAlgorithms.Span);
                    writer.WriteEncodedValue(encapContentInfo.Span);
                    if(certificateEntries.Length > 0)
                    {
                        using(writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)))
                        {
                            foreach(ReadOnlyMemory<byte> entry in certificateEntries)
                            {
                                writer.WriteEncodedValue(entry.Span);
                            }
                        }
                    }

                    writer.WriteEncodedValue(signerInfos.Span);
                }
            }
        }

        byte[] encoded = writer.Encode();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encoded.Length);
        encoded.CopyTo(owner.Memory.Span);

        return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
    }


    /// <summary>
    /// Wraps arbitrary DER content in a context-specific constructed tag — the shape of a tagged
    /// <c>CertificateChoices</c> alternative (<c>extendedCertificate [0]</c>, <c>v1AttrCert [1]</c>,
    /// <c>v2AttrCert [2]</c>, <c>other [3]</c>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc5652#section-10.2.2">RFC 5652 §10.2.2</see>) a
    /// tag-discriminating reader must skip rather than feed to <see cref="ManagedCertificate.Parse"/>.
    /// <paramref name="content"/>'s own semantics are irrelevant: the skip path never interprets what it
    /// consumes.
    /// </summary>
    /// <param name="content">The bytes to wrap.</param>
    /// <param name="tagNumber">The context-specific tag number (0 through 3).</param>
    /// <returns>The tagged TLV.</returns>
    public static byte[] BuildTaggedCertificateChoice(ReadOnlySpan<byte> content, int tagNumber)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber, isConstructed: true)))
        {
            writer.WriteEncodedValue(content);
        }

        return writer.Encode();
    }


    /// <summary>
    /// Builds a structurally otherwise well-formed X.509 certificate — the shape a genuine
    /// <c>Certificate</c> <c>CertificateChoices</c> alternative takes, decodable by a generic ASN.1
    /// certificate reader that does not range-check field values — whose <c>[0]</c> EXPLICIT version
    /// wrapper carries <c>5</c>, a value RFC 5280 §4.1.2.1 admits only 0, 1, or 2 for.
    /// <see cref="ManagedCertificate.Parse"/> rejects it on that one narrower check while the outer tag
    /// still passes tag discrimination as a legal untagged-<c>Certificate</c> candidate — a well-formed
    /// TLV whose content is genuinely broken, mirroring
    /// <c>TimestampTokenEmbeddedMaterialTests.BuildBrokenCertificateMember</c>'s identically-shaped
    /// malformed-certificates fixture.
    /// </summary>
    /// <returns>The broken member's TLV.</returns>
    public static byte[] BuildBrokenCertificateMember()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(5);                                 //RFC 5280 §4.1.2.1 admits only 0, 1, 2.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                using(writer.PushSequence())                                //issuer -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(TestClock.CanonicalEpoch.AddYears(-1));
                    writer.WriteUtcTime(TestClock.CanonicalEpoch.AddYears(9));
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo.
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                    }

                    writer.WriteBitString([0x00]);
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        return writer.Encode();
    }
}

using System.Buffers;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Extension surface for mdoc credentials — brings mdoc onto the same
/// <c>extension(X)</c> shape <see cref="Verifiable.Core.Model.DataIntegrity.CredentialDataIntegrityExtensions"/>,
/// <see cref="Verifiable.Core.Model.DataIntegrity.CredentialEcdsaSd2023Extensions"/>,
/// and <see cref="Verifiable.Core.Model.DataIntegrity.PresentationDataIntegrityExtensions"/>
/// already use for VC and DataIntegrity.
/// </summary>
/// <remarks>
/// <para>
/// The extension blocks hang off the host type that matches each operation's
/// real input: <see cref="MdocLogicalDocument"/> for issuance-time signing
/// (a logical → signed transformation), and <see cref="MdocDocument"/> for
/// post-signing verification.
/// </para>
/// <para>
/// Bodies forward to the underlying static helper <see cref="MdocCborIssuance"/>
/// verbatim. Issuer-auth COSE_Sign1 signature verification has moved to
/// <see cref="Verifiable.Core.Model.Mdoc.MdocVerificationExtensions"/> in Verifiable.Core
/// (it crosses ParseCoseSign1/BuildSigStructure seams rather than calling the CBOR helpers
/// directly). The remaining static helpers remain available for callers that prefer them; the
/// extension surface is additive. It includes <see cref="DeviceSignAsync"/>,
/// <c>VerifyDeviceSignedAsync</c>, <see cref="VerifyDigestBinding"/>,
/// <c>Derive</c>, and the corresponding <c>*Verbose</c> siblings that mirror
/// <see cref="Verifiable.Core.Model.DataIntegrity.CredentialEcdsaSd2023Extensions"/>'s
/// production/verbose pairing convention.
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Design", "CA1034:Nested types should not be visible",
    Justification = "The analyzer is not up to date with the C# 14 extension(X) syntax.")]
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Naming", "CA1708:Names should differ by more than case",
    Justification = "The C# 14 compiler lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension blocks are clearly distinct hosts (MdocLogicalDocument vs MdocDocument).")]
public static class MdocCborExtensions
{
    extension(MdocLogicalDocument logical)
    {
        /// <summary>
        /// Signs the logical document, producing a wire-valid
        /// <see cref="MdocDocument"/> with each item's
        /// <see cref="MdocIssuerSignedItem.WireBytes"/> attached and
        /// <see cref="MdocIssuerSigned.IssuerAuth"/> populated with the
        /// signed MSO.
        /// </summary>
        /// <param name="config">
        /// The issuer's MSO commitments: digest algorithm, device key,
        /// validity bounds, optional kid + x5chain.
        /// </param>
        /// <param name="signingKey">
        /// The issuer's signing key. Its <see cref="Tag"/> determines the
        /// COSE <c>alg</c> in the protected header and the signing function
        /// the registry resolves to.
        /// </param>
        /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The signed document; the caller owns and must dispose. Ownership
        /// of the logical document's salts transfers to the returned signed
        /// document — the caller must not use or dispose
        /// <see langword="this"/> after the call.
        /// </returns>
        public async ValueTask<MdocDocument> SignAsync(
            MdocIssuerSigningConfig config,
            PrivateKeyMemory signingKey,
            MemoryPool<byte> signaturePool,
            CancellationToken cancellationToken = default)
        {
            (MdocDocument document, _) = await logical.SignVerboseAsync(
                config, signingKey, signaturePool, cancellationToken).ConfigureAwait(false);

            return document;
        }


        /// <summary>
        /// Signs the logical document and additionally returns the signed MSO payload — the
        /// Tag 24-wrapped MSO bytes the COSE_Sign1 signature covers — the canonical body
        /// <c>SignAsync</c> forwards to. Mirrors the issuance verbose pairing the SD-CWT and
        /// SD-JWT issuers already expose; forwards to <see cref="MdocCborIssuance.SignVerboseAsync"/>.
        /// </summary>
        /// <param name="config">The issuer's MSO commitments: digest algorithm, device key, validity bounds, optional kid + x5chain.</param>
        /// <param name="signingKey">The issuer's signing key; its <see cref="Tag"/> picks the COSE <c>alg</c> and the signing function.</param>
        /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The signed document (caller owns and must dispose; ownership of the logical document's
        /// salts transfers to it, so the caller must not use or dispose <see langword="this"/>
        /// after the call) and the Tag 24-wrapped MSO bytes that were signed — a standalone
        /// buffer independent of the document's lifetime.
        /// </returns>
        public ValueTask<(MdocDocument Document, ReadOnlyMemory<byte> SignedMsoPayload)> SignVerboseAsync(
            MdocIssuerSigningConfig config,
            PrivateKeyMemory signingKey,
            MemoryPool<byte> signaturePool,
            CancellationToken cancellationToken = default)
        {
            return MdocCborIssuance.SignVerboseAsync(
                logical,
                config,
                signingKey,
                signaturePool,
                cancellationToken);
        }
    }


    extension(MdocDocument document)
    {
        /// <summary>
        /// Validates that every <see cref="MdocIssuerSignedItem"/> in the
        /// document is committed by the MSO's <c>valueDigests</c> map under
        /// the declared digest algorithm. Verifier-side digest-binding check
        /// per ISO/IEC 18013-5 §9.1.2.5.
        /// </summary>
        /// <returns>
        /// An <see cref="MdocDigestBindingResult"/> carrying the overall
        /// pass/fail plus per-item outcomes.
        /// </returns>
        public MdocDigestBindingResult VerifyDigestBinding()
        {
            return MdocMsoDigestBindingValidator.Validate(document.IssuerSigned);
        }


        /// <summary>
        /// Derives a non-owning presentation projection of the document
        /// containing only the items whose paths appear in
        /// <paramref name="selectedPaths"/>. Mirrors the
        /// <see cref="Verifiable.Core.Model.DataIntegrity.CredentialEcdsaSd2023Extensions"/>
        /// <c>DeriveProofAsync</c> shape: full credential in, presentation
        /// projection out.
        /// </summary>
        /// <param name="selectedPaths">
        /// The two-segment <c>[namespace, element_identifier]</c> paths the
        /// wallet chose to present — typically the output of the DCQL
        /// evaluator + selective-disclosure decision graph.
        /// </param>
        /// <returns>
        /// A presentation document carrying the trimmed view and the
        /// document's <see cref="MdocDocument.DocType"/>;
        /// <see cref="MdocPresentationDocument.DeviceSigned"/> is null and
        /// the wallet attaches it at presentation time via the
        /// device-sign extension method.
        /// </returns>
        /// <remarks>
        /// The trimmed view borrows item references from
        /// <paramref name="document"/>; the document's lifetime must bracket
        /// the presentation document's. Disposing
        /// <paramref name="document"/> releases the salts the view points
        /// at — same lifetime contract <see cref="MdocIssuerSignedView"/>
        /// already documents.
        /// </remarks>
        public MdocPresentationDocument Derive(IReadOnlySet<CredentialPath> selectedPaths)
        {
            MdocIssuerSignedView view = MdocIssuerSignedTrimmer.Trim(document.IssuerSigned, selectedPaths);

            return new MdocPresentationDocument(document.DocType, view);
        }
    }


    extension(MdocPresentationDocument presentation)
    {
        /// <summary>
        /// Validates that every <see cref="MdocIssuerSignedItem"/> in the
        /// presentation projection is committed by the MSO's
        /// <c>valueDigests</c> map under the declared digest algorithm. The
        /// view-side overload — the MSO commits to ALL items, the
        /// presentation surfaces a subset, and the validator iterates only
        /// the presented items.
        /// </summary>
        /// <returns>
        /// An <see cref="MdocDigestBindingResult"/> carrying the overall
        /// pass/fail plus per-item outcomes.
        /// </returns>
        public MdocDigestBindingResult VerifyDigestBinding()
        {
            return MdocMsoDigestBindingValidator.Validate(presentation.IssuerSigned);
        }


        /// <summary>
        /// Produces a COSE_Sign1 over the <c>DeviceAuthentication</c> array
        /// bound to <paramref name="sessionTranscript"/> per ISO/IEC
        /// 18013-5 §9.1.3.4, and returns a new
        /// <see cref="MdocPresentationDocument"/> with the resulting
        /// <see cref="MdocDeviceSigned"/> attached.
        /// </summary>
        /// <param name="nameSpaces">
        /// The device-side claim assertions. Typically
        /// <see cref="MdocDeviceNameSpaces.Empty"/> for OID4VP flows —
        /// EUDI ARF places semantic claims under <c>issuerSigned</c>, not
        /// <c>deviceSigned</c>.
        /// </param>
        /// <param name="sessionTranscript">
        /// The encoded SessionTranscript bytes the wallet and verifier
        /// share. For OID4VP this comes from
        /// <see cref="Oid4VpMdocSessionTranscriptEncoder.Encode"/>.
        /// </param>
        /// <param name="deviceSigningKey">
        /// The wallet's device-binding private key. Must match the
        /// <see cref="MdocDeviceKeyInfo.DeviceKey"/> the MSO commits to.
        /// </param>
        /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A new presentation document with the same
        /// <see cref="MdocPresentationDocument.DocType"/> and
        /// <see cref="MdocPresentationDocument.IssuerSigned"/> as
        /// <paramref name="presentation"/>, plus the
        /// freshly-signed <see cref="MdocPresentationDocument.DeviceSigned"/>.
        /// The original presentation document remains usable for additional
        /// device-signing sessions if needed (e.g. the same trimmed credential
        /// presented to two verifiers).
        /// </returns>
        public async ValueTask<MdocPresentationDocument> DeviceSignAsync(
            MdocDeviceNameSpaces nameSpaces,
            ReadOnlyMemory<byte> sessionTranscript,
            PrivateKeyMemory deviceSigningKey,
            MemoryPool<byte> signaturePool,
            CancellationToken cancellationToken = default)
        {
            (MdocPresentationDocument signedPresentation, _) = await presentation.DeviceSignVerboseAsync(
                nameSpaces, sessionTranscript, deviceSigningKey, signaturePool, cancellationToken).ConfigureAwait(false);

            return signedPresentation;
        }


        /// <summary>
        /// Device-signs the presentation and additionally returns the <c>DeviceAuthenticationBytes</c>
        /// — the Tag 24-wrapped <c>DeviceAuthentication</c> array the COSE_Sign1 signature covers —
        /// the canonical body <c>DeviceSignAsync</c> forwards to. Mirrors the issuance verbose
        /// pairing; forwards to <see cref="MdocCborDeviceSignedSigner.SignVerboseAsync"/>.
        /// </summary>
        /// <param name="nameSpaces">
        /// The device-side claim assertions. Typically
        /// <see cref="MdocDeviceNameSpaces.Empty"/> for OID4VP flows.
        /// </param>
        /// <param name="sessionTranscript">
        /// The encoded SessionTranscript bytes the wallet and verifier share — for OID4VP from
        /// <see cref="Oid4VpMdocSessionTranscriptEncoder.Encode"/>.
        /// </param>
        /// <param name="deviceSigningKey">
        /// The wallet's device-binding private key. Must match the
        /// <see cref="MdocDeviceKeyInfo.DeviceKey"/> the MSO commits to.
        /// </param>
        /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A new presentation document with the freshly-signed
        /// <see cref="MdocPresentationDocument.DeviceSigned"/> (the original presentation document
        /// remains usable for additional device-signing sessions), and the
        /// <c>DeviceAuthenticationBytes</c> that were signed — a standalone buffer independent of
        /// the returned document's lifetime.
        /// </returns>
        public async ValueTask<(MdocPresentationDocument Presentation, ReadOnlyMemory<byte> DeviceAuthenticationBytes)> DeviceSignVerboseAsync(
            MdocDeviceNameSpaces nameSpaces,
            ReadOnlyMemory<byte> sessionTranscript,
            PrivateKeyMemory deviceSigningKey,
            MemoryPool<byte> signaturePool,
            CancellationToken cancellationToken = default)
        {
            (MdocDeviceSigned deviceSigned, ReadOnlyMemory<byte> deviceAuthenticationBytes) =
                await MdocCborDeviceSignedSigner.SignVerboseAsync(
                    nameSpaces,
                    presentation.DocType,
                    sessionTranscript,
                    deviceSigningKey,
                    signaturePool,
                    cancellationToken).ConfigureAwait(false);

            MdocPresentationDocument signedPresentation = new(
                presentation.DocType,
                presentation.IssuerSigned,
                deviceSigned);

            return (signedPresentation, deviceAuthenticationBytes);
        }
    }
}

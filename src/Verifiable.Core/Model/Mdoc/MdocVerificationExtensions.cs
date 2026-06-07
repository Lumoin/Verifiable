using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Verification orchestration for issued mdoc documents — pairs the POCO
/// <see cref="MdocIssuerAuth"/> / <see cref="MdocDocument"/> with the issuer-auth COSE_Sign1
/// signature check.
/// </summary>
/// <remarks>
/// <para>
/// The issuer-auth verification is crypto orchestration — the COSE_Sign1 signature check
/// (<c>Cose.VerifyAsync</c>) over the Tag 24-wrapped MSO — not serialization, so it lives beside
/// the credential model rather than in <c>Verifiable.Cbor</c>, mirroring
/// <see cref="Verifiable.Core.Model.SelectiveDisclosure.SdCwtVerificationExtensions"/> on the
/// SD-CWT side and the Data Integrity extensions. The only CBOR it touches — parsing the
/// COSE_Sign1 wire form and building the COSE Sig_structure — crosses the
/// <see cref="ParseCoseSign1Delegate"/> and <see cref="BuildSigStructureDelegate"/> seams the
/// application wires to <c>Verifiable.Cbor.CoseSerialization</c>.
/// </para>
/// <para>
/// The <see cref="MdocIssuerAuth"/> block is the signature primitive (the COSE_Sign1 lives on the
/// IssuerAuth); the <see cref="MdocDocument"/> block forwards to it and additionally exposes the
/// verbose <see cref="MdocIssuerAuthVerificationContext"/>. The verifier checks only the issuer
/// signature — NOT the MSO digest-binding (the <c>VerifyDigestBinding</c> check) nor any trust
/// chain beyond what the supplied <see cref="ResolveMdocIssuerKeyDelegate"/> resolves.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension hosts are clearly distinct.")]
public static class MdocVerificationExtensions
{
    extension(MdocIssuerAuth issuerAuth)
    {
        /// <summary>
        /// Verifies that this IssuerAuth's COSE_Sign1 signature validates under
        /// <paramref name="issuerVerificationKey"/> via <c>Cose.VerifyAsync</c> (registry-resolved
        /// from the key's tag). The signature primitive the document-level surface forwards to.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's signing-key public half.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><see langword="true"/> when the signature is valid; otherwise <see langword="false"/>.</returns>
        public async ValueTask<bool> VerifyAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerAuth);
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(parseCoseSign1);
            ArgumentNullException.ThrowIfNull(buildSigStructure);

            using CoseSign1Message message = parseCoseSign1(issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);

            return await Cose.VerifyAsync(
                message, buildSigStructure, issuerVerificationKey, cancellationToken).ConfigureAwait(false);
        }


        /// <summary>
        /// Verifies that this IssuerAuth's COSE_Sign1 signature validates under the leaf key the
        /// trust delegate resolved from the IssuerAuth's <c>x5chain</c> per ISO/IEC 18013-5
        /// §9.1.2.4. Composes trust resolution with signature verification in one call.
        /// </summary>
        /// <param name="resolveIssuerKey">The IACA trust delegate (typically <c>MdocCborIacaTrustResolver.Create</c>).</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> when both trust resolution and signature verification succeed;
        /// <see langword="false"/> otherwise. Callers needing per-failure IACA detail run
        /// <paramref name="resolveIssuerKey"/> directly.
        /// </returns>
        public async ValueTask<bool> VerifyAsync(
            ResolveMdocIssuerKeyDelegate resolveIssuerKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerAuth);
            ArgumentNullException.ThrowIfNull(resolveIssuerKey);
            ArgumentNullException.ThrowIfNull(pool);

            using MdocIacaTrustResolution resolution = await resolveIssuerKey(issuerAuth, cancellationToken).ConfigureAwait(false);
            if(!resolution.IsTrusted || resolution.IssuerVerificationKey is null)
            {
                return false;
            }

            return await issuerAuth.VerifyAsync(
                resolution.IssuerVerificationKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);
        }
    }


    extension(MdocDocument document)
    {
        /// <summary>
        /// Verifies the issuer signature on the document's
        /// <see cref="MdocIssuerSigned.IssuerAuth"/> against <paramref name="issuerVerificationKey"/>
        /// and returns the intermediate state — the canonical body the direct-key
        /// <c>VerifyIssuerAuthAsync</c> forwards to.
        /// </summary>
        /// <remarks>
        /// <para>
        /// On success the returned <see cref="MdocIssuerAuthVerificationContext"/> is non-null and
        /// owned by the caller (dispose it); it carries the parsed COSE_Sign1 message and the MSO
        /// the signature covers. When the signature is invalid the context is <see langword="null"/>
        /// — the SD-CWT/SD-JWT verbose convention that a context exists only past the signature
        /// check. The signature step parses the COSE_Sign1 a second time so the returned context
        /// can own a live message; production callers that don't need it use
        /// <c>VerifyIssuerAuthAsync</c>, which disposes the context.
        /// </para>
        /// </remarks>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The signature outcome and, once the signature verifies, the
        /// <see cref="MdocIssuerAuthVerificationContext"/> with the parsed message and MSO.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned MdocIssuerAuthVerificationContext takes ownership of the parsed message; the caller disposes the context.")]
        public async ValueTask<(bool Result, MdocIssuerAuthVerificationContext? Context)> VerifyIssuerAuthVerboseAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(parseCoseSign1);
            ArgumentNullException.ThrowIfNull(buildSigStructure);

            MdocIssuerAuth issuerAuth = document.IssuerSigned.IssuerAuth;

            bool isVerified = await issuerAuth.VerifyAsync(
                issuerVerificationKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);
            if(!isVerified)
            {
                return (false, null);
            }

            //Re-parse to hand the caller a live message; the verify step above disposed its own
            //copy. The returned context owns this one — the caller disposes the context.
            CoseSign1Message message = parseCoseSign1(issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);

            return (true, new MdocIssuerAuthVerificationContext(message, issuerAuth.Mso));
        }


        /// <summary>
        /// Verifies the issuer signature on the document's
        /// <see cref="MdocIssuerSigned.IssuerAuth"/> against <paramref name="issuerVerificationKey"/>.
        /// Forwards to <c>VerifyIssuerAuthVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><see langword="true"/> when the issuer signature verifies; otherwise <see langword="false"/>.</returns>
        public async ValueTask<bool> VerifyIssuerAuthAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            (bool result, MdocIssuerAuthVerificationContext? context) = await document.VerifyIssuerAuthVerboseAsync(
                issuerVerificationKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }


        /// <summary>
        /// Verifies the issuer signature through the IACA trust-resolution delegate and returns the
        /// intermediate state — the canonical body the trust-resolver <c>VerifyIssuerAuthAsync</c>
        /// forwards to. Inlines the resolve-then-verify sequence so the successful
        /// <see cref="MdocIacaTrustResolution"/> survives into the returned context.
        /// </summary>
        /// <remarks>
        /// <para>
        /// On success the returned <see cref="MdocIssuerAuthVerificationContext"/> is non-null and
        /// owned by the caller; it carries the parsed COSE_Sign1 message, the MSO, and the
        /// successful trust resolution (whose resolved key the context owns). The context is
        /// <see langword="null"/> when trust resolution fails OR the resolved key fails to verify
        /// the signature. Callers that need the per-failure IACA detail run
        /// <paramref name="resolveIssuerKey"/> directly.
        /// </para>
        /// </remarks>
        /// <param name="resolveIssuerKey">The IACA trust delegate.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The combined trust-and-signature outcome and, on success, the
        /// <see cref="MdocIssuerAuthVerificationContext"/> with the parsed message, MSO, and trust resolution.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned MdocIssuerAuthVerificationContext takes ownership of the parsed message and the successful trust resolution; failure paths dispose the resolution explicitly and the caller disposes the context.")]
        public async ValueTask<(bool Result, MdocIssuerAuthVerificationContext? Context)> VerifyIssuerAuthVerboseAsync(
            ResolveMdocIssuerKeyDelegate resolveIssuerKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(document);
            ArgumentNullException.ThrowIfNull(resolveIssuerKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(parseCoseSign1);
            ArgumentNullException.ThrowIfNull(buildSigStructure);

            MdocIssuerAuth issuerAuth = document.IssuerSigned.IssuerAuth;

            MdocIacaTrustResolution resolution = await resolveIssuerKey(issuerAuth, cancellationToken).ConfigureAwait(false);
            if(!resolution.IsTrusted || resolution.IssuerVerificationKey is null)
            {
                resolution.Dispose();
                return (false, null);
            }

            bool isVerified = await issuerAuth.VerifyAsync(
                resolution.IssuerVerificationKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);
            if(!isVerified)
            {
                resolution.Dispose();
                return (false, null);
            }

            //Re-parse to hand the caller a live message; the verify step above disposed its own
            //copy. The returned context owns this message and the trust resolution.
            CoseSign1Message message = parseCoseSign1(issuerAuth.EncodedCoseSign1.AsReadOnlyMemory(), pool);

            return (true, new MdocIssuerAuthVerificationContext(message, issuerAuth.Mso, resolution));
        }


        /// <summary>
        /// Verifies the issuer signature through the IACA trust-resolution delegate.
        /// Forwards to <c>VerifyIssuerAuthVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="resolveIssuerKey">The IACA trust delegate.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">Delegate that parses the COSE_Sign1 wire form. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> when trust resolution succeeds AND the signature verifies under
        /// the resolved key; <see langword="false"/> otherwise.
        /// </returns>
        public async ValueTask<bool> VerifyIssuerAuthAsync(
            ResolveMdocIssuerKeyDelegate resolveIssuerKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            (bool result, MdocIssuerAuthVerificationContext? context) = await document.VerifyIssuerAuthVerboseAsync(
                resolveIssuerKey, pool, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }
    }


    extension(MdocDeviceSigned deviceSigned)
    {
        /// <summary>
        /// Verifies the device-side COSE_Sign1 signature on this <see cref="MdocDeviceSigned"/> per
        /// ISO/IEC 18013-5 §9.1.3.4 and returns the intermediate state — the canonical body the
        /// device-signed <c>VerifyAsync</c> forwards to. Reconstructs the
        /// <c>DeviceAuthenticationBytes</c> the wire form omits (nil payload) from the session
        /// transcript, doctype, and the preserved namespace bytes, re-attaches them as the COSE
        /// payload, and runs <c>Cose.VerifyAsync</c>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// On success the returned <see cref="MdocDeviceSignedVerificationContext"/> is non-null and
        /// owned by the caller (dispose it). It is <see langword="null"/> when the signature is
        /// invalid or when the device half carries a MAC rather than a signature — the verbose
        /// convention that a context exists only past the signature check. The session transcript
        /// MUST be byte-identical to what the wallet signed, or the signature verifies as invalid.
        /// </para>
        /// </remarks>
        /// <param name="docType">The enclosing document's docType URI.</param>
        /// <param name="encodedSessionTranscript">The session transcript bytes; MUST match what the device used at signing time.</param>
        /// <param name="deviceVerificationKey">The device's verification key — the public half the MSO committed to.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1AllowingNilPayload">Delegate that parses the nil-payload COSE_Sign1. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</param>
        /// <param name="encodeDeviceAuthenticationBytes">Delegate that reconstructs the Tag 24 DeviceAuthenticationBytes. Wired to <c>Verifiable.Cbor.Mdoc.MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The signature outcome and, once the signature verifies, the
        /// <see cref="MdocDeviceSignedVerificationContext"/> with the parsed message and the
        /// reconstructed <c>DeviceAuthenticationBytes</c>.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "On success the verifiable header/signature carriers chain into the returned context's message, which the caller disposes; the invalid-signature and exception paths dispose the message explicitly.")]
        public async ValueTask<(bool Result, MdocDeviceSignedVerificationContext? Context)> VerifyVerboseAsync(
            string docType,
            ReadOnlyMemory<byte> encodedSessionTranscript,
            PublicKeyMemory deviceVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytesDelegate encodeDeviceAuthenticationBytes,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(deviceSigned);
            ArgumentException.ThrowIfNullOrEmpty(docType);
            ArgumentNullException.ThrowIfNull(deviceVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(parseCoseSign1AllowingNilPayload);
            ArgumentNullException.ThrowIfNull(encodeDeviceAuthenticationBytes);
            ArgumentNullException.ThrowIfNull(buildSigStructure);

            if(deviceSigned.DeviceAuth.DeviceSignature is not MdocDeviceSignature signature)
            {
                return (false, null);
            }

            //Reconstruct the DeviceAuthenticationBytes from the same inputs the signer used. The
            //device half preserves EncodedDeviceNameSpacesBytes verbatim so the verifier hashes the
            //same byte pattern.
            ReadOnlyMemory<byte> deviceAuthenticationBytes = encodeDeviceAuthenticationBytes(
                encodedSessionTranscript, docType, deviceSigned.EncodedDeviceNameSpacesBytes);

            //Parse the detached-payload COSE_Sign1 into pool-routed carriers. The Sig_structure
            //computation reads the carriers' bytes and re-attaches the reconstructed payload for
            //the actual verification call; this detached parse is disposed regardless of outcome.
            using CoseSign1Message detachedMessage = parseCoseSign1AllowingNilPayload(signature.EncodedCoseSign1.AsReadOnlyMemory(), pool);

            //Re-pool-allocate the protected header and signature for the verifiable message — the
            //same EncodedCoseProtectedHeader / Signature cannot be shared between two IDisposable
            //messages without a disposal conflict.
            ReadOnlySpan<byte> phSpan = detachedMessage.ProtectedHeader.AsReadOnlySpan();
            IMemoryOwner<byte> phOwner = pool.Rent(phSpan.Length);
            phSpan.CopyTo(phOwner.Memory.Span);
            EncodedCoseProtectedHeader verifiableHeader = new(phOwner, CryptoTags.CoseEncodedProtectedHeader);

            ReadOnlySpan<byte> sigSpan = detachedMessage.Signature.AsReadOnlySpan();
            IMemoryOwner<byte> sigOwner = pool.Rent(sigSpan.Length);
            sigSpan.CopyTo(sigOwner.Memory.Span);
            Verifiable.Cryptography.Signature verifiableSignature = new(sigOwner, detachedMessage.Signature.Tag);

            //verifiableMessage owns verifiableHeader + verifiableSignature; it borrows only the
            //plain UnprotectedHeader dict and the standalone payload from detachedMessage, so it
            //outlives detachedMessage's disposal. On success it transfers to the returned context;
            //otherwise it is disposed here.
            CoseSign1Message verifiableMessage = new(
                verifiableHeader,
                detachedMessage.UnprotectedHeader,
                deviceAuthenticationBytes,
                verifiableSignature);

            bool isVerified;
            try
            {
                isVerified = await Cose.VerifyAsync(
                    verifiableMessage, buildSigStructure, deviceVerificationKey, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                verifiableMessage.Dispose();
                throw;
            }

            if(!isVerified)
            {
                verifiableMessage.Dispose();
                return (false, null);
            }

            return (true, new MdocDeviceSignedVerificationContext(verifiableMessage, deviceAuthenticationBytes));
        }


        /// <summary>
        /// Verifies the device signature on this <see cref="MdocDeviceSigned"/>. Forwards to
        /// <c>VerifyVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="docType">The enclosing document's docType URI.</param>
        /// <param name="encodedSessionTranscript">The session transcript bytes; MUST match what the device used at signing time.</param>
        /// <param name="deviceVerificationKey">The device's verification key.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1AllowingNilPayload">Delegate that parses the nil-payload COSE_Sign1. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</param>
        /// <param name="encodeDeviceAuthenticationBytes">Delegate that reconstructs the DeviceAuthenticationBytes. Wired to <c>Verifiable.Cbor.Mdoc.MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> when the device signature verifies against the reconstructed
        /// <c>DeviceAuthenticationBytes</c>; otherwise <see langword="false"/> (including when the
        /// device half carries a MAC rather than a signature).
        /// </returns>
        public async ValueTask<bool> VerifyAsync(
            string docType,
            ReadOnlyMemory<byte> encodedSessionTranscript,
            PublicKeyMemory deviceVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytesDelegate encodeDeviceAuthenticationBytes,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            (bool result, MdocDeviceSignedVerificationContext? context) = await deviceSigned.VerifyVerboseAsync(
                docType, encodedSessionTranscript, deviceVerificationKey, pool,
                parseCoseSign1AllowingNilPayload, encodeDeviceAuthenticationBytes, buildSigStructure, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }
    }


    extension(MdocPresentationDocument presentation)
    {
        /// <summary>
        /// Verifies the device-side COSE_Sign1 on the presentation's
        /// <see cref="MdocPresentationDocument.DeviceSigned"/> and returns the intermediate state —
        /// the canonical body <c>VerifyDeviceSignedAsync</c> forwards to. Delegates to the
        /// <see cref="MdocDeviceSigned"/> device-signed verifier with the document's docType.
        /// </summary>
        /// <param name="sessionTranscript">The SessionTranscript bytes; MUST be byte-identical to what the wallet signed.</param>
        /// <param name="deviceVerificationKey">The device public key, typically resolved from the MSO after the issuer signature has verified.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1AllowingNilPayload">Delegate that parses the nil-payload COSE_Sign1. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</param>
        /// <param name="encodeDeviceAuthenticationBytes">Delegate that reconstructs the DeviceAuthenticationBytes. Wired to <c>Verifiable.Cbor.Mdoc.MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The signature outcome and, once the signature verifies, the
        /// <see cref="MdocDeviceSignedVerificationContext"/>.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when <see cref="MdocPresentationDocument.DeviceSigned"/> is <see langword="null"/>
        /// — there is no device signature to verify.
        /// </exception>
        public async ValueTask<(bool Result, MdocDeviceSignedVerificationContext? Context)> VerifyDeviceSignedVerboseAsync(
            ReadOnlyMemory<byte> sessionTranscript,
            PublicKeyMemory deviceVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytesDelegate encodeDeviceAuthenticationBytes,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(presentation);

            if(presentation.DeviceSigned is not MdocDeviceSigned deviceSigned)
            {
                throw new InvalidOperationException(
                    "MdocPresentationDocument.DeviceSigned is null; call DeviceSignAsync before verifying.");
            }

            return await deviceSigned.VerifyVerboseAsync(
                presentation.DocType, sessionTranscript, deviceVerificationKey, pool,
                parseCoseSign1AllowingNilPayload, encodeDeviceAuthenticationBytes, buildSigStructure, cancellationToken).ConfigureAwait(false);
        }


        /// <summary>
        /// Verifies the device-side COSE_Sign1 on the presentation's
        /// <see cref="MdocPresentationDocument.DeviceSigned"/>. Forwards to
        /// <c>VerifyDeviceSignedVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="sessionTranscript">The SessionTranscript bytes; MUST be byte-identical to what the wallet signed.</param>
        /// <param name="deviceVerificationKey">The device public key.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1AllowingNilPayload">Delegate that parses the nil-payload COSE_Sign1. Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1AllowingNilPayload</c>.</param>
        /// <param name="encodeDeviceAuthenticationBytes">Delegate that reconstructs the DeviceAuthenticationBytes. Wired to <c>Verifiable.Cbor.Mdoc.MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes</c>.</param>
        /// <param name="buildSigStructure">Delegate that builds the COSE Sig_structure. Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><see langword="true"/> when the device signature verifies; otherwise <see langword="false"/>.</returns>
        /// <exception cref="InvalidOperationException">Thrown when <see cref="MdocPresentationDocument.DeviceSigned"/> is <see langword="null"/>.</exception>
        public async ValueTask<bool> VerifyDeviceSignedAsync(
            ReadOnlyMemory<byte> sessionTranscript,
            PublicKeyMemory deviceVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1AllowingNilPayload,
            EncodeDeviceAuthenticationBytesDelegate encodeDeviceAuthenticationBytes,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            (bool result, MdocDeviceSignedVerificationContext? context) = await presentation.VerifyDeviceSignedVerboseAsync(
                sessionTranscript, deviceVerificationKey, pool,
                parseCoseSign1AllowingNilPayload, encodeDeviceAuthenticationBytes, buildSigStructure, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }
    }
}

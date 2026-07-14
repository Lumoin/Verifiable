using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Verification orchestration for issued SD-CWT tokens — pairs the POCO
/// <see cref="SdToken{TEnvelope}"/> (with the SD-CWT envelope shape
/// <see cref="ReadOnlyMemory{T}"/> of <see cref="byte"/>) with the COSE_Sign1
/// verification path and the disclosure-to-path digest binding.
/// </summary>
/// <remarks>
/// <para>
/// Verification is crypto orchestration — the COSE_Sign1 signature check
/// (<c>Cose.VerifyAsync</c>) plus disclosure-to-path digest binding — not serialization,
/// so it lives beside the credential model and the key-binding code
/// (<c>KbCwtVerification</c>) rather than in <c>Verifiable.Cbor</c>. The CBOR the
/// orchestration touches — parsing the COSE_Sign1 wire form and recomputing the
/// disclosure-to-path bindings from the redacted payload — crosses delegate seams the
/// application wires to <c>Verifiable.Cbor</c> implementations:
/// <see cref="ParseCoseSign1Delegate"/> (wired to
/// <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>),
/// <see cref="ExtractSdCwtPathsDelegate"/> (wired to
/// <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>), and
/// <see cref="BuildSigStructureDelegate"/> (wired to
/// <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>). The issuance side
/// is the sibling <see cref="SdCwtIssuanceExtensions"/>, which crosses its own CBOR
/// issue-pipeline seam (<see cref="IssueSdCwtVerboseDelegate"/>, wired to
/// <c>Verifiable.Cbor.Sd.SdCwtIssuance.IssueVerboseAsync</c>).
/// </para>
/// <para>
/// Mirrors the registry/delegate split <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, CancellationToken)"/>
/// vs <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CancellationToken)"/>
/// already exposes: the explicit-delegate overload carries the entire verification body; the
/// registry overload resolves the verification function via
/// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> and then delegates.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension hosts are clearly distinct.")]
public static class SdCwtVerificationExtensions
{
    extension(SdToken<ReadOnlyMemory<byte>> token)
    {
        /// <summary>
        /// Verifies the COSE_Sign1 signature on the SD-CWT envelope against
        /// <paramref name="issuerVerificationKey"/> using
        /// <paramref name="verificationDelegate"/>. The signature covers the
        /// protected header and the redacted payload — selective disclosures
        /// in the unprotected header don't participate, so a presentation
        /// token produced by <see cref="SdToken{TEnvelope}.SelectDisclosures(System.Func{SdDisclosure, bool}, MemoryPool{byte})"/>
        /// verifies under the same issuer key as the original.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="verificationDelegate">The verification function to use.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> when the issuer signature verifies under
        /// <paramref name="issuerVerificationKey"/>; <see langword="false"/>
        /// otherwise.
        /// </returns>
        public async ValueTask<bool> VerifyIssuerSignatureAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            VerificationDelegate verificationDelegate,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(token);
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(verificationDelegate);
            ArgumentNullException.ThrowIfNull(parseCoseSign1);
            ArgumentNullException.ThrowIfNull(buildSigStructure);

            using CoseSign1Message message = parseCoseSign1(token.IssuerSigned, pool);

            return await Cose.VerifyAsync(
                message,
                buildSigStructure,
                issuerVerificationKey,
                verificationDelegate,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }


        /// <summary>
        /// Verifies the COSE_Sign1 signature on the SD-CWT envelope against
        /// <paramref name="issuerVerificationKey"/>, resolving the
        /// verification function from
        /// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/>
        /// via the key's <see cref="SensitiveMemory.Tag"/>. Delegates to the
        /// <see cref="VerificationDelegate"/>-accepting overload above with
        /// the resolved function — callers that need a non-registry function
        /// (custom backend, test stub, hardware-bound verifier) should call
        /// the other overload directly.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// <see langword="true"/> when the issuer signature verifies under
        /// <paramref name="issuerVerificationKey"/>; <see langword="false"/>
        /// otherwise.
        /// </returns>
        public ValueTask<bool> VerifyIssuerSignatureAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            BuildSigStructureDelegate buildSigStructure,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);

            CryptoAlgorithm algorithm = issuerVerificationKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = issuerVerificationKey.Tag.Get<Purpose>();
            VerificationDelegate verificationDelegate =
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return token.VerifyIssuerSignatureAsync(
                issuerVerificationKey, pool, verificationDelegate, parseCoseSign1, buildSigStructure, cancellationToken);
        }


        /// <summary>
        /// Structurally verifies the SD-CWT and returns the intermediate state — the
        /// parameter-taking canonical body. Checks the issuer signature, then binds each
        /// holder-selected disclosure to its claim path via the redacted payload's digests.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The signature step covers the protected header and redacted payload only. The
        /// digest-binding step parses <em>only</em> the payload from
        /// <see cref="SdToken{TEnvelope}.IssuerSigned"/> and binds against
        /// <see cref="SdToken{TEnvelope}.Disclosures"/> — the holder-selected set. The wire
        /// form's unprotected header still carries the issuer's original full disclosure set;
        /// re-reading it would process claims the holder chose not to present, so it is never
        /// read here. A disclosure with no matching digest in the payload is reported with
        /// <see cref="SdClaimVerificationFailureReason.DigestMismatch"/>.
        /// </para>
        /// <para>
        /// On success or digest-mismatch the returned <see cref="SdCwtVerificationContext"/> is
        /// non-null and owned by the caller (dispose it). When the issuer signature is invalid the
        /// context is <see langword="null"/> — no payload is parsed. Production callers use
        /// <c>VerifyAsync</c>, which discards the context.
        /// </para>
        /// </remarks>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="verificationDelegate">The verification function to use.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="encoder">Delegate for Base64Url encoding used in disclosure-digest computation.</param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The verification result and, once past the signature check, the
        /// <see cref="SdCwtVerificationContext"/> with the parsed message and bound-path map.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned SdCwtVerificationContext takes ownership of the parsed message; the caller disposes the context.")]
        public async ValueTask<(SdVerificationResult Result, SdCwtVerificationContext? Context)> VerifyVerboseAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            VerificationDelegate verificationDelegate,
            ParseCoseSign1Delegate parseCoseSign1,
            ExtractSdCwtPathsDelegate extractPaths,
            BuildSigStructureDelegate buildSigStructure,
            EncodeDelegate encoder,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(token);
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(verificationDelegate);
            ArgumentNullException.ThrowIfNull(parseCoseSign1);
            ArgumentNullException.ThrowIfNull(extractPaths);
            ArgumentNullException.ThrowIfNull(buildSigStructure);
            ArgumentNullException.ThrowIfNull(encoder);

            bool signatureValid = await token.VerifyIssuerSignatureAsync(
                issuerVerificationKey, pool, verificationDelegate, parseCoseSign1, buildSigStructure, cancellationToken).ConfigureAwait(false);
            if(!signatureValid)
            {
                return (SdVerificationResult.Failed(SdVerificationFailureReason.IssuerSignatureInvalid), null);
            }

            //Parse ONLY the payload. token.IssuerSigned still carries the issuer's original
            //full disclosure set in its unprotected header; the verifier must trust the
            //holder-selected token.Disclosures, so disclosures are never re-read from the wire.
            //The returned context takes ownership of the message; the caller disposes the context.
            CoseSign1Message message = parseCoseSign1(token.IssuerSigned, pool);

            IReadOnlyDictionary<SdDisclosure, CredentialPath> boundPaths =
                extractPaths(message.Payload, token.Disclosures, encoder, pool, hashAlgorithm);

            var claimResults = new List<SdClaimVerificationResult>(token.Disclosures.Count);
            bool allBound = true;
            foreach(SdDisclosure disclosure in token.Disclosures)
            {
                if(boundPaths.TryGetValue(disclosure, out CredentialPath path))
                {
                    claimResults.Add(SdClaimVerificationResult.Success(path));
                }
                else
                {
                    //An unbound disclosure has no path in the payload; label the failure with
                    //the claim name when present (object property) or the root (array element).
                    CredentialPath failedPath = disclosure.ClaimName is { } claimName
                        ? CredentialPath.FromJsonPointer($"/{claimName}")
                        : CredentialPath.Root;
                    claimResults.Add(SdClaimVerificationResult.Failed(
                        failedPath, SdClaimVerificationFailureReason.DigestMismatch));
                    allBound = false;
                }
            }

            SdVerificationResult result = allBound
                ? SdVerificationResult.Success(claimResults)
                : SdVerificationResult.Failed(SdVerificationFailureReason.ClaimVerificationFailed, claimResults);

            return (result, new SdCwtVerificationContext(message, boundPaths));
        }


        /// <summary>
        /// Structurally verifies the SD-CWT, returning a per-claim <see cref="SdVerificationResult"/>.
        /// Forwards to <c>VerifyVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="verificationDelegate">The verification function to use.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="encoder">Delegate for Base64Url encoding used in disclosure-digest computation.</param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// A <see cref="SdVerificationResult"/> that is valid only when the issuer signature
        /// verifies and every selected disclosure binds to a path in the payload.
        /// </returns>
        public async ValueTask<SdVerificationResult> VerifyAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            VerificationDelegate verificationDelegate,
            ParseCoseSign1Delegate parseCoseSign1,
            ExtractSdCwtPathsDelegate extractPaths,
            BuildSigStructureDelegate buildSigStructure,
            EncodeDelegate encoder,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            (SdVerificationResult result, SdCwtVerificationContext? context) = await token.VerifyVerboseAsync(
                issuerVerificationKey, pool, verificationDelegate, parseCoseSign1, extractPaths, buildSigStructure, encoder, hashAlgorithm, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }


        /// <summary>
        /// Structurally verifies the SD-CWT and returns the intermediate state, resolving the
        /// verification function from <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/>
        /// via the key's tag and forwarding to the <see cref="VerificationDelegate"/>-accepting overload.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="encoder">Delegate for Base64Url encoding used in disclosure-digest computation.</param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result and, once past the signature check, the context.</returns>
        public ValueTask<(SdVerificationResult Result, SdCwtVerificationContext? Context)> VerifyVerboseAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            ExtractSdCwtPathsDelegate extractPaths,
            BuildSigStructureDelegate buildSigStructure,
            EncodeDelegate encoder,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);

            CryptoAlgorithm algorithm = issuerVerificationKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = issuerVerificationKey.Tag.Get<Purpose>();
            VerificationDelegate verificationDelegate =
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return token.VerifyVerboseAsync(
                issuerVerificationKey, pool, verificationDelegate, parseCoseSign1, extractPaths, buildSigStructure, encoder, hashAlgorithm, cancellationToken);
        }


        /// <summary>
        /// Structurally verifies the SD-CWT, resolving the verification function from
        /// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> via the key's tag
        /// and forwarding to the <see cref="VerificationDelegate"/>-accepting overload.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool the parsed message rents its carriers from.</param>
        /// <param name="parseCoseSign1">
        /// Delegate that parses the COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
        /// </param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Cbor.SdCwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="buildSigStructure">
        /// Delegate that builds the COSE Sig_structure for the signature check.
        /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
        /// </param>
        /// <param name="encoder">Delegate for Base64Url encoding used in disclosure-digest computation.</param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A per-claim <see cref="SdVerificationResult"/>.</returns>
        public ValueTask<SdVerificationResult> VerifyAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ParseCoseSign1Delegate parseCoseSign1,
            ExtractSdCwtPathsDelegate extractPaths,
            BuildSigStructureDelegate buildSigStructure,
            EncodeDelegate encoder,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);

            CryptoAlgorithm algorithm = issuerVerificationKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = issuerVerificationKey.Tag.Get<Purpose>();
            VerificationDelegate verificationDelegate =
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return token.VerifyAsync(
                issuerVerificationKey, pool, verificationDelegate, parseCoseSign1, extractPaths, buildSigStructure, encoder, hashAlgorithm, cancellationToken);
        }
    }
}

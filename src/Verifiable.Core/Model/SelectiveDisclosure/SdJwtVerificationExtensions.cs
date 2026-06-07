using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Verification orchestration for issued SD-JWT tokens — pairs the POCO
/// <see cref="SdToken{TEnvelope}"/> (with the SD-JWT envelope shape <see cref="string"/>, the
/// compact JWS) with the JWS verification path and the disclosure-to-path digest binding.
/// </summary>
/// <remarks>
/// <para>
/// Verification is crypto orchestration — the issuer JWS signature check
/// (<c>Jws.VerifyAsync</c>) plus disclosure-to-path digest binding — not serialization, so it
/// lives beside the credential model and the key-binding code rather than in
/// <c>Verifiable.Json</c>. The JSON the orchestration touches — walking the redacted payload to
/// recompute the disclosure-to-path bindings — crosses the
/// <see cref="ExtractSdJwtPathsDelegate"/> seam the application wires to
/// <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>. The base64url JWK coders are obtained
/// from <see cref="DefaultCoderSelector"/> (a <c>Verifiable.Cryptography</c> registry, not a
/// serialization library), so the compact JWS can be split and its payload segment decoded here.
/// The issuance side is the sibling <see cref="SdJwtIssuanceExtensions"/>, which crosses its own
/// JSON issue-pipeline seam. This mirrors <see cref="SdCwtVerificationExtensions"/> on the SD-CWT side.
/// </para>
/// <para>
/// Mirrors the registry/delegate split the rest of the verification surface exposes: the
/// explicit-<see cref="VerificationDelegate"/> overload carries the entire verification body; the
/// registry overload resolves the verification function via
/// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> and then forwards.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension hosts are clearly distinct.")]
public static class SdJwtVerificationExtensions
{
    extension(SdToken<string> token)
    {
        /// <summary>
        /// Structurally verifies the SD-JWT and returns the intermediate state — the
        /// parameter-taking canonical body. Checks the issuer JWS signature, then binds each
        /// holder-selected disclosure to its claim path via the payload's <c>_sd</c> digests.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The compact form in <see cref="SdToken{TEnvelope}.IssuerSigned"/> is the bare JWS
        /// (<c>header.payload.signature</c>) and carries no disclosures — those live in
        /// <see cref="SdToken{TEnvelope}.Disclosures"/>, the holder-selected set. The signature
        /// covers the redacted payload; the binding step (<paramref name="extractPaths"/>) parses
        /// that payload and matches its <c>_sd</c> digests against the selected disclosures. A
        /// disclosure with no matching digest is reported with
        /// <see cref="SdClaimVerificationFailureReason.DigestMismatch"/>.
        /// </para>
        /// <para>
        /// On success or digest-mismatch the returned <see cref="SdJwtVerificationContext"/> is
        /// non-null and owned by the caller (dispose it). When the issuer signature is invalid the
        /// context is <see langword="null"/> — no payload is decoded. Production callers use
        /// <c>VerifyAsync</c>, which discards the context.
        /// </para>
        /// </remarks>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool for decoding and signing-input allocations.</param>
        /// <param name="verificationDelegate">The verification function to use.</param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        /// The verification result and, once past the signature check, the
        /// <see cref="SdJwtVerificationContext"/> with the redacted payload and bound-path map.
        /// </returns>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The returned SdJwtVerificationContext takes ownership of the decoded payload buffer; the caller disposes the context.")]
        public async ValueTask<(SdVerificationResult Result, SdJwtVerificationContext? Context)> VerifyVerboseAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            VerificationDelegate verificationDelegate,
            ExtractSdJwtPathsDelegate extractPaths,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(token);
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(verificationDelegate);
            ArgumentNullException.ThrowIfNull(extractPaths);

            DecodeDelegate decoder = DefaultCoderSelector.SelectDecoder(WellKnownKeyFormats.PublicKeyJwk);
            EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

            //Verify the issuer JWS signature over header.payload. Jws.VerifyAsync requires a
            //payload decoder for symmetry with VerifyAndDecodeAsync but does not invoke it for
            //signature-only verification, so a no-op decoder suffices; the payload is decoded
            //separately below.
            bool signatureValid = await Jws.VerifyAsync(
                token.IssuerSigned, decoder, NoPayloadDecode, pool,
                issuerVerificationKey, verificationDelegate, cancellationToken).ConfigureAwait(false);
            if(!signatureValid)
            {
                return (SdVerificationResult.Failed(SdVerificationFailureReason.IssuerSignatureInvalid), null);
            }

            //Bind each holder-selected disclosure to its path. extractPaths parses the payload
            //from token.IssuerSigned and matches its _sd digests against token.Disclosures (the
            //selected set); the compact form carries no original full set to leak.
            IReadOnlyDictionary<SdDisclosure, CredentialPath> boundPaths =
                extractPaths(token, decoder, encoder, pool, hashAlgorithm);

            //Decode the redacted payload segment to expose it as a verbose intermediate. The
            //compact form verified above, so it has exactly three parts. The returned context
            //takes ownership of the rented buffer; the caller disposes the context.
            string payloadSegment = token.IssuerSigned.Split('.')[1];
            IMemoryOwner<byte> payloadOwner = decoder(payloadSegment, pool);

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

            return (result, new SdJwtVerificationContext(payloadOwner, boundPaths));
        }


        /// <summary>
        /// Structurally verifies the SD-JWT, returning a per-claim <see cref="SdVerificationResult"/>.
        /// Forwards to <c>VerifyVerboseAsync</c> and discards the intermediate context.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool for decoding and signing-input allocations.</param>
        /// <param name="verificationDelegate">The verification function to use.</param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>.
        /// </param>
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
            ExtractSdJwtPathsDelegate extractPaths,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            (SdVerificationResult result, SdJwtVerificationContext? context) = await token.VerifyVerboseAsync(
                issuerVerificationKey, pool, verificationDelegate, extractPaths, hashAlgorithm, cancellationToken).ConfigureAwait(false);

            context?.Dispose();
            return result;
        }


        /// <summary>
        /// Structurally verifies the SD-JWT and returns the intermediate state, resolving the
        /// verification function from <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/>
        /// via the key's tag and forwarding to the <see cref="VerificationDelegate"/>-accepting overload.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool for decoding and signing-input allocations.</param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The verification result and, once past the signature check, the context.</returns>
        public ValueTask<(SdVerificationResult Result, SdJwtVerificationContext? Context)> VerifyVerboseAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ExtractSdJwtPathsDelegate extractPaths,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);

            CryptoAlgorithm algorithm = issuerVerificationKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = issuerVerificationKey.Tag.Get<Purpose>();
            VerificationDelegate verificationDelegate =
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return token.VerifyVerboseAsync(
                issuerVerificationKey, pool, verificationDelegate, extractPaths, hashAlgorithm, cancellationToken);
        }


        /// <summary>
        /// Structurally verifies the SD-JWT, resolving the verification function from
        /// <see cref="CryptoFunctionRegistry{CryptoAlgorithm, Purpose}"/> via the key's tag
        /// and forwarding to the <see cref="VerificationDelegate"/>-accepting overload.
        /// </summary>
        /// <param name="issuerVerificationKey">The issuer's public key for signature verification.</param>
        /// <param name="pool">Memory pool for decoding and signing-input allocations.</param>
        /// <param name="extractPaths">
        /// Delegate that binds the holder-selected disclosures to their credential paths from the
        /// redacted payload. Wired to <c>Verifiable.Json.SdJwtPathExtraction.ExtractPaths</c>.
        /// </param>
        /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A per-claim <see cref="SdVerificationResult"/>.</returns>
        public ValueTask<SdVerificationResult> VerifyAsync(
            PublicKeyMemory issuerVerificationKey,
            MemoryPool<byte> pool,
            ExtractSdJwtPathsDelegate extractPaths,
            string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana,
            CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(issuerVerificationKey);

            CryptoAlgorithm algorithm = issuerVerificationKey.Tag.Get<CryptoAlgorithm>();
            Purpose purpose = issuerVerificationKey.Tag.Get<Purpose>();
            VerificationDelegate verificationDelegate =
                CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

            return token.VerifyAsync(
                issuerVerificationKey, pool, verificationDelegate, extractPaths, hashAlgorithm, cancellationToken);
        }
    }


    /// <summary>
    /// A no-op JWT-part decoder. <see cref="Jws.VerifyAsync{TJwtPart}(string, DecodeDelegate, System.Func{System.ReadOnlySpan{byte}, TJwtPart}, MemoryPool{byte}, PublicKeyMemory, VerificationDelegate, System.Threading.CancellationToken)"/>
    /// requires a part decoder for symmetry with the verify-and-decode path but does not invoke
    /// it for signature-only verification, so the structural verifier supplies this.
    /// </summary>
    private static byte NoPayloadDecode(ReadOnlySpan<byte> _) => 0;
}

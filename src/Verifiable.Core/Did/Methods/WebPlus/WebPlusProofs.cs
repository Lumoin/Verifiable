using System;
using System.Buffers;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// Verifies the detached-JWS <c>proofs</c> of a did:webplus DID document: each proof is a detached, unencoded
/// (RFC 7797 <c>b64:false</c>) JWS over the document's signing input, signed by the key its <c>kid</c> MBPubKey
/// names (did:webplus Draft v0.4, Self-Hashed Signed Data; WP-PRF-1/2/3, WP-VAL-6).
/// </summary>
/// <remarks>
/// <para>
/// The signing input <c>S</c> is the JCS of the document with its <c>proofs</c> member removed and every
/// self-hash slot set to the algorithm's placeholder — the same length-preserving substitution self-hash
/// verification uses, applied here to the document minus its proofs (<see cref="WebPlusSelfHash"/>). Every proof
/// on a document signs the same <c>S</c>, so it is reconstructed once.
/// </para>
/// <para>
/// Each proof is verified under the key named by its <c>kid</c> (an MBPubKey, a multibase-multikey whose
/// self-describing multicodec fixes the algorithm), not under the wire <c>alg</c>, so there is no algorithm
/// confusion; the <c>alg</c> header is additionally checked to name that same algorithm. WP-VAL-6 fails closed:
/// the first proof that does not verify rejects the whole document. A root document carries no proofs and is
/// authorized by the microledger genesis rules, not here.
/// </para>
/// </remarks>
internal static class WebPlusProofs
{
    /// <summary>
    /// The <c>crit</c> extensions a did:webplus proof verifier understands: only <c>b64</c> (RFC 7797), which a
    /// proof header MUST mark critical (<c>"crit":["b64"]</c>).
    /// </summary>
    private static IReadOnlySet<string> UnderstoodCriticalExtensions { get; } =
        new HashSet<string>(StringComparer.Ordinal) { WellKnownJoseHeaderNames.B64 }.ToFrozenSet(StringComparer.Ordinal);


    /// <summary>
    /// Verifies every proof on a did:webplus DID document, failing closed: ANY invalid proof rejects the document
    /// (WP-VAL-6).
    /// </summary>
    /// <param name="received">The received DID document bytes (its JCS form, as served in the microledger).</param>
    /// <param name="selfHash">The document's <c>selfHash</c> value occupying every self-hash slot.</param>
    /// <param name="multihashCode">The multihash code naming the self-hash's hash function, e.g. <see cref="MultihashHeaders.Blake3"/>.</param>
    /// <param name="digestLength">The digest length in bytes for that hash function.</param>
    /// <param name="extractor">The <see cref="WebPlusProofExtractor"/> that extracts the proofs and the JCS of the document with <c>proofs</c> removed.</param>
    /// <param name="base64UrlDecoder">The base64url (no padding) decoder.</param>
    /// <param name="base64UrlEncoder">The base64url (no padding) encoder.</param>
    /// <param name="base58Decoder">The base58btc decoder, used when an MBPubKey is in its base58btc (<c>z</c>) form.</param>
    /// <param name="pool">The memory pool for working buffers.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>
    /// A result whose <see cref="WebPlusProofVerificationResult.Error"/> is <see langword="null"/> when every
    /// proof verifies (or the document carries none) and whose
    /// <see cref="WebPlusProofVerificationResult.SatisfiedKeys"/> are the MBPubKeys (<c>kid</c>) that produced the
    /// valid proofs — the input the microledger's update-rule evaluation consumes (WP-VAL-7e). On the first
    /// invalid proof the error is set and the key set is empty (WP-VAL-6 fails closed).
    /// </returns>
    public static async ValueTask<WebPlusProofVerificationResult> VerifyAllAsync(
        ReadOnlyMemory<byte> received,
        string selfHash,
        ReadOnlyMemory<byte> multihashCode,
        int digestLength,
        WebPlusProofExtractor extractor,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selfHash);
        ArgumentNullException.ThrowIfNull(extractor);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);

        WebPlusProofExtraction extraction = extractor(received);
        ImmutableArray<string> proofs = extraction.Proofs;
        if(proofs.IsDefaultOrEmpty)
        {
            //A root document is self-authorizing and carries no proofs. A non-root document that carries none
            //yields this same empty satisfied-key set, which the microledger replay rejects explicitly in
            //WebPlusMicroledger.ValidateAgainstPredecessorAsync (a non-root document MUST carry at least one valid
            //proof), so an empty result here is not by itself an authorization.
            return new WebPlusProofVerificationResult(null, FrozenSet<string>.Empty);
        }

        //WP-PRF-1: every proof on the document signs the same input S — JCS(document − proofs) with all self-hash
        //slots reduced to the placeholder — so it is reconstructed once and shared across the proofs.
        if(!WebPlusSelfHash.TryRentWithSelfHashSlotsPlaceholdered(
            extraction.SigningInputBase.Span, selfHash, multihashCode.Span, digestLength, base64UrlEncoder, pool, out IMemoryOwner<byte> signingInputOwner, out int signingInputLength))
        {
            return new WebPlusProofVerificationResult($"The did:webplus 'selfHash' '{selfHash}' is not a self-hash of the proof's hash algorithm.", FrozenSet<string>.Empty);
        }

        using(signingInputOwner)
        {
            ReadOnlyMemory<byte> signingInput = signingInputOwner.Memory[..signingInputLength];

            var satisfiedKeys = new HashSet<string>(StringComparer.Ordinal);
            for(int i = 0; i < proofs.Length; i++)
            {
                (string? error, string? kid) = await VerifyProofAsync(
                    proofs[i], signingInput, base64UrlDecoder, base64UrlEncoder, base58Decoder, pool, cancellationToken).ConfigureAwait(false);
                if(error is not null)
                {
                    return new WebPlusProofVerificationResult(error, FrozenSet<string>.Empty);
                }

                satisfiedKeys.Add(kid!);
            }

            return new WebPlusProofVerificationResult(null, satisfiedKeys.ToFrozenSet(StringComparer.Ordinal));
        }
    }


    /// <summary>
    /// Verifies one proof: splits the detached compact JWS, then validates its header and signature, mapping any
    /// malformed-input exception to a fail-closed rejection reason. On success the proof's <c>kid</c> (its
    /// MBPubKey) is returned so the microledger can test it against the predecessor's update rules.
    /// </summary>
    private static async ValueTask<(string? Error, string? Kid)> VerifyProofAsync(
        string proof,
        ReadOnlyMemory<byte> signingInput,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        //WP-PRF-2: a proof is a detached-payload compact JWS — three '.'-separated segments whose middle
        //(payload) segment is empty.
        string[] segments = proof.Split('.');
        if(segments.Length != 3)
        {
            return ("A did:webplus proof MUST be a compact JWS of three '.'-separated segments.", null);
        }

        string protectedSegment = segments[0];
        if(protectedSegment.Length == 0)
        {
            return ("A did:webplus proof MUST carry a protected header.", null);
        }

        if(segments[1].Length != 0)
        {
            return ("A did:webplus proof MUST have a detached (empty) payload.", null);
        }

        if(segments[2].Length == 0)
        {
            return ("A did:webplus proof MUST carry a signature.", null);
        }

        try
        {
            return await VerifyDecodedProofAsync(
                protectedSegment, segments[2], signingInput, base64UrlDecoder, base64UrlEncoder, base58Decoder, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException or NotSupportedException)
        {
            //A malformed protected header, MBPubKey or signature is a rejected proof, not a fault — the input is
            //untrusted wire data.
            return ($"A did:webplus proof could not be verified: {exception.Message}.", null);
        }
    }


    /// <summary>
    /// Validates a proof's protected header (<c>b64:false</c>, <c>crit:["b64"]</c>, <c>kid</c>, <c>alg</c>),
    /// resolves the verifying key from the <c>kid</c> MBPubKey, and verifies the detached unencoded-payload
    /// signature over the signing input (WP-PRF-2/3).
    /// </summary>
    private static async ValueTask<(string? Error, string? Kid)> VerifyDecodedProofAsync(
        string protectedSegment,
        string signatureSegment,
        ReadOnlyMemory<byte> signingInput,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> headerOwner = base64UrlDecoder(protectedSegment, pool);
        ReadOnlyMemory<byte> headerJson = headerOwner.Memory;

        //The header is read member-by-member (b64/crit/kid/alg) with first-occurrence semantics, and its exact
        //bytes are what the signature covers; a header repeating a top-level member is ambiguous — a
        //validate-one/act-on-another smuggling shape — so it is rejected, matching the JWS compact-verify path.
        if(JwkJsonReader.HasDuplicateTopLevelKeys(headerJson.Span))
        {
            return ("A did:webplus proof header MUST NOT repeat a top-level member.", null);
        }

        //WP-PRF-2: the payload is unencoded (RFC 7797 b64:false), and b64 is marked critical so a consumer that
        //does not implement RFC 7797 rejects the proof rather than mis-verifying it as a base64url payload. The
        //header MUST carry b64 explicitly set to false.
        if(!JwkJsonReader.TryExtractBooleanValue(headerJson.Span, WellKnownJoseHeaderNames.B64Utf8, out bool base64UrlPayload) || base64UrlPayload)
        {
            return ("A did:webplus proof header MUST set 'b64' to false (RFC 7797 unencoded payload).", null);
        }

        //RFC 7797 §6: because the payload is unencoded (b64:false), b64 MUST be listed in 'crit' so a consumer that
        //does not implement RFC 7797 rejects the proof rather than mis-verifying it. 'crit' MUST therefore be
        //PRESENT and name b64 — an absent 'crit' is not sufficient (RFC 7515 treats 'crit' as optional in general,
        //but RFC 7797 §6 makes it mandatory here) — and every listed critical extension must be one this verifier
        //understands (only b64).
        if(!JoseCriticalHeaderValidation.MarksCritical(headerJson.Span, WellKnownJoseHeaderNames.B64)
            || !JoseCriticalHeaderValidation.IsSatisfied(headerJson.Span, UnderstoodCriticalExtensions))
        {
            return ("A did:webplus proof header MUST mark 'b64' critical (\"crit\":[\"b64\"]).", null);
        }

        string? kid = JwkJsonReader.ExtractStringValue(headerJson.Span, WellKnownJwkMemberNames.KidUtf8);
        if(kid is not { Length: > 0 })
        {
            return ("A did:webplus proof header MUST carry a 'kid' (the signing key's MBPubKey).", null);
        }

        string? algorithmName = JwkJsonReader.ExtractStringValue(headerJson.Span, WellKnownJwkMemberNames.AlgUtf8);
        if(algorithmName is not { Length: > 0 })
        {
            return ("A did:webplus proof header MUST carry an 'alg'.", null);
        }

        (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) decoded =
            CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(kid, pool, base58Decoder);

        using(decoded.keyMaterial)
        {
            //WP-PRF-3: the proof is verified under the algorithm the MBPubKey's self-describing multicodec fixes,
            //never the wire 'alg', so an attacker cannot swap algorithms; the 'alg' header is then checked to
            //name that same algorithm.
            string? expectedAlgorithmName = WebPlusAlgorithmName(decoded.Algorithm);
            if(expectedAlgorithmName is null)
            {
                return ($"A did:webplus proof key algorithm '{decoded.Algorithm}' is not supported.", null);
            }

            if(!string.Equals(algorithmName, expectedAlgorithmName, StringComparison.Ordinal))
            {
                return ($"A did:webplus proof 'alg' '{algorithmName}' does not match its key algorithm '{expectedAlgorithmName}'.", null);
            }

            using IMemoryOwner<byte> signatureOwner = base64UrlDecoder(signatureSegment, pool);

            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(decoded.Algorithm, Purpose.Verification);

            bool valid = await Jws.VerifySignatureAsync(
                protectedSegment,
                signingInput,
                base64UrlPayload: false,
                signatureOwner.Memory,
                base64UrlEncoder,
                verify,
                decoded.keyMaterial.Memory,
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            return valid ? (null, kid) : ("A did:webplus proof signature is invalid.", null);
        }
    }


    /// <summary>
    /// The did:webplus JWS <c>alg</c> name expected for a key algorithm, or <see langword="null"/> when the
    /// algorithm is not supported for a did:webplus proof. The Draft v0.4 worked example fixes the Ed25519 name;
    /// further algorithms are added here as their conformance vectors land.
    /// </summary>
    private static string? WebPlusAlgorithmName(CryptoAlgorithm algorithm)
    {
        return algorithm.Equals(CryptoAlgorithm.Ed25519) ? WellKnownWebPlusValues.Ed25519SignatureAlgorithm : null;
    }
}


/// <summary>
/// The outcome of verifying a did:webplus document's proofs: the rejection reason (or <see langword="null"/> when
/// every proof verified, WP-VAL-6) and the MBPubKeys (<c>kid</c>) that produced the valid proofs — the set the
/// microledger's update-rule evaluation consumes (WP-VAL-7e).
/// </summary>
/// <param name="Error">The reason a proof is invalid, or <see langword="null"/> when all proofs verified.</param>
/// <param name="SatisfiedKeys">The MBPubKeys of the valid proofs; empty when <paramref name="Error"/> is set.</param>
internal readonly record struct WebPlusProofVerificationResult(string? Error, IReadOnlySet<string> SatisfiedKeys);
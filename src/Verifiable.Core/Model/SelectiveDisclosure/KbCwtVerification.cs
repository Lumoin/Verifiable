using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Core.Model.SelectiveDisclosure;

/// <summary>
/// Parses and cryptographically verifies an SD-CWT presented as an SD-CWT Key
/// Binding Token (KBT) per
/// <see href="https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html">
/// draft-ietf-spice-sd-cwt §7.1</see>. The CBOR/COSE twin of <c>KbCwtIssuance</c>.
/// </summary>
/// <remarks>
/// <para>
/// This class contains no serialization dependencies. The KBT is a COSE_Sign1 the
/// holder signs; unlike the SD-JWT KB-JWT there is <strong>no <c>sd_hash</c></strong> —
/// the binding is that the holder signs over the embedded presentation SD-CWT, which
/// rides in the KBT protected header under the <c>kcwt</c> parameter (label 13).
/// All CBOR parsing/extraction flows through delegate seams the application wires to
/// <c>Verifiable.Cbor</c> implementations; the cryptographic steps flow through
/// <c>Cose.VerifyAsync</c> (holder signature) and the existing SD-CWT verification
/// reachable on <see cref="SdToken{TEnvelope}"/> (issuer signature plus per-disclosure
/// digest binding).
/// </para>
/// <para>
/// The verification sequence:
/// </para>
/// <list type="number">
///   <item><description>Parse the KBT COSE_Sign1 from the wire bytes via <see cref="ParseCoseSign1Delegate"/>.</description></item>
///   <item><description>Extract the embedded SD-CWT from the KBT protected-header <c>kcwt</c> via <see cref="ExtractKcwtFromKbtDelegate"/>.</description></item>
///   <item><description>Parse the embedded SD-CWT into an <see cref="SdToken{TEnvelope}"/> via <see cref="ParseSdCwtTokenDelegate"/>.</description></item>
///   <item><description>Extract the holder public key from the embedded SD-CWT <c>cnf</c> COSE_Key via <see cref="ExtractSdCwtHolderKeyDelegate"/>.</description></item>
///   <item><description>Verify the KBT holder signature against the holder key via <c>Cose.VerifyAsync</c>.</description></item>
///   <item><description>Read KBT payload claims <c>aud</c>/<c>iat</c>/<c>cnonce</c> via <see cref="ReadKbtCwtClaimsDelegate"/>.</description></item>
///   <item><description>Resolve the issuer key from the embedded SD-CWT <c>iss</c> via <see cref="ExtractSdCwtIssuerDelegate"/> + <see cref="ResolveSdCwtIssuerKeyDelegate"/>.</description></item>
///   <item><description>Verify the embedded SD-CWT (issuer signature + per-disclosure digest binding) reusing the existing SD-CWT verification.</description></item>
///   <item><description>Collect disclosed claims from the embedded SD-CWT disclosures.</description></item>
/// </list>
/// <para>
/// What this is: the holder's presentation-time proof of possession of the key the issuer bound into
/// the credential (the <c>cnf</c> claim) — the SD-CWT form of the holder binding a verifiable
/// presentation carries. The same role appears as SD-JWT's <c>KB-JWT</c>, mdoc's <c>DeviceAuth</c>,
/// and Data Integrity's authentication-purpose presentation proof.
/// </para>
/// </remarks>
public static class KbCwtVerification
{
    /// <summary>
    /// Verifies an SD-CWT Key Binding Token and returns the extracted, verified contents.
    /// </summary>
    /// <param name="kbtToken">The serialized SD-CWT Key Binding Token (COSE_Sign1) wire bytes.</param>
    /// <param name="parseCoseSign1">
    /// Delegate that parses a COSE_Sign1 wire form into a <see cref="CoseSign1Message"/>.
    /// Wired to <c>Verifiable.Cbor.CoseSerialization.ParseCoseSign1</c>.
    /// </param>
    /// <param name="extractKcwt">
    /// Delegate that extracts the embedded SD-CWT bytes from the KBT protected-header
    /// <c>kcwt</c> parameter. Wired to <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractKcwt</c>.
    /// </param>
    /// <param name="parseSdCwt">
    /// Delegate that parses the embedded SD-CWT wire bytes into an
    /// <see cref="SdToken{TEnvelope}"/>. Wired to
    /// <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ParseEmbeddedSdCwt</c>.
    /// </param>
    /// <param name="extractHolderKey">
    /// Delegate that reconstructs the holder public key from the embedded SD-CWT
    /// <c>cnf</c> COSE_Key. Wired to <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractHolderKey</c>.
    /// </param>
    /// <param name="readKbtClaims">
    /// Delegate that reads <c>aud</c>/<c>iat</c>/<c>cnonce</c> from the KBT payload.
    /// Wired to <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ReadKbtClaims</c>.
    /// </param>
    /// <param name="extractIssuer">
    /// Delegate that reads the <c>iss</c> claim from the embedded SD-CWT payload.
    /// Wired to <c>Verifiable.Cbor.Sd.SdCwtVpParsing.ExtractIssuer</c>.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Application-provided delegate that resolves the issuer's public key from its identifier.
    /// </param>
    /// <param name="verifyCredential">
    /// Delegate that verifies the embedded SD-CWT in full (issuer signature plus
    /// per-disclosure digest binding). Wired to the existing SD-CWT verification —
    /// typically <c>SdCwtVerificationExtensions.VerifyAsync</c>.
    /// </param>
    /// <param name="buildSigStructure">
    /// Delegate that builds the COSE Sig_structure for the holder-signature check.
    /// Wired to <c>Verifiable.Cbor.CoseSerialization.BuildSigStructure</c>.
    /// </param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The parsed and crypto-verified KBT contents.</returns>
    public static async ValueTask<SdCwtKbtVerificationResult> VerifyAsync(
        ReadOnlyMemory<byte> kbtToken,
        ParseCoseSign1Delegate parseCoseSign1,
        ExtractKcwtFromKbtDelegate extractKcwt,
        ParseSdCwtTokenDelegate parseSdCwt,
        ExtractSdCwtHolderKeyDelegate extractHolderKey,
        ReadKbtCwtClaimsDelegate readKbtClaims,
        ExtractSdCwtIssuerDelegate extractIssuer,
        ResolveSdCwtIssuerKeyDelegate resolveIssuerKey,
        VerifySdCwtCredentialDelegate verifyCredential,
        BuildSigStructureDelegate buildSigStructure,
        CommitmentReuseDetectionSeam? saltReuseSeam,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(parseCoseSign1);
        ArgumentNullException.ThrowIfNull(extractKcwt);
        ArgumentNullException.ThrowIfNull(parseSdCwt);
        ArgumentNullException.ThrowIfNull(extractHolderKey);
        ArgumentNullException.ThrowIfNull(readKbtClaims);
        ArgumentNullException.ThrowIfNull(extractIssuer);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(verifyCredential);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        //Parse the KBT COSE_Sign1 from the wire bytes. The message owns its
        //pool-routed protected-header and signature carriers; dispose it once
        //the holder-signature check and claim reads are done.
        using CoseSign1Message parsedKbt = parseCoseSign1(kbtToken, pool);

        //Extract and parse the embedded presentation SD-CWT from the kcwt
        //protected-header parameter. The parsed token owns its disclosures;
        //dispose it after collecting the disclosed claims.
        ReadOnlyMemory<byte> embeddedSdCwt = extractKcwt(parsedKbt.ProtectedHeader.AsReadOnlyMemory());
        using SdToken<ReadOnlyMemory<byte>> embeddedToken = parseSdCwt(embeddedSdCwt);

        //Reconstruct the holder public key from the embedded SD-CWT cnf COSE_Key
        //and verify the KBT holder signature against it.
        bool holderSignatureValid = false;
        using(PublicKeyMemory? holderPublicKey = extractHolderKey(embeddedToken, pool))
        {
            if(holderPublicKey is not null)
            {
                holderSignatureValid = await Cose.VerifyAsync(
                    parsedKbt,
                    buildSigStructure,
                    holderPublicKey,
                    cancellationToken).ConfigureAwait(false);
            }
        }

        //Read the session-binding claims (aud/iat/cnonce) from the KBT payload.
        KbtCwtClaims kbtClaims = readKbtClaims(parsedKbt.Payload);

        //Resolve the issuer key from the embedded SD-CWT iss claim, then verify the
        //embedded SD-CWT in full: issuer signature plus per-disclosure digest binding.
        //The digest binding is performed by the existing SD-CWT verification — not
        //reimplemented here.
        string? issuer = extractIssuer(embeddedToken);
        PublicKeyMemory? issuerPublicKey = issuer is not null ? resolveIssuerKey(issuer) : null;

        bool credentialSignatureValid = false;
        if(issuerPublicKey is not null)
        {
            credentialSignatureValid = await verifyCredential(
                embeddedToken, issuerPublicKey, pool, cancellationToken).ConfigureAwait(false);
        }

        //Collect disclosed claims from the embedded SD-CWT disclosures, and observe the shortest salt
        //length (the verifier-side salt-length signal — RFC 9901 §9.3).
        var disclosedClaims = new Dictionary<string, string>();
        int? minimumSaltLength = null;
        foreach(SdDisclosure disclosure in embeddedToken.Disclosures)
        {
            int saltLength = disclosure.Salt.Length;
            if(minimumSaltLength is null || saltLength < minimumSaltLength)
            {
                minimumSaltLength = saltLength;
            }

            if(disclosure.ClaimName is not null)
            {
                disclosedClaims[disclosure.ClaimName] = disclosure.ClaimValue?.ToString() ?? "";
            }
        }

        //Salt-reuse detection (opt-in): commit to each disclosure salt while the embedded token's salts
        //are still alive, and ask the application store. Only true when a seam was wired and a reuse
        //was found — the verifier mirror of DPoP-JTI replay.
        bool saltReused = false;
        if(saltReuseSeam is not null)
        {
            var commitments = new List<DigestValue>();
            try
            {
                foreach(SdDisclosure disclosure in embeddedToken.Disclosures)
                {
                    commitments.Add(disclosure.Salt.ComputeCommitment(
                        saltReuseSeam.HashFunction, saltReuseSeam.HashOutputByteLength, saltReuseSeam.HashTag, pool));
                }

                IReadOnlyList<DigestValue> reused = await CommitmentReuseDetection.DetectAsync(
                    commitments, saltReuseSeam.IsSeen, saltReuseSeam.Record, cancellationToken).ConfigureAwait(false);
                saltReused = reused.Count > 0;
            }
            finally
            {
                foreach(DigestValue commitment in commitments)
                {
                    commitment.Dispose();
                }
            }
        }

        return new SdCwtKbtVerificationResult
        {
            HolderSignatureValid = holderSignatureValid,
            CredentialSignatureValid = credentialSignatureValid,
            Issuer = issuer,
            Audience = kbtClaims.Aud,
            Cnonce = kbtClaims.Cnonce,
            IssuedAt = kbtClaims.Iat,
            DisclosedClaims = disclosedClaims,
            MinimumDisclosureSaltLengthBytes = minimumSaltLength,
            SaltReused = saltReused
        };
    }
}

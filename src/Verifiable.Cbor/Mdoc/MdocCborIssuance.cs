using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Configuration carried into <see cref="MdocCborIssuance.SignAsync"/> — the
/// fields the issuer commits to that are NOT already on the logical
/// <see cref="MdocDocument"/>.
/// </summary>
/// <remarks>
/// <para>
/// The logical document from <see cref="MdocIssuance.BuildDocument"/>
/// carries the doctype, namespaces, claim items, randoms, and digestIDs.
/// The signing step adds the MSO-specific commitments:
/// <see cref="DigestAlgorithm"/> (how items hash), <see cref="DeviceKey"/>
/// (which wallet key the credential binds to), and
/// <see cref="Validity"/> (the temporal bounds).
/// </para>
/// </remarks>
public sealed class MdocIssuerSigningConfig
{
    /// <summary>
    /// The IANA hash-algorithm name used for the MSO <c>valueDigests</c>
    /// commitments — one of <see cref="MdocMsoWellKnownKeys.DigestAlgorithmSha256"/>,
    /// <see cref="MdocMsoWellKnownKeys.DigestAlgorithmSha384"/>, or
    /// <see cref="MdocMsoWellKnownKeys.DigestAlgorithmSha512"/>.
    /// </summary>
    public required string DigestAlgorithm { get; init; }

    /// <summary>The temporal bounds the issuer commits to for this credential.</summary>
    public required MdocValidityInfo Validity { get; init; }

    /// <summary>
    /// The wallet-side COSE_Key the MSO binds to. The wallet uses this
    /// key's matching private half to sign <c>DeviceAuth</c> at presentation
    /// time (M.3b).
    /// </summary>
    public required CoseKey DeviceKey { get; init; }

    /// <summary>
    /// Optional <c>kid</c> for the COSE_Sign1 protected header. Verifiers
    /// use it to disambiguate keys when an issuer rotates keys; leave
    /// <see langword="null"/> when out-of-band issuer-key resolution suffices.
    /// </summary>
    public string? Kid { get; init; }

    /// <summary>
    /// Optional DER-encoded X.509 certificate chain to emit as the
    /// <c>x5chain</c> COSE unprotected header parameter (label 33) per
    /// RFC 9360 §2. ISO/IEC 18013-5 §9.1.2.4 mandates its presence for
    /// IACA-rooted IssuerAuth — verifiers walk the chain to a trusted
    /// IACA root before verifying the signature.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Convention: leaf certificate first, intermediates following, root
    /// optional (the verifier supplies the trusted root from its IACA
    /// trust list). Each entry is the raw DER bytes for one certificate.
    /// </para>
    /// <para>
    /// A single-element list emits the value as a single bstr per RFC 9360
    /// §2; a multi-element list emits an array of bstrs. The verifier
    /// extractor accepts both shapes.
    /// </para>
    /// </remarks>
    public IReadOnlyList<ReadOnlyMemory<byte>>? X5Chain { get; init; }
}


/// <summary>
/// Format-specific CBOR issuance for mdoc — takes an
/// <see cref="MdocLogicalDocument"/> from <see cref="MdocIssuance.BuildDocument"/>,
/// encodes each <see cref="MdocLogicalIssuerSignedItem"/> as Tag 24 wire
/// bytes, hashes those bytes to build the MSO <c>valueDigests</c> map,
/// encodes the MSO, wraps it in Tag 24, signs the result as COSE_Sign1 via
/// <see cref="Cose.SignAsync(ReadOnlyMemory{byte}, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, MemoryPool{byte}, System.Threading.CancellationToken)"/>,
/// and returns a wire-valid <see cref="MdocDocument"/> with item wire bytes
/// filled and <see cref="MdocIssuerSigned.IssuerAuth"/> populated.
/// </summary>
/// <remarks>
/// <para>
/// Parallels <see cref="Verifiable.Cbor.Sd.SdCwtIssuance"/> in shape: a
/// public static <c>SignAsync</c> that takes the per-call inputs and
/// returns a wire-ready result. The format-agnostic stage
/// (<see cref="MdocIssuance.BuildDocument"/>) and the format-specific
/// signing stage (this method) compose: the caller picks the random
/// generator at the first stage and the signing key at the second.
/// </para>
/// <para>
/// The signature uses two distinct types for the unsigned and signed
/// shapes — <see cref="MdocLogicalDocument"/> and <see cref="MdocDocument"/>
/// — so the type system carries ISO/IEC 18013-5's structural invariant
/// that a wire-valid document always has <c>IssuerAuth</c>. The defensive
/// "IssuerAuth must be populated" checks the writer side used to need are
/// statically impossible against <see cref="MdocDocument"/>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> The function consumes the input
/// <paramref name="logical"/> document: it transfers each item's
/// <see cref="MdocLogicalIssuerSignedItem.Random"/> salt onto a new
/// <see cref="MdocIssuerSignedItem"/> that also carries the
/// freshly-computed <see cref="MdocIssuerSignedItem.WireBytes"/>. The
/// caller must not use or dispose the input document after this call
/// returns; the returned document is the only valid handle.
/// </para>
/// </remarks>
public static class MdocCborIssuance
{
    /// <summary>
    /// Signs the supplied logical document, producing a wire-valid
    /// <see cref="MdocDocument"/> with each item's wire bytes attached and
    /// <see cref="MdocIssuerSigned.IssuerAuth"/> populated with the parsed
    /// MSO and the original COSE_Sign1 wire bytes. Forwards to
    /// <c>SignVerboseAsync</c> and discards the signed MSO payload.
    /// </summary>
    /// <param name="logical">
    /// The logical document from <see cref="MdocIssuance.BuildDocument"/>.
    /// Ownership transfers to the returned document — the caller must not
    /// use or dispose <paramref name="logical"/> after this call.
    /// </param>
    /// <param name="config">The issuer's MSO commitments.</param>
    /// <param name="signingKey">
    /// The issuer's signing key. Its <see cref="Tag"/> determines both the
    /// COSE <c>alg</c> in the protected header (via
    /// <see cref="CryptoFormatConversions.DefaultTagToCoseConverter"/>) and
    /// the signing function used (via the
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>).
    /// </param>
    /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed document; caller owns and must dispose.</returns>
    public static async ValueTask<MdocDocument> SignAsync(
        MdocLogicalDocument logical,
        MdocIssuerSigningConfig config,
        PrivateKeyMemory signingKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken = default)
    {
        (MdocDocument document, _) = await SignVerboseAsync(
            logical, config, signingKey, signaturePool, cancellationToken).ConfigureAwait(false);

        return document;
    }


    /// <summary>
    /// Signs the supplied logical document and additionally returns the signed MSO payload —
    /// the Tag 24-wrapped MSO bytes the COSE_Sign1 signature covers — as the canonical body
    /// <c>SignAsync</c> forwards to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The signed payload is what the issuer commits the signature over; production
    /// <c>SignAsync</c> embeds the MSO into the returned document's
    /// <see cref="MdocIssuerSigned.IssuerAuth"/> and discards the standalone payload bytes,
    /// so recovering them otherwise means re-parsing the COSE_Sign1. Verbose threads them out
    /// directly for spec-vector validation — the bytes are a public commitment (digests, the
    /// device public key, validity, doctype), independent of the returned document's lifetime.
    /// The per-claim salts and digests are NOT re-surfaced here: they already live on the
    /// returned document's items (<see cref="MdocIssuerSignedItem.Random"/>) and MSO
    /// (<see cref="MdocMobileSecurityObject.ValueDigests"/>), so this verbose captures only the
    /// payload production discards.
    /// </para>
    /// </remarks>
    /// <param name="logical">
    /// The logical document from <see cref="MdocIssuance.BuildDocument"/>.
    /// Ownership transfers to the returned document — the caller must not
    /// use or dispose <paramref name="logical"/> after this call.
    /// </param>
    /// <param name="config">The issuer's MSO commitments.</param>
    /// <param name="signingKey">
    /// The issuer's signing key. Its <see cref="Tag"/> determines both the
    /// COSE <c>alg</c> in the protected header (via
    /// <see cref="CryptoFormatConversions.DefaultTagToCoseConverter"/>) and
    /// the signing function used (via the
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>).
    /// </param>
    /// <param name="signaturePool">Memory pool for the signing operation's transient allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The signed document (caller owns and must dispose) and the Tag 24-wrapped MSO bytes that
    /// were signed. The payload is a standalone buffer independent of the document's lifetime.
    /// </returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the constructed MdocIssuerSigned transfers to the returned MdocDocument.")]
    public static async ValueTask<(MdocDocument Document, ReadOnlyMemory<byte> SignedMsoPayload)> SignVerboseAsync(
        MdocLogicalDocument logical,
        MdocIssuerSigningConfig config,
        PrivateKeyMemory signingKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(logical);
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentNullException.ThrowIfNull(signaturePool);

        //Phase 1: encode each logical item to Tag 24 wire bytes and hash
        //them under the chosen digest algorithm. The hash output is the
        //MSO's valueDigests commitment for that item.
        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> newNamespaces =
            new(logical.IssuerSigned.NameSpaces.Count, StringComparer.Ordinal);
        Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> valueDigests =
            new(logical.IssuerSigned.NameSpaces.Count, StringComparer.Ordinal);

        foreach(KeyValuePair<string, IReadOnlyList<MdocLogicalIssuerSignedItem>> nsEntry in logical.IssuerSigned.NameSpaces)
        {
            List<MdocIssuerSignedItem> rewrittenItems = new(nsEntry.Value.Count);
            Dictionary<uint, ReadOnlyMemory<byte>> nsDigests = new(nsEntry.Value.Count);

            foreach(MdocLogicalIssuerSignedItem oldItem in nsEntry.Value)
            {
                ReadOnlyMemory<byte> wireBytes = MdocCborIssuerSignedItemEncoder.Encode(oldItem);
                byte[] digest = ComputeDigest(config.DigestAlgorithm, wireBytes.Span);

                //Build the signed item with the wire bytes filled; the salt
                //transfers from the logical item to the signed item without
                //re-allocation.
                MdocIssuerSignedItem newItem = new(
                    digestId: oldItem.DigestId,
                    random: oldItem.Random,
                    elementIdentifier: oldItem.ElementIdentifier,
                    encodedElementValue: oldItem.EncodedElementValue,
                    wireBytes: wireBytes);

                rewrittenItems.Add(newItem);
                nsDigests[oldItem.DigestId] = digest;
            }

            newNamespaces[nsEntry.Key] = rewrittenItems.ToArray();
            valueDigests[nsEntry.Key] = nsDigests;
        }

        //Phase 2: build the MSO, encode it, wrap in Tag 24, build the
        //protected header, sign as COSE_Sign1.
        MdocMobileSecurityObject mso = new(
            version: MdocMsoWellKnownKeys.Version10,
            digestAlgorithm: config.DigestAlgorithm,
            valueDigests: valueDigests,
            deviceKeyInfo: new MdocDeviceKeyInfo(config.DeviceKey),
            docType: logical.DocType,
            validityInfo: config.Validity);

        ReadOnlyMemory<byte> msoBytes = MdocCborMsoWriter.Write(mso);
        EncodedCborItem msoWrapped = EncodedCborItem.Wrap(msoBytes.Span);

        int coseAlgorithm = CryptoFormatConversions.DefaultTagToCoseConverter(signingKey.Tag);
        EncodedCoseProtectedHeader protectedHeader = BuildProtectedHeader(coseAlgorithm, config.Kid, signaturePool);
        IReadOnlyDictionary<int, object>? unprotectedHeader = BuildUnprotectedHeader(config.X5Chain);

        //SignAsync takes ownership of protectedHeader; the returned coseSign1
        //owns the Signature + the protectedHeader. After we serialize the
        //wire form (which copies the bytes into an EncodedCoseSign1 carrier
        //MdocIssuerAuth then owns), we dispose coseSign1 to release the
        //intermediate carriers.
        using CoseSign1Message coseSign1 = await Cose.SignAsync(
            protectedHeader,
            unprotectedHeader,
            msoWrapped.WireBytes,
            CoseSerialization.BuildSigStructure,
            signingKey,
            signaturePool,
            cancellationToken).ConfigureAwait(false);

        EncodedCoseSign1 coseSign1Bytes = CoseSerialization.SerializeCoseSign1(coseSign1, signaturePool);
        MdocIssuerAuth issuerAuth = new(mso, coseSign1Bytes);

        MdocDocument document = new(
            docType: logical.DocType,
            issuerSigned: new MdocIssuerSigned(newNamespaces, issuerAuth),
            deviceSigned: null);

        //msoWrapped.WireBytes is the Tag 24-wrapped MSO the signature covers — a plain,
        //non-pooled buffer (EncodedCborItem.Wrap backs it with a byte[]), so it outlives this
        //method and the returned document independently.
        return (document, msoWrapped.WireBytes);
    }


    /// <summary>
    /// Builds the COSE_Sign1 protected header map carrying <c>alg</c> and
    /// optionally <c>kid</c>. Returns a pool-routed carrier the caller
    /// transfers to <see cref="Cose.SignAsync(EncodedCoseProtectedHeader, IReadOnlyDictionary{int, object}?, ReadOnlyMemory{byte}, BuildSigStructureDelegate, PrivateKeyMemory, MemoryPool{byte}, CancellationToken)"/>.
    /// </summary>
    private static EncodedCoseProtectedHeader BuildProtectedHeader(int coseAlgorithm, string? kid, MemoryPool<byte> pool)
    {
        var writer = new System.Formats.Cbor.CborWriter(System.Formats.Cbor.CborConformanceMode.Canonical);

        writer.WriteStartMap(kid is null ? 1 : 2);

        writer.WriteInt32(MdocCoseHeaderLabels.Alg);
        writer.WriteInt32(coseAlgorithm);

        if(kid is not null)
        {
            writer.WriteInt32(MdocCoseHeaderLabels.Kid);
            writer.WriteByteString(System.Text.Encoding.UTF8.GetBytes(kid));
        }

        writer.WriteEndMap();

        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return new EncodedCoseProtectedHeader(owner, CryptoTags.CoseEncodedProtectedHeader);
    }


    /// <summary>
    /// Builds the COSE_Sign1 unprotected header map. Returns
    /// <see langword="null"/> when there is nothing to put in it — the
    /// signer treats null as "emit an empty map" downstream.
    /// </summary>
    /// <remarks>
    /// <para>
    /// When <paramref name="x5Chain"/> is supplied, the value follows the
    /// RFC 9360 §2 shape rule: a single-element list emits the value as a
    /// single <c>bstr</c>; a multi-element list emits an array of
    /// <c>bstr</c>s. The carrier here uses <c>byte[]</c> for the single
    /// case and <c>byte[][]</c> for the array case so the existing
    /// <see cref="CborValueConverter"/> wiring in
    /// <see cref="CoseSerialization.SerializeCoseSign1"/> picks the right
    /// encoding.
    /// </para>
    /// </remarks>
    private static Dictionary<int, object>? BuildUnprotectedHeader(
        IReadOnlyList<ReadOnlyMemory<byte>>? x5Chain)
    {
        if(x5Chain is null || x5Chain.Count == 0)
        {
            return null;
        }

        object value;
        if(x5Chain.Count == 1)
        {
            value = x5Chain[0].ToArray();
        }
        else
        {
            byte[][] chainArray = new byte[x5Chain.Count][];
            for(int i = 0; i < x5Chain.Count; i++)
            {
                chainArray[i] = x5Chain[i].ToArray();
            }

            value = chainArray;
        }

        return new Dictionary<int, object> { [MdocCoseHeaderLabels.X5Chain] = value };
    }


    /// <summary>
    /// Computes the MSO digest of one IssuerSignedItem's wire bytes under
    /// the spec-permitted hash algorithm. ISO/IEC 18013-5 §9.1.2.5 limits
    /// the choices to SHA-256, SHA-384, and SHA-512.
    /// </summary>
    private static byte[] ComputeDigest(string digestAlgorithm, ReadOnlySpan<byte> input)
    {
        return digestAlgorithm switch
        {
            MdocMsoWellKnownKeys.DigestAlgorithmSha256 => SHA256.HashData(input),
            MdocMsoWellKnownKeys.DigestAlgorithmSha384 => SHA384.HashData(input),
            MdocMsoWellKnownKeys.DigestAlgorithmSha512 => SHA512.HashData(input),
            _ => throw new NotSupportedException(
                $"MSO digestAlgorithm '{digestAlgorithm}' is not one of the SHA-256/384/512 set " +
                $"permitted by ISO/IEC 18013-5 §9.1.2.5.")
        };
    }
}

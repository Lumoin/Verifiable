using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Cbor.Mdoc;

/// <summary>
/// Produces a signed <see cref="MdocDeviceSigned"/> by computing the
/// COSE_Sign1 over the <c>DeviceAuthentication</c> bytes per
/// ISO/IEC 18013-5 §9.1.3.4. The COSE_Sign1 emitted has a nil payload —
/// the <c>DeviceAuthenticationBytes</c> are reconstructed at verification
/// time and fed into the Sig_structure rather than transmitted.
/// </summary>
/// <remarks>
/// <para>
/// Parallels <see cref="MdocCborIssuance.SignAsync"/> on the issuer side:
/// pure static, takes per-call inputs, returns the signed result. The
/// caller supplies the device private key (whose
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/> picks the
/// COSE alg in the protected header via
/// <see cref="CryptoFormatConversions.DefaultTagToCoseConverter"/>) and the
/// session-transcript bytes the transport binding produced.
/// </para>
/// </remarks>
public static class MdocCborDeviceSignedSigner
{
    /// <summary>
    /// Signs the supplied device-side claims for a presentation, producing
    /// an <see cref="MdocDeviceSigned"/> with the COSE_Sign1 attached.
    /// Forwards to <c>SignVerboseAsync</c> and discards the
    /// <c>DeviceAuthenticationBytes</c>.
    /// </summary>
    /// <param name="nameSpaces">
    /// The device's own claim assertions. Pass <see cref="MdocDeviceNameSpaces.Empty"/>
    /// for the common case where the device asserts nothing of its own and
    /// the signature only proves possession of the bound device key.
    /// </param>
    /// <param name="docType">The enclosing document's docType URI.</param>
    /// <param name="encodedSessionTranscript">
    /// The transport-binding's session transcript bytes. The device side
    /// and verifier side MUST agree on these bytes byte-for-byte.
    /// </param>
    /// <param name="deviceSigningKey">The device's signing key.</param>
    /// <param name="signaturePool">Memory pool for signing-operation transient allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The signed <see cref="MdocDeviceSigned"/>.</returns>
    public static async ValueTask<MdocDeviceSigned> SignAsync(
        MdocDeviceNameSpaces nameSpaces,
        string docType,
        ReadOnlyMemory<byte> encodedSessionTranscript,
        PrivateKeyMemory deviceSigningKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken = default)
    {
        (MdocDeviceSigned deviceSigned, _) = await SignVerboseAsync(
            nameSpaces, docType, encodedSessionTranscript, deviceSigningKey, signaturePool, cancellationToken).ConfigureAwait(false);

        return deviceSigned;
    }


    /// <summary>
    /// Signs the supplied device-side claims and additionally returns the
    /// <c>DeviceAuthenticationBytes</c> — the Tag 24-wrapped
    /// <c>DeviceAuthentication</c> array the COSE_Sign1 signature covers — the canonical body
    /// <c>SignAsync</c> forwards to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>DeviceAuthenticationBytes</c> are the session-bound signing material per
    /// ISO/IEC 18013-5 §9.1.3.4: they embed the session transcript, the doctype, and the
    /// device namespaces. Production signs over them but emits a <em>nil</em> payload on the
    /// wire (the detached form), so the bytes are not transmitted — recovering them otherwise
    /// means re-encoding from the session transcript + doctype + the preserved
    /// <see cref="MdocDeviceSigned.EncodedDeviceNameSpacesBytes"/>. Verbose threads them out
    /// directly for spec-vector validation. They are public protocol bytes (no key material),
    /// backed by a plain <c>byte[]</c>, and independent of the returned
    /// <see cref="MdocDeviceSigned"/>'s lifetime.
    /// </para>
    /// </remarks>
    /// <param name="nameSpaces">
    /// The device's own claim assertions. Pass <see cref="MdocDeviceNameSpaces.Empty"/>
    /// for the common case where the device asserts nothing of its own and
    /// the signature only proves possession of the bound device key.
    /// </param>
    /// <param name="docType">The enclosing document's docType URI.</param>
    /// <param name="encodedSessionTranscript">
    /// The transport-binding's session transcript bytes. The device side
    /// and verifier side MUST agree on these bytes byte-for-byte.
    /// </param>
    /// <param name="deviceSigningKey">The device's signing key.</param>
    /// <param name="signaturePool">Memory pool for signing-operation transient allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The signed <see cref="MdocDeviceSigned"/> and the <c>DeviceAuthenticationBytes</c> that
    /// were signed — a standalone buffer independent of the device-signed half's lifetime.
    /// </returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the protected header, EncodedCoseSign1 wire bytes, MdocDeviceSignature, and MdocDeviceAuth all chain into the returned MdocDeviceSigned; the caller disposes that.")]
    public static async ValueTask<(MdocDeviceSigned DeviceSigned, ReadOnlyMemory<byte> DeviceAuthenticationBytes)> SignVerboseAsync(
        MdocDeviceNameSpaces nameSpaces,
        string docType,
        ReadOnlyMemory<byte> encodedSessionTranscript,
        PrivateKeyMemory deviceSigningKey,
        MemoryPool<byte> signaturePool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(deviceSigningKey);
        ArgumentNullException.ThrowIfNull(signaturePool);

        ReadOnlyMemory<byte> encodedDeviceNameSpacesBytes = MdocCborDeviceNameSpacesEncoder.EncodeWrapped(nameSpaces);
        ReadOnlyMemory<byte> deviceAuthenticationBytes = MdocCborDeviceAuthenticationEncoder.EncodeAuthenticationBytes(
            encodedSessionTranscript, docType, encodedDeviceNameSpacesBytes);

        int coseAlgorithm = CryptoFormatConversions.DefaultTagToCoseConverter(deviceSigningKey.Tag);
        EncodedCoseProtectedHeader protectedHeader = BuildProtectedHeader(coseAlgorithm, signaturePool);

        //COSE_Sign1 with nil payload — the DeviceAuthenticationBytes are
        //fed into the Sig_structure as the payload field but are NOT
        //transmitted on the wire. ISO 18013-5 §9.1.3.4 calls this the
        //"detached" form. coseSign1 owns the protected header + signature;
        //we serialize directly to the nil-payload wire form (sharing
        //references into coseSign1, no intermediate message) then dispose
        //coseSign1 to release its carriers.
        using CoseSign1Message coseSign1 = await Cose.SignAsync(
            protectedHeader,
            null,
            deviceAuthenticationBytes,
            CoseSerialization.BuildSigStructure,
            deviceSigningKey,
            signaturePool,
            cancellationToken).ConfigureAwait(false);

        EncodedCoseSign1 coseSign1Bytes = SerializeCoseSign1WithNilPayload(coseSign1, signaturePool);

        MdocDeviceSigned deviceSigned = new(
            nameSpaces: nameSpaces,
            encodedDeviceNameSpacesBytes: encodedDeviceNameSpacesBytes,
            deviceAuth: new MdocDeviceAuth(new MdocDeviceSignature(coseSign1Bytes)));

        //deviceAuthenticationBytes is the Tag 24-wrapped DeviceAuthentication array the
        //signature covers — a plain, non-pooled buffer (EncodedCborItem.Wrap backs it with a
        //byte[]), so it outlives this method and the returned device-signed half independently.
        return (deviceSigned, deviceAuthenticationBytes);
    }


    private static EncodedCoseProtectedHeader BuildProtectedHeader(int coseAlgorithm, MemoryPool<byte> pool)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //label 1 = alg per RFC 9052 §3.1
        writer.WriteInt32(coseAlgorithm);
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
    /// Serializes a COSE_Sign1 message with an explicit nil payload field
    /// per RFC 9052 §4.2 — the standard
    /// <see cref="CoseSerialization.SerializeCoseSign1"/> writes the
    /// payload as a byte string (which would emit an empty bstr for an
    /// empty payload, not nil). The detached form ISO 18013-5 mandates
    /// requires the actual nil sentinel. Output is pool-routed.
    /// </summary>
    private static EncodedCoseSign1 SerializeCoseSign1WithNilPayload(CoseSign1Message message, MemoryPool<byte> pool)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);

        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);
        writer.WriteByteString(message.ProtectedHeader.AsReadOnlySpan());
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteNull();
        writer.WriteByteString(message.Signature.AsReadOnlySpan());
        writer.WriteEndArray();

        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    }
}

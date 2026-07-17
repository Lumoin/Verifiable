using System.Buffers;
using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Text;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Shared FIDO2 test-vector builders: assembles the WebAuthn L3
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section 6.1</see> authenticator data
/// binary layout, the
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see> attested
/// credential data layout, and a P-256 COSE_Key encoding used as the <c>credentialPublicKey</c> — so the
/// individual test files stay focused on the assertions they make.
/// </summary>
internal static class Fido2TestVectors
{
    /// <summary>
    /// Produces a deterministic, non-zero 32-byte value standing in for the RP ID hash
    /// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section 6.1</see> calls for the
    /// SHA-256 of the RP ID; the reader under test treats it as an opaque 32-byte slice, so the actual digest
    /// value is immaterial to the tests).
    /// </summary>
    /// <returns>A fresh 32-byte array with sequential, non-zero content.</returns>
    public static byte[] CreateRpIdHash()
    {
        byte[] rpIdHash = new byte[32];
        for(int i = 0; i < rpIdHash.Length; i++)
        {
            rpIdHash[i] = (byte)(i + 1);
        }

        return rpIdHash;
    }


    /// <summary>
    /// Wraps already-known bytes (typically from <see cref="CreateRpIdHash"/> or a wire-parsed
    /// <c>rpIdHash</c>) in a pooled <see cref="DigestValue"/> tagged SHA-256, mirroring how
    /// <see cref="AuthenticatorDataReader.Read"/> copies the wire <c>rpIdHash</c> slice into a
    /// carrier. No hashing occurs here — the bytes are copied verbatim.
    /// </summary>
    /// <param name="rpIdHash">The bytes to copy.</param>
    /// <param name="pool">The memory pool the returned carrier rents from.</param>
    /// <returns>A new <see cref="DigestValue"/> containing a copy of <paramref name="rpIdHash"/>.</returns>
    public static DigestValue WrapRpIdHash(ReadOnlySpan<byte> rpIdHash, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(rpIdHash.Length);
        rpIdHash.CopyTo(owner.Memory.Span);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>
    /// Assembles the authenticator data binary layout per WebAuthn L3
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">section 6.1</see>: <c>rpIdHash</c>
    /// (32) | <c>flags</c> (1) | <c>signCount</c> (4, big-endian) | [<c>attestedCredentialData</c>] |
    /// [<c>extensions</c>].
    /// </summary>
    /// <param name="rpIdHash">The 32-byte RP ID hash.</param>
    /// <param name="flags">The flags byte.</param>
    /// <param name="signCount">The signature counter, written big-endian.</param>
    /// <param name="attestedCredentialData">The optional attested credential data bytes to append.</param>
    /// <param name="extensions">The optional extension data bytes to append.</param>
    /// <returns>The assembled authenticator data bytes.</returns>
    public static byte[] BuildAuthenticatorData(
        byte[] rpIdHash,
        byte flags,
        uint signCount,
        byte[]? attestedCredentialData = null,
        byte[]? extensions = null)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);

        int attestedLength = attestedCredentialData?.Length ?? 0;
        int extensionsLength = extensions?.Length ?? 0;
        byte[] buffer = new byte[37 + attestedLength + extensionsLength];

        rpIdHash.AsSpan().CopyTo(buffer.AsSpan(0, 32));
        buffer[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(33, 4), signCount);

        int offset = 37;
        if(attestedCredentialData is not null)
        {
            attestedCredentialData.AsSpan().CopyTo(buffer.AsSpan(offset));
            offset += attestedCredentialData.Length;
        }

        if(extensions is not null)
        {
            extensions.AsSpan().CopyTo(buffer.AsSpan(offset));
        }

        return buffer;
    }


    /// <summary>
    /// Assembles the attested credential data layout per WebAuthn L3
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">section 6.5.1</see>:
    /// <c>aaguid</c> (16, big-endian) | <c>credentialIdLength</c> (2, big-endian) | <c>credentialId</c> |
    /// <c>credentialPublicKey</c>.
    /// </summary>
    /// <param name="aaguid">The authenticator AAGUID.</param>
    /// <param name="credentialId">The credential ID bytes.</param>
    /// <param name="credentialPublicKeyCbor">The CBOR-encoded COSE_Key credential public key bytes.</param>
    /// <returns>The assembled attested credential data bytes.</returns>
    public static byte[] BuildAttestedCredentialData(Guid aaguid, byte[] credentialId, byte[] credentialPublicKeyCbor)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        ArgumentNullException.ThrowIfNull(credentialPublicKeyCbor);

        byte[] buffer = new byte[16 + 2 + credentialId.Length + credentialPublicKeyCbor.Length];

        aaguid.TryWriteBytes(buffer.AsSpan(0, 16), bigEndian: true, out _);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(16, 2), checked((ushort)credentialId.Length));
        credentialId.AsSpan().CopyTo(buffer.AsSpan(18, credentialId.Length));
        credentialPublicKeyCbor.AsSpan().CopyTo(buffer.AsSpan(18 + credentialId.Length));

        return buffer;
    }


    /// <summary>
    /// Builds a fresh P-256 EC2 <see cref="CoseKey"/> declaring <see cref="WellKnownCoseAlgorithms.Es256"/>
    /// from test key material and serializes it to COSE_Key CBOR bytes via
    /// <see cref="MdocCborCoseKeyWriter.Write(CoseKey)"/> — the bytes used as the <c>credentialPublicKey</c>
    /// portion of attested credential data (section 6.5.1). The <c>alg</c> parameter is included because
    /// <see cref="AuthenticatorDataReader.Read"/>'s section 6.5.1 conformance enforcement rejects a
    /// credential public key that omits it.
    /// </summary>
    /// <returns>The CBOR-encoded COSE_Key bytes.</returns>
    public static byte[] EncodeP256CoseKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        try
        {
            (byte[] x, byte[] y) = DecodeEcPoint(keyMaterial.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            CoseKey coseKey = new(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: x, y: y);

            return MdocCborCoseKeyWriter.Write(coseKey).ToArray();
        }
        finally
        {
            MdocTestFixtures.DisposeKeyMaterial(keyMaterial);
        }
    }


    /// <summary>
    /// Concatenates byte arrays into a single buffer, used to assemble malformed or near-valid wire layouts from
    /// their component parts.
    /// </summary>
    /// <param name="parts">The byte arrays to concatenate, in order.</param>
    /// <returns>A single buffer holding every part back to back.</returns>
    public static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach(byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] part in parts)
        {
            part.AsSpan().CopyTo(result.AsSpan(offset));
            offset += part.Length;
        }

        return result;
    }


    /// <summary>
    /// An adapter over <see cref="MdocCborCoseKeyReader.ReadFromReader(CborReader, out IReadOnlyList{int})"/>
    /// matching <see cref="ReadCredentialPublicKeyDelegate"/>: constructs a lax-mode <see cref="CborReader"/>
    /// over the supplied source, reads the self-describing COSE_Key at its start, and reports the number of
    /// bytes the CBOR reader actually consumed — so the caller can locate the following extensions slice —
    /// together with the top-level labels encountered, so <c>AuthenticatorDataReader</c>'s WebAuthn L3
    /// section 6.5.1 parameter-completeness enforcement can see the credential public key's exact on-wire
    /// shape. The production codec arrives with the upcoming CBOR switch; this edge wiring is exactly what
    /// tests are for.
    /// </summary>
    public static ReadCredentialPublicKeyDelegate TestCredentialPublicKeyReader { get; } = source =>
    {
        var reader = new CborReader(source, CborConformanceMode.Lax);
        CoseKey coseKey = MdocCborCoseKeyReader.ReadFromReader(reader, out IReadOnlyList<int> labels);
        int bytesConsumed = source.Length - reader.BytesRemaining;

        return new CredentialPublicKeyReadResult(coseKey, bytesConsumed, labels);
    };


    /// <summary>
    /// Encodes a COSE_Key CBOR map from raw label/value entries in
    /// <see cref="CborConformanceMode.Lax"/> mode, so shapes that violate the WebAuthn L3 section 6.5.1
    /// credential public key clauses — duplicate labels, extraneous labels, or missing required
    /// parameters — can be crafted for the reader's negative-path tests without the CBOR writer itself
    /// rejecting them.
    /// </summary>
    /// <param name="entries">The label/value-writer pairs to emit, in the given order.</param>
    /// <returns>The CBOR-encoded COSE_Key bytes.</returns>
    public static byte[] EncodeRawCoseKey(params (int Label, Action<CborWriter> WriteValue)[] entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(entries.Length);
        foreach((int label, Action<CborWriter> writeValue) in entries)
        {
            writer.WriteInt32(label);
            writeValue(writer);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Builds a raw COSE_Key entry value writer that emits <paramref name="value"/> as a CBOR integer.</summary>
    /// <param name="value">The integer to write.</param>
    /// <returns>The value writer, for use with <see cref="EncodeRawCoseKey"/>.</returns>
    public static Action<CborWriter> IntValue(int value) => writer => writer.WriteInt32(value);


    /// <summary>Builds a raw COSE_Key entry value writer that emits <paramref name="value"/> as a CBOR byte string.</summary>
    /// <param name="value">The bytes to write.</param>
    /// <returns>The value writer, for use with <see cref="EncodeRawCoseKey"/>.</returns>
    public static Action<CborWriter> BytesValue(byte[] value) => writer => writer.WriteByteString(value);


    /// <summary>Builds a raw COSE_Key entry value writer that emits <paramref name="value"/> as a CBOR boolean.</summary>
    /// <param name="value">The boolean to write.</param>
    /// <returns>The value writer, for use with <see cref="EncodeRawCoseKey"/>.</returns>
    public static Action<CborWriter> BoolValue(bool value) => writer => writer.WriteBoolean(value);


    /// <summary>
    /// Recovers the uncompressed <c>x</c>/<c>y</c> coordinate pair from a compressed SEC1 EC public key,
    /// for building EC2 COSE_Key test vectors whose curve is not P-256 (<see cref="EncodeP256CoseKey"/>
    /// covers the P-256 case via the canonical writer).
    /// </summary>
    /// <param name="compressedPublicKey">The compressed SEC1-encoded public key.</param>
    /// <param name="curveType">The curve the key belongs to.</param>
    /// <returns>The recovered <c>x</c> and <c>y</c> coordinates.</returns>
    public static (byte[] X, byte[] Y) DecodeEcPoint(ReadOnlySpan<byte> compressedPublicKey, EllipticCurveTypes curveType)
    {
        byte[] y = EllipticCurveUtilities.Decompress(compressedPublicKey, curveType);

        return (compressedPublicKey[1..].ToArray(), y);
    }


    /// <summary>
    /// Extracts the modulus and public exponent from a DER PKCS#1 <c>RSAPublicKey ::= SEQUENCE { modulus
    /// INTEGER, publicExponent INTEGER }</c>, so the wire fields can be fed into a raw COSE_Key test vector
    /// without ever sharing the RSA key object itself across the issuer/verifier firewall.
    /// </summary>
    /// <param name="derEncodedPublicKey">The DER-encoded PKCS#1 RSA public key.</param>
    /// <returns>The unsigned big-endian modulus and public exponent.</returns>
    public static (byte[] Modulus, byte[] Exponent) DecodeRsaPublicKeyComponents(ReadOnlyMemory<byte> derEncodedPublicKey)
    {
        var sequence = new AsnReader(derEncodedPublicKey, AsnEncodingRules.DER).ReadSequence();
        byte[] modulus = StripLeadingZero(sequence.ReadIntegerBytes());
        byte[] exponent = StripLeadingZero(sequence.ReadIntegerBytes());

        return (modulus, exponent);

        //Strips a single leading 0x00 sign octet from a DER INTEGER's two's-complement encoding,
        //recovering the unsigned big-endian magnitude RFC 8230 §4 expects for the RSA n/e labels.
        static byte[] StripLeadingZero(ReadOnlyMemory<byte> integer) =>
            (integer.Length > 1 && integer.Span[0] == 0x00 ? integer[1..] : integer).ToArray();
    }


    /// <summary>Encodes <paramref name="text"/> as UTF-8, for building a test <see cref="Fido2ExtensionOutput.Value"/> or wire document.</summary>
    /// <param name="text">The text to encode.</param>
    /// <returns>The UTF-8 encoded bytes.</returns>
    public static ReadOnlyMemory<byte> Encode(string text) => Encoding.UTF8.GetBytes(text);


    /// <summary>Builds a JSON array literal nested <paramref name="depth"/> levels deep (e.g. <c>[[[]]]</c> for a depth of 3), for exercising a reader's nesting-depth limit.</summary>
    /// <param name="depth">The nesting depth.</param>
    /// <returns>The nested array literal.</returns>
    public static string BuildDeeplyNestedArray(int depth)
    {
        var builder = new StringBuilder(depth * 2);
        for(int i = 0; i < depth; i++)
        {
            builder.Append('[');
        }

        for(int i = 0; i < depth; i++)
        {
            builder.Append(']');
        }

        return builder.ToString();
    }
}

using System;
using System.Buffers;
using Verifiable.Fido2.Ctap.Authenticator.Automata;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// The shipped default <see cref="EncodeCtapAuthenticatorSnapshotDelegate"/> implementation: writes the
/// PERSISTENT subset of a <see cref="CtapAuthenticatorState"/> (contract R-2) plus its R-2b
/// personalization fingerprint as a versioned, definite-length-only CBOR array.
/// </summary>
/// <remarks>
/// Field order is FIXED by <see cref="CtapAuthenticatorSnapshotFormat.CurrentVersion"/> — this codec
/// never emits a CBOR map, since both the writer and the shipped
/// <see cref="CtapAuthenticatorSnapshotCborReader"/> already agree on every field's position by
/// construction; a future format change bumps <see cref="CtapAuthenticatorSnapshotFormat.CurrentVersion"/>
/// rather than growing this one layout, so <see cref="CtapAuthenticatorSnapshotCborReader"/> can keep
/// rejecting anything but the version it understands (fail closed, R-5).
/// </remarks>
public static class CtapAuthenticatorSnapshotCborWriter
{
    /// <summary>The fixed AAGUID byte length this codec writes (RFC 4122, 16 bytes).</summary>
    private const int AaguidByteLength = 16;


    /// <summary>
    /// A generous initial scratch capacity for the CBOR build buffer: a typical few-credential snapshot
    /// fits without a single reallocation, so no intermediate backing array (which would hold secret bytes
    /// the scrubbing <see cref="PooledMemory"/> return path cannot reach) is ever abandoned to the GC. A
    /// snapshot larger than this still encodes correctly; only then does <see cref="ArrayBufferWriter{T}"/>
    /// grow and leave a transient uncleared copy — a bounded, in-simulator-only residual tracked rather than
    /// engineered away, since the shipped, returned payload is always the scrubbing carrier below.
    /// </summary>
    private const int ScratchInitialCapacity = 4096;


    /// <summary>
    /// Encodes <paramref name="state"/>'s persistent subset and personalization fingerprint. Has the
    /// <see cref="EncodeCtapAuthenticatorSnapshotDelegate"/> shape.
    /// </summary>
    /// <param name="state">The state to encode.</param>
    /// <param name="pool">The memory pool the returned scrubbing payload is rented from.</param>
    /// <returns>The encoded snapshot payload in a scrubbing <see cref="PooledMemory"/> the caller must dispose.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="state"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="CtapAuthenticatorSnapshotException">
    /// A credential in <paramref name="state"/>'s <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/>
    /// carries no <see cref="CtapCredentialRecord.CredentialKeyCustodyExport"/> — this codec cannot
    /// persist a credential whose signing key has no custody-exportable copy (see that property's own
    /// remarks for why the copy exists and which shipped backend populates it).
    /// </exception>
    public static PooledMemory Write(CtapAuthenticatorState state, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(pool);

        ArrayBufferWriter<byte> writer = new(ScratchInitialCapacity);

        CborPrimitives.WriteArrayHeader(writer, 16);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, CtapAuthenticatorSnapshotFormat.CurrentVersion);

        Span<byte> aaguidBytes = stackalloc byte[AaguidByteLength];
        state.Aaguid.TryWriteBytes(aaguidBytes, bigEndian: true, out _);
        CborPrimitives.WriteByteString(writer, aaguidBytes);

        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)state.FirmwareVersion);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, state.NextCredentialSequence);
        CborPrimitives.WriteNullableByteString(
            writer, state.CurrentStoredPin is null ? default : state.CurrentStoredPin.AsReadOnlySpan(), state.CurrentStoredPin is null);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)state.PinCodePointLength);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)state.PinRetries);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)state.UvRetries);
        CborPrimitives.WriteBool(writer, state.IsForcePinChangeRequired);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)state.MinPinCodePointLength);

        CborPrimitives.WriteArrayHeader(writer, state.MinPinLengthRpIds.Count);
        foreach(string rpId in state.MinPinLengthRpIds)
        {
            CborPrimitives.WriteTextString(writer, rpId);
        }

        CborPrimitives.WriteBool(writer, state.IsAlwaysUvEnabled);
        CborPrimitives.WriteBool(writer, state.IsEnterpriseAttestationEnabled);
        CborPrimitives.WriteByteString(writer, state.SerializedLargeBlobArray.AsReadOnlySpan());

        CborPrimitives.WriteArrayHeader(writer, state.CredentialsByCredentialId.Count);
        foreach(CtapCredentialRecord credential in state.CredentialsByCredentialId.Values)
        {
            WriteCredentialEntry(writer, credential);
        }

        CborPrimitives.WriteArrayHeader(writer, state.BioEnrollmentTemplatesByTemplateId.Count);
        foreach(CtapBioEnrollmentTemplateRecord template in state.BioEnrollmentTemplatesByTemplateId.Values)
        {
            CborPrimitives.WriteArrayHeader(writer, 2);
            CborPrimitives.WriteByteString(writer, template.TemplateId.AsReadOnlySpan());
            CborPrimitives.WriteNullableTextString(writer, template.FriendlyName);
        }

        //Copy the built bytes into a scrubbing carrier and zero the scratch buffer's written region (the
        //secret bytes — raw signing keys, PIN digest, credRandom — must not linger in the reusable
        //ArrayBufferWriter backing array after this call). The RETURNED PooledMemory is the only surviving
        //holder of the plaintext, and it clears itself on dispose (contract R-5).
        PooledMemory payload = PooledMemory.FromBytes(writer.WrittenSpan, pool, CtapAuthenticatorCustodyBufferTags.SnapshotPayload);
        writer.Clear();

        return payload;
    }


    /// <summary>
    /// Writes one credential's full persisted field set (contract R-2: "every <c>CtapCredentialRecord</c>
    /// field") as a fixed 16-item array.
    /// </summary>
    /// <param name="writer">The buffer to append to.</param>
    /// <param name="credential">The credential to write.</param>
    /// <exception cref="CtapAuthenticatorSnapshotException"><paramref name="credential"/> carries no <see cref="CtapCredentialRecord.CredentialKeyCustodyExport"/>.</exception>
    private static void WriteCredentialEntry(ArrayBufferWriter<byte> writer, CtapCredentialRecord credential)
    {
        if(credential.CredentialKeyCustodyExport is null)
        {
            throw new CtapAuthenticatorSnapshotException(
                $"Credential '{Convert.ToHexStringLower(credential.CredentialId.AsReadOnlySpan())}' carries no custody-exportable private-key-material copy — "
                + "compose the simulator's credential-signing backend so it populates CtapCredentialKeyPair.CredentialKeyCustodyExport (the shipped "
                + "CtapCredentialSigningBackend.CreateEs256Default() backend does so unconditionally).");
        }

        CborPrimitives.WriteArrayHeader(writer, 16);
        CborPrimitives.WriteByteString(writer, credential.CredentialId.AsReadOnlySpan());
        CborPrimitives.WriteTextString(writer, credential.RpId);
        CborPrimitives.WriteByteString(writer, credential.UserId.AsReadOnlySpan());
        CborPrimitives.WriteNullableTextString(writer, credential.UserName);
        CborPrimitives.WriteNullableTextString(writer, credential.UserDisplayName);
        CborPrimitives.WriteInt(writer, credential.Algorithm);
        CborPrimitives.WriteBool(writer, credential.IsResident);
        CborPrimitives.WriteTextString(writer, credential.CredentialKey.Id);
        CborPrimitives.WriteByteString(writer, credential.CredentialKeyCustodyExport.AsReadOnlySpan());
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, credential.SignCount);
        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, credential.CreationSequence);

        CborPrimitives.WriteArrayHeader(writer, 8);
        CborPrimitives.WriteInt(writer, credential.PublicKey.Kty);
        WriteNullableInt(writer, credential.PublicKey.Alg);
        WriteNullableInt(writer, credential.PublicKey.Curve);
        WriteNullableSpan(writer, credential.PublicKey.X);
        WriteNullableSpan(writer, credential.PublicKey.Y);
        WriteNullableBool(writer, credential.PublicKey.EncodedYCompressionSign);
        WriteNullableSpan(writer, credential.PublicKey.N);
        WriteNullableSpan(writer, credential.PublicKey.E);

        CborPrimitives.WriteHeader(writer, CborPrimitives.MajorUnsigned, (ulong)credential.CredProtectLevel);
        CborPrimitives.WriteByteString(writer, credential.CredRandomWithUV.Memory.Span);
        CborPrimitives.WriteByteString(writer, credential.CredRandomWithoutUV.Memory.Span);
        CborPrimitives.WriteNullableByteString(
            writer, credential.LargeBlobKey is null ? default : credential.LargeBlobKey.Memory.Span, credential.LargeBlobKey is null);
    }


    /// <summary>Writes an optional <see cref="int"/> as either the null simple value or an integer item.</summary>
    private static void WriteNullableInt(ArrayBufferWriter<byte> writer, int? value)
    {
        if(value is null)
        {
            CborPrimitives.WriteNull(writer);
        }
        else
        {
            CborPrimitives.WriteInt(writer, value.Value);
        }
    }


    /// <summary>Writes an optional <see cref="bool"/> as either the null simple value or a boolean item.</summary>
    private static void WriteNullableBool(ArrayBufferWriter<byte> writer, bool? value)
    {
        if(value is null)
        {
            CborPrimitives.WriteNull(writer);
        }
        else
        {
            CborPrimitives.WriteBool(writer, value.Value);
        }
    }


    /// <summary>Writes an optional COSE_Key byte-valued parameter as either the null simple value or a byte string item.</summary>
    private static void WriteNullableSpan(ArrayBufferWriter<byte> writer, ReadOnlyMemory<byte>? value)
    {
        if(value is null)
        {
            CborPrimitives.WriteNull(writer);
        }
        else
        {
            CborPrimitives.WriteByteString(writer, value.Value.Span);
        }
    }
}

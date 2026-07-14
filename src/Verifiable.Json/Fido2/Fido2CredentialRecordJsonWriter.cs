using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;
using Verifiable.JCose;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> writer for a <see cref="Fido2CredentialRecord"/> — the shipped
/// persisted-state shape a relying party stores after a successful registration ceremony and
/// reloads for every subsequent authentication ceremony. Lives beside
/// <see cref="Fido2CredentialRecordJsonReader"/> for the same reason <see cref="ClientDataJsonReader"/>
/// lives here rather than in <c>Verifiable.Fido2</c>: the FIDO2 library stays serialization-agnostic.
/// </summary>
/// <remarks>
/// <para>
/// This document is a shipped default the caller chooses to persist a
/// <see cref="Fido2CredentialRecord"/> across ceremonies with — not a WebAuthn wire format the
/// specification defines. Its shape therefore carries a <c>version</c> member for forward
/// evolution, and <see cref="Fido2CredentialRecordJsonReader"/> reads it strictly (unknown
/// members rejected, duplicates rejected) rather than the "skip unrecognised members" leniency
/// wire-format readers such as <see cref="ClientDataJsonReader"/> apply to genuinely
/// spec-defined, client-authored input.
/// </para>
/// <para>
/// Every binary member — <see cref="Fido2CredentialRecord.Id"/> and the <c>publicKey</c>
/// sub-object's <c>x</c>/<c>y</c>/<c>n</c>/<c>e</c> COSE_Key parameters — is Base64url encoded,
/// matching every other FIDO2 JSON reader/writer in this project.
/// </para>
/// </remarks>
public static class Fido2CredentialRecordJsonWriter
{
    /// <summary>The document schema version this writer emits.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The <c>version</c> member name.</summary>
    private const string VersionMember = "version";

    /// <summary>The <c>type</c> member name.</summary>
    private const string TypeMember = "type";

    /// <summary>The <c>id</c> member name.</summary>
    private const string IdMember = "id";

    /// <summary>The <c>publicKey</c> member name.</summary>
    private const string PublicKeyMember = "publicKey";

    /// <summary>The <c>signCount</c> member name.</summary>
    private const string SignCountMember = "signCount";

    /// <summary>The <c>uvInitialized</c> member name.</summary>
    private const string UvInitializedMember = "uvInitialized";

    /// <summary>The <c>transports</c> member name.</summary>
    private const string TransportsMember = "transports";

    /// <summary>The <c>backupEligible</c> member name.</summary>
    private const string BackupEligibleMember = "backupEligible";

    /// <summary>The <c>backupState</c> member name.</summary>
    private const string BackupStateMember = "backupState";

    /// <summary>
    /// The <c>authenticatorAttachment</c> member name. Additive-optional within
    /// <see cref="CurrentVersion"/> — see <see cref="Fido2CredentialRecord.AuthenticatorAttachment"/>'s
    /// own remarks; omitted entirely rather than written as <see langword="null"/>.
    /// </summary>
    private const string AuthenticatorAttachmentMember = "authenticatorAttachment";

    /// <summary>The <c>publicKey.kty</c> member name.</summary>
    private const string KtyMember = "kty";

    /// <summary>The <c>publicKey.alg</c> member name.</summary>
    private const string AlgMember = "alg";

    /// <summary>The <c>publicKey.crv</c> member name.</summary>
    private const string CrvMember = "crv";

    /// <summary>The <c>publicKey.x</c> member name.</summary>
    private const string XMember = "x";

    /// <summary>The <c>publicKey.y</c> member name.</summary>
    private const string YMember = "y";

    /// <summary>The <c>publicKey.yCompressionSign</c> member name.</summary>
    private const string YCompressionSignMember = "yCompressionSign";

    /// <summary>The <c>publicKey.n</c> member name (RSA modulus).</summary>
    private const string NMember = "n";

    /// <summary>The <c>publicKey.e</c> member name (RSA public exponent).</summary>
    private const string EMember = "e";


    /// <summary>
    /// Writes <paramref name="record"/> as UTF-8 JSON to <paramref name="destination"/>.
    /// </summary>
    /// <param name="record">The credential record to write.</param>
    /// <param name="destination">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="record"/> or <paramref name="destination"/> is <see langword="null"/>.
    /// </exception>
    public static void Write(Fido2CredentialRecord record, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentNullException.ThrowIfNull(destination);

        using Utf8JsonWriter writer = new(destination);
        writer.WriteStartObject();
        writer.WriteNumber(VersionMember, CurrentVersion);
        writer.WriteString(TypeMember, record.Type);
        writer.WriteString(IdMember, Base64Url.EncodeToString(record.Id.AsReadOnlySpan()));
        WritePublicKey(writer, record.PublicKey);
        writer.WriteNumber(SignCountMember, record.SignCount);
        writer.WriteBoolean(UvInitializedMember, record.UvInitialized);
        WriteTransports(writer, record.Transports);
        writer.WriteBoolean(BackupEligibleMember, record.BackupEligible);
        writer.WriteBoolean(BackupStateMember, record.BackupState);
        WriteOptionalString(writer, AuthenticatorAttachmentMember, record.AuthenticatorAttachment);
        writer.WriteEndObject();
        writer.Flush();
    }


    /// <summary>
    /// Writes the <c>publicKey</c> sub-object from a <see cref="CoseKey"/>'s parsed parameters,
    /// omitting every optional parameter <see langword="null"/> on <paramref name="publicKey"/>.
    /// </summary>
    private static void WritePublicKey(Utf8JsonWriter writer, CoseKey publicKey)
    {
        writer.WriteStartObject(PublicKeyMember);
        writer.WriteNumber(KtyMember, publicKey.Kty);
        WriteOptionalInt(writer, AlgMember, publicKey.Alg);
        WriteOptionalInt(writer, CrvMember, publicKey.Curve);
        WriteOptionalBinary(writer, XMember, publicKey.X);
        WriteOptionalBinary(writer, YMember, publicKey.Y);
        WriteOptionalBool(writer, YCompressionSignMember, publicKey.EncodedYCompressionSign);
        WriteOptionalBinary(writer, NMember, publicKey.N);
        WriteOptionalBinary(writer, EMember, publicKey.E);
        writer.WriteEndObject();
    }


    /// <summary>
    /// Writes the <c>transports</c> array from <paramref name="transports"/>.
    /// </summary>
    private static void WriteTransports(Utf8JsonWriter writer, IReadOnlyList<string> transports)
    {
        writer.WriteStartArray(TransportsMember);
        foreach(string transport in transports)
        {
            writer.WriteStringValue(transport);
        }
        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes <paramref name="value"/> under <paramref name="memberName"/> when present; omits the
    /// member entirely when <see langword="null"/>.
    /// </summary>
    private static void WriteOptionalInt(Utf8JsonWriter writer, string memberName, int? value)
    {
        if(value is not null)
        {
            writer.WriteNumber(memberName, value.Value);
        }
    }


    /// <summary>
    /// Writes <paramref name="value"/> under <paramref name="memberName"/> when present; omits the
    /// member entirely when <see langword="null"/>.
    /// </summary>
    private static void WriteOptionalBool(Utf8JsonWriter writer, string memberName, bool? value)
    {
        if(value is not null)
        {
            writer.WriteBoolean(memberName, value.Value);
        }
    }


    /// <summary>
    /// Writes <paramref name="value"/>, Base64url encoded, under <paramref name="memberName"/> when
    /// present; omits the member entirely when <see langword="null"/>.
    /// </summary>
    private static void WriteOptionalBinary(Utf8JsonWriter writer, string memberName, ReadOnlyMemory<byte>? value)
    {
        if(value is not null)
        {
            writer.WriteString(memberName, Base64Url.EncodeToString(value.Value.Span));
        }
    }


    /// <summary>
    /// Writes <paramref name="value"/> under <paramref name="memberName"/> when present; omits the
    /// member entirely when <see langword="null"/>.
    /// </summary>
    private static void WriteOptionalString(Utf8JsonWriter writer, string memberName, string? value)
    {
        if(value is not null)
        {
            writer.WriteString(memberName, value);
        }
    }
}

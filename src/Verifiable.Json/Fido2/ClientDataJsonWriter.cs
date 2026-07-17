using System;
using System.Buffers;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> writer for the <c>clientDataJSON</c> wire bytes — the production
/// counterpart to <see cref="ClientDataJsonReader"/>, living beside it for the same reason: the FIDO2
/// library stays serialization-agnostic.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3,
/// section 5.8.1: Client Data Used in WebAuthn Signatures</see> defines the <c>CollectedClientData</c>
/// members this writer emits. Uses <see cref="Utf8JsonWriter"/>'s own string escaping — real JSON
/// escaping of <c>"</c>, <c>\</c>, and control characters in <see cref="ClientData.Challenge"/> and
/// <see cref="ClientData.Origin"/>, rather than the ad hoc string interpolation an earlier composition
/// edge used, which did not escape those characters at all.
/// </para>
/// <para>
/// <see cref="ClientDataJsonReader.Read"/> tolerates any member order (only a repeated member name is
/// rejected), so this writer's fixed emission order — <c>type</c>, <c>challenge</c>, <c>origin</c>, then
/// the optional <c>crossOrigin</c> and <c>topOrigin</c> — matches the <c>CollectedClientData</c>
/// dictionary's own declaration order without that order being load-bearing for round-tripping.
/// </para>
/// </remarks>
public static class ClientDataJsonWriter
{
    /// <summary>The <c>type</c> member name.</summary>
    private const string TypeMember = "type";

    /// <summary>The <c>challenge</c> member name.</summary>
    private const string ChallengeMember = "challenge";

    /// <summary>The <c>origin</c> member name.</summary>
    private const string OriginMember = "origin";

    /// <summary>The <c>crossOrigin</c> member name.</summary>
    private const string CrossOriginMember = "crossOrigin";

    /// <summary>The <c>topOrigin</c> member name.</summary>
    private const string TopOriginMember = "topOrigin";


    /// <summary>
    /// Writes <paramref name="clientData"/> as UTF-8 JSON to <paramref name="destination"/>.
    /// </summary>
    /// <param name="clientData">The client data to write.</param>
    /// <param name="destination">The buffer the UTF-8 JSON bytes are written to.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="clientData"/> or <paramref name="destination"/> is <see langword="null"/>.
    /// </exception>
    public static void Write(ClientData clientData, IBufferWriter<byte> destination)
    {
        ArgumentNullException.ThrowIfNull(clientData);
        ArgumentNullException.ThrowIfNull(destination);

        using Utf8JsonWriter writer = new(destination);
        writer.WriteStartObject();
        writer.WriteString(TypeMember, clientData.Type);
        writer.WriteString(ChallengeMember, clientData.Challenge);
        writer.WriteString(OriginMember, clientData.Origin);

        if(clientData.CrossOrigin is bool crossOrigin)
        {
            writer.WriteBoolean(CrossOriginMember, crossOrigin);
        }

        if(clientData.TopOrigin is not null)
        {
            writer.WriteString(TopOriginMember, clientData.TopOrigin);
        }

        writer.WriteEndObject();
        writer.Flush();
    }
}

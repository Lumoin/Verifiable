using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Shared byte-level frame construction for tests that drive a TPM 2.0 Library Part 2, clause 6.6.1 wire check
/// directly — a malformed <c>TPM2B</c> size, a truncated authorization area, an out-of-range handle — past
/// every typed <c>ITpmCommandInput</c>'s own well-formedness, straight at the command parser a
/// <see cref="TpmSimulator"/> or a scripted device handler carries. Every command frame here follows the
/// header (Part 1, clause 15.9), then the handle area, then (on the sessions form) the authorization area
/// (TPM 2.0 Library Part 2, clause 10.12.2, Table 156's <c>TPMS_AUTH_COMMAND</c>; validated per Part 3, clause
/// 5.5's session area validation; Part 2, clause 6.6.2's session designation), then the parameter area, in
/// that order.
/// </summary>
internal static class TpmCommandFrameHarness
{
    /// <summary>The fixed size of a command or response header (TPM 2.0 Library Part 1, clause 15.9/15.10).</summary>
    private const int HeaderSize = TpmHeader.HeaderSize;

    /// <summary>
    /// Appends a big-endian <c>UINT32</c> to a frame body under construction — a handle, a ticket's
    /// <c>hierarchy</c> selector (<c>TPMI_RH_HIERARCHY</c>), or any other four-octet wire field a test builds
    /// by hand ahead of a deliberately malformed field that follows it.
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    public static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        body.AddRange(octets.ToArray());
    }

    /// <summary>
    /// Appends a big-endian <c>UINT16</c> to a frame body under construction — a scheme selector
    /// (<c>TPMI_ALG_SIG_SCHEME</c>), a ticket's <c>tag</c>, or any other two-octet wire field a test builds by
    /// hand ahead of a deliberately malformed field that follows it.
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    public static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, value);
        body.AddRange(octets.ToArray());
    }

    /// <summary>
    /// Appends a <c>TPM2B</c> field — a two-octet declared size followed by its body octets — whose declared
    /// size and actual body may disagree on purpose: a <paramref name="declaredSize"/> greater than
    /// <paramref name="actualOctets"/>'s own length frames the INSUFFICIENT shape (the field ends before its
    /// declared size is satisfied, TPM 2.0 Library Part 3, clause 5.8.2, Table 2's own body-length check); a
    /// <paramref name="declaredSize"/> beyond the field's structural bound frames the SIZE shape independent of
    /// how many octets follow (Part 2, clause 10.3.2, Table 90: "As with all sized buffers, the size is checked
    /// to see if it is within the prescribed range. If not, the response code is TPM_RC_SIZE"). A well-formed
    /// field is the case where the two agree.
    /// </summary>
    /// <param name="body">The frame body under construction.</param>
    /// <param name="actualOctets">The octets actually written after the declared size.</param>
    /// <param name="declaredSize">The size octet-pair to declare, independent of <paramref name="actualOctets"/>'s length.</param>
    public static void AppendTpm2b(List<byte> body, ReadOnlySpan<byte> actualOctets, int declaredSize)
    {
        AppendUInt16(body, (ushort)declaredSize);
        body.AddRange(actualOctets.ToArray());
    }

    /// <summary>Appends a well-formed <c>TPM2B</c> field: the declared size equals <paramref name="octets"/>'s own length.</summary>
    /// <param name="body">The frame body under construction.</param>
    /// <param name="octets">The field's octets.</param>
    public static void AppendTpm2b(List<byte> body, ReadOnlySpan<byte> octets) => AppendTpm2b(body, octets, octets.Length);

    /// <summary>Appends the handle area: each handle as a big-endian <c>UINT32</c>, in the command's own Part 3 table order.</summary>
    /// <param name="body">The frame body under construction.</param>
    /// <param name="handles">The handle-area values.</param>
    private static void AppendHandles(List<byte> body, ReadOnlySpan<uint> handles)
    {
        foreach(uint handle in handles)
        {
            AppendUInt32(body, handle);
        }
    }

    /// <summary>
    /// Builds one <c>TPMS_AUTH_COMMAND</c> slot's own octets — <c>sessionHandle</c>, <c>nonceCaller</c> (a
    /// <c>TPM2B</c> whose declared size may disagree with the octets actually written), <c>sessionAttributes</c>,
    /// and <c>hmac</c> (likewise) — with NO size prefix of its own, so several such slots can be concatenated
    /// under one shared authorization-area size (TPM 2.0 Library Part 2, clause 10.12.2, Table 156).
    /// </summary>
    /// <param name="sessionHandle">The session handle to name.</param>
    /// <param name="nonceOctets">The <c>nonceCaller</c> octets actually written.</param>
    /// <param name="declaredNonceSize">The size to declare for <c>nonceCaller</c>, independent of <paramref name="nonceOctets"/>'s length.</param>
    /// <param name="sessionAttributes">The <c>sessionAttributes</c> octet.</param>
    /// <param name="hmacOctets">The <c>hmac</c> octets actually written.</param>
    /// <param name="declaredHmacSize">The size to declare for <c>hmac</c>, independent of <paramref name="hmacOctets"/>'s length.</param>
    /// <returns>The slot's own octets, unwrapped.</returns>
    public static byte[] BuildSessionSlotOctets(
        uint sessionHandle, ReadOnlySpan<byte> nonceOctets, int declaredNonceSize, TpmaSession sessionAttributes,
        ReadOnlySpan<byte> hmacOctets, int declaredHmacSize)
    {
        var slot = new List<byte>();
        AppendUInt32(slot, sessionHandle);
        AppendTpm2b(slot, nonceOctets, declaredNonceSize);
        slot.Add((byte)sessionAttributes);
        AppendTpm2b(slot, hmacOctets, declaredHmacSize);

        return [.. slot];
    }

    /// <summary>
    /// Builds one empty <c>TPM_RH_PW</c> slot's own octets — <c>sessionHandle</c>, an empty <c>nonceCaller</c>,
    /// a clear <c>sessionAttributes</c>, and an empty <c>hmac</c> carrying no password (TPM 2.0 Library Part 2,
    /// clause 10.12.2, Table 156; "either an HMAC, a password, or an EmptyAuth") — with no size prefix of its
    /// own, so it can stand alone or be concatenated with other slots under one shared authorization-area size.
    /// </summary>
    /// <returns>The slot's own octets, unwrapped.</returns>
    public static byte[] BuildPasswordSlotOctets() =>
        BuildSessionSlotOctets((uint)TpmRh.TPM_RH_PW, ReadOnlySpan<byte>.Empty, 0, default, ReadOnlySpan<byte>.Empty, 0);

    /// <summary>
    /// Appends a size-prefixed authorization area holding exactly the octets given, the declared size
    /// independent of their count — so a caller can declare MORE than one slot's own bytes physically carry
    /// (a later slot's leading read then finds too few octets left), or otherwise disagree with what follows
    /// (TPM 2.0 Library Part 2, clause 6.6.1).
    /// </summary>
    /// <param name="body">The frame body under construction.</param>
    /// <param name="authorizationAreaOctets">The authorization area's own octets, verbatim.</param>
    /// <param name="declaredAuthorizationSize">The size to declare, independent of <paramref name="authorizationAreaOctets"/>'s length.</param>
    public static void AppendRawAuthorizationArea(List<byte> body, ReadOnlySpan<byte> authorizationAreaOctets, int declaredAuthorizationSize)
    {
        AppendUInt32(body, (uint)declaredAuthorizationSize);
        body.AddRange(authorizationAreaOctets.ToArray());
    }

    /// <summary>
    /// Appends one empty <c>TPM_RH_PW</c> authorization slot, size-prefixed as the whole authorization area
    /// (TPM 2.0 Library Part 2, clause 6.6.1).
    /// </summary>
    /// <param name="body">The frame body under construction.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body)
    {
        byte[] slot = BuildPasswordSlotOctets();
        AppendRawAuthorizationArea(body, slot, slot.Length);
    }

    /// <summary>
    /// Appends one REAL (non-password) authorization slot whose <c>nonceCaller</c> and <c>hmac</c> fields each
    /// carry an independently declared size, so a truncated or malformed session area can be framed, size
    /// -prefixed as the whole authorization area (TPM 2.0 Library Part 2, clause 6.6.1).
    /// </summary>
    /// <param name="body">The frame body under construction.</param>
    /// <param name="sessionHandle">The session handle to name.</param>
    /// <param name="nonceOctets">The <c>nonceCaller</c> octets actually written.</param>
    /// <param name="declaredNonceSize">The size to declare for <c>nonceCaller</c>.</param>
    /// <param name="sessionAttributes">The <c>sessionAttributes</c> octet.</param>
    /// <param name="hmacOctets">The <c>hmac</c> octets actually written.</param>
    /// <param name="declaredHmacSize">The size to declare for <c>hmac</c>.</param>
    private static void AppendRealSessionAuthorizationArea(
        List<byte> body, uint sessionHandle, ReadOnlySpan<byte> nonceOctets, int declaredNonceSize,
        TpmaSession sessionAttributes, ReadOnlySpan<byte> hmacOctets, int declaredHmacSize)
    {
        byte[] slot = BuildSessionSlotOctets(sessionHandle, nonceOctets, declaredNonceSize, sessionAttributes, hmacOctets, declaredHmacSize);
        AppendRawAuthorizationArea(body, slot, slot.Length);
    }

    /// <summary>
    /// Frames a complete <c>TPM_ST_NO_SESSIONS</c> command: the header, the handle area, then the parameter
    /// area, with no authorization area at all (TPM 2.0 Library Part 2, clause 6.6.1).
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handles">The handle-area values, in the command's own table order.</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete command frame.</returns>
    public static byte[] FrameNoSessionsCommand(TpmCcConstants commandCode, ReadOnlySpan<uint> handles, ReadOnlySpan<byte> parameters)
    {
        var body = new List<byte>();
        AppendHandles(body, handles);
        body.AddRange(parameters.ToArray());

        return BuildFrame((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)commandCode, body.ToArray());
    }

    /// <summary>
    /// Frames a complete <c>TPM_ST_SESSIONS</c> command authorized by a single empty <c>TPM_RH_PW</c> slot: the
    /// header, the handle area, one empty password authorization area, then the parameter area.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handles">The handle-area values, in the command's own table order.</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete command frame.</returns>
    public static byte[] FramePasswordAuthorizedCommand(TpmCcConstants commandCode, ReadOnlySpan<uint> handles, ReadOnlySpan<byte> parameters)
    {
        var body = new List<byte>();
        AppendHandles(body, handles);
        AppendPasswordAuthorizationArea(body);
        body.AddRange(parameters.ToArray());

        return BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandCode, body.ToArray());
    }

    /// <summary>
    /// Frames a complete <c>TPM_ST_SESSIONS</c> command authorized by a single REAL session slot built from the
    /// caller's own fields, so a truncated or malformed session area can be framed: the header, the handle
    /// area, the authorization area, then the parameter area.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handles">The handle-area values, in the command's own table order.</param>
    /// <param name="sessionHandle">The authorizing session handle.</param>
    /// <param name="nonceOctets">The <c>nonceCaller</c> octets actually written.</param>
    /// <param name="declaredNonceSize">The size to declare for <c>nonceCaller</c>, independent of <paramref name="nonceOctets"/>'s length.</param>
    /// <param name="sessionAttributes">The <c>sessionAttributes</c> octet.</param>
    /// <param name="hmacOctets">The <c>hmac</c> octets actually written.</param>
    /// <param name="declaredHmacSize">The size to declare for <c>hmac</c>, independent of <paramref name="hmacOctets"/>'s length.</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete command frame.</returns>
    public static byte[] FrameRealSessionCommand(
        TpmCcConstants commandCode, ReadOnlySpan<uint> handles, uint sessionHandle, ReadOnlySpan<byte> nonceOctets, int declaredNonceSize,
        TpmaSession sessionAttributes, ReadOnlySpan<byte> hmacOctets, int declaredHmacSize, ReadOnlySpan<byte> parameters)
    {
        var body = new List<byte>();
        AppendHandles(body, handles);
        AppendRealSessionAuthorizationArea(body, sessionHandle, nonceOctets, declaredNonceSize, sessionAttributes, hmacOctets, declaredHmacSize);
        body.AddRange(parameters.ToArray());

        return BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandCode, body.ToArray());
    }

    /// <summary>
    /// Frames a complete <c>TPM_ST_SESSIONS</c> command whose authorization area is exactly the caller's own
    /// octets under a caller-chosen declared size: the header, the handle area, the raw authorization area,
    /// then the parameter area. The one building block general enough for a multi-slot area where a declared
    /// size exceeds what the physically-present slot(s) carry — so a parser that reads a first slot cleanly and
    /// then, believing more of the declared area remains, attempts a SECOND slot finds too few octets left.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="handles">The handle-area values, in the command's own table order.</param>
    /// <param name="authorizationAreaOctets">The authorization area's own octets, verbatim — one slot's, or several concatenated with <see cref="BuildSessionSlotOctets"/>/<see cref="BuildPasswordSlotOctets"/>.</param>
    /// <param name="declaredAuthorizationSize">The size to declare, independent of <paramref name="authorizationAreaOctets"/>'s length.</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete command frame.</returns>
    public static byte[] FrameCommandWithRawAuthorizationArea(
        TpmCcConstants commandCode, ReadOnlySpan<uint> handles, ReadOnlySpan<byte> authorizationAreaOctets, int declaredAuthorizationSize, ReadOnlySpan<byte> parameters)
    {
        var body = new List<byte>();
        AppendHandles(body, handles);
        AppendRawAuthorizationArea(body, authorizationAreaOctets, declaredAuthorizationSize);
        body.AddRange(parameters.ToArray());

        return BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)commandCode, body.ToArray());
    }

    /// <summary>
    /// Frames a complete <c>TPM_ST_NO_SESSIONS</c> response or handle-free command: the header followed by
    /// <paramref name="parameters"/> verbatim, with no handle area at all — the shape every response carries
    /// (TPM 2.0 Library Part 1, clause 15.10).
    /// </summary>
    /// <param name="code">The response code (or, for a handle-free command, the command code).</param>
    /// <param name="parameters">The already-marshaled parameter octets.</param>
    /// <returns>The complete frame.</returns>
    public static byte[] BuildNoSessionsFrame(uint code, ReadOnlySpan<byte> parameters) =>
        BuildFrame((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, code, parameters);

    /// <summary>
    /// Frames a complete <c>TPM_ST_SESSIONS</c> response: the header, the size-prefixed parameters, then the
    /// response authorization area exactly as given — so a test can hand a scripted device a malformed response
    /// authorization area (TPM 2.0 Library Part 1, clause 15.10; Part 2, clause 6.6.1).
    /// </summary>
    /// <param name="responseCode">The response code.</param>
    /// <param name="parameters">The response parameters.</param>
    /// <param name="authArea">The response authorization area octets, verbatim.</param>
    /// <returns>The complete frame.</returns>
    public static byte[] BuildSessionsResponseFrame(uint responseCode, ReadOnlySpan<byte> parameters, ReadOnlySpan<byte> authArea)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)parameters.Length);
        body.AddRange(parameters.ToArray());
        body.AddRange(authArea.ToArray());

        return BuildFrame((ushort)TpmStConstants.TPM_ST_SESSIONS, responseCode, body.ToArray());
    }

    /// <summary>
    /// Writes a complete frame: the ten-octet header (TPM 2.0 Library Part 1, clause 15.9/15.10) followed by
    /// <paramref name="body"/> verbatim. Shared by every frame-construction method above, since a command's header and a
    /// response's header share one wire layout, differing only in whether the third field is read as a command
    /// code or a response code.
    /// </summary>
    /// <param name="tag">The structure tag (<c>TPM_ST_SESSIONS</c> or <c>TPM_ST_NO_SESSIONS</c>).</param>
    /// <param name="code">The command code (a request) or response code (a response).</param>
    /// <param name="body">Everything after the header.</param>
    /// <returns>The complete frame.</returns>
    public static byte[] BuildFrame(ushort tag, uint code, ReadOnlySpan<byte> body)
    {
        int length = HeaderSize + body.Length;
        byte[] framed = new byte[length];
        var writer = new TpmWriter(framed);
        var header = new TpmHeader(tag, (uint)length, code);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        return framed;
    }

    /// <summary>
    /// Submits a hand-framed command straight to the simulator and returns the response code its header
    /// carries: a parse refusal is a header-only response rather than a transport failure, so the header alone
    /// is what a malformed-frame proof needs.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool the response is framed from.</param>
    /// <param name="command">The complete command frame.</param>
    /// <param name="cancellationToken">A token observed across the exchange.</param>
    /// <returns>The response code the simulator answered with.</returns>
    public static async Task<TpmRcConstants> SubmitRawAsync(
        TpmSimulator simulator, BaseMemoryPool pool, ReadOnlyMemory<byte> command, CancellationToken cancellationToken)
    {
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(command, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "A refused frame must still be answered with a framed response.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }
}

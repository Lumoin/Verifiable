using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Fido2;

namespace Verifiable.Cbor.Ctap;

/// <summary>
/// Decodes the top-level integer-keyed CBOR map every CTAP2 command's request parameters share, one
/// pass, without interpreting each member's value.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#commands">
/// CTAP 2.3, section 8.1: Command Codes</see>: "Command parameters are encoded using a CBOR map
/// (CBOR major type 5). The CBOR map MUST be encoded using the definite length variant." Every
/// CTAP2 command's request parameters share this shape (small-integer keys at the top level,
/// <c>authenticatorMakeCredential</c>'s <c>clientDataHash</c>(1)/<c>rp</c>(2)/<c>user</c>(3)/... and
/// <c>authenticatorGetAssertion</c>'s <c>rpId</c>(1)/<c>clientDataHash</c>(2)/... are both instances
/// of it), so this reader is a command-agnostic building block: it captures each top-level key's
/// still-encoded value (mirroring <c>CredentialPublicKeyCborReader</c>'s two-pass approach) without
/// assuming which command produced the map, leaving type-specific interpretation to a command's own
/// reader.
/// </para>
/// <para>
/// <c>authenticatorGetInfo</c> itself takes no input parameters
/// (<see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// section 6.4</see>: "This method takes no inputs"), so wave 1 has no command whose request this
/// reader decodes in production; it is proven here against a synthetic vector and is the seam a
/// later wave's <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> request reader
/// builds on.
/// </para>
/// </remarks>
public static class CtapParameterMapReader
{
    /// <summary>
    /// Decodes the top-level integer-keyed CBOR map in <paramref name="parametersCbor"/>.
    /// </summary>
    /// <param name="parametersCbor">The CBOR-encoded command parameter map.</param>
    /// <returns>
    /// Each top-level key's still-CBOR-encoded value, in the wire's key order. The caller decodes
    /// each value according to the command-specific meaning of its key.
    /// </returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="parametersCbor"/> is not a valid CTAP2 canonical CBOR map (classified
    /// <see cref="Fido2FormatFailureKind.MalformedCbor"/>, including a duplicate top-level key), or a
    /// top-level key/value has an unexpected CBOR type (classified
    /// <see cref="Fido2FormatFailureKind.UnexpectedStructure"/>).
    /// </exception>
    public static IReadOnlyDictionary<int, ReadOnlyMemory<byte>> Read(ReadOnlyMemory<byte> parametersCbor)
    {
        try
        {
            var reader = new CborReader(parametersCbor, CborConformanceMode.Ctap2Canonical);
            int? entryCount = reader.ReadStartMap();

            var rawValuesByKey = new Dictionary<int, ReadOnlyMemory<byte>>();
            int entriesRead = 0;
            while(entryCount is null ? reader.PeekState() != CborReaderState.EndMap : entriesRead < entryCount.Value)
            {
                int key = checked((int)reader.ReadInt64());
                entriesRead++;
                ReadOnlyMemory<byte> encodedValue = reader.ReadEncodedValue();

                if(!rawValuesByKey.TryAdd(key, encodedValue))
                {
                    //A duplicate top-level key is itself a canonical-CBOR encoding violation (CTAP 2.3
                    //section 8's canonical form forbids it), not a value-typing problem, so it classifies
                    //as MalformedCbor alongside the syntax-error catch below.
                    throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, $"The CTAP2 command parameter map carries the key {key} more than once, which the canonical CBOR encoding form forbids.");
                }
            }

            reader.ReadEndMap();

            return rawValuesByKey;
        }
        catch(CborContentException exception)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.MalformedCbor, "The CTAP2 command parameter bytes are not valid CTAP2 canonical CBOR.", exception);
        }
        catch(Exception exception) when(exception is InvalidOperationException or OverflowException)
        {
            throw new Fido2FormatException(Fido2FormatFailureKind.UnexpectedStructure, "The CTAP2 command parameter map carries a top-level key or value of an unexpected CBOR type.", exception);
        }
    }
}

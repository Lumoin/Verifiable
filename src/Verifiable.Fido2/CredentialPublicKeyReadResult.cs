using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.Fido2;

/// <summary>
/// The result of reading a COSE_Key <c>credentialPublicKey</c> from the start of a buffer.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
/// </remarks>
/// <param name="CoseKey">The parsed COSE_Key.</param>
/// <param name="BytesConsumed">
/// The number of bytes the COSE_Key encoding occupied at the start of the source buffer,
/// so the caller can locate the extensions slice, if any, that follows it.
/// </param>
/// <param name="Labels">
/// The top-level integer labels the reader encountered while parsing the COSE_Key, in wire order,
/// including duplicates if the wire bytes carried any. An implementation of
/// <see cref="ReadCredentialPublicKeyDelegate"/> MUST report every top-level label it read — including
/// ones it otherwise ignores — so the WebAuthn L3 section 6.5.1 parameter-completeness enforcement at the
/// parse boundary can see the credential public key's exact on-wire shape.
/// </param>
[DebuggerDisplay("CredentialPublicKeyReadResult(BytesConsumed={BytesConsumed}, Labels={Labels.Count})")]
public sealed record CredentialPublicKeyReadResult(CoseKey CoseKey, int BytesConsumed, IReadOnlyList<int> Labels);


/// <summary>
/// Reads the self-describing COSE_Key at the start of <paramref name="source"/> and reports
/// how many bytes it consumed.
/// </summary>
/// <param name="source">
/// The buffer whose leading bytes are a COSE_Key encoding; any bytes beyond the encoding
/// (the extensions slice) are not consumed.
/// </param>
/// <returns>
/// The parsed COSE_Key together with the number of bytes it occupied and the top-level labels
/// encountered while parsing it.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data">W3C Web Authentication Level 3, section 6.5.1: Attested Credential Data.</see>
/// </para>
/// <para>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic.
/// </para>
/// </remarks>
public delegate CredentialPublicKeyReadResult ReadCredentialPublicKeyDelegate(ReadOnlyMemory<byte> source);

using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// The logical result of processing a command in the eMRTD card simulator. The pure transition function
/// produces an intent; <see cref="CardSimulator"/> serializes it to response-APDU bytes (the data field,
/// if any, followed by the status word) against the injected memory pool when the response leaves the card.
/// </summary>
/// <remarks>
/// Keeping the response logical — a status word plus an optional data window — rather than raw bytes keeps
/// the transition function free of buffer allocation, so all framing happens in one place against a pooled
/// buffer, mirroring the TPM simulator's response-intent design.
/// </remarks>
/// <param name="StatusWord">The status word carried in the response trailer.</param>
public abstract record CardResponseIntent(StatusWord StatusWord);

/// <summary>
/// A response carrying only a status word and no data field — a successful SELECT (<c>9000</c>) or any
/// error response.
/// </summary>
/// <param name="StatusWord">The status word.</param>
public sealed record StatusOnlyResponse(StatusWord StatusWord): CardResponseIntent(StatusWord);

/// <summary>
/// The successful response to READ BINARY: the requested octets of the selected file followed by
/// <c>9000</c>.
/// </summary>
/// <remarks>
/// <see cref="Data"/> is a window into the selected <see cref="ElementaryFile"/>, which the card holds for
/// its lifetime; <see cref="CardSimulator"/> copies the window into the framed response immediately after
/// the transition, so the view is never read after the file could be released.
/// </remarks>
/// <param name="StatusWord">The status word (success).</param>
/// <param name="Data">The octets read from the selected file (a borrowed view, not owned).</param>
[DebuggerDisplay("BinaryReadResponse({Data.Length} bytes, {StatusWord})")]
public sealed record BinaryReadResponse(StatusWord StatusWord, ReadOnlyMemory<byte> Data): CardResponseIntent(StatusWord);

/// <summary>
/// The successful response to GET CHALLENGE: the chip nonce RND.IC followed by <c>9000</c>.
/// </summary>
/// <remarks>
/// The octets are held in a pooled buffer rented by the RNG action executor. <see cref="CardSimulator"/>
/// copies them into the framed response and then disposes <see cref="Challenge"/>; the intent is the
/// terminal owner of that buffer and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="StatusWord">The status word (success).</param>
/// <param name="Challenge">The pooled buffer holding the issued challenge octets; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="Challenge"/>.</param>
[DebuggerDisplay("ChallengeResponse({Length} bytes, {StatusWord})")]
public sealed record ChallengeResponse(StatusWord StatusWord, IMemoryOwner<byte> Challenge, int Length): CardResponseIntent(StatusWord);

/// <summary>
/// The successful response to EXTERNAL AUTHENTICATE: the card's Basic Access Control token <c>EIC || MIC</c>
/// followed by <c>9000</c>.
/// </summary>
/// <remarks>
/// The token is held in a pooled buffer produced by the BAC responder. <see cref="CardSimulator"/> copies it
/// into the framed response and then disposes <see cref="Token"/>; the intent is the terminal owner of that
/// buffer and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="StatusWord">The status word (success).</param>
/// <param name="Token">The pooled buffer holding <c>EIC || MIC</c>; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="Token"/>.</param>
[DebuggerDisplay("BacAuthenticateResponse({Length} bytes, {StatusWord})")]
public sealed record BacAuthenticateResponse(StatusWord StatusWord, IMemoryOwner<byte> Token, int Length): CardResponseIntent(StatusWord);

/// <summary>
/// The response to a PACE GENERAL AUTHENTICATE round: a dynamic authentication data object (tag <c>0x7C</c>)
/// — the encrypted nonce, a public key, or a token, depending on the round — followed by <c>9000</c>.
/// </summary>
/// <remarks>
/// The object is held in a pooled buffer the round's action executor produced. <see cref="CardSimulator"/>
/// copies it into the framed response and then disposes <see cref="Data"/>; the intent is the terminal owner
/// of that buffer and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="StatusWord">The status word (success).</param>
/// <param name="Data">The pooled buffer holding the <c>7C</c> response object; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="Data"/>.</param>
[DebuggerDisplay("DynamicAuthenticationDataResponse({Length} bytes, {StatusWord})")]
public sealed record DynamicAuthenticationDataResponse(StatusWord StatusWord, IMemoryOwner<byte> Data, int Length): CardResponseIntent(StatusWord);

/// <summary>
/// The successful response to INTERNAL AUTHENTICATE: the chip's Active Authentication signature over the
/// challenge followed by <c>9000</c>.
/// </summary>
/// <remarks>
/// The signature is held in a pooled buffer produced by the Active Authentication responder.
/// <see cref="CardSimulator"/> copies it into the framed response (or, over Secure Messaging, protects it)
/// and then disposes <see cref="Signature"/>; the intent is the terminal owner of that buffer and is
/// consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="StatusWord">The status word (success).</param>
/// <param name="Signature">The pooled buffer holding the signature; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="Signature"/>.</param>
[DebuggerDisplay("ActiveAuthenticationResponse({Length} bytes, {StatusWord})")]
public sealed record ActiveAuthenticationResponse(StatusWord StatusWord, IMemoryOwner<byte> Signature, int Length): CardResponseIntent(StatusWord);

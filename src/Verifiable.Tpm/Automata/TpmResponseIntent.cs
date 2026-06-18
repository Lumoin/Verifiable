using System.Buffers;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The logical result of processing a command in the simulator. The pure transition function produces
/// an intent; <see cref="TpmSimulator"/> serializes it to TPM response bytes against the injected
/// memory pool when the response leaves the device.
/// </summary>
/// <remarks>
/// Keeping the response logical — a response code plus an optional typed payload — rather than raw
/// bytes keeps the transition function free of buffer allocation, so all framing happens in one place
/// against a pooled buffer.
/// </remarks>
/// <param name="ResponseCode">The TPM response code carried in the response header.</param>
public abstract record TpmResponseIntent(TpmRcConstants ResponseCode);

/// <summary>
/// A response carrying only the 10-byte header with no parameters. Used for command successes that
/// return no data (<c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>) and for
/// every error response.
/// </summary>
/// <param name="ResponseCode">The response code.</param>
public sealed record TpmHeaderOnlyResponse(TpmRcConstants ResponseCode): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetTestResult()</c>: an outData buffer (empty in this lifecycle
/// skeleton) followed by the self-test result code.
/// </summary>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="TestResult">
/// The self-test outcome reported in the response body: <c>TPM_RC_SUCCESS</c> when the self-test
/// passed, <c>TPM_RC_FAILURE</c> when it failed (TPM 2.0 Library Part 1, clause 10.4).
/// </param>
public sealed record TpmTestResultResponse(TpmRcConstants ResponseCode, TpmRcConstants TestResult): TpmResponseIntent(ResponseCode);

/// <summary>
/// The successful response to <c>TPM2_GetRandom()</c>: a <c>TPM2B_DIGEST</c> carrying the random
/// octets (TPM 2.0 Library Part 3, clause 16.1).
/// </summary>
/// <remarks>
/// The octets are held in a pooled buffer rented by the RNG action executor. <see cref="TpmSimulator"/>
/// copies them into the framed response and then disposes <see cref="RandomBytes"/>; the intent is the
/// terminal owner of that buffer and is consumed exactly once, immediately after the transition.
/// </remarks>
/// <param name="ResponseCode">The command response code (success).</param>
/// <param name="RandomBytes">The pooled buffer holding the produced octets; disposed after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="RandomBytes"/>.</param>
public sealed record TpmRandomResponse(TpmRcConstants ResponseCode, IMemoryOwner<byte> RandomBytes, int Length): TpmResponseIntent(ResponseCode);

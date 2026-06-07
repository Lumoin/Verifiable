using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The Receiver's delivery-method-agnostic reception pipeline for one SET:
/// verify and validate via <see cref="SecurityEventTokenVerification"/>, then
/// decide how to dispose of it — acknowledge, acknowledge-as-duplicate, or
/// reject with a SET error per the delivery RFCs.
/// </summary>
/// <remarks>
/// <para>
/// Push (RFC 8935) and poll (RFC 8936) deliver the same SETs over different
/// transports, so the decision is computed once here: a push endpoint maps
/// <see cref="SsfDeliveryOutcome.Accepted"/>/<see cref="SsfDeliveryOutcome.AcceptedDuplicate"/>
/// to <c>202 Accepted</c> and <see cref="SsfDeliveryOutcome.Rejected"/> to
/// <c>400</c> with the <see cref="SsfSetError"/> body; a poll client routes the
/// <c>jti</c> into the next poll request's <c>ack</c> or <c>setErrs</c>.
/// </para>
/// <para>
/// A replayed <c>jti</c> is NOT an error: delivery is at-least-once and a
/// Transmitter may legitimately redeliver an unacknowledged SET, so Receivers
/// SHOULD re-acknowledge repeats (RFC 8936 §2.4). The pipeline therefore turns
/// the verifier's <see cref="SecurityEventTokenValidationError.Replayed"/> into
/// <see cref="SsfDeliveryOutcome.AcceptedDuplicate"/> — acknowledged, but with no
/// token to act on.
/// </para>
/// <para>
/// When the Receiver has an outstanding verification request (SSF §8.1.4), it
/// passes the expected <c>state</c>; a received SSF verification event whose
/// <c>state</c> does not match is rejected with
/// <see cref="SsfDeliveryErrorCodes.InvalidState"/> per SSF §8.1.4.1.
/// </para>
/// </remarks>
public static class SecurityEventTokenReception
{
    /// <summary>
    /// Receives one compact SET: verifies, validates, and decides its disposition.
    /// </summary>
    /// <param name="compactSet">The compact SET as delivered (push body or a poll <c>sets</c> value).</param>
    /// <param name="signingPublicKey">The Transmitter's public key (resolved from its <c>jwks_uri</c>).</param>
    /// <param name="expectedIssuer">The issuer the <c>iss</c> claim MUST equal (the stream's <c>iss</c>).</param>
    /// <param name="expectedAudience">The audience the <c>aud</c> claim MUST include.</param>
    /// <param name="headerDeserializer">Deserializes the header segment's JSON bytes.</param>
    /// <param name="payloadDeserializer">Deserializes the payload segment's JSON bytes.</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the compact segments.</param>
    /// <param name="isJtiSeen">The replay tracker consulted during verification.</param>
    /// <param name="context">Per-call exchange context, threaded to the replay check.</param>
    /// <param name="memoryPool">Memory pool for transient verification buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="expectedVerificationState">
    /// The <c>state</c> from the Receiver's outstanding verification request, if any. When set
    /// and the SET carries an SSF verification event, the event's <c>state</c> MUST match.
    /// </param>
    public static async ValueTask<SsfDeliveryDecision> ReceiveAsync(
        string compactSet,
        PublicKeyMemory signingPublicKey,
        string expectedIssuer,
        string expectedAudience,
        SecurityEventTokenPartDeserializer headerDeserializer,
        SecurityEventTokenPartDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        IsSecurityEventTokenJtiSeenDelegate isJtiSeen,
        ExchangeContext context,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken,
        string? expectedVerificationState = null)
    {
        SecurityEventTokenVerificationResult result = await SecurityEventTokenVerification.VerifyAsync(
            compactSet,
            signingPublicKey,
            expectedIssuer,
            expectedAudience,
            headerDeserializer,
            payloadDeserializer,
            base64UrlDecoder,
            isJtiSeen,
            context,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        if(result.IsValid)
        {
            SecurityEventToken token = result.Token!;
            if(expectedVerificationState is not null && !VerificationStateMatches(token, expectedVerificationState))
            {
                return new SsfDeliveryDecision
                {
                    Outcome = SsfDeliveryOutcome.Rejected,
                    Error = new SsfSetError
                    {
                        Err = SsfDeliveryErrorCodes.InvalidState,
                        Description = "The verification event state does not match the requested state."
                    }
                };
            }

            return new SsfDeliveryDecision { Outcome = SsfDeliveryOutcome.Accepted, Token = token };
        }

        if(result.Error == SecurityEventTokenValidationError.Replayed)
        {
            return new SsfDeliveryDecision { Outcome = SsfDeliveryOutcome.AcceptedDuplicate };
        }

        return new SsfDeliveryDecision
        {
            Outcome = SsfDeliveryOutcome.Rejected,
            Error = MapToSetError(result.Error!.Value)
        };
    }


    /// <summary>
    /// Maps a verification failure to the SET delivery error reported on the wire
    /// (RFC 8935 §2.4 / RFC 8936 §2.6 error codes).
    /// </summary>
    public static SsfSetError MapToSetError(SecurityEventTokenValidationError error) => error switch
    {
        SecurityEventTokenValidationError.SignatureInvalid => new SsfSetError
        {
            Err = SsfDeliveryErrorCodes.InvalidKey,
            Description = "The SET signature did not verify against the Transmitter's key."
        },
        SecurityEventTokenValidationError.IssuerMismatch => new SsfSetError
        {
            Err = SsfDeliveryErrorCodes.InvalidIssuer,
            Description = "The SET issuer is invalid for this Receiver."
        },
        SecurityEventTokenValidationError.AudienceMismatch => new SsfSetError
        {
            Err = SsfDeliveryErrorCodes.InvalidAudience,
            Description = "The SET audience does not correspond to this Receiver."
        },
        //Malformed, ExplicitTypeMissing, MissingIssuedAt, MissingJwtId, NoEvents —
        //and Replayed, which callers divert to AcceptedDuplicate before mapping —
        //are structural: the SET cannot be parsed or is otherwise invalid.
        _ => new SsfSetError
        {
            Err = SsfDeliveryErrorCodes.InvalidRequest,
            Description = "The SET could not be parsed or is otherwise invalid."
        }
    };


    //SSF §8.1.4.1: when an expected state exists, a carried verification event must
    //echo it exactly; a missing or different state fails the verification round trip.
    private static bool VerificationStateMatches(SecurityEventToken token, string expectedState)
    {
        foreach(SecurityEvent securityEvent in token.Events)
        {
            if(!SsfEventTypes.IsVerification(securityEvent.EventType))
            {
                continue;
            }

            if(!securityEvent.Payload.TryGetValue(SsfStreamManagementParameterNames.State, out object? value) || value is not string state)
            {
                return false;
            }

            return string.Equals(state, expectedState, StringComparison.Ordinal);
        }

        //No verification event present: the expectation does not apply to this SET.
        return true;
    }
}

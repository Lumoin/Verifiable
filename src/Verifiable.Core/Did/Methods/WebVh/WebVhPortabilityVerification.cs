using System;
using System.Collections.Generic;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Verifies did:webvh portability: a DID may change the <c>id</c> in its DIDDoc (move to a different HTTPS
/// location) across log entries only under the conditions the specification fixes (did:webvh v1.0, DID
/// Portability). The check runs after the entry replay has verified the chain, proofs and parameters, and
/// terminates resolution fail-closed when a rename does not satisfy every condition.
/// </summary>
/// <remarks>
/// <para>
/// The conditions for a valid rename are: portability was active going into the entry, the new <c>id</c>
/// retains the established SCID, and the new DIDDoc lists the prior DID in its <c>alsoKnownAs</c>. The full
/// DID Log from creation and a valid rename entry building on its predecessors are already guaranteed by the
/// preceding replay (the resolver fetches and verifies the whole <c>did.jsonl</c>).
/// </para>
/// <para>
/// Portability is governed by the <em>prior</em> entry's <c>portable</c> flag — the value active before the
/// renaming entry — matching <c>didwebvh-py</c> (<c>prev_state.portable</c>); <c>portable</c> can only be
/// enabled in the first entry, so this is the established setting at the time of the move.
/// </para>
/// <para>
/// Prior domain components are never used to judge history or trust: the check binds a move through the SCID,
/// the verified entry chain and the <c>alsoKnownAs</c> back-reference, never through domain reputation (the
/// did:webvh v1.0 "Misleading Prior Domain Association" security note). Only the current hosting location —
/// enforced by the resolved entry's <c>id</c> matching the requested DID — is relevant.
/// </para>
/// </remarks>
public static class WebVhPortabilityVerification
{
    private const string WebVhMethodPrefix = "did:webvh:";


    /// <summary>
    /// Confirms every DIDDoc <c>id</c> across the replayed entries bears the established SCID and that any
    /// change of <c>id</c> is an authorized rename (did:webvh v1.0, DID Portability).
    /// </summary>
    /// <param name="states">The verified replay states up to and including the resolved target, in order.</param>
    /// <param name="identities">The DIDDoc identity fields of the same entries, in the same order.</param>
    /// <returns><see langword="null"/> when every entry is valid; otherwise an error message.</returns>
    public static string? Verify(IReadOnlyList<WebVhState> states, IReadOnlyList<WebVhDocumentIdentity> identities)
    {
        ArgumentNullException.ThrowIfNull(states);
        ArgumentNullException.ThrowIfNull(identities);

        string? priorId = null;
        for(int index = 0; index < states.Count; index++)
        {
            WebVhDocumentIdentity identity = identities[index];

            //Every entry's DIDDoc id MUST be a did:webvh identifier that retains the established SCID. The SCID
            //binds the DID across any move; a renamed DID keeps it (did:webvh v1.0, DID Portability).
            string scidPrefix = $"{WebVhMethodPrefix}{states[index].Parameters.Scid}:";
            if(identity.Id is not { Length: > 0 } currentId || !currentId.StartsWith(scidPrefix, StringComparison.Ordinal))
            {
                return $"The did:webvh entry '{states[index].VersionId}' DIDDoc id MUST be a did:webvh identifier bearing the established SCID.";
            }

            if(index > 0 && !string.Equals(currentId, priorId, StringComparison.Ordinal))
            {
                //A change to the DIDDoc id is a rename: portability MUST have been active before this entry, and
                //the new DIDDoc MUST list the prior DID in alsoKnownAs (did:webvh v1.0, DID Portability).
                if(!states[index - 1].Parameters.Portable)
                {
                    return $"The did:webvh DID id changed at '{states[index].VersionId}' but portability was not enabled.";
                }

                if(priorId is null || !identity.AlsoKnownAs.Contains(priorId))
                {
                    return $"The renamed did:webvh entry '{states[index].VersionId}' MUST list the prior DID in alsoKnownAs.";
                }

                //A move MUST retain the SAME SCID, which is already guaranteed: the per-entry check above requires
                //every id (the prior and the renamed one) to bear the established SCID prefix, so a moved id whose
                //SCID segment differs is rejected there before this point (did:webvh v1.0, DID Portability).
            }

            priorId = currentId;
        }

        return null;
    }
}

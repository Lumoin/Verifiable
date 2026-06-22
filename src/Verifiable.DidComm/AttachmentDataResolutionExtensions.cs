using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.Foundation;

namespace Verifiable.DidComm;

/// <summary>
/// Resolves a DIDComm attachment's <c>data</c> object to its payload bytes — inline by value
/// (<c>base64</c> / <c>json</c>) or by reference (<c>links</c> + <c>hash</c>), per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#attachments">DIDComm Messaging v2.1 §Attachments</see>.
/// </summary>
/// <remarks>
/// <para>
/// A <c>data</c> object MUST carry at least one access form, and "enough to allow access to the content"
/// (DIDComm v2.1 §Attachments). The resolution is a fixed <em>precedence</em>, not a fallback chain: a
/// present-but-malformed inline form is a HARD FAIL and never silently falls back to a remote fetch.
/// The order is: no form -> <see cref="AttachmentResolutionError.MissingData"/>; only <c>jws</c> ->
/// <see cref="AttachmentResolutionError.JwsResolutionNotSupported"/> (a signed attachment is a different
/// trust axis); prefer INLINE — <c>base64</c> then <c>json</c>, verifying <c>hash</c> if present; else
/// <c>links</c> — require <c>hash</c> first, then fetch each location through the SSRF-policed
/// <see cref="OutboundFetch"/> until one yields a size-bounded, hash-verified body.
/// </para>
/// <para>
/// Fail-closed and never-throwing on the untrusted path: every decoder is wrapped so a malformed value is
/// a typed <see cref="AttachmentResolutionError"/>, the outbound fetch fails closed by return, and a
/// transport exception is caught (cancellation is re-thrown). A <c>hash</c> mismatch — inline or fetched —
/// NEVER returns the bytes. Producer-side null/argument guards on the seam delegates MAY throw.
/// </para>
/// </remarks>
public static class AttachmentDataResolutionExtensions
{
    //did:webvh / did:peer:4 fix the multihash to varint(code) || varint(length) || digest. The resolver
    //accepts only the single-byte code/length form (no multi-byte varint reader exists in the repo); the
    //algorithm is read from the code byte and resolved through the supplied HashFunctionSelector.
    //MaximumDigestLength caps the recompute stack buffer (64 = SHA-512, the widest the family produces).
    private const int MaximumDigestLength = 64;

    //A conforming single-algorithm multihash hash string is short — a sha2-256 multihash is 34 bytes, under
    //~70 chars across base58/base64/hex. The string length is bounded BEFORE any decode (bound-before-decode
    //doctrine) so a hostile hash cannot drive a decode allocation; 128 is comfortably above any real value.
    private const int MaximumHashStringLength = 128;


    /// <summary>
    /// The hard upper bound on the decoded length of an inline (<c>base64</c> / <c>json</c>) attachment
    /// payload. Inline content is attacker-controlled wire data, so the decoded length is bounded BEFORE
    /// the bytes are accepted, capping the pooled allocation a hostile attachment can drive.
    /// </summary>
    public static int MaximumInlineAttachmentLength => 4 * 1024 * 1024;

    /// <summary>
    /// The hard upper bound on the length of a fetched (<c>links</c>) attachment body accepted from the
    /// transport. The outbound-fetch policy does not bound bytes, so the body length is checked BEFORE it
    /// is hash-verified or accepted.
    /// </summary>
    public static int MaximumFetchedAttachmentLength => 16 * 1024 * 1024;

    /// <summary>
    /// The hard upper bound on how many <c>links</c> locations are fetched while resolving one attachment.
    /// DIDComm v2.1 §Attachments lets an attachment carry unboundedly many <c>links</c> ("a list of zero or
    /// more locations"), but a receiver need not chase them all: bounding the count stops a single inbound
    /// message from driving an arbitrary number of outbound requests (an amplification vector that the
    /// per-target SSRF policy does not address). The first verified body wins, so reachable fallbacks are
    /// still tried in order up to this cap.
    /// </summary>
    public static int MaximumLinkFetchAttempts => 8;


    /// <summary>
    /// Resolves <paramref name="attachmentData"/> to its payload, resolving ONLY the base64url and base58btc
    /// decoders from the <see cref="DefaultCoderSelector"/> (the seams with a library registry), then
    /// delegating to the explicit-delegate overload (the registry-delegates-to-parameter rule). The hash
    /// selector, the <see cref="JsonValueSerializer"/>, and the outbound transport carry no library registry —
    /// they are cryptographic / serialization / transport policy the application (or the test setup) wires —
    /// so they are taken as parameters and forwarded unchanged.
    /// </summary>
    /// <param name="attachmentData">The attachment <c>data</c> object to resolve.</param>
    /// <param name="exchangeContext">The per-operation exchange context carrying the outbound-fetch policy.</param>
    /// <param name="transport">The single-hop outbound transport <c>links</c> fetches route through, or <see langword="null"/> for an inline-only deployment.</param>
    /// <param name="hashFunctionSelector">Selects the hash function for a self-describing multihash code, or <see langword="null"/> (every hashed path then fails closed as <see cref="AttachmentResolutionError.UnsupportedHashAlgorithm"/>).</param>
    /// <param name="jsonValueSerializer">Serializer for the inline <c>json</c> form (the leaf-confined JSON seam).</param>
    /// <param name="memoryPool">The pool the decoded/fetched payload and transient buffers are drawn from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed resolution result the caller disposes.</returns>
    /// <exception cref="InvalidOperationException">The base64url or base58btc decoder is not registered on the <see cref="DefaultCoderSelector"/> — a producer-side configuration error.</exception>
    public static ValueTask<AttachmentResolutionResult> ResolveAsync(
        this AttachmentData attachmentData,
        ExchangeContext exchangeContext,
        OutboundTransportDelegate? transport,
        HashFunctionSelector? hashFunctionSelector,
        JsonValueSerializer jsonValueSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attachmentData);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(jsonValueSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        //The two coders are the only attachment seams with a library registry: base58btc is the
        //PublicKeyMultibase decoder, base64url the PublicKeyJwk decoder (the same key the Out-of-Band URL
        //path resolves). The hash selector / json serializer / transport have no registry and arrive as
        //parameters.
        DecodeDelegate base58Decoder = DefaultCoderSelector.SelectDecoder(WellKnownKeyFormats.PublicKeyMultibase);
        DecodeDelegate base64UrlDecoder = DefaultCoderSelector.SelectDecoder(WellKnownKeyFormats.PublicKeyJwk);

        return attachmentData.ResolveAsync(
            exchangeContext,
            transport,
            base64UrlDecoder,
            base58Decoder,
            hashFunctionSelector,
            jsonValueSerializer,
            memoryPool,
            cancellationToken);
    }


    /// <summary>
    /// Resolves <paramref name="attachmentData"/> to its payload using explicit decode, hash, and
    /// serialization delegates. Fail-closed: the <c>data</c> object is attacker-controlled wire input, so
    /// every malformed, integrity-failing, or policy-denied outcome is a typed
    /// <see cref="AttachmentResolutionError"/> and never thrown (DIDComm v2.1 §Attachments).
    /// </summary>
    /// <remarks>
    /// The access-form precedence is enforced here: <c>jws</c>-only is reported distinctly so a future
    /// signed-attachment verifier can slot in; the inline path prefers <c>base64</c> then <c>json</c> and a
    /// malformed inline is a hard fail; the <c>links</c> path requires <c>hash</c> first (no fetch without
    /// it), iterates locations in order, and accepts only the first size-bounded, hash-verified 200 body,
    /// copied into an owned pooled buffer.
    /// </remarks>
    /// <param name="attachmentData">The attachment <c>data</c> object to resolve.</param>
    /// <param name="exchangeContext">The per-operation exchange context carrying the outbound-fetch policy.</param>
    /// <param name="transport">The single-hop outbound transport <c>links</c> fetches route through, or <see langword="null"/> (the <c>links</c> branch then fails closed).</param>
    /// <param name="base64UrlDecoder">Base64url decoder for the inline <c>base64</c> form.</param>
    /// <param name="hashBase58Decoder">Base58btc decoder for the raw / multibase <c>hash</c> multihash string.</param>
    /// <param name="hashFunctionSelector">Selects the hash function for the <c>hash</c>'s self-describing multihash code, or <see langword="null"/> (every hashed path then fails closed as <see cref="AttachmentResolutionError.UnsupportedHashAlgorithm"/>); the algorithm choice lives in the data, never hardcoded here.</param>
    /// <param name="jsonValueSerializer">Serializer for the inline <c>json</c> form (the leaf-confined JSON seam).</param>
    /// <param name="memoryPool">The pool the decoded/fetched payload and transient buffers are drawn from.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A fail-closed resolution result the caller disposes.</returns>
    /// <remarks>
    /// This resolver resolves the attachment PAYLOAD; it does NOT verify a detached <c>jws</c> signature over
    /// that payload — a signed attachment is a distinct trust axis a future signed-attachment verifier owns,
    /// so a resolved payload is "the bytes the access form / integrity hash committed to", never "the bytes a
    /// signature authenticated". The <c>hash</c> string is decoded as a multihash: a leading recognized
    /// multibase prefix (<c>z</c> = base58btc, <c>u</c> = base64url, <c>m</c> = base64, <c>f</c> = base16) is
    /// stripped and dispatched, and an unprefixed string is treated as raw base58btc (the DIDComm / IPFS
    /// <c>Qm…</c> convention); any other leading character fails closed as
    /// <see cref="AttachmentResolutionError.MalformedHash"/>.
    /// </remarks>
    public static async ValueTask<AttachmentResolutionResult> ResolveAsync(
        this AttachmentData attachmentData,
        ExchangeContext exchangeContext,
        OutboundTransportDelegate? transport,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate hashBase58Decoder,
        HashFunctionSelector? hashFunctionSelector,
        JsonValueSerializer jsonValueSerializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(attachmentData);
        ArgumentNullException.ThrowIfNull(exchangeContext);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(hashBase58Decoder);
        ArgumentNullException.ThrowIfNull(jsonValueSerializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        bool hasBase64 = attachmentData.Base64 is { Length: > 0 };
        bool hasJson = attachmentData.Json is not null;
        bool hasLinks = attachmentData.Links is { Count: > 0 };
        bool hasJws = attachmentData.Jws is not null;
        bool hasHash = attachmentData.Hash is { Length: > 0 };

        //(1) No usable access form at all (DIDComm v2.1 §Attachments: "MUST contain at least one").
        if(!hasBase64 && !hasJson && !hasLinks && !hasHash && !hasJws)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.MissingData);
        }

        //(2) Only jws present: a signed attachment is a distinct trust axis, out of scope for this payload
        //resolver. Reported distinctly (not MissingData) so a future signed-attachment verifier slots in.
        if(hasJws && !hasBase64 && !hasJson && !hasLinks)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.JwsResolutionNotSupported);
        }

        //(3) Prefer INLINE by value — base64 then json. A present-but-malformed inline form is a HARD FAIL
        //(MalformedInline), never a fall-back to fetch.
        if(hasBase64)
        {
            return ResolveInline(attachmentData.Base64!, isBase64: true, attachmentData,
                base64UrlDecoder, hashBase58Decoder, hashFunctionSelector, jsonValueSerializer, memoryPool);
        }

        if(hasJson)
        {
            return ResolveInline(inline: null, isBase64: false, attachmentData,
                base64UrlDecoder, hashBase58Decoder, hashFunctionSelector, jsonValueSerializer, memoryPool);
        }

        //(4) By reference — links. With no inline content and no links, the data object carries only a hash
        //(and/or jws) — no access to content at all (a hash alone is an integrity check, not content).
        if(!hasLinks)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.MissingData);
        }

        //The hash is REQUIRED for a by-reference attachment and is verified over each fetched body; without it
        //nothing is fetched (DIDComm v2.1 §Attachments: "MUST be used if the data is referenced via links").
        if(!hasHash)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.HashMissingForLinks);
        }

        return await ResolveLinksAsync(
            attachmentData,
            exchangeContext,
            transport,
            base64UrlDecoder,
            hashBase58Decoder,
            hashFunctionSelector,
            memoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    //Resolves an inline (by-value) attachment: decode base64 OR serialize json into an owned pooled buffer
    //bounded by MaximumInlineAttachmentLength, then verify the multihash hash when present. A malformed
    //decode/serialize, an over-bound length, or a hash mismatch is fail-closed; nothing throws.
    private static AttachmentResolutionResult ResolveInline(
        string? inline,
        bool isBase64,
        AttachmentData attachmentData,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate hashBase58Decoder,
        HashFunctionSelector? hashFunctionSelector,
        JsonValueSerializer jsonValueSerializer,
        MemoryPool<byte> memoryPool)
    {
        //Bound the inline length BEFORE decoding so a hostile value cannot drive an unbounded allocation.
        //For base64 the bound is over the encoded char count (the decoder rents proportional to input).
        if(isBase64 && inline!.Length > MaximumInlineAttachmentLength)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.MalformedInline);
        }

        IMemoryOwner<byte> payload;
        int payloadLength;
        try
        {
            if(isBase64)
            {
                payload = base64UrlDecoder(inline!, memoryPool);
            }
            else
            {
                payload = jsonValueSerializer(attachmentData.Json!, memoryPool);
            }
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.MalformedInline);
        }

        payloadLength = payload.Memory.Length;

        //The decoded/serialized length is bounded after the fact too (a json value has no pre-decode length).
        if(payloadLength > MaximumInlineAttachmentLength)
        {
            payload.Dispose();

            return AttachmentResolutionResult.Failed(AttachmentResolutionError.MalformedInline);
        }

        //Verify the multihash hash when present — an integrity check on inline content too. A mismatch or a
        //non-conforming hash NEVER returns the bytes.
        if(attachmentData.Hash is { Length: > 0 } hash)
        {
            HashVerification verification = VerifyMultihash(
                hash, payload.Memory.Span[..payloadLength], base64UrlDecoder, hashBase58Decoder, hashFunctionSelector, memoryPool);

            if(verification != HashVerification.Match)
            {
                payload.Dispose();

                return AttachmentResolutionResult.Failed(MapHashVerification(verification));
            }
        }

        return AttachmentResolutionResult.ResolvedInline(payload, payloadLength);
    }


    //Resolves a by-reference attachment: iterate links in order, routing each GET through the SSRF-policed
    //OutboundFetch, requiring a fetched 200 whose body is size-bounded and whose multihash hash verifies.
    //The first match wins (its body copied into an owned pooled buffer). Every URL policy-denied is
    //FetchDenied; fetched-but-none-verify is AllLinksFailed. A hash mismatch on a fetched body never returns
    //the bytes. Fail-closed and never-throwing (cancellation is re-thrown).
    private static async ValueTask<AttachmentResolutionResult> ResolveLinksAsync(
        AttachmentData attachmentData,
        ExchangeContext exchangeContext,
        OutboundTransportDelegate? transport,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate hashBase58Decoder,
        HashFunctionSelector? hashFunctionSelector,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        string hash = attachmentData.Hash!;

        //No transport wired: an inline-only deployment cannot satisfy a by-reference attachment. Fail closed
        //as if every link were denied — no fetch is possible.
        if(transport is null)
        {
            return AttachmentResolutionResult.Failed(AttachmentResolutionError.FetchDenied);
        }

        int fetchAttempts = 0;
        bool anyContacted = false;
        foreach(string link in attachmentData.Links!)
        {
            if(string.IsNullOrWhiteSpace(link) || !Uri.TryCreate(link, UriKind.Absolute, out Uri? target))
            {
                //A non-absolute or empty link is not fetchable; skip it (it never reaches the transport). It
                //is not a policy denial, so it does not count toward FetchDenied either.
                continue;
            }

            if(fetchAttempts >= MaximumLinkFetchAttempts)
            {
                //Stop after the fetch-attempt cap so one inbound message cannot drive an unbounded number of
                //outbound requests (DIDComm v2.1 §Attachments allows unboundedly many links; a receiver need
                //not fetch them all). Remaining links are left untried; a capped prefix that reached the
                //transport reports AllLinksFailed below, exactly as an all-failed set does.
                break;
            }

            fetchAttempts++;

            OutboundFetchResult fetch;
            try
            {
                fetch = await OutboundFetch.FetchAsync(
                    new OutboundRequest { Target = target, Method = "GET", MaxResponseBytes = MaximumFetchedAttachmentLength },
                    exchangeContext,
                    transport,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(OperationCanceledException)
            {
                throw;
            }
            catch
            {
                //A transport failure (socket/DNS) for this link means the transport WAS reached but the link
                //did not yield content — it is fail-closed AllLinksFailed territory, not a policy denial.
                anyContacted = true;
                continue;
            }

            if(!fetch.IsFetched)
            {
                //A non-fetched outcome (DeniedByPolicy / RedirectNotFollowed / TooManyRedirects) never reached
                //the transport — it is a policy denial, NOT a contact. Leave anyContacted untouched so an
                //all-denied set reports FetchDenied (the SSRF gate), distinct from fetched-but-unverified.
                continue;
            }

            if(fetch.Response is not { StatusCode: 200 } response)
            {
                //The transport WAS reached but returned a non-200; this link did not yield content.
                anyContacted = true;
                continue;
            }

            anyContacted = true;

            //Bound the fetched body length BEFORE accepting it — the policy bounds nothing.
            ReadOnlySpan<byte> body = response.Body.Memory.Span;
            if(body.Length > MaximumFetchedAttachmentLength)
            {
                continue;
            }

            HashVerification verification = VerifyMultihash(hash, body, base64UrlDecoder, hashBase58Decoder, hashFunctionSelector, memoryPool);
            if(verification != HashVerification.Match)
            {
                //A hash mismatch (or a non-conforming hash) NEVER returns the fetched bytes — try the next
                //link in case another location serves the content the hash actually commits to.
                continue;
            }

            //The first verified body wins: COPY it into an owned pooled buffer the result disposes (the
            //response body is a GC-managed TaggedMemory we do not own).
            IMemoryOwner<byte> owned = memoryPool.Rent(body.Length);
            body.CopyTo(owned.Memory.Span);

            return AttachmentResolutionResult.ResolvedFetched(owned, body.Length, target);
        }

        //No link verified. If not one link was even contacted (every absolute link was denied by policy, or
        //all links were non-absolute), report FetchDenied; otherwise the fetches happened but none verified.
        return anyContacted
            ? AttachmentResolutionResult.Failed(AttachmentResolutionError.AllLinksFailed)
            : AttachmentResolutionResult.Failed(AttachmentResolutionError.FetchDenied);
    }


    //The outcome of a multihash verification: a clean match, or a typed reason it did not match.
    private enum HashVerification
    {
        Match = 0,
        UnsupportedAlgorithm,
        MalformedHash,
        Mismatch
    }


    private static AttachmentResolutionError MapHashVerification(HashVerification verification) => verification switch
    {
        HashVerification.UnsupportedAlgorithm => AttachmentResolutionError.UnsupportedHashAlgorithm,
        HashVerification.MalformedHash => AttachmentResolutionError.MalformedHash,
        _ => AttachmentResolutionError.HashMismatch
    };


    //Verifies a multihash hash string over content: decode the hash (stripping a recognized multibase prefix
    //z/u/m/f, else treating it as RAW base58btc — the Aries / DIDComm / IPFS Qm… convention), read the
    //self-describing algorithm CODE from the decoded bytes and ask the selector for the matching hash
    //function (a null selection -> UnsupportedAlgorithm, fail-closed — the algorithm choice lives in the data,
    //never hardcoded here), assert the single-byte length header, recompute the digest over the content into a
    //stack buffer, and compare with SequenceEqual. Modeled on WebVhHash.IsSha256Multihash and
    //PeerDid4.IsHashValid. Fail-closed: an undecodable hash is MalformedHash, never thrown.
    private static HashVerification VerifyMultihash(
        string hash,
        ReadOnlySpan<byte> content,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate base58Decoder,
        HashFunctionSelector? hashFunctionSelector,
        MemoryPool<byte> memoryPool)
    {
        //Bound the hash string length BEFORE any decode (bound-before-decode doctrine): a sha2-256 multihash
        //is 34 bytes, under ~70 chars across base58/base64/hex, so a string this long is not a conforming
        //single-algorithm multihash and is rejected without renting a decode buffer for it.
        if(hash.Length > MaximumHashStringLength)
        {
            return HashVerification.MalformedHash;
        }

        try
        {
            using IMemoryOwner<byte> decoded = DecodeMultibaseOrRawBase58(hash, base64UrlDecoder, base58Decoder, memoryPool);
            ReadOnlySpan<byte> multihash = decoded.Memory.Span;

            //The multihash is self-describing: byte 0 is the algorithm CODE, byte 1 the digest length. A
            //single-byte-code multihash is all the repo's span decoders mint (did:webvh / did:peer:4 fix
            //sha2-256 to varint(0x12)||varint(0x20)||32-byte); a too-short value is not a multihash at all.
            if(multihash.Length < 2)
            {
                return HashVerification.MalformedHash;
            }

            //Read the algorithm from the data and resolve its hash function through the selector. A null
            //selector or a null selection means "no algorithm for this code" — fail closed rather than
            //guessing one (e.g. a sha3-256 hash with no sha3 wired is UnsupportedHashAlgorithm, not a silent
            //sha2-256 attempt).
            int multihashCode = multihash[0];
            HashFunctionDelegate? hashFunction = hashFunctionSelector?.Invoke(multihashCode);
            if(hashFunction is null)
            {
                return HashVerification.UnsupportedAlgorithm;
            }

            //The declared digest length (byte 1) drives the recompute width; the multihash MUST carry exactly
            //code || length || that-many digest bytes. A length the selector's function does not produce is a
            //value mismatch, caught by SequenceEqual.
            int declaredLength = multihash[1];
            if(declaredLength <= 0 || declaredLength > MaximumDigestLength || multihash.Length != 2 + declaredLength)
            {
                return HashVerification.MalformedHash;
            }

            Span<byte> digest = stackalloc byte[MaximumDigestLength];
            int written = hashFunction(content, digest[..declaredLength]);

            return written == declaredLength && multihash[2..].SequenceEqual(digest[..declaredLength])
                ? HashVerification.Match
                : HashVerification.Mismatch;
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException)
        {
            return HashVerification.MalformedHash;
        }
    }


    //Decodes a multihash hash string. A leading recognized multibase prefix (z=base58btc, u=base64url,
    //m=base64, f=base16) is stripped and dispatched; an unprefixed string is treated as RAW base58btc (the
    //DIDComm / IPFS Qm… convention). base58btc uses the injected base58 decoder and base64url the injected
    //base64url decoder; base64 (m) and base16 (f) use the framework's span decoders. MultibaseSerializer.Decode
    //is deliberately NOT used because it hard-requires a leading z.
    private static IMemoryOwner<byte> DecodeMultibaseOrRawBase58(
        string hash,
        DecodeDelegate base64UrlDecoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> memoryPool)
    {
        if(hash.Length == 0)
        {
            throw new FormatException("An empty hash string is not a multihash.");
        }

        char prefix = hash[0];

        return prefix switch
        {
            'z' => base58Decoder(hash.AsSpan(1), memoryPool),
            'u' => base64UrlDecoder(hash.AsSpan(1), memoryPool),
            'm' => DecodeBytes(Convert.FromBase64String(PadBase64(hash.AsSpan(1))), memoryPool),
            'f' => DecodeBytes(Convert.FromHexString(hash.AsSpan(1)), memoryPool),
            _ => base58Decoder(hash, memoryPool)
        };
    }


    //Copies a decoded byte array into an owned, exact-length pooled buffer, then the source array is no
    //longer referenced. Used for the multibase forms whose framework decoders return arrays.
    private static IMemoryOwner<byte> DecodeBytes(byte[] bytes, MemoryPool<byte> memoryPool)
    {
        IMemoryOwner<byte> owner = memoryPool.Rent(bytes.Length);
        bytes.AsSpan().CopyTo(owner.Memory.Span);

        return owner;
    }


    //Pads a base64 string to a multiple of four with '='. Used by the base64 ('m') multibase branch.
    private static string PadBase64(ReadOnlySpan<char> source)
    {
        int remainder = source.Length % 4;
        if(remainder == 0)
        {
            return new string(source);
        }

        int padded = source.Length + (4 - remainder);
        Span<char> buffer = padded <= 256 ? stackalloc char[padded] : new char[padded];
        source.CopyTo(buffer);
        buffer[source.Length..].Fill('=');

        return new string(buffer);
    }
}

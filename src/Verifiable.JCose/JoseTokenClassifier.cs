using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Classifies a raw token string into a <see cref="JoseTokenShape"/> by
/// structural inspection. Composes <see cref="JwsParsing.ParseCompact"/>
/// for the JWS path and an inline header parse for the JWE path.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Classification algorithm.</strong>
/// The classifier counts the number of <c>.</c>-separated segments in the
/// input. Three segments indicate JWS compact form per RFC 7515 §7.1; five
/// segments indicate JWE compact form per RFC 7516 §7.1. For both shapes
/// the header (first segment) is Base64Url-decoded and parsed to a JSON
/// object; the presence or absence of the <c>enc</c> claim distinguishes
/// JWE from JWS structurally.
/// </para>
/// <para>
/// Inputs with segment counts other than 3 or 5 — and non-empty inputs in
/// general — are classified as <see cref="OpaqueShape"/>. Empty inputs,
/// segments that fail Base64Url decoding, headers that do not parse to a
/// JSON object, and structurally inconsistent shape-and-header pairs all
/// produce <see cref="MalformedShape"/> with stable reason strings.
/// </para>
/// <para>
/// <strong>Hostile-input safety.</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <em>Deterministic.</em> The same input produces the same classification
/// regardless of timing, request order, or cancellation state up to the
/// point of token inspection. No timing oracle on token shape.
/// </description></item>
/// <item><description>
/// <em>Bounded work.</em> Segment counting and Base64Url decoding are O(n)
/// in input length; the JSON parse is bounded by the header segment length.
/// No unbounded recursion or unbounded loops.
/// </description></item>
/// <item><description>
/// <em>No exception escape.</em> Every malformed input returns a
/// <see cref="MalformedShape"/> with a stable reason; the classifier does
/// not throw <see cref="FormatException"/> or similar on bad bytes. Hostile
/// inputs cannot use exception throwing as a side channel.
/// </description></item>
/// <item><description>
/// <em>No alg-confusion fallthrough.</em> A token with the wrong segment
/// count for its <c>enc</c>-claim status is <see cref="MalformedShape"/>,
/// not best-effort classified into the wrong subtype. A 3-segment string
/// with <c>enc</c> is malformed; a 5-segment string without <c>enc</c> is
/// malformed.
/// </description></item>
/// <item><description>
/// <em>No alg-policy enforcement at classification.</em> A token with
/// <c>alg=none</c> classifies as <see cref="JwsShape"/> with the claimed
/// algorithm surfaced through
/// <see cref="UnverifiedJwsSignature.ClaimedAlgorithm"/>. The classifier
/// does not make security decisions; it shapes the data so verifiers can
/// enforce policy.
/// </description></item>
/// </list>
/// </remarks>
public static class JoseTokenClassifier
{
    private const int JwsSegmentCount = 3;
    private const int JweSegmentCount = 5;

    private const string ReasonEmpty = "Empty token.";
    private const string ReasonHeaderDecodeFailed = "Header segment is not valid Base64Url.";
    private const string ReasonHeaderJsonParseFailed = "Header segment is not a valid JSON object.";
    private const string ReasonJwsHasEnc = "Three segments but header carries an enc claim; a JWS must not have enc.";
    private const string ReasonJweMissingEnc = "Five segments but header carries no enc claim; a JWE must have enc.";
    private const string ReasonJsonNeitherJwsNorJwe = "JSON object is neither a JWS (no 'payload'/'signatures'/'signature') nor a JWE (no 'ciphertext').";
    private const string ReasonJsonBothJwsAndJwe = "JSON object carries both JWS members and a 'ciphertext'; RFC 7516 §9 makes the forms mutually exclusive.";
    private const string ReasonJweJsonNoRecipientKey = "JSON JWE has neither a 'recipients' array (general) nor a top-level 'encrypted_key' (flattened).";
    private const string ReasonJwsJsonNoSignature = "JSON JWS has neither a 'signatures' array (general) nor a top-level 'signature' (flattened).";


    /// <summary>
    /// Classifies a raw token string into a <see cref="JoseTokenShape"/> by
    /// structural inspection.
    /// </summary>
    /// <param name="token">
    /// The raw token string. Attacker-controlled bytes; no parsing or trust
    /// assumptions allowed before classification.
    /// </param>
    /// <param name="base64UrlDecoder">
    /// Delegate for Base64Url decoding of the header segment.
    /// </param>
    /// <param name="headerDeserializer">
    /// Delegate for deserializing header bytes to a key-value dictionary.
    /// The application supplies this from its chosen JSON library;
    /// <see cref="Verifiable.JCose"/> does not import a JSON serializer.
    /// </param>
    /// <param name="memoryPool">
    /// Memory pool for the JWS-path parse allocations.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The classified token. Always non-<see langword="null"/>; malformed
    /// inputs produce <see cref="MalformedShape"/> rather than null.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any of <paramref name="token"/>,
    /// <paramref name="base64UrlDecoder"/>,
    /// <paramref name="headerDeserializer"/>, or
    /// <paramref name="memoryPool"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// Thrown when <paramref name="cancellationToken"/> is canceled.
    /// </exception>
    public static ValueTask<JoseTokenShape> ClassifyAsync(
        string token,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(headerDeserializer);
        ArgumentNullException.ThrowIfNull(memoryPool);

        cancellationToken.ThrowIfCancellationRequested();

        if(token.Length == 0)
        {
            return ValueTask.FromResult<JoseTokenShape>(new MalformedShape(ReasonEmpty));
        }

        //RFC 7516 §9: a JSON-serialized JOSE object begins with '{'. Classify it by its members
        //rather than by segment count, which only applies to the compact serializations.
        if(StartsWithJsonObject(token))
        {
            return ValueTask.FromResult(ClassifyJson(token));
        }

        int segmentCount = CountSegments(token);

        return segmentCount switch
        {
            JwsSegmentCount =>
                ClassifyThreeSegment(token, base64UrlDecoder, headerDeserializer, memoryPool),
            JweSegmentCount =>
                ClassifyFiveSegment(token, base64UrlDecoder, headerDeserializer, memoryPool),
            _ =>
                ValueTask.FromResult<JoseTokenShape>(new OpaqueShape(token))
        };
    }


    /// <summary>
    /// Classifies a JSON-serialized JOSE object by its top-level members per RFC 7516 §9.
    /// </summary>
    /// <remarks>
    /// <para>
    /// RFC 7516 §9 distinguishes the JSON serializations by member presence: "JWSs have a
    /// 'payload' member and JWEs do not. JWEs have a 'ciphertext' member and JWSs do not." A JWE
    /// is general when it carries a <c>recipients</c> array and flattened when it carries a
    /// top-level <c>encrypted_key</c> (RFC 7516 §7.2.1/§7.2.2). A JWS is general when it carries
    /// a <c>signatures</c> array and flattened when it carries a top-level <c>signature</c>
    /// (RFC 7515 §7.2.1/§7.2.2).
    /// </para>
    /// <para>
    /// Members are read directly from the raw UTF-8 token bytes with the library's span reader,
    /// so JSON classification needs no header deserializer. An object that carries both JWS and
    /// JWE members, or neither, is <see cref="MalformedShape"/> — it is structurally ambiguous,
    /// not best-effort classified into one form.
    /// </para>
    /// </remarks>
    private static JoseTokenShape ClassifyJson(string token)
    {
        ReadOnlySpan<byte> bytes = System.Text.Encoding.UTF8.GetBytes(token);

        bool hasCiphertext = JwkJsonReader.ContainsKey(bytes, "ciphertext"u8);
        bool hasPayload = JwkJsonReader.ContainsKey(bytes, "payload"u8);
        bool hasSignatures = JwkJsonReader.ContainsKey(bytes, "signatures"u8);
        bool hasSignature = JwkJsonReader.ContainsKey(bytes, "signature"u8);
        bool looksLikeJws = hasPayload || hasSignatures || hasSignature;

        if(hasCiphertext && looksLikeJws)
        {
            return new MalformedShape(ReasonJsonBothJwsAndJwe);
        }

        if(hasCiphertext)
        {
            //JWE: general when a recipients array is present, flattened when the recipient's
            //encrypted_key is hoisted to the top level. A JWE with neither is malformed.
            if(JwkJsonReader.ContainsKey(bytes, "recipients"u8))
            {
                return new GeneralJweShape(token);
            }

            if(JwkJsonReader.ContainsKey(bytes, "encrypted_key"u8))
            {
                return new FlattenedJweShape(token);
            }

            return new MalformedShape(ReasonJweJsonNoRecipientKey);
        }

        if(looksLikeJws)
        {
            //JWS: general when a signatures array is present, flattened when a single signature
            //sits at the top level. "signatures" wins so a general form is not misread when both
            //appear (a malformed producer object), and the top-level "signature" check is the
            //flattened discriminator (RFC 7515 §7.2.2).
            if(hasSignatures)
            {
                return new GeneralJwsShape(token);
            }

            if(hasSignature)
            {
                return new FlattenedJwsShape(token);
            }

            return new MalformedShape(ReasonJwsJsonNoSignature);
        }

        return new MalformedShape(ReasonJsonNeitherJwsNorJwe);
    }


    //Whether the first non-whitespace byte/char of the token is a JSON object's '{'. The token
    //is inspected as a char span; a leading byte-order mark or other non-'{' opener routes to
    //the compact path, which then classifies it Opaque or Malformed.
    private static bool StartsWithJsonObject(string token)
    {
        ReadOnlySpan<char> span = token.AsSpan();
        for(int i = 0; i < span.Length; i++)
        {
            char c = span[i];
            if(c is ' ' or '\t' or '\r' or '\n')
            {
                continue;
            }

            return c == '{';
        }

        return false;
    }


    /// <summary>
    /// Classifies a 3-segment string as <see cref="JwsShape"/> unless its
    /// header carries an <c>enc</c> claim (which indicates a structurally
    /// inconsistent token — three segments suggest JWS, the <c>enc</c>
    /// claim suggests JWE).
    /// </summary>
    private static ValueTask<JoseTokenShape> ClassifyThreeSegment(
        string token,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        MemoryPool<byte> memoryPool)
    {
        UnverifiedJwsMessage? parsed = null;
        try
        {
            try
            {
                parsed = JwsParsing.ParseCompact(token, base64UrlDecoder, headerDeserializer, memoryPool);
            }
            catch
            {
                //Translate any parse failure to MalformedShape rather than
                //letting the exception escape. The classifier is the first
                //attacker-controlled-input boundary; exception escape would
                //give attackers a side channel through unhandled exceptions.
                return ValueTask.FromResult<JoseTokenShape>(
                    new MalformedShape(ReasonHeaderJsonParseFailed));
            }

            UnverifiedJwtHeader header = parsed.Signatures[0].ProtectedHeader;
            if(header.ContainsKey(WellKnownJoseHeaderNames.Enc))
            {
                return ValueTask.FromResult<JoseTokenShape>(new MalformedShape(ReasonJwsHasEnc));
            }

            //Ownership transferred to JwsShape; the finally below must not dispose.
            JoseTokenShape result = new JwsShape(parsed);
            parsed = null;
            return ValueTask.FromResult(result);
        }
        finally
        {
            parsed?.Dispose();
        }
    }


    /// <summary>
    /// Classifies a 5-segment string as <see cref="JweShape"/> if and only
    /// if its header parses successfully and carries an <c>enc</c> claim.
    /// </summary>
    private static ValueTask<JoseTokenShape> ClassifyFiveSegment(
        string token,
        DecodeDelegate base64UrlDecoder,
        Func<ReadOnlySpan<byte>, IReadOnlyDictionary<string, object>> headerDeserializer,
        MemoryPool<byte> memoryPool)
    {
        ReadOnlySpan<char> tokenSpan = token.AsSpan();
        int firstDot = tokenSpan.IndexOf('.');
        ReadOnlySpan<char> headerSegment = tokenSpan[..firstDot];

        IReadOnlyDictionary<string, object> headerDict;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(headerSegment, memoryPool);
            headerDict = headerDeserializer(headerBytes.Memory.Span);
        }
        catch
        {
            return ValueTask.FromResult<JoseTokenShape>(
                new MalformedShape(ReasonHeaderDecodeFailed));
        }

        if(!headerDict.ContainsKey(WellKnownJoseHeaderNames.Enc))
        {
            return ValueTask.FromResult<JoseTokenShape>(new MalformedShape(ReasonJweMissingEnc));
        }

        UnverifiedJwtHeader unverifiedHeader = new(headerDict);
        UnverifiedCompactJwe wrapper = new(token, unverifiedHeader);
        return ValueTask.FromResult<JoseTokenShape>(new JweShape(wrapper));
    }


    /// <summary>
    /// Counts the number of <c>.</c>-separated segments in a string by
    /// counting dot occurrences and adding one. Operates on the raw span;
    /// allocates nothing.
    /// </summary>
    private static int CountSegments(string token)
    {
        int dotCount = 0;
        ReadOnlySpan<char> span = token.AsSpan();
        for(int i = 0; i < span.Length; i++)
        {
            if(span[i] == '.')
            {
                dotCount++;
            }
        }
        return dotCount + 1;
    }
}

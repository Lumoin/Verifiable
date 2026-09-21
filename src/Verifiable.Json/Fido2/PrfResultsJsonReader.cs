using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Reads the <c>prf</c> client extension output's SECRET <c>results</c> bytes straight into pooled
/// memory, handing them to the caller as <see cref="SymmetricKeyMemory"/>, the library's disposable
/// carrier for symmetric key material.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-prf-extension">W3C Web Authentication Level 3,
/// section 10.1.4: Pseudo-random function extension (prf)</see>, dictionary
/// <c>AuthenticationExtensionsPRFOutputsJSON</c>'s <c>results</c> member: an
/// <c>AuthenticationExtensionsPRFValuesJSON</c> whose <c>first</c> is a required base64url string and
/// whose <c>second</c> is an optional one. <see cref="PrfExtensionProcessor"/> reports only whether
/// <c>results</c> was present; this reader is the SEPARATE, deliberately independent path a caller
/// takes when it actually needs the secret bytes — it never runs through the claim/audit pipeline, so
/// nothing about the secret is ever recorded as evidence.
/// </para>
/// <para>
/// <strong>Ownership.</strong> Lives beside <see cref="PrfExtensionProcessor"/> and
/// <see cref="ClientExtensionOutputsJsonReader"/> for the same reason: decoding the still-encoded wire
/// JSON needs <see cref="System.Text.Json"/>, which <c>Verifiable.Fido2</c> is architecturally barred
/// from referencing. <see cref="Read"/> takes the CALLER'S own <see cref="BaseMemoryPool"/> — this
/// reader rents from it, never from a pool of its own, matching every other pooled decode in this
/// library. The returned <see cref="Fido2PrfResults"/> owns everything it rents; the caller disposes
/// it, normally via a <see langword="using"/> declaration, and that disposal wipes the secret bytes.
/// The same code serves a browser host and a desktop host: what protects the rented memory beyond
/// wiping it (pinning, locking, exclusion from dumps) is a property of the pool the application
/// wires, and a pool without operating-system protections is still the owner of these bytes.
/// </para>
/// <para>
/// <strong>No unowned buffer ever carries the secret.</strong> The base64url text is decoded straight
/// from the JSON reader's own UTF-8 value bytes (<see cref="Utf8JsonReader.ValueSpan"/>) into memory
/// already rented from the caller's pool — no managed string, no naked array, and no intermediate
/// pooled buffer in the common case, because <see cref="Base64Url.GetMaxDecodedLength(int)"/> computes
/// the exact decoded length for the 32-byte values section 10.1.4 defines. On the rare input whose
/// decoded length comes in under that upper bound, a second, exactly sized buffer is rented, the
/// decoded bytes are copied into it, and the oversized first rental is zeroed and returned before this
/// method returns — the caller never sees it. A JSON string value that arrives escaped is rejected
/// rather than unescaped through a managed string: base64url's own alphabet never needs escaping, so an
/// escaped value is already malformed.
/// </para>
/// </remarks>
public static class PrfResultsJsonReader
{
    /// <summary>The <c>results</c> member name.</summary>
    private const string ResultsMember = "results";

    /// <summary>The required <c>results.first</c> member name.</summary>
    private const string FirstMember = "first";

    /// <summary>The optional <c>results.second</c> member name.</summary>
    private const string SecondMember = "second";

    /// <summary>
    /// Bounds JSON nesting depth for the untrusted <c>prf</c> client extension output value: the
    /// top-level object plus one nested <c>results</c> object.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 4 };


    /// <summary>
    /// Decodes the <c>prf</c> client extension output's <c>results</c> member, if present, into a
    /// <see cref="Fido2PrfResults"/> renting from <paramref name="pool"/>.
    /// </summary>
    /// <param name="prfOutputJson">The <c>prf</c> client extension output's raw JSON bytes, exactly as received.</param>
    /// <param name="pool">The caller's memory pool; every byte this call rents comes from here.</param>
    /// <returns>
    /// A <see cref="Fido2PrfResults"/> owning the decoded <c>first</c> and, when present,
    /// <c>second</c> secret bytes, when a <c>results</c> member is present; <see langword="null"/>
    /// when it is absent — section 10.1.4's own documented "outputs may not be available" case, not
    /// a wire defect.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="prfOutputJson"/> is not valid JSON, its top level is not an object, a
    /// <c>results</c> member is present but is not a JSON object, its required <c>first</c> member
    /// is absent, or either <c>first</c> or a present <c>second</c> is not valid base64url — every
    /// rented buffer already claimed for the failing decode is cleared and returned before this
    /// method throws.
    /// </exception>
    public static Fido2PrfResults? Read(ReadOnlyMemory<byte> prfOutputJson, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        try
        {
            return ReadObject(prfOutputJson.Span, pool);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The prf extension output is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Reads the <c>prf</c> client extension output's top-level JSON object, dispatching to
    /// <see cref="ReadResults"/> when a <c>results</c> member appears. Disposes any secret carrier
    /// already decoded before rethrowing, so a later parse failure never leaks a rental.
    /// </summary>
    private static Fido2PrfResults? ReadObject(ReadOnlySpan<byte> objectJson, BaseMemoryPool pool)
    {
        Utf8JsonReader reader = new(objectJson, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The prf extension output MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        Fido2PrfResults? results = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The prf extension output member '{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The prf extension output member '{memberName}' is truncated.");
                }

                if(string.Equals(memberName, ResultsMember, StringComparison.Ordinal))
                {
                    results = ReadResults(ref reader, pool);
                }
                else
                {
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException("The prf extension output object is not terminated.");
            }

            if(reader.Read())
            {
                throw new Fido2FormatException("The prf extension output carries content trailing its closing brace.");
            }

            return results;
        }
        catch
        {
            results?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Reads the reader's current <c>results</c> value — a required <c>first</c> and an optional
    /// <c>second</c> — decoding each present member's base64url text straight into pooled secret
    /// memory via <see cref="DecodeResultValue"/>. Disposes any secret carrier already decoded
    /// before rethrowing, so a malformed <c>second</c> never leaks the buffer already rented for
    /// <c>first</c>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "first and second transfer ownership to the returned Fido2PrfResults on the success path; the catch block disposes whichever of the two was already decoded on every other path, so nothing rented here outlives this method.")]
    private static Fido2PrfResults ReadResults(ref Utf8JsonReader reader, BaseMemoryPool pool)
    {
        if(reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}' MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        SymmetricKeyMemory? first = null;
        SymmetricKeyMemory? second = null;
        try
        {
            while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
            {
                string memberName = reader.GetString()!;
                if(!seenMembers.Add(memberName))
                {
                    throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is repeated.");
                }

                if(!reader.Read())
                {
                    throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is truncated.");
                }

                if(string.Equals(memberName, FirstMember, StringComparison.Ordinal))
                {
                    first = DecodeResultValue(ref reader, FirstMember, pool);
                }
                else if(string.Equals(memberName, SecondMember, StringComparison.Ordinal))
                {
                    second = DecodeResultValue(ref reader, SecondMember, pool);
                }
                else
                {
                    reader.Skip();
                }
            }

            if(reader.TokenType != JsonTokenType.EndObject)
            {
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}' object is not terminated.");
            }

            if(first is null)
            {
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{FirstMember}' is required.");
            }

            return new Fido2PrfResults(first, second);
        }
        catch
        {
            first?.Dispose();
            second?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Decodes one base64url-encoded <c>results</c> member straight from the reader's own UTF-8
    /// value bytes into memory rented from <paramref name="pool"/>, tagged
    /// <see cref="Fido2BufferTags.PrfResult"/>. Rejects an escaped string value: base64url's
    /// alphabet never needs JSON escaping, so an escaped value is already malformed and this method
    /// never unescapes one through a managed string. Malformed base64url is rejected whether the
    /// underlying decoder reports it by returning <see langword="false"/> or by throwing
    /// <see cref="FormatException"/> — both outcomes fail closed the same way.
    /// </summary>
    private static SymmetricKeyMemory DecodeResultValue(ref Utf8JsonReader reader, string memberName, BaseMemoryPool pool)
    {
        if(reader.TokenType != JsonTokenType.String || reader.ValueIsEscaped)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' MUST be a base64url string.");
        }

        ReadOnlySpan<byte> encoded = reader.ValueSpan;
        if(encoded.IsEmpty)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' MUST NOT be empty.");
        }

        int maxLength = Base64Url.GetMaxDecodedLength(encoded.Length);
        if(maxLength <= 0)
        {
            throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is not valid base64url.");
        }

        IMemoryOwner<byte>? rented = pool.Rent(maxLength);
        try
        {
            bool decoded;
            int bytesWritten;
            try
            {
                decoded = Base64Url.TryDecodeFromUtf8(encoded, rented.Memory.Span, out bytesWritten);
            }
            catch(FormatException exception)
            {
                //Base64Url.TryDecodeFromUtf8 throws for some malformed inputs rather than returning
                //false for every one of them; either outcome is the same "not valid base64url" fact.
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is not valid base64url.", exception);
            }

            if(!decoded)
            {
                throw new Fido2FormatException($"The prf extension output member '{ResultsMember}.{memberName}' is not valid base64url.");
            }

            if(bytesWritten == maxLength)
            {
                IMemoryOwner<byte> exact = rented;
                rented = null;

                return new SymmetricKeyMemory(exact, Fido2BufferTags.PrfResult);
            }

            IMemoryOwner<byte> trimmed = pool.Rent(bytesWritten);
            rented.Memory.Span[..bytesWritten].CopyTo(trimmed.Memory.Span);

            return new SymmetricKeyMemory(trimmed, Fido2BufferTags.PrfResult);
        }
        finally
        {
            if(rented is not null)
            {
                CryptographicOperations.ZeroMemory(rented.Memory.Span);
                rented.Dispose();
            }
        }
    }
}

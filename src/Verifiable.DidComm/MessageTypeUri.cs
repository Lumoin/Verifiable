using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm;

/// <summary>
/// A parsed DIDComm Message Type URI (MTURI) as defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#message-type-uri">DIDComm Messaging v2.1 §Message Type URI</see>.
/// </summary>
/// <remarks>
/// <para>
/// An MTURI identifies a plaintext message type unambiguously. It is a Protocol Identifier URI
/// (PIURI) with a message-type name appended:
/// </para>
/// <code>
/// message-type-uri        = protocol-identifier-uri "/" message-type-name
/// protocol-identifier-uri = doc-uri delim protocol-name "/" semver
/// delim                   = "?" / "/" / "&amp;" / ":" / ";" / "="
/// identifier              = alpha *(*(alphanum / "_" / "-" / ".") alphanum)
/// </code>
/// <para>
/// The reference loose-parse regex is
/// <c>(.*?)([a-z0-9._-]+)/(\d[^/]*)/([a-z0-9._-]+)$</c> with capture groups (1) doc-uri,
/// (2) protocol-name, (3) protocol-version, (4) message-type-name. This parser implements the
/// same decomposition over spans. Per the spec, agents comparing MTURIs MUST do more than an
/// exact string compare — protocol and message names are compared ignoring case and punctuation,
/// and the version is matched with semver compatibility — so the parsed components are exposed
/// for a handler-dispatch layer to compare; this type itself only parses and holds them.
/// </para>
/// <para>
/// The patch component of a protocol's semver is not used in MTURIs or PIURIs
/// (DIDComm v2.1 §Semver Rules), so only <see cref="MajorVersion"/> and <see cref="MinorVersion"/>
/// are surfaced from the version token; any further components are retained verbatim in
/// <see cref="ProtocolVersion"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("MessageTypeUri({Value})")]
public sealed class MessageTypeUri: IEquatable<MessageTypeUri>
{
    private MessageTypeUri(
        string value,
        string documentationUri,
        string protocolName,
        string protocolVersion,
        int majorVersion,
        int minorVersion,
        string messageTypeName)
    {
        Value = value;
        DocumentationUri = documentationUri;
        ProtocolName = protocolName;
        ProtocolVersion = protocolVersion;
        MajorVersion = majorVersion;
        MinorVersion = minorVersion;
        MessageTypeName = messageTypeName;
    }


    /// <summary>The full MTURI string exactly as supplied.</summary>
    public string Value { get; }

    /// <summary>
    /// The documentation URI prefix — capture group (1), everything up to and including the
    /// <c>delim</c> that precedes the protocol name. It SHOULD resolve to human-friendly
    /// documentation about the protocol.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The MTURI doc-uri is an opaque spec token parsed verbatim and may not be a dereferenceable System.Uri (e.g. 'did:example:1234567890;spec/').")]
    public string DocumentationUri { get; }

    /// <summary>The protocol name token — capture group (2).</summary>
    public string ProtocolName { get; }

    /// <summary>The protocol version token (semver) — capture group (3), e.g. <c>2.0</c>.</summary>
    public string ProtocolVersion { get; }

    /// <summary>The major version parsed from <see cref="ProtocolVersion"/>.</summary>
    public int MajorVersion { get; }

    /// <summary>The minor version parsed from <see cref="ProtocolVersion"/>, or <c>0</c> when absent.</summary>
    public int MinorVersion { get; }

    /// <summary>The message-type name token — capture group (4), e.g. <c>forward</c>.</summary>
    public string MessageTypeName { get; }

    /// <summary>
    /// The Protocol Identifier URI (PIURI) prefix of this MTURI — the MTURI without the trailing
    /// <c>"/" message-type-name</c>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The PIURI is an opaque spec token parsed verbatim and may not be a dereferenceable System.Uri (e.g. 'did:example:1234567890;spec/lets_do_lunch/1.0').")]
    public string ProtocolIdentifierUri => Value[..(Value.Length - MessageTypeName.Length - 1)];


    /// <summary>
    /// Parses <paramref name="value"/> as an MTURI.
    /// </summary>
    /// <param name="value">The MTURI string.</param>
    /// <param name="result">The parsed MTURI when parsing succeeds.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is a well-formed MTURI.</returns>
    public static bool TryParse([NotNullWhen(true)] string? value, [NotNullWhen(true)] out MessageTypeUri? result)
    {
        result = null;
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        //Split off the trailing message-type-name (capture group 4).
        int lastSlash = value.LastIndexOf('/');
        if(lastSlash <= 0 || lastSlash == value.Length - 1)
        {
            return false;
        }

        string messageTypeName = value[(lastSlash + 1)..];
        string piuri = value[..lastSlash];

        //Split the version token (capture group 3) off the PIURI.
        int versionSlash = piuri.LastIndexOf('/');
        if(versionSlash <= 0 || versionSlash == piuri.Length - 1)
        {
            return false;
        }

        string version = piuri[(versionSlash + 1)..];
        string beforeVersion = piuri[..versionSlash];

        //The version token MUST start with a digit (the regex \d[^/]*).
        if(!char.IsAsciiDigit(version[0]) || !TryParseVersion(version, out int major, out int minor))
        {
            return false;
        }

        //The protocol name (capture group 2) is the maximal trailing run of identifier characters
        //in the pre-version segment; the documentation URI is everything before that run.
        int nameStart = beforeVersion.Length;
        while(nameStart > 0 && IsIdentifierChar(beforeVersion[nameStart - 1]))
        {
            nameStart--;
        }

        string protocolName = beforeVersion[nameStart..];
        string documentationUri = beforeVersion[..nameStart];

        if(!IsIdentifier(protocolName) || !IsIdentifier(messageTypeName))
        {
            return false;
        }

        result = new MessageTypeUri(value, documentationUri, protocolName, version, major, minor, messageTypeName);

        return true;
    }


    /// <summary>
    /// Parses <paramref name="value"/> as an MTURI, throwing when it is not well-formed.
    /// </summary>
    /// <param name="value">The MTURI string.</param>
    /// <returns>The parsed MTURI.</returns>
    /// <exception cref="FormatException">Thrown when <paramref name="value"/> is not a well-formed MTURI.</exception>
    public static MessageTypeUri Parse(string value)
    {
        if(!TryParse(value, out MessageTypeUri? result))
        {
            throw new FormatException(
                $"'{value}' is not a well-formed DIDComm Message Type URI " +
                "(expected <doc-uri><delim><protocol-name>/<semver>/<message-type-name>).");
        }

        return result;
    }


    /// <summary>
    /// Whether <paramref name="other"/> identifies the same message type as this one for handler-dispatch
    /// purposes — the spec-mandated MTURI comparison (DIDComm v2.1 §Message Type URI: agents "must do more
    /// than compare the string for exact equality... It may need to check for semver compatibility, and it
    /// has to compare the protocol name and message type name ignoring case and punctuation").
    /// </summary>
    /// <remarks>
    /// The <see cref="ProtocolName"/> and <see cref="MessageTypeName"/> are compared ignoring case and the
    /// identifier punctuation (<c>_</c>, <c>-</c>, <c>.</c>); the <see cref="DocumentationUri"/> (the
    /// protocol authority) must match EXACTLY (ordinal, case-sensitive) — the spec scopes case/punctuation
    /// insensitivity to the protocol-name and message-type-name tokens only, and a doc-uri may be a
    /// case-sensitive DID, so two same-named protocols under different authorities do not collide; and the
    /// versions are semver-compatible when they share a <see cref="MajorVersion"/> (DIDComm v2.1 §Semver
    /// Rules: a minor-version increment only adds backward-compatible functionality, so a handler for a given
    /// major version processes any minor of it, gracefully ignoring features it predates). This is distinct
    /// from <see cref="Equals(MessageTypeUri?)"/>, which is exact structural identity over <see cref="Value"/>.
    /// </remarks>
    /// <param name="other">The MTURI to compare against.</param>
    /// <returns><see langword="true"/> when both name the same protocol message type, semver-compatibly.</returns>
    public bool IsSameMessageType(MessageTypeUri? other) =>
        other is not null
        && MajorVersion == other.MajorVersion
        && string.Equals(DocumentationUri, other.DocumentationUri, StringComparison.Ordinal)
        && NamesMatchIgnoringCaseAndPunctuation(ProtocolName, other.ProtocolName)
        && NamesMatchIgnoringCaseAndPunctuation(MessageTypeName, other.MessageTypeName);


    /// <summary>
    /// Whether <paramref name="otherMtUri"/> parses as an MTURI naming the same message type as this one
    /// (see <see cref="IsSameMessageType(MessageTypeUri?)"/>). A value that is not a well-formed MTURI never
    /// matches.
    /// </summary>
    /// <param name="otherMtUri">The candidate MTURI string.</param>
    /// <returns><see langword="true"/> when it parses and names the same message type, semver-compatibly.</returns>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "An MTURI is an opaque spec token parsed verbatim and may not be a dereferenceable System.Uri (e.g. 'did:example:1234567890;spec/lets_do_lunch/1.0/proposal').")]
    public bool IsSameMessageType([NotNullWhen(true)] string? otherMtUri) =>
        TryParse(otherMtUri, out MessageTypeUri? other) && IsSameMessageType(other);


    //Compares two identifier tokens ignoring case and the identifier punctuation set ('_', '-', '.') —
    //the DIDComm v2.1 §Message Type URI rule for protocol and message-type names. Walks both tokens with
    //two cursors, skipping punctuation on each side, and matches the remaining letters/digits
    //case-insensitively; the tokens match only when both are exhausted together.
    private static bool NamesMatchIgnoringCaseAndPunctuation(string left, string right)
    {
        int i = 0;
        int j = 0;
        while(true)
        {
            while(i < left.Length && IsIdentifierPunctuation(left[i]))
            {
                i++;
            }

            while(j < right.Length && IsIdentifierPunctuation(right[j]))
            {
                j++;
            }

            bool leftDone = i == left.Length;
            bool rightDone = j == right.Length;
            if(leftDone || rightDone)
            {
                return leftDone && rightDone;
            }

            if(char.ToLowerInvariant(left[i]) != char.ToLowerInvariant(right[j]))
            {
                return false;
            }

            i++;
            j++;
        }
    }


    private static bool IsIdentifierPunctuation(char c) => c == '_' || c == '-' || c == '.';


    //identifier = alpha *(*(alphanum / "_" / "-" / ".") alphanum): starts with a letter, ends with
    //an alphanumeric, and every interior character is alphanumeric, '_', '-', or '.'.
    private static bool IsIdentifier(string token)
    {
        if(token.Length == 0 || !char.IsAsciiLetter(token[0]) || !char.IsAsciiLetterOrDigit(token[^1]))
        {
            return false;
        }

        for(int i = 1; i < token.Length - 1; ++i)
        {
            if(!IsIdentifierChar(token[i]))
            {
                return false;
            }
        }

        return true;
    }


    private static bool IsIdentifierChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-' || c == '.';


    //The version token is semver-shaped. The major and minor components are taken from the first
    //two dot-separated numeric fields; the patch and any pre-release suffix are not used in MTURIs.
    private static bool TryParseVersion(string version, out int major, out int minor)
    {
        minor = 0;

        int firstDot = version.IndexOf('.', StringComparison.Ordinal);
        string majorText = firstDot < 0 ? version : version[..firstDot];
        if(!int.TryParse(majorText, out major))
        {
            return false;
        }

        if(firstDot < 0)
        {
            return true;
        }

        string afterMajor = version[(firstDot + 1)..];
        int secondDot = afterMajor.IndexOf('.', StringComparison.Ordinal);
        string minorText = secondDot < 0 ? afterMajor : afterMajor[..secondDot];

        //A trailing pre-release marker on the minor (e.g. "0-rc1") is tolerated by reading the
        //leading digits; an empty or non-numeric minor field is malformed.
        int digits = 0;
        while(digits < minorText.Length && char.IsAsciiDigit(minorText[digits]))
        {
            digits++;
        }

        return digits > 0 && int.TryParse(minorText[..digits], out minor);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(MessageTypeUri? other) =>
        other is not null && string.Equals(Value, other.Value, StringComparison.Ordinal);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is MessageTypeUri other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public override string ToString() => Value;
}

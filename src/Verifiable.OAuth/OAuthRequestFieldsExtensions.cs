using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth;

/// <summary>
/// Presence-testing extensions over <see cref="RequestFields"/> that apply
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>'s value-presence rule
/// uniformly across the OAuth endpoints.
/// </summary>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
internal static class OAuthRequestFieldsExtensions
{
    /// <summary>
    /// Presence test over the raw wire values a parameter carried, independent of
    /// <see cref="RequestFields.TryGetValue"/>'s exactly-one repetition guard.
    /// </summary>
    extension(RequestFields fields)
    {
        /// <summary>
        /// Whether <paramref name="name"/> is present under
        /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>: "Parameters
        /// sent without a value MUST be treated as if they were omitted from the request." A parameter is
        /// present when at least one of its occurrences carries a non-empty value; a whitespace-only
        /// occurrence is such a value, since the specification distinguishes only the empty value from
        /// every other one. A repeated parameter — "Request and response parameters MUST NOT be included
        /// more than once" — is judged by this same rule and stays repeated for
        /// <see cref="RequestFields.TryGetValue"/>: an endpoint that needs the single value still fails
        /// closed on a repeat, even when this method reports the parameter present.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>
        /// <see langword="true"/> when at least one occurrence of <paramref name="name"/> carries a
        /// non-empty value; otherwise <see langword="false"/>.
        /// </returns>
        public bool HasParameter(string name)
        {
            IReadOnlyList<string> values = fields.GetValues(name);
            for(int i = 0; i < values.Count; i++)
            {
                if(!string.IsNullOrEmpty(values[i]))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Whether <paramref name="name"/> was repeated on the wire, independent of whether any
        /// occurrence carries a non-empty value. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">
        /// RFC 6749 §3.1</see>: "Request and response parameters MUST NOT be included more than
        /// once" holds even when every repeated occurrence is itself empty, so a wholly empty
        /// repeat is not silently normalized away by <see cref="HasParameter"/>'s omission rule —
        /// a caller that needs that rule for a singleton parameter checks this alongside it.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <returns>
        /// <see langword="true"/> when <paramref name="name"/> carries more than one occurrence on
        /// the wire; otherwise <see langword="false"/>.
        /// </returns>
        public bool HasRepeatedOccurrence(string name) =>
            fields.GetValues(name).Count > 1;
    }
}

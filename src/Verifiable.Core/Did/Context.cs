using System.Collections.Generic;

public sealed class Context
{
    /// <summary>
    /// DID Core 1.0 context URI as defined in the W3C Recommendation.
    /// </summary>
    public static string DidCore10 { get; } = "https://www.w3.org/ns/did/v1";

    /// <summary>
    /// DID Core 1.1 context URI.
    /// </summary>
    public static string DidCore11 { get; } = "https://www.w3.org/ns/did/v1.1";


    public List<object>? Contexes { get; set; }

    public IDictionary<string, object>? AdditionalData { get; set; }
}
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Did;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// Constructs a <see cref="DidDocument"/> for one DID method from public key material and method-specific
/// options. This is the per-method builder seam the registration Create flow dispatches to.
/// </summary>
/// <param name="keys">
/// The public key material to construct verification methods from (the resolved
/// <c>secret.verificationMethod</c> templates of a DIF create request).
/// </param>
/// <param name="options">
/// The method-specific create options (the DIF <c>options</c> object) — for example
/// <see cref="WellKnownDidRegistrationValues.WebDomainOption"/>. Never <see langword="null"/> (empty when the
/// request carried none).
/// </param>
/// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
/// <returns>The constructed DID document.</returns>
public delegate ValueTask<DidDocument> DidDocumentBuildDelegate(
    IReadOnlyList<KeyMaterialInput> keys,
    IReadOnlyDictionary<string, object?> options,
    CancellationToken cancellationToken);

/// <summary>
/// A method-name &#8594; builder registry that joins the per-method DID document builders
/// (<see cref="KeyDidBuilder"/>, <see cref="WebDidBuilder"/>, and others a consumer registers) into the DIF
/// DID Registration Create flow. The builders consume key material (<see cref="KeyMaterialInput"/>) and produce a
/// <see cref="DidDocument"/>, whereas the registration PDA carries a <see cref="BeginCreate"/> request; this
/// registry's <see cref="CreateMethodHandler"/> bridges the two (rows J1/J2 of the registration matrix).
/// </summary>
/// <remarks>
/// <para>
/// See the DIF
/// <see href="https://identity.foundation/did-registration/#create">create(method, options, secret, didDocument)</see>
/// function: a create request supplying key material (rather than a pre-built document) is dispatched to the
/// builder registered for its method, which constructs the document from that key material plus the
/// method-specific <c>options</c>.
/// </para>
/// <para>
/// Builders that need only key material and options (<c>did:key</c>, <c>did:web</c>) are registered by
/// <see cref="CreateDefault"/>. Builders that need additional injected seams (for example the <c>did:webplus</c>
/// builder's serializer/hash/encoder seams, which keep <see cref="Verifiable.Core"/> serializer-free) are
/// registered by the consuming application, which bakes its own seams into the registered delegate.
/// </para>
/// </remarks>
public sealed class DidRegistrationBuilders
{
    /// <summary>An empty options bag passed to a builder when the request carried no options.</summary>
    private static readonly IReadOnlyDictionary<string, object?> EmptyOptions =
        ReadOnlyDictionary<string, object?>.Empty;

    /// <summary>The registered builders keyed by DID method name (the token after <c>did:</c>, e.g. <c>key</c>).</summary>
    private Dictionary<string, DidDocumentBuildDelegate> Builders { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The DID method names whose DIDs are immutable (generative — fully determined by their content, with no
    /// registrar-side state to mutate), so <c>update</c> and <c>deactivate</c> are rejected for them.
    /// </summary>
    private HashSet<string> GenerativeMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Registers <paramref name="builder"/> as the document builder for <paramref name="method"/>, replacing any
    /// builder previously registered for that method.
    /// </summary>
    /// <param name="method">The DID method name (the token after <c>did:</c>, e.g. <c>key</c> or <c>web</c>).</param>
    /// <param name="builder">The builder to invoke for create requests naming <paramref name="method"/>.</param>
    /// <returns>This instance, to allow registration calls to be chained.</returns>
    public DidRegistrationBuilders Register(string method, DidDocumentBuildDelegate builder)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method, nameof(method));
        ArgumentNullException.ThrowIfNull(builder);

        Builders[method] = builder;

        return this;
    }

    /// <summary>
    /// Marks <paramref name="method"/> as a generative method whose DIDs are immutable (for example <c>did:key</c>,
    /// whose DID is fully derived from its key), so the registrar rejects an <c>update</c> or <c>deactivate</c> of one
    /// of its DIDs with <c>methodNotSupported</c> rather than applying the generic document algebra.
    /// </summary>
    /// <param name="method">The DID method name (the token after <c>did:</c>, e.g. <c>key</c>).</param>
    /// <returns>This instance, to allow registration calls to be chained.</returns>
    public DidRegistrationBuilders RegisterGenerative(string method)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method, nameof(method));

        _ = GenerativeMethods.Add(method);

        return this;
    }

    /// <summary>
    /// Gets the builder registered for <paramref name="method"/>, if any.
    /// </summary>
    /// <param name="method">The DID method name.</param>
    /// <param name="builder">The registered builder when found; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when a builder is registered for <paramref name="method"/>.</returns>
    public bool TryGetBuilder(string method, out DidDocumentBuildDelegate? builder)
    {
        ArgumentNullException.ThrowIfNull(method);

        return Builders.TryGetValue(method, out builder);
    }

    /// <summary>
    /// Creates a registry pre-populated with the builders that need no application-injected seams: the
    /// <c>did:key</c> builder and the <c>did:web</c> builder (the latter reading
    /// <see cref="WellKnownDidRegistrationValues.WebDomainOption"/> from the create options). A consumer registers
    /// any further method builders (such as <c>did:webplus</c>, whose builder needs injected seams) onto the
    /// returned instance.
    /// </summary>
    /// <returns>A registry with the <c>did:key</c> and <c>did:web</c> builders registered.</returns>
    public static DidRegistrationBuilders CreateDefault()
    {
        var registry = new DidRegistrationBuilders();

        _ = registry.Register("key", static (keys, options, cancellationToken) =>
            new KeyDidBuilder().BuildAsync(keys, cancellationToken: cancellationToken));

        //did:key DIDs are immutable — the DID is the key, with no registrar state to update or deactivate.
        _ = registry.RegisterGenerative("key");

        _ = registry.Register("web", static (keys, options, cancellationToken) =>
        {
            //Each option key maps to a WebDidBuilder.BuildAsync named parameter; the untyped DIF options bag is
            //adapted to the builder's strongly-typed surface here, at the method boundary.
            string domain = RequireWebDomain(options);
            DidRepresentationType representation = ReadRepresentation(options);
            string? didCoreVersion = ReadOptionalString(options, WellKnownDidRegistrationValues.WebDidCoreVersionOption);
            string[]? additionalContexts = ReadOptionalStringSequence(options, WellKnownDidRegistrationValues.WebAdditionalContextsOption);

            return new WebDidBuilder().BuildAsync(keys, domain, representation, didCoreVersion, additionalContexts, cancellationToken);
        });

        return registry;
    }

    /// <summary>
    /// Creates the registration PDA method handler that dispatches a create to the registered method builder (the
    /// builder join, matrix row J1) and applies the generic, proof-free <c>update</c>/<c>deactivate</c>
    /// operations. A <see cref="BeginCreate"/> carrying <see cref="BeginCreate.Keys"/> is built by the method's
    /// builder and completes the flow; a <see cref="BeginCreate"/> carrying only a pre-built
    /// <see cref="BeginCreate.Document"/> completes directly; a create naming an unregistered method fails. A
    /// <see cref="BeginUpdate"/> applies its <see cref="BeginUpdate.Operations"/> in sequence through
    /// <see cref="DidDocumentOperations"/> and completes; a <see cref="BeginDeactivate"/> completes the DID with no
    /// document.
    /// </summary>
    /// <remarks>
    /// The update/deactivate handling here is the method-agnostic document algebra, correct for hosted methods
    /// (<c>did:web</c>) where no proof anchors the change. An update or deactivate of a generative method's DID
    /// (one registered via <see cref="RegisterGenerative"/>, e.g. <c>did:key</c>) is rejected with
    /// <c>methodNotSupported</c>, since such DIDs are immutable. Proof-based anchoring (the <c>did:webplus</c> update
    /// builder, matrix row J2) layers on top per method and is still gated on the proof-signing seam.
    /// </remarks>
    /// <returns>A method handler suitable for <see cref="DidRegistrationTransitions.Create"/>.</returns>
    public Func<RegistrationFlowState, RegistrationInput, CancellationToken, ValueTask<RegistrationFlowState>> CreateMethodHandler()
    {
        return async (state, input, cancellationToken) => input switch
        {
            BeginCreate create => await HandleCreateAsync(create, cancellationToken).ConfigureAwait(false),
            BeginUpdate update => HandleUpdate(update),
            BeginDeactivate deactivate => HandleDeactivate(deactivate),

            //The signing/confirmation round-trips are handled by the PDA's other transitions; leave the state.
            _ => state
        };
    }

    /// <summary>
    /// Handles a <see cref="BeginCreate"/>: dispatches key material to the registered method builder, or completes
    /// directly with a pre-built document.
    /// </summary>
    /// <param name="create">The create request.</param>
    /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
    /// <returns>The resulting registration state.</returns>
    private async ValueTask<RegistrationFlowState> HandleCreateAsync(BeginCreate create, CancellationToken cancellationToken)
    {
        if(create.Keys is { Count: > 0 } keys)
        {
            if(!Builders.TryGetValue(create.Method, out DidDocumentBuildDelegate? builder))
            {
                return new RegistrationFailed($"methodNotSupported: no builder registered for did:{create.Method}.");
            }

            DidDocument document = await builder(keys, create.Options ?? EmptyOptions, cancellationToken).ConfigureAwait(false);

            return new RegistrationCompleted(document.Id?.Id ?? string.Empty, document);
        }

        if(create.Document is { } prebuilt)
        {
            //A pre-built document was supplied directly; no builder dispatch is needed.
            return new RegistrationCompleted(prebuilt.Id?.Id ?? string.Empty, prebuilt);
        }

        return new RegistrationFailed($"missingInput: create for did:{create.Method} supplied neither key material nor a document.");
    }

    /// <summary>
    /// Handles a <see cref="BeginUpdate"/>: validates the operation and operands, then applies the
    /// <c>didDocumentOperation</c> through <see cref="DidDocumentOperations"/> to complete the flow with the
    /// updated document.
    /// </summary>
    /// <param name="update">The update request.</param>
    /// <returns>The resulting registration state — completed, or failed with a DIF-shaped error code.</returns>
    private RegistrationFlowState HandleUpdate(BeginUpdate update)
    {
        if(DidMethodOf(update.Did) is { } method && GenerativeMethods.Contains(method))
        {
            return new RegistrationFailed(
                $"methodNotSupported: did:{method} DIDs are immutable; update is not a valid operation for them.");
        }

        if(update.Operations is not { Count: > 0 } operations)
        {
            return new RegistrationFailed($"missingInput: update for {update.Did} supplied no didDocumentOperation.");
        }

        //Every step must name one of the three document-transform operations; deactivate has its own flow and a
        //method-specific operation is not applied by this generic, proof-free handler.
        foreach(DidDocumentOperationStep step in operations)
        {
            if(step.Operation != WellKnownDidRegistrationValues.SetDidDocument
                && step.Operation != WellKnownDidRegistrationValues.AddToDidDocument
                && step.Operation != WellKnownDidRegistrationValues.RemoveFromDidDocument)
            {
                return new RegistrationFailed($"invalidDidDocumentOperation: '{step.Operation}' is not valid for an update.");
            }
        }

        //Only the first step consumes the supplied current document; later steps transform the running result. So the
        //current document is required when the first step is add/remove (a leading set replaces it wholesale).
        if(operations[0].Operation != WellKnownDidRegistrationValues.SetDidDocument && update.CurrentDocument is null)
        {
            return new RegistrationFailed(
                $"missingInput: update '{operations[0].Operation}' for {update.Did} requires the current DID document.");
        }

        DidDocument updated = DidDocumentOperations.Apply(update.CurrentDocument, operations);

        return new RegistrationCompleted(update.Did, updated);
    }

    /// <summary>
    /// Handles a <see cref="BeginDeactivate"/>: completes the DID with no document, mirroring the DIF deactivate
    /// result (a deactivated DID resolves to no document).
    /// </summary>
    /// <param name="deactivate">The deactivate request.</param>
    /// <returns>The resulting registration state — completed with a <see langword="null"/> document, or failed with a DIF-shaped error code.</returns>
    private RegistrationFlowState HandleDeactivate(BeginDeactivate deactivate)
    {
        if(DidMethodOf(deactivate.Did) is { } method && GenerativeMethods.Contains(method))
        {
            return new RegistrationFailed(
                $"methodNotSupported: did:{method} DIDs are immutable; deactivate is not a valid operation for them.");
        }

        //A deactivated DID resolves to no document (DIF didState.state = finished, no didDocument). Proof-based
        //anchoring of the deactivation layers on top per method.
        return new RegistrationCompleted(deactivate.Did, Document: null);
    }

    /// <summary>
    /// Extracts the DID method name (the token between <c>did:</c> and the next colon) from a DID, or
    /// <see langword="null"/> when the string is not a well-formed <c>did:&lt;method&gt;:&lt;id&gt;</c>.
    /// </summary>
    /// <param name="did">The DID to read the method from.</param>
    /// <returns>The method name, or <see langword="null"/>.</returns>
    private static string? DidMethodOf(string did)
    {
        const string scheme = "did:";
        if(string.IsNullOrEmpty(did) || !did.StartsWith(scheme, StringComparison.Ordinal))
        {
            return null;
        }

        int methodEnd = did.IndexOf(':', scheme.Length);

        return methodEnd > scheme.Length ? did[scheme.Length..methodEnd] : null;
    }

    /// <summary>
    /// Reads the required <c>did:web</c> host from the create options
    /// (<see cref="WellKnownDidRegistrationValues.WebDomainOption"/>).
    /// </summary>
    /// <param name="options">The method-specific create options.</param>
    /// <returns>The web domain string.</returns>
    /// <exception cref="ArgumentException">Thrown when the domain option is missing or not a non-empty string.</exception>
    private static string RequireWebDomain(IReadOnlyDictionary<string, object?> options)
    {
        if(options.TryGetValue(WellKnownDidRegistrationValues.WebDomainOption, out object? value)
            && value is string domain
            && !string.IsNullOrWhiteSpace(domain))
        {
            return domain;
        }

        throw new ArgumentException(
            $"A did:web create requires the '{WellKnownDidRegistrationValues.WebDomainOption}' option (the host).",
            nameof(options));
    }

    /// <summary>
    /// Reads the optional <c>did:web</c> representation option
    /// (<see cref="WellKnownDidRegistrationValues.WebRepresentationOption"/>), defaulting to the builder's JSON-LD
    /// default when absent.
    /// </summary>
    /// <param name="options">The method-specific create options.</param>
    /// <returns>The selected representation type.</returns>
    /// <exception cref="ArgumentException">Thrown when the option is present but not a recognized token.</exception>
    private static DidRepresentationType ReadRepresentation(IReadOnlyDictionary<string, object?> options)
    {
        if(!options.TryGetValue(WellKnownDidRegistrationValues.WebRepresentationOption, out object? value) || value is null)
        {
            return DidRepresentationType.JsonLd;
        }

        if(value is string token && WellKnownDidRegistrationValues.ToDidRepresentationType(token) is DidRepresentationType representation)
        {
            return representation;
        }

        throw new ArgumentException(
            $"The '{WellKnownDidRegistrationValues.WebRepresentationOption}' option must be one of "
            + $"'{WellKnownDidRegistrationValues.RepresentationJsonLd}', '{WellKnownDidRegistrationValues.RepresentationJsonWithContext}', "
            + $"or '{WellKnownDidRegistrationValues.RepresentationJsonWithoutContext}'.",
            nameof(options));
    }

    /// <summary>
    /// Reads an optional non-empty string option, or <see langword="null"/> when the key is absent (or carries a
    /// null/non-string/blank value).
    /// </summary>
    /// <param name="options">The method-specific create options.</param>
    /// <param name="key">The option key to read.</param>
    /// <returns>The string value, or <see langword="null"/>.</returns>
    private static string? ReadOptionalString(IReadOnlyDictionary<string, object?> options, string key)
    {
        return options.TryGetValue(key, out object? value) && value is string text && !string.IsNullOrWhiteSpace(text)
            ? text
            : null;
    }

    /// <summary>
    /// Reads an optional sequence-of-strings option (e.g. additional <c>@context</c> entries), or
    /// <see langword="null"/> when the key is absent or carries an empty sequence.
    /// </summary>
    /// <param name="options">The method-specific create options.</param>
    /// <param name="key">The option key to read.</param>
    /// <returns>The materialized string array, or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentException">Thrown when the option is present but not a sequence of strings.</exception>
    private static string[]? ReadOptionalStringSequence(IReadOnlyDictionary<string, object?> options, string key)
    {
        if(!options.TryGetValue(key, out object? value) || value is null)
        {
            return null;
        }

        if(value is IEnumerable<string> sequence)
        {
            string[] contexts = sequence.ToArray();

            return contexts.Length == 0 ? null : contexts;
        }

        throw new ArgumentException($"The '{key}' option must be a sequence of strings.", nameof(options));
    }
}

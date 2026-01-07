using System.Buffers;

namespace Verifiable.Cryptography;

/// <summary>
/// Resolves and loads key material from a format-specific context.
/// </summary>
/// <remarks>
/// <para>
/// This delegate handles the first two steps of the three-step key resolution flow:
/// </para>
/// <list type="number">
/// <item><description>
/// <strong>Identification</strong> - Determining which key to use based on context
/// (e.g., kid header, verification method ID, issuer configuration).
/// </description></item>
/// <item><description>
/// <strong>Loading</strong> - Fetching the key bytes and metadata from storage
/// (database, file, JWKS endpoint, DID document, TPM, HSM, cloud KMS).
/// </description></item>
/// </list>
/// <para>
/// The third step (binding cryptographic functions) is handled separately by
/// <see cref="KeyMaterialBinder{TInput, TResult, TState}"/>.
/// </para>
/// <para>
/// <strong>Format Independence</strong>
/// </para>
/// <para>
/// The <typeparamref name="TContext"/> parameter allows format-specific contexts:
/// </para>
/// <list type="bullet">
/// <item><description>
/// JOSE: header and payload (kid, jku, alg, iss).
/// </description></item>
/// <item><description>
/// COSE: protected header (kid bytes, alg int).
/// </description></item>
/// <item><description>
/// DID: verification method ID, controller, purpose.
/// </description></item>
/// <item><description>
/// OIDC: client_id, jwks_uri, issuer metadata.
/// </description></item>
/// </list>
/// <para>
/// <strong>State Pattern</strong>
/// </para>
/// <para>
/// The <typeparamref name="TState"/> parameter enables allocation-free resolution by
/// passing infrastructure (HTTP clients, database connections, configuration) without
/// closure capture. This enables static lambdas for better performance.
/// </para>
/// </remarks>
/// <typeparam name="TResult">
/// The type of key material to return. Must derive from <see cref="SensitiveMemory"/>.
/// Typically <see cref="PublicKeyMemory"/> or <see cref="PrivateKeyMemory"/>.
/// </typeparam>
/// <typeparam name="TContext">
/// The format-specific context type containing information needed to identify and locate the key.
/// </typeparam>
/// <typeparam name="TState">
/// The state type containing infrastructure needed for resolution (clients, connections, config).
/// </typeparam>
/// <param name="context">The format-specific context for key identification.</param>
/// <param name="pool">The memory pool for allocating the key material.</param>
/// <param name="state">The resolution infrastructure state.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>
/// The resolved key material, or <see langword="null"/> if the key could not be found.
/// </returns>
/// <seealso cref="KeyMaterialBinder{TInput, TResult, TState}"/>
/// <seealso cref="SensitiveMemory"/>
/// <seealso cref="PublicKeyMemory"/>
/// <seealso cref="PrivateKeyMemory"/>
public delegate ValueTask<TResult?> KeyMaterialResolver<TResult, TContext, TState>(TContext context, MemoryPool<byte> pool, TState state, CancellationToken cancellationToken = default) where TResult: SensitiveMemory;


/// <summary>
/// Binds cryptographic functions to key material, producing a ready-to-use key.
/// </summary>
/// <remarks>
/// <para>
/// This delegate handles the third step of the three-step key resolution flow:
/// </para>
/// <list type="number">
/// <item><description>
/// Identification - handled by <see cref="KeyMaterialResolver{TResult, TContext, TState}"/>.
/// </description></item>
/// <item><description>
/// Loading - handled by <see cref="KeyMaterialResolver{TResult, TContext, TState}"/>.
/// </description></item>
/// <item><description>
/// <strong>Binding</strong> - Attaching the appropriate cryptographic function based on
/// the material's <see cref="Tag"/> (algorithm, purpose, <see cref="Context.MaterialSemantics"/>).
/// </description></item>
/// </list>
/// <para>
/// <strong>Backend Selection</strong>
/// </para>
/// <para>
/// The binder uses the <see cref="Tag"/> from the input material to select the appropriate
/// cryptographic backend:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="Context.MaterialSemantics.Direct"/> - Software implementation (BouncyCastle, NSec, Microsoft).
/// </description></item>
/// <item><description>
/// <see cref="Context.MaterialSemantics.TpmHandle"/> - TPM operations using the handle bytes.
/// </description></item>
/// <item><description>
/// Custom semantics - User-defined backends (HSM, cloud KMS, WASM).
/// </description></item>
/// </list>
/// <para>
/// <strong>Separation of Concerns</strong>
/// </para>
/// <para>
/// Separating binding from resolution enables:
/// </para>
/// <list type="bullet">
/// <item><description>
/// Inspecting material without binding (debugging, logging, policy checks).
/// </description></item>
/// <item><description>
/// Reusing binders across formats (same binding logic for JOSE, COSE, DID).
/// </description></item>
/// <item><description>
/// Swapping backends independently of resolution.
/// </description></item>
/// <item><description>
/// Testing with mock binders.
/// </description></item>
/// </list>
/// </remarks>
/// <typeparam name="TInput">
/// The type of key material to bind. Must derive from <see cref="SensitiveMemory"/>.
/// Typically <see cref="PublicKeyMemory"/> or <see cref="PrivateKeyMemory"/>.
/// </typeparam>
/// <typeparam name="TResult">
/// The type of bound key to produce.
/// Typically <see cref="PublicKey"/> or <see cref="PrivateKey"/>.
/// </typeparam>
/// <typeparam name="TState">
/// The state type containing binding infrastructure (registry, backend connections).
/// </typeparam>
/// <param name="material">The key material to bind.</param>
/// <param name="state">The binding infrastructure state.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>The bound key ready for cryptographic operations.</returns>
/// <seealso cref="KeyMaterialResolver{TResult, TContext, TState}"/>
/// <seealso cref="PublicKey"/>
/// <seealso cref="PrivateKey"/>
public delegate ValueTask<TResult> KeyMaterialBinder<TInput, TResult, TState>(TInput material, TState state, CancellationToken cancellationToken = default) where TInput: SensitiveMemory;
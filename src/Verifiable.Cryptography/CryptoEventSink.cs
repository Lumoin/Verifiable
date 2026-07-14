namespace Verifiable.Cryptography;

/// <summary>
/// Receives a <see cref="CryptoEvent"/> a signing or verification operation produced, as an explicit
/// per-call parameter — never a captured closure (the house rule for every library extension point:
/// caller data reaches library callbacks as an explicit argument, not ambient state).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/> (and every sibling delegate family
/// that shares their <c>(TResult, CryptoEvent? Event)</c> tuple shape) already construct the event; the
/// only remaining question at each call site is where it goes. A caller that resolves and invokes one of
/// these delegates directly — rather than through the <see cref="PrivateKey.SignAsync"/>/
/// <see cref="PublicKey.VerifyAsync"/> choke points, which always forward to
/// <see cref="CryptographicKeyEvents.Events"/> — accepts a trailing, optional
/// <c>CryptoEventSink? eventSink = null</c> parameter and invokes
/// <c>(eventSink ?? CryptographicKeyEvents.DefaultSink)(cryptoEvent)</c> when the tuple's event is
/// non-null.
/// </para>
/// <para>
/// <strong>Default routes to the global stream, by design.</strong> An earlier draft of this seam
/// considered defaulting to a no-op (matching the discard behavior every one of these call sites had
/// before this type existed). That default was rejected: the key-object choke points and the handful of
/// call sites already granted <c>InternalsVisibleTo</c> access to
/// <see cref="CryptographicKeyEvents"/>'s internal emit hook already publish unconditionally to
/// <see cref="CryptographicKeyEvents.Events"/> — a default-discard would have made every OTHER call site
/// (COSE/JOSE, SD-JWT/SD-CWT, the APDU/eMRTD stack) permanently second-class, institutionalizing exactly
/// the inconsistency this type exists to remove. The event is already constructed by the tuple seam and
/// thrown away either way; forwarding it to the same stream every other path uses costs one delegate
/// invocation. A caller that wants to suppress publication for a specific call passes an explicit no-op
/// sink (<c>static _ => { }</c>) rather than relying on an implicit default.
/// </para>
/// <para>
/// This is the second sanctioned route alongside binding a <see cref="PrivateKey"/>/<see cref="PublicKey"/>
/// object around the same key material (the resolver/binder overloads in <c>Verifiable.JCose</c>): a
/// caller that already holds — or can cheaply construct — a key object gets <see cref="CryptographicKeyEvents.Events"/>
/// for free through the choke point; a caller that only holds raw, disassembled key material (the APDU
/// "forced" sites, per the wave-7 emit-surface scout) uses this sink parameter instead, with no
/// <c>InternalsVisibleTo</c> growth and no new public <c>Emit</c> surface.
/// </para>
/// </remarks>
/// <param name="cryptoEvent">
/// The event a signing or verification operation produced. Never <see langword="null"/> — a call site
/// invokes the sink only after checking the tuple's event for non-null, the same guard
/// <see cref="CryptographicKeyEvents"/>'s own wrapper methods apply before calling
/// <see cref="CryptographicKeyEvents.Events"/>.
/// </param>
public delegate void CryptoEventSink(CryptoEvent cryptoEvent);

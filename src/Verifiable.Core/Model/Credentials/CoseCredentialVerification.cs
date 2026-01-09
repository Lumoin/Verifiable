using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Verification methods for COSE-secured Verifiable Credentials.
/// </summary>
public static class CoseCredentialVerification
{
    /// <summary>
    /// Verifies a COSE_Sign1-secured credential.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        CryptoAlgorithm algorithm = publicKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = publicKey.Tag.Get<Purpose>();
        VerificationDelegate verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose);

        bool isValid = await verificationDelegate(
            toBeSigned,
            message.Signature,
            publicKey.AsReadOnlyMemory());

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        Dictionary<int, object> header = new(headerParser(message.ProtectedHeaderBytes.Span));
        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        return CoseCredentialVerificationResult.Success(header, credential, alg, kid);
    }


    /// <summary>
    /// Verifies a COSE_Sign1-secured credential using an explicit verification function.
    /// </summary>
    /// <param name="message">The COSE_Sign1 message to verify.</param>
    /// <param name="buildSigStructure">Delegate to build the Sig_structure for verification.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="verificationFunction">The verification function to use.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="credentialDeserializer">Delegate for deserializing the credential from the payload.</param>
    /// <param name="headerParser">Delegate for parsing the protected header bytes.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The verification result containing validity status and decoded credential.</returns>
    public static async ValueTask<CoseCredentialVerificationResult> VerifyAsync(
        CoseSign1Message message,
        BuildSigStructureDelegate buildSigStructure,
        PublicKeyMemory publicKey,
        VerificationFunction<byte, byte, Signature, ValueTask<bool>> verificationFunction,
        MemoryPool<byte> pool,
        CredentialFromJsonBytesDelegate credentialDeserializer,
        ParseProtectedHeaderDelegate headerParser,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(buildSigStructure);
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(verificationFunction);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(credentialDeserializer);
        ArgumentNullException.ThrowIfNull(headerParser);

        byte[] toBeSigned = buildSigStructure(
            message.ProtectedHeaderBytes.Span,
            message.Payload.Span,
            ReadOnlySpan<byte>.Empty);

        IMemoryOwner<byte> signatureMemory = pool.Rent(message.Signature.Length);
        message.Signature.Span.CopyTo(signatureMemory.Memory.Span);

        using var signature = new Signature(signatureMemory, publicKey.Tag);

        bool isValid = await verificationFunction(publicKey.AsReadOnlyMemory(), toBeSigned, signature);

        if(!isValid)
        {
            return CoseCredentialVerificationResult.Failed();
        }

        Dictionary<int, object> header = new(headerParser(message.ProtectedHeaderBytes.Span));
        VerifiableCredential credential = credentialDeserializer(message.Payload.Span);

        int? alg = header.TryGetValue(CoseHeaderParameters.Alg, out object? algValue) && algValue is int a ? a : null;
        string? kid = header.TryGetValue(CoseHeaderParameters.Kid, out object? kidValue) && kidValue is string k ? k : null;

        return CoseCredentialVerificationResult.Success(header, credential, alg, kid);
    }
}
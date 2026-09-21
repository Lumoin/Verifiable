namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Frames a caller-supplied <c>TPMT_SIGNATURE</c> (TPM 2.0 Library Part 2, clause 11.3.6, Table 219) for the
/// command inputs that carry one as a parameter: the <c>sigAlg</c> selector, the member's <c>hash</c>, then the
/// <c>sigAlg</c>-selected <c>TPMU_SIGNATURE</c> member — the ECDSA <c>r</c>/<c>s</c> pair as two
/// <c>TPM2B_ECC_PARAMETER</c>s (clause 11.3.2, Table 214), an RSA signature as one <c>TPM2B_PUBLIC_KEY_RSA</c>
/// (clause 11.3.1, Table 212), and the HMAC member as a <c>TPMT_HA</c> whose digest is UNSIZED, its width fixed by
/// the hash (clause 10.2.2, Table 89). The two guards a mis-sized member needs — an even-length IEEE P1363 pair,
/// a digest of exactly the hash's width — live here once, so every input frames the union identically.
/// </summary>
internal static class TpmtSignatureFraming
{
    /// <summary>
    /// Gets the serialized size of a <c>TPMT_SIGNATURE</c> carrying <paramref name="signatureLength"/> signature
    /// octets under <paramref name="sigAlg"/>: the selector and hash fields plus the member's own framing — two
    /// TPM2B size prefixes for the ECDSA pair, one for the RSA buffer, none for the unsized HMAC digest.
    /// </summary>
    /// <param name="sigAlg">The <c>TPMU_SIGNATURE</c> selector.</param>
    /// <param name="signatureLength">The signature octets' length as the caller supplied them.</param>
    /// <returns>The number of octets <see cref="Write"/> produces.</returns>
    public static int GetSerializedSize(TpmAlgIdConstants sigAlg, int signatureLength)
    {
        int memberPrefixes = sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => 2 * sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_HMAC => 0,
            TpmAlgIdConstants.TPM_ALG_ERROR => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_RSA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_TDES => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_AES => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_MGF1 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_XOR => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA384 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA512 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA256_192 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_NULL => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SM3_256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SM4 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_RSASSA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_RSAES => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_RSAPSS => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_OAEP => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECDH => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECDAA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SM2 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECMQV => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_HKDF => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KDF2 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECC => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CAMELLIA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA3_256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA3_384 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHA3_512 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHAKE128 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHAKE256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHAKE256_192 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHAKE256_256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_SHAKE256_512 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CMAC => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CTR => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_OFB => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CBC => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CFB => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_ECB => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_CCM => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_GCM => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KW => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KWP => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_EAX => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_EDDSA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_EDDSA_PH => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_LMS => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_XMSS => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KEYEDXOF => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KMACXOF128 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KMACXOF256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KMAC128 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_KMAC256 => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_MLKEM => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_MLDSA => sizeof(ushort),
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => sizeof(ushort),
            _ => sizeof(ushort)
        };

        return sizeof(ushort) + sizeof(ushort) + memberPrefixes + signatureLength;
    }

    /// <summary>
    /// Writes the <c>TPMT_SIGNATURE</c>: <paramref name="sigAlg"/>, <paramref name="schemeHashAlg"/>, then the
    /// selected member built from <paramref name="signature"/>.
    /// </summary>
    /// <param name="writer">The writer positioned at the signature parameter.</param>
    /// <param name="sigAlg">The <c>TPMU_SIGNATURE</c> selector.</param>
    /// <param name="schemeHashAlg">The hash carried inside the member.</param>
    /// <param name="signature">The signature octets: IEEE P1363 <c>r ‖ s</c> for ECDSA, the raw RSA signature for RSASSA/RSAPSS, or the raw HMAC digest for <c>TPM_ALG_HMAC</c>.</param>
    /// <exception cref="InvalidOperationException">An ECDSA pair of odd length, or an HMAC digest whose width is not the hash's.</exception>
    public static void Write(ref TpmWriter writer, TpmAlgIdConstants sigAlg, TpmAlgIdConstants schemeHashAlg, ReadOnlySpan<byte> signature)
    {
        writer.WriteUInt16((ushort)sigAlg);
        writer.WriteUInt16((ushort)schemeHashAlg);

        if(sigAlg == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature — the same
            //framing the simulator's response serializer uses for TPM2_Sign()/TPM2_Certify() and the other
            //attest-producing commands.
            if((signature.Length & 1) != 0)
            {
                throw new InvalidOperationException(
                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {signature.Length} octets.");
            }

            int fieldWidth = signature.Length / 2;
            writer.WriteTpm2b(signature[..fieldWidth]);
            writer.WriteTpm2b(signature[fieldWidth..]);

            return;
        }

        if(sigAlg == TpmAlgIdConstants.TPM_ALG_HMAC)
        {
            //TPMU_SIGNATURE's HMAC member is a TPMT_HA (Table 89): the hash just written followed by an UNSIZED
            //digest whose width that hash fixes — no TPM2B length prefix — so a digest of any other width would
            //desynchronize every parameter after it on the wire; refused here, as the ECDSA arm refuses an
            //odd-length pair. An unsized hash is framed as given so the TPM's own unmarshal answers it.
            if(schemeHashAlg.GetDigestSize() is int digestWidth && signature.Length != digestWidth)
            {
                throw new InvalidOperationException(
                    $"A TPM_ALG_HMAC signature is a TPMT_HA whose digest is exactly the hash's width; got {signature.Length} octets for {schemeHashAlg}, which needs {digestWidth}.");
            }

            writer.WriteBytes(signature);

            return;
        }

        //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
        writer.WriteTpm2b(signature);
    }
}

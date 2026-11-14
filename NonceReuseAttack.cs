public static class NonceReuseAttack
{
    public static byte[] RecoverSecondMessage(
        byte[] knownPlaintext,
        byte[] firstCiphertext,
        byte[] secondCiphertext)
    {
        byte[] recovered = new byte[secondCiphertext.Length];

        for (int i = 0; i < recovered.Length; i++)
        {
            // Recover keystream byte using known message and its ciphertext.
            byte recoveredKeystreamByte = (byte)(
                knownPlaintext[i] ^ firstCiphertext[i]);

            // Use same keystream byte to recover second message.
            byte recoveredPlaintextByte = (byte)(
                secondCiphertext[i] ^ recoveredKeystreamByte);

            recovered[i] = recoveredPlaintextByte;
        }

        return recovered;
    }
}

public static class NonceReuseAttack
{
    public static byte[] RecoverSecondMessage(
        byte[] knownPlaintext,
        byte[] firstCiphertext,
        byte[] secondCiphertext)
    {
        //Recover only the positions where the first plaintext is known.
        byte[] recovered = new byte[knownPlaintext.Length];

        for (int i = 0; i < recovered.Length; i++)
        {
            //Recover a keystream byte using the known plaintext.
            byte recoveredKeystreamByte = (byte)(
                knownPlaintext[i] ^ firstCiphertext[i]);

            //Use that keystream byte to recover the corresponding byte.
            byte recoveredPlaintextByte = (byte)(
                secondCiphertext[i] ^ recoveredKeystreamByte);

            recovered[i] = recoveredPlaintextByte;
        }

        return recovered;
    }
}
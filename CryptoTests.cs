using System.Security.Cryptography;
using System.Text;

public static class CryptoTests
{
    private const string ExpectedCiphertextHex = "0388DACE60B6A392F328C2B971B2FE78";
    private const string ExpectedTagHex = "AB6E47D42CEC13BDF53A67B21257BDDF";

    public static bool RunEncryptionTests(
        byte[] key,
        byte[] nonce,
        byte[] plaintext,
        byte[] ciphertext,
        byte[] tag,
        byte[] authenticatedHeader)
    {
        using var aesGcm = new AesGcm(key, tag.Length);
        var decrypted = new byte[ciphertext.Length];
        aesGcm.Decrypt(nonce, ciphertext, tag, decrypted, authenticatedHeader);
        var messagesMatch = plaintext.SequenceEqual(decrypted);

        Console.WriteLine($"Recovered message: {Encoding.UTF8.GetString(decrypted)}");
        Console.WriteLine($"Messages match: {messagesMatch}");

        //Run every check, even when an earlier check has failed.
        var ciphertextPassed =
            RunCiphertextTamperTest(aesGcm, nonce, ciphertext, tag, authenticatedHeader);

        var headerPassed =
            RunHeaderTamperTest(aesGcm, nonce, ciphertext, tag, authenticatedHeader);

        var additionalChecksPassed =
            RunAdditionalRejectionTests(aesGcm, key, nonce, ciphertext, tag, authenticatedHeader);

        return messagesMatch
            && ciphertextPassed
            && headerPassed
            && additionalChecksPassed;
    }

    public static bool IsRecoveredMessage(byte[] recovered, byte[] expected)
    {
        return recovered.SequenceEqual(expected);
    }

    public static bool VerifyAttackOutcome(bool attackSucceeded, bool flawedMode)
    {
        return attackSucceeded == flawedMode;
    }

    private static bool RunCiphertextTamperTest(
        AesGcm aesGcm,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        byte[] authenticatedHeader)
    {
        var tamperedCiphertext = (byte[])ciphertext.Clone();
        tamperedCiphertext[0] ^= 1;//Flip one bit to simulate tampering.

        Console.WriteLine("Tamper ciphertext test:");
        Console.WriteLine($"Original Ciphertext:{Convert.ToHexString(ciphertext)}");
        Console.WriteLine($"Tampered Ciphertext:{Convert.ToHexString(tamperedCiphertext)}");

        return ExpectAuthenticationRejection("Altered ciphertext", () =>
            aesGcm.Decrypt(nonce, tamperedCiphertext, tag,
                new byte[ciphertext.Length], authenticatedHeader));
    }

    private static bool RunHeaderTamperTest(
        AesGcm aesGcm,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        byte[] authenticatedHeader)
    {
        var alteredHeader = Encoding.UTF8.GetBytes("meter-id=999");

        Console.WriteLine("Header tampering test:");
        Console.WriteLine($"Original header: {Encoding.UTF8.GetString(authenticatedHeader)}");
        Console.WriteLine($"Altered header:  {Encoding.UTF8.GetString(alteredHeader)}");

        return ExpectAuthenticationRejection("Altered header", () =>
            aesGcm.Decrypt(nonce, ciphertext, tag,
                new byte[ciphertext.Length], alteredHeader));
    }

    private static bool RunAdditionalRejectionTests(
        AesGcm aesGcm,
        byte[] key,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        byte[] authenticatedHeader)
    {
        var wrongKey = (byte[])key.Clone();
        //Flip one bit
        wrongKey[0] ^= 1;
        using var wrongAes = new AesGcm(wrongKey, tag.Length);
        var passed = ExpectAuthenticationRejection("Wrong key", () =>
            wrongAes.Decrypt(nonce, ciphertext, tag,
                new byte[ciphertext.Length], authenticatedHeader));

        var alteredTag = (byte[])tag.Clone();
        //Flip one bit.
        alteredTag[0] ^= 1;
        var tagRejected = ExpectAuthenticationRejection("Altered tag", () =>
            aesGcm.Decrypt(nonce, ciphertext, alteredTag,
                new byte[ciphertext.Length], authenticatedHeader));

        if (!tagRejected)
        {
            passed = false;
        }

        var alteredNonce = (byte[])nonce.Clone();
        //Flip one bit in the last byte of the nonce.
        alteredNonce[^1] ^= 1;
        var nonceRejected = ExpectAuthenticationRejection("Altered nonce", () =>
            aesGcm.Decrypt(alteredNonce, ciphertext, tag,
                new byte[ciphertext.Length], authenticatedHeader));

        if (!nonceRejected)
        {
            passed = false;
        }

        return passed;
    }

    private static bool ExpectAuthenticationRejection(string testName, Action attempt)
    {
        try
        {
            attempt();
            Console.WriteLine($"FAIL: {testName} was accepted.");
            return false;
        }
        catch (AuthenticationTagMismatchException)
        {
            Console.WriteLine($"PASS: {testName} was rejected.");
            return true;
        }
    }
}

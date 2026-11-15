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

        var knownAnswerPassed = RunKnownAnswerTest();
        
        var knownAnswerWithAadPassed = RunKnownAnswerTestWithAad();

        return messagesMatch
            && ciphertextPassed
            && headerPassed
            && additionalChecksPassed
            && knownAnswerPassed
            && knownAnswerWithAadPassed;
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

    //McGrew and Viega (2005), Appendix B, Test Case 2.
    private static bool RunKnownAnswerTest()
    {
        Console.WriteLine("AES-GCM known-answer test:");
        
        var testKey = new byte[16];
        var testNonce = new byte[12];
        var testPlaintext = new byte[16];
        var expectedCiphertext = Convert.FromHexString(ExpectedCiphertextHex);
        var expectedTag = Convert.FromHexString(ExpectedTagHex);
        var actualCiphertext = new byte[testPlaintext.Length];
        var actualTag = new byte[16];

        using var testAes = new AesGcm(testKey, actualTag.Length);
        testAes.Encrypt(
            testNonce, testPlaintext, actualCiphertext, actualTag, Array.Empty<byte>());
        
        var ciphertextMatches = actualCiphertext.SequenceEqual(expectedCiphertext);
        var tagMatches = actualTag.SequenceEqual(expectedTag);
        var passed = ciphertextMatches && tagMatches;
        
        Console.WriteLine($"Expected ciphertext: {Convert.ToHexString(expectedCiphertext)}");
        Console.WriteLine($"Actual ciphertext:   {Convert.ToHexString(actualCiphertext)}");
        Console.WriteLine($"Ciphertext matches: {ciphertextMatches}");
        Console.WriteLine($"Expected tag: {Convert.ToHexString(expectedTag)}");
        Console.WriteLine($"Actual tag:   {Convert.ToHexString(actualTag)}");
        Console.WriteLine($"Tag matches: {tagMatches}");
        Console.WriteLine(passed
            ? "PASS: Published vector matched."
            : "FAIL: Published vector did not match.");
        
        return passed;
    }
    
    //McGrew and Viega (2005), Appendix B, Test Case 4.
    //Check encryption and decryption with additional authenticated data.
    private static bool RunKnownAnswerTestWithAad()
    {
        var key = Convert.FromHexString("FEFFE9928665731C6D6A8F9467308308");
        var nonce = Convert.FromHexString("CAFEBABEFACEDBADDECAF888");
        var plaintext = Convert.FromHexString(
            "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");
        
        var aad = Convert.FromHexString(
            "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
        
        var expectedCiphertext = Convert.FromHexString(
            "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091");
        
        var expectedTag = Convert.FromHexString(
            "5BC94FBC3221A5DB94FAE95AE7121A47");
        
        // Encrypt the test message.
        using var aes = new AesGcm(key, 16);
        
        var ciphertext = new byte[plaintext.Length];
        
        var tag = new byte[16];
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        
        var decrypted = new byte[plaintext.Length];
        aes.Decrypt(nonce, expectedCiphertext, expectedTag, decrypted, aad);
        
        bool ciphertextMatches = ciphertext.SequenceEqual(expectedCiphertext);
        bool tagMatches = tag.SequenceEqual(expectedTag);
        bool plaintextMatches = decrypted.SequenceEqual(plaintext);
        bool passed = ciphertextMatches && tagMatches && plaintextMatches;
        
        Console.WriteLine($"Published AAD vector (case 4) matched: {passed}");
        
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

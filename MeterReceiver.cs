using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

public sealed class MeterReceiver : IDisposable
{
    private readonly AesGcm aesGcm;
    private readonly string expectedHeader;
    private readonly byte[] expectedSenderId;
    private int highestAcceptedCounter;

    public MeterReceiver(byte[] key, string expectedHeader, string senderId = "METER001")
    {
        if (senderId.Length != 8 || senderId.Any(c => c > 127))
            throw new ArgumentException("Sender identifier must be eight ASCII characters.");

        expectedSenderId = Encoding.ASCII.GetBytes(senderId);
        aesGcm = new AesGcm(key, 16);
        this.expectedHeader = expectedHeader;
    }

    public byte[] Decrypt(EncryptedRecord record)
    {
        if (record is null || record.Header is null || record.Nonce is null ||
            record.Ciphertext is null || record.Tag is null ||
            record.Nonce.Length != 12 || record.Tag.Length != 16)
        {
            throw new InvalidRecordException();
        }

        var plaintext = new byte[record.Ciphertext.Length];

        try
        {
            aesGcm.Decrypt(record.Nonce, record.Ciphertext, record.Tag,
                plaintext, Encoding.UTF8.GetBytes(record.Header));
        }
        catch (AuthenticationTagMismatchException)
        {
            // Return the same error when authentication fails.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidRecordException();
        }

        if (!string.Equals(record.Header, expectedHeader, StringComparison.Ordinal) ||
            !record.Nonce.AsSpan(0, 8).SequenceEqual(expectedSenderId))
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidRecordException();
        }

        int counter = BinaryPrimitives.ReadInt32BigEndian(record.Nonce.AsSpan(8, 4));
        if (counter <= highestAcceptedCounter)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new InvalidRecordException();
        }

        highestAcceptedCounter = counter;
        return plaintext;
    }

    public void Dispose() => aesGcm.Dispose();
}

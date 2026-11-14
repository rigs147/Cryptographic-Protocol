using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

public sealed class MeterSender : IDisposable
{
    private readonly AesGcm aes;
    private readonly string header;
    private readonly bool flawedMode;
    private readonly byte[] senderId;
    private int messageCounter;

    public MeterSender(byte[] key, string header, bool flawedMode = false, string senderId = "METER001")
    {
        if (senderId.Length != 8 || senderId.Any(c => c > 127))
            throw new ArgumentException("Sender identifier must be eight ASCII characters.");

        this.senderId = Encoding.ASCII.GetBytes(senderId);
        aes = new AesGcm(key, 16);
        this.header = header;
        this.flawedMode = flawedMode;
    }

    public EncryptedRecord Encrypt(byte[] plaintext)
    {
        // Start at 1. Correct mode advances before every later encryption.
        // Deliberate flaw: later messages keep the previous counter value.
        if (messageCounter == 0 || !flawedMode)
        {
            messageCounter = checked(messageCounter + 1);
        }

        var nonce = CreateNonce(messageCounter);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.UTF8.GetBytes(header));
        return new EncryptedRecord(header, nonce, ciphertext, tag);
    }

    private byte[] CreateNonce(int counter)
    {
        // Sender namespace (8 bytes) followed by a positive counter (4 bytes).
        var nonce = new byte[12];
        senderId.CopyTo(nonce, 0);
        BinaryPrimitives.WriteInt32BigEndian(nonce.AsSpan(8, 4), counter);
        return nonce;
    }

    public void Dispose() => aes.Dispose();
}

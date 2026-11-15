using System.Text.Json;

public sealed record EncryptedRecord(
    string Header, byte[] Nonce, byte[] Ciphertext, byte[] Tag)
{
    public string ToJson() => JsonSerializer.Serialize(this);

    public static EncryptedRecord FromJson(string json)
    {
        if (json is null)
        {
            throw new InvalidRecordException();
        }

        try
        {
            return JsonSerializer.Deserialize<EncryptedRecord>(json)
                ?? throw new InvalidRecordException();
        }
        catch (JsonException)
        {
            throw new InvalidRecordException();
        }
    }
}

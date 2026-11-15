using System.Security.Cryptography;
using System.Text;

public static class RecordTests
{
    private const string Header = "meter-id=001";

    public static bool Run()
    {
        var recordsPassed = RunRecordValidationTests();
        var receiverStatePassed = RunReceiverStateTests();
        var orderingPassed = RunOrderingTest();
        var flawedModePassed = RunFlawedModeTests();

        var passed = recordsPassed
            && receiverStatePassed
            && orderingPassed
            && flawedModePassed;

        Console.WriteLine($"Record checks passed: {passed}");
        return passed;
    }

    private static bool RunRecordValidationTests()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var plaintext = Encoding.UTF8.GetBytes("record round trip");

        using var sender = new MeterSender(key, Header);
        using var receiver = new MeterReceiver(key, Header);

        //Simulate sending and receiving a record by converting it to JSON and back.
        var first = EncryptedRecord.FromJson(
            sender.Encrypt(plaintext).ToJson());

        var second = sender.Encrypt(plaintext);

        //Check that the message survives JSON conversion and the two messages use different nonces.
        var roundTrip = receiver.Decrypt(first).SequenceEqual(plaintext);
        var uniqueNonces = !first.Nonce.SequenceEqual(second.Nonce);

        //Reject incorrect nonce and tag lengths.
        var invalidNonce = Rejected(() =>
            receiver.Decrypt(first with { Nonce = new byte[11] }));

        var invalidTag = Rejected(() =>
            receiver.Decrypt(first with { Tag = new byte[15] }));

        //Reject missing record fields and text that is not valid JSON.
        var missingFields = Rejected(() =>
            receiver.Decrypt(EncryptedRecord.FromJson("{}")));

        var invalidJson = Rejected(() =>
            EncryptedRecord.FromJson("not JSON"));

        //Changing the authenticated header should invalidate the tag.
        var alteredHeader = Rejected(() =>
            receiver.Decrypt(first with { Header = "meter-id=999" }));

        //Even with the same key, a record for another meter should be rejected.
        using var otherSender = new MeterSender(
            key, "meter-id=999", senderId: "METER999");

        var otherRecord = otherSender.Encrypt(plaintext);

        var wrongContext = Rejected(() =>
            receiver.Decrypt(otherRecord));

        //Check that two different meters do not use the same nonce.
        var senderSeparation =
            !first.Nonce.SequenceEqual(otherRecord.Nonce);

        using var otherReceiver = new MeterReceiver(
            key, "meter-id=999", senderId: "METER001");

        //Reject the record as its sender ID is wrong, even though its header matches.
        var wrongSender = Rejected(() =>
            otherReceiver.Decrypt(otherRecord));

        var passed = roundTrip
            && uniqueNonces
            && invalidNonce
            && invalidTag
            && missingFields
            && invalidJson
            && alteredHeader
            && wrongContext
            && senderSeparation
            && wrongSender;

        Console.WriteLine($"Record validation passed: {passed}");
        return passed;
    }

    private static bool RunReceiverStateTests()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var plaintext = Encoding.UTF8.GetBytes("receiver state");

        using var sender = new MeterSender(key, Header);
        using var receiver = new MeterReceiver(key, Header);

        //Create messages with counters 1, 2 and 3. The third has an empty payload.
        var first = sender.Encrypt(plaintext);
        var second = sender.Encrypt(plaintext);
        var third = sender.Encrypt([]);

        //Accept the first message, then check that replaying it is rejected.
        receiver.Decrypt(first);

        var replayRejected = Rejected(() =>
            receiver.Decrypt(first));

        //An unauthenticated message should not advance the receivers counter.
        var badTag = (byte[])third.Tag.Clone();
        badTag[0] ^= 1;

        var badFutureRejected = Rejected(() =>
            receiver.Decrypt(third with { Tag = badTag }));

        //The rejected message should not prevent valid message being accepted.
        var statePreserved =
            receiver.Decrypt(second).SequenceEqual(plaintext);

        var emptyMessage = receiver.Decrypt(third).Length == 0;

        var invalidRecordPreservesState =
            badFutureRejected && statePreserved && emptyMessage;

        var passed = replayRejected && invalidRecordPreservesState;

        Console.WriteLine($"Replay rejected: {replayRejected}");
        Console.WriteLine(
            $"Invalid record leaves receiver state unchanged: {invalidRecordPreservesState}");

        return passed;
    }

    private static bool RunOrderingTest()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var plaintext = Encoding.UTF8.GetBytes("record ordering");

        using var sender = new MeterSender(key, Header);
        using var receiver = new MeterReceiver(key, Header);

        var first = sender.Encrypt(plaintext);
        var second = sender.Encrypt(plaintext);

        //Deliver the second message first, advancing the accepted counter to 2.
        receiver.Decrypt(second);

        //The first message should be rejected as its counter is older.
        var reorderingRejected = Rejected(() =>
            receiver.Decrypt(first));

        Console.WriteLine($"Reordering rejected: {reorderingRejected}");
        return reorderingRejected;
    }

    private static bool RunFlawedModeTests()
    {
        var key = RandomNumberGenerator.GetBytes(16);
        var plaintext = Encoding.UTF8.GetBytes("nonce reuse");

        //Flawed mode deliberately keeps the same counter for both messages.
        using var sender = new MeterSender(
            key, Header, flawedMode: true);

        using var receiver = new MeterReceiver(key, Header);

        var first = sender.Encrypt(plaintext);
        var second = sender.Encrypt(plaintext);

        //Confirm the sender reused the nonce.
        var reusedNonce = first.Nonce.SequenceEqual(second.Nonce);

        receiver.Decrypt(first);

        //Replay protection should still reject the repeated counter in flawed mode.
        var reusedRecordRejected = Rejected(() =>
            receiver.Decrypt(second));

        var passed = reusedNonce && reusedRecordRejected;

        Console.WriteLine($"Flawed-mode record checks passed: {passed}");
        return passed;
    }

    private static bool Rejected(Action operation)
    {
        try
        {
            operation();
            return false;
        }
        catch (InvalidRecordException error)
        {
            return error.Message == "Invalid record.";
        }
    }
}
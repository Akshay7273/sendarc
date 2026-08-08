/**
 * Transfer protocol — messages carried as plaintext INSIDE AES-GCM frames, over the
 * DataChannel or the relay (plan.md §6.2). The frame header (§6.3) is the GCM AAD.
 */
/** Frame type tags (the `type` byte in the header). */
export var FrameType;
(function (FrameType) {
    FrameType[FrameType["Caps"] = 1] = "Caps";
    FrameType[FrameType["Manifest"] = 2] = "Manifest";
    FrameType[FrameType["BlockData"] = 3] = "BlockData";
    FrameType[FrameType["BlockHash"] = 4] = "BlockHash";
    FrameType[FrameType["BlockRecv"] = 5] = "BlockRecv";
    FrameType[FrameType["Ack"] = 6] = "Ack";
    FrameType[FrameType["Nack"] = 7] = "Nack";
    FrameType[FrameType["Control"] = 8] = "Control";
    FrameType[FrameType["Complete"] = 9] = "Complete";
    FrameType[FrameType["Done"] = 10] = "Done";
    FrameType[FrameType["Fail"] = 11] = "Fail";
})(FrameType || (FrameType = {}));
//# sourceMappingURL=transfer.js.map
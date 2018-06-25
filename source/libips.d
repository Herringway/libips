module libips;

import std.exception;
import std.range;
import std.string;

struct IPSPatch {
	struct IPSDiff {
		uint offset;
		ubyte[] data;
	}
	IPSDiff[] diffs;
	int truncatedLength = -1;
	this(ubyte[] data) @safe pure {
		enforce!IPSException(data[0..5] == "PATCH".representation, "Not an IPS patch!");
		for(int i = 5; i < data.length; i++) {
			if (data[i..i+3] == "EOF".representation) {
				if (i+6 == data.length)
					truncatedLength = (data[i+3]<<16) + (data[i+4]<<8) + data[i+5];
				break;
			}
			auto diff = IPSDiff();
			diff.offset = (data[i]<<16) + (data[i+1]<<8) + data[i+2];
			if ((data[i+3]<<8)+(data[i+4]) > 0) {
				diff.data = data[i+5..i+5+(data[i+3]<<8)+(data[i+4])];
				i += (data[i+3]<<8)+(data[i+4])+4;
			} else {
				auto rle_len = (data[i+5]<<8)+(data[i+6]);
				diff.data = new ubyte[rle_len];
				diff.data[] = data[i+7];
				i += 7;
			}
			diffs ~= diff;
		}
	}
	this(T, U)(T originalFile, U changedFile) @safe pure if (isInputRange!T && isInputRange!U && is(ElementType!T == ubyte) && is(ElementType!U == ubyte)) {
		enforce!IPSException(originalFile.length < 0xFFFFFF, "Unable to patch data greater than 16MB!");
		for (int i = 0; i < originalFile.length; i++) {
			if (i >= changedFile.length) {
				truncatedLength = i;
				break;
			}
			if (originalFile[i] != changedFile[i]) {
				auto diff = IPSDiff();
				diff.offset = i;
				while ((i < originalFile.length) && (originalFile[i] != changedFile[i])) {
					diff.data ~= changedFile[i];
					if (diff.data.length == 0xFFFF)
						break;
					if (i >= changedFile.length-1)
						break;
					i++;
				}
				diffs ~= diff;
			}
		}
	}
	@property ubyte[] patchData() @safe pure {
		ubyte[] output = "PATCH".representation.dup;
		foreach (diff; diffs) {
			bool rle;
			if (diff.data.length > 3) {
				rle = true;
				foreach (datum; diff.data)
					if (datum != diff.data[0]) {
						rle = false;
						break;
					}
			}
			if (!rle) {
				output ~= [cast(ubyte)(diff.offset>>16), cast(ubyte)(diff.offset>>8), cast(ubyte)diff.offset];
				output ~= [cast(ubyte)(diff.data.length>>8), cast(ubyte)diff.data.length];
				output ~= diff.data;
			} else {
				output ~= [cast(ubyte)(diff.offset>>16), cast(ubyte)(diff.offset>>8), cast(ubyte)diff.offset];
				output ~= [0, 0];
				output ~= [cast(ubyte)(diff.data.length>>8), cast(ubyte)diff.data.length];
				output ~= diff.data[0];
			}
		}
		output ~= "EOF".representation;
		if (truncatedLength > -1)
			output ~= [cast(ubyte)(truncatedLength>>16), cast(ubyte)(truncatedLength>>8), cast(ubyte)truncatedLength];
		return output;
	}
}
@safe pure unittest {
	assert(IPSPatch(cast(ubyte[])[1], cast(ubyte[])[0]).patchData == [0x50, 0x41, 0x54, 0x43, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x45, 0x4F, 0x46], "Mismatch in basic patch");
	assert(IPSPatch(cast(ubyte[])[1,0], cast(ubyte[])[0]).patchData == [0x50, 0x41, 0x54, 0x43, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x45, 0x4F, 0x46, 0x00, 0x00, 0x01], "Truncation error");
	assert(IPSPatch(cast(ubyte[])[1,1,1,1,1,1,1,1], cast(ubyte[])[0,0,0,0,0,0,0,0]).patchData == [0x50, 0x41, 0x54, 0x43, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x4F, 0x46], "RLE");

}
package class IPSException : Exception {
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure {
		super(msg);
	}
}
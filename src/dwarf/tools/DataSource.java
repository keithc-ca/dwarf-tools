package dwarf.tools;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Optional;
import java.util.function.LongFunction;

final class DataSource {

	static final Charset UTF8 = Charset.forName("UTF-8");

	private static long getU4(ByteBuffer data) {
		return data.getInt() & ((1L << 32) - 1);
	}

	private static long getU8(ByteBuffer data) {
		return data.getLong();
	}

	static long getUDATA(ByteBuffer data) {
		long result = 0;

		for (int shift = 0;; shift += 7) {
			byte digit = data.get();

			result |= ((long) (digit & 0x7F)) << shift;

			if (digit >= 0) {
				return result;
			}
		}
	}

	private final int addressSize;

	private final ByteBuffer buffer;

	private final int offsetSize;

	private final LongFunction<String> stringLookup;

	DataSource(ByteBuffer data) {
		this(data, 0, 0, offset -> "");
	}

	private DataSource(ByteBuffer data, int addressSize, int offsetSize, LongFunction<String> stringLookup) {
		super();
		this.addressSize = addressSize;
		this.buffer = data;
		this.offsetSize = offsetSize;
		this.stringLookup = stringLookup;
	}

	DataSource(DataSource data, int addressSize, int offsetSize, LongFunction<String> stringLookup) {
		this(data.buffer, addressSize, offsetSize, stringLookup);
	}

	long getAddress() {
		return getRef(addressSize);
	}

	void getBlock(byte[] block) {
		buffer.get(block);
	}

	long getOffset() {
		return getRef(offsetSize);
	}

	private long getRef(int refSize) {
		switch (refSize) {
		case 4:
			return getU4();
		case 8:
			return getU8();
		default:
			throw new IllegalStateException();
		}
	}

	long getSDATA() {
		long result = 0;

		for (int shift = 0;; shift += 7) {
			byte digit = buffer.get();

			result |= ((long) (digit & 0x7F)) << shift;

			if (digit >= 0) {
				if (shift < 64 && (digit & 0x40) != 0) {
					result |= -(1L << shift);
				}

				return result;
			}
		}
	}

	String getString() {
		ByteArrayOutputStream content = new ByteArrayOutputStream();

		while (hasRemaining()) {
			byte ch = (byte) getU1();

			if (ch == 0) {
				break;
			}

			content.write(ch);
		}

		return new String(content.toByteArray(), DataSource.UTF8);
	}

	int getU1() {
		return buffer.get() & 0xFF;
	}

	int getU2() {
		return buffer.getShort() & 0xFFFF;
	}

	int getU3() {
		int result = getU2();

		if (buffer.order() == ByteOrder.LITTLE_ENDIAN) {
			result += getU1() << 16;
		} else {
			result <<= 8;
			result += getU1();
		}

		return result;
	}

	long getU4() {
		return getU4(buffer);
	}

	long getU8() {
		return getU8(buffer);
	}

	long getUDATA() {
		return getUDATA(buffer);
	}

	boolean hasRemaining() {
		return buffer.hasRemaining();
	}

	DataSource limit(long offset) {
		if (buffer.position() <= offset && offset <= buffer.limit()) {
			buffer.limit((int) offset);
			return this;
		} else {
			throw new IllegalArgumentException("limit=" + offset);
		}
	}

	String lookupString(long offset) {
		return Optional.ofNullable(stringLookup.apply(offset)).orElse("");
	}

	long position() {
		return buffer.position();
	}

	DataSource position(long offset) {
		if (0 <= offset && offset <= buffer.limit()) {
			buffer.position((int) offset);
			return this;
		}

		throw new IllegalArgumentException("position=" + offset);
	}

	DataSource duplicate() {
		return new DataSource(buffer.duplicate().order(buffer.order()), addressSize, offsetSize, stringLookup);
	}

}
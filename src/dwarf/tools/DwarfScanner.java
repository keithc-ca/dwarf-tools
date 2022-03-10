/*******************************************************************************
 * Copyright (c) 2017, 2022 IBM Corp. and others
 *
 * This program and the accompanying materials are made available under
 * the terms of the Eclipse Public License 2.0 which accompanies this
 * distribution and is available at http://eclipse.org/legal/epl-2.0
 * or the Apache License, Version 2.0 which accompanies this distribution
 * and is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * This Source Code may also be made available under the following Secondary
 * Licenses when the conditions for such availability set forth in the
 * Eclipse Public License, v. 2.0 are satisfied: GNU General Public License,
 * version 2 with the GNU Classpath Exception [1] and GNU General Public
 * License, version 2 with the OpenJDK Assembly Exception [2].
 *
 * [1] https://www.gnu.org/software/classpath/license.html
 * [2] http://openjdk.java.net/legal/assembly-exception.html
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0 OR GPL-2.0 WITH Classpath-exception-2.0 OR LicenseRef-GPL-2.0 WITH Assembly-exception
 *******************************************************************************/
package dwarf.tools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.function.Function;
import java.util.function.LongFunction;

@SuppressWarnings("boxing")
public class DwarfScanner {

	private static final class Abbreviation {

		private static Abbreviation find(Abbreviation[] abbreviations, long code) {
			Abbreviation abbreviation = null;
			int lo = 0;
			int hi = abbreviations.length;
			int mid;

			if (lo < code && code <= hi) {
				// if codes are contiguous starting at 1,
				// we'll find it on the first test
				mid = (int) code - 1;
			} else {
				mid = hi / 2;
			}

			// do a binary search
			for (; lo < hi; mid = (lo + hi) >>> 1) {
				abbreviation = abbreviations[mid];

				if (code == abbreviation.code) {
					return abbreviation;
				} else if (code > abbreviation.code) {
					lo = mid + 1;
				} else {
					hi = mid;
				}
			}

			return null;
		}

		static LongFunction<Abbreviation> readFrom(DataSource data) {
			List<Abbreviation> abbreviations = new ArrayList<>();

			while (data.hasRemaining()) {
				long code = data.getUDATA();

				if (code == 0) {
					break;
				}

				long tag = data.getUDATA();
				boolean hasChildren = data.getU1() != 0;
				List<AttributeReader> attributes = new ArrayList<>();

				// attributes
				for (;;) {
					long name = data.getUDATA();
					long form = data.getUDATA();

					if (name == 0 || form == 0) {
						break;
					}

					if ((0 < name && name <= Integer.MAX_VALUE) && (0 < form && form <= Integer.MAX_VALUE)) {
						attributes.add(AttributeReader.create((int) name, (int) form, data));
					} else {
						throw new IllegalArgumentException("attribute=" + name + " form=" + form);
					}
				}

				abbreviations.add(new Abbreviation(code, tag, hasChildren, attributes));
			}

			Abbreviation[] list = abbreviations.toArray(new Abbreviation[abbreviations.size()]);

			Arrays.sort(list, Comparator.comparingLong(abbreviation -> abbreviation.code));

			return code -> find(list, code);
		}

		private final AttributeReader[] attributes;

		private final long code;

		final boolean hasChildren;

		final int tag;

		private Abbreviation(long code, long tag, boolean hasChildren, List<AttributeReader> attributes) {
			super();
			this.attributes = attributes.toArray(new AttributeReader[attributes.size()]);
			this.code = code;
			this.hasChildren = hasChildren;
			this.tag = (int) tag;
		}

		void readAttributes(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
			for (AttributeReader attribute : attributes) {
				attribute.read(requestor, data, addresses);
			}
		}

		@Override
		public String toString() {
			return "abbrev(" + code + ") tag=" + tag;
		}

	}

	private static final class AddressTable {

		private int addressBase;

		private final int addressSize;

		private final DataSource data;

		private final int segmentSelectorSize;

		AddressTable(DataSource data) {
			super();
			if (data.hasRemaining()) {
				long unitLength = data.getU4();

				if (unitLength == 0 || unitLength == 0xFFFFFFFFL) {
					unitLength = data.getU8();
				}

				int version = data.getU2();

				if (version != 5) {
					throw new IllegalArgumentException();
				}

				this.addressBase = 0;
				this.addressSize = data.getU1();
				this.data = data;
				this.segmentSelectorSize = data.getU1();
			} else {
				this.addressBase = 0;
				this.addressSize = 0;
				this.data = data;
				this.segmentSelectorSize = 0;
			}
		}

		long getAddress(int index) {
			if (addressBase == 0) {
				throw new IllegalStateException();
			}

			data.position(addressBase + ((addressSize + segmentSelectorSize) * (long) index));
			if (addressSize == 4) {
				return data.getU4();
			} else {
				return data.getU8();
			}
		}

		void setAddressBase(int base) {
			addressBase = base;
		}

	}

	private abstract static class AttributeReader {

		private static final class Address extends AttributeReader {

			Address(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long address = data.getAddress();

				requestor.acceptAddress(attribute, form, address);
			}

		}

		private static final class Block extends AttributeReader {

			Block(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			final void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long length;

				switch (form) {
				case DwarfForm.DW_FORM_block:
					length = data.getUDATA();
					break;
				case DwarfForm.DW_FORM_block1:
					length = data.getU1();
					break;
				case DwarfForm.DW_FORM_block2:
					length = data.getU2();
					break;
				case DwarfForm.DW_FORM_block4:
					length = data.getU4();
					break;
				default:
					throw unexpectedForm();
				}

				byte[] block = new byte[checkUInt(length)];

				data.getBlock(block);

				requestor.acceptBlock(attribute, form, block);
			}

		}

		private static final class Constant extends AttributeReader {

			Constant(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long value;

				switch (form) {
				case DwarfForm.DW_FORM_data1:
					value = data.getU1();
					break;
				case DwarfForm.DW_FORM_data2:
					value = data.getU2();
					break;
				case DwarfForm.DW_FORM_data4:
					value = data.getU4();
					break;
				case DwarfForm.DW_FORM_data8:
					value = data.getU8();
					break;
				case DwarfForm.DW_FORM_sdata:
					value = data.getSDATA();
					break;
				case DwarfForm.DW_FORM_udata:
					value = data.getUDATA();
					break;
				default:
					throw unexpectedForm();
				}

				requestor.acceptConstant(attribute, form, value);
			}

		}

		private static final class Expression extends AttributeReader {

			Expression(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			final void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long length;

				switch (form) {
				case DwarfForm.DW_FORM_exprloc:
					length = data.getUDATA();
					break;
				default:
					throw unexpectedForm();
				}

				byte[] expression = new byte[checkUInt(length)];

				data.getBlock(expression);

				requestor.acceptExpression(attribute, form, expression);
			}

		}

		private static final class Flag extends AttributeReader {

			Flag(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				boolean flag;

				switch (form) {
				case DwarfForm.DW_FORM_flag:
					flag = data.getU1() != 0;
					break;
				case DwarfForm.DW_FORM_flag_present:
					flag = true;
					break;
				default:
					throw unexpectedForm();
				}

				requestor.acceptFlag(attribute, form, flag);
			}

		}

		private static final class ImplicitConstant extends AttributeReader {

			private final long value;

			ImplicitConstant(int attribute, int form, DataSource data) {
				super(attribute, form);
				this.value = data.getSDATA();
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				requestor.acceptConstant(attribute, form, value);
			}

		}

		private static final class IndexedAddress extends AttributeReader {

			IndexedAddress(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long index;

				switch (form) {
				case DwarfForm.DW_FORM_addrx:
					index = data.getUDATA();
					break;
				case DwarfForm.DW_FORM_addrx1:
					index = data.getU1();
					break;
				case DwarfForm.DW_FORM_addrx2:
					index = data.getU2();
					break;
				case DwarfForm.DW_FORM_addrx3:
					index = data.getU3();
					break;
				case DwarfForm.DW_FORM_addrx4:
					index = data.getU4();
					break;
				default:
					throw unexpectedForm();
				}

				if (index >= 0) {
					throw new IllegalArgumentException("attribute=" + attribute + " form=" + form);
				}

				long address = addresses.getAddress(checkUInt(index));

				requestor.acceptAddress(attribute, form, address);
			}

		}

		private static final class Indirect extends AttributeReader {

			Indirect(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				int actualForm = checkUInt(data.getUDATA());
				AttributeReader actualReader = create(attribute, actualForm, data);

				actualReader.read(requestor, data, addresses);
			}

		}

		private static final class Reference extends AttributeReader {

			Reference(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				long offset;

				switch (form) {
				case DwarfForm.DW_FORM_ref1:
					offset = data.getU1();
					break;
				case DwarfForm.DW_FORM_ref2:
					offset = data.getU2();
					break;
				case DwarfForm.DW_FORM_ref4:
					offset = data.getU4();
					break;
				case DwarfForm.DW_FORM_ref8:
				case DwarfForm.DW_FORM_ref_sig8:
					offset = data.getU8();
					break;
				case DwarfForm.DW_FORM_ref_udata:
					offset = data.getUDATA();
					break;
				case DwarfForm.DW_FORM_ref_addr:
					offset = data.getAddress();
					break;
				case DwarfForm.DW_FORM_sec_offset:
					offset = data.getOffset();
					break;
				default:
					throw unexpectedForm();
				}

				requestor.acceptReference(attribute, form, offset);
			}

		}

		private static final class Str extends AttributeReader {

			Str(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				String string;

				switch (form) {
				case DwarfForm.DW_FORM_string:
					string = data.getString();
					break;
				case DwarfForm.DW_FORM_strp:
					long position = data.position();
					long offset = data.getOffset();

					try {
						string = data.lookupString(offset);

						// FIXME remove this
						if (string.endsWith("checkcast.cpp")) {
							offset += 0;
						}
					} catch (RuntimeException e) {
						// FIXME remove this
						string = String.format("0x%x -> 0x%x", position, offset);
						System.out.format("DW_FORM_strp %s%n", string);
					}
					break;
				default:
					throw unexpectedForm();
				}

				requestor.acceptString(attribute, form, string);
			}

		}

		/**
		 * This class allows us to parse abbreviations using unknown forms.
		 * If the abbreviation is unused this poses no problem.
		 * If it is used, we won't know how to handle the data associated
		 * with the attribute and instead throw an exception.
		 */
		private static final class Unknown extends AttributeReader {

			Unknown(int attribute, int form) {
				super(attribute, form);
			}

			@Override
			void read(DwarfRequestor requestor, DataSource data, AddressTable addresses) {
				throw new IllegalArgumentException("attribute=" + attribute + " form=" + form);
			}

		}

		static AttributeReader create(int attribute, int form, DataSource data) {
			switch (form) {
			case DwarfForm.DW_FORM_addr:
				return new Address(attribute, form);

			case DwarfForm.DW_FORM_block:
			case DwarfForm.DW_FORM_block1:
			case DwarfForm.DW_FORM_block2:
			case DwarfForm.DW_FORM_block4:
				return new Block(attribute, form);

			case DwarfForm.DW_FORM_flag:
			case DwarfForm.DW_FORM_flag_present:
				return new Flag(attribute, form);

			case DwarfForm.DW_FORM_data1:
			case DwarfForm.DW_FORM_data2:
			case DwarfForm.DW_FORM_data4:
			case DwarfForm.DW_FORM_data8:
			case DwarfForm.DW_FORM_sdata:
			case DwarfForm.DW_FORM_udata:
				return new Constant(attribute, form);

			case DwarfForm.DW_FORM_exprloc:
				return new Expression(attribute, form);

			case DwarfForm.DW_FORM_implicit_const:
				return new ImplicitConstant(attribute, form, data);

			case DwarfForm.DW_FORM_indirect:
				return new Indirect(attribute, form);

			case DwarfForm.DW_FORM_string:
			case DwarfForm.DW_FORM_strp:
				return new Str(attribute, form);

			case DwarfForm.DW_FORM_ref1:
			case DwarfForm.DW_FORM_ref2:
			case DwarfForm.DW_FORM_ref4:
			case DwarfForm.DW_FORM_ref8:
			case DwarfForm.DW_FORM_ref_addr:
			case DwarfForm.DW_FORM_ref_sig8:
			case DwarfForm.DW_FORM_ref_udata:
			case DwarfForm.DW_FORM_sec_offset:
				return new Reference(attribute, form);

			/*
			 * An indirect index into a table of addresses (as described in the
			 * The index is relative to the value of the DW_AT_addr_base attribute of the associated compilation unit.
			 */
			case DwarfForm.DW_FORM_addrx:
			case DwarfForm.DW_FORM_addrx1:
			case DwarfForm.DW_FORM_addrx2:
			case DwarfForm.DW_FORM_addrx3:
			case DwarfForm.DW_FORM_addrx4:
				return new IndexedAddress(attribute, form);

			case DwarfForm.DW_FORM_strx:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_ref_sup4:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_strp_sup:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_data16:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_line_strp:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_loclistx:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_rnglistx:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_ref_sup8:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_strx1:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_strx2:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_strx3:
				return new Unknown(attribute, form); // TODO
			case DwarfForm.DW_FORM_strx4:
				return new Unknown(attribute, form); // TODO

			default:
				return new Unknown(attribute, form);
			}
		}

		final int attribute;

		final int form;

		AttributeReader(int attribute, int form) {
			super();
			this.attribute = attribute;
			this.form = form;
		}

		abstract void read(DwarfRequestor requestor, DataSource data, AddressTable addresses);

		final IllegalStateException unexpectedForm() {
			return new IllegalStateException("form=" + form);
		}

	}

	private static abstract class DwarfContainer {

		ByteBuffer abbrev;
		ByteBuffer addr;
		ByteBuffer info;
		ByteBuffer strings;

		DwarfContainer() {
			super();

			ByteBuffer empty = ByteBuffer.allocate(0);

			this.abbrev = empty;
			this.addr = empty;
			this.info = empty;
			this.strings = empty;
		}

	}

	private static final class ELF extends DwarfContainer {

		private static String getName(ByteBuffer nameData, int sh_name) {
			if (0 <= sh_name && sh_name < nameData.limit()) {
				StringBuilder buffer = new StringBuilder();

				for (int index = sh_name; index < nameData.limit(); ++index) {
					byte ch = nameData.get(index);

					if (ch == 0) {
						break;
					}

					buffer.append((char) (ch & 0xFF));
				}

				return buffer.toString();
			} else {
				return "";
			}
		}

		static boolean isELF(FileChannel channel) throws IOException {
			ByteBuffer buffer = channel.map(MapMode.READ_ONLY, 0, 4);

			// check the magic number (0x7F,E,L,F)
			int magic = 0;

			magic |= (buffer.get(0) & 0xFF) << 24;
			magic |= (buffer.get(1) & 0xFF) << 16;
			magic |= (buffer.get(2) & 0xFF) << 8;
			magic |= (buffer.get(3) & 0xFF);

			return magic == 0x7F454C46;
		}

		ELF(FileChannel channel) throws IOException {
			super();

			ByteBuffer buffer = channel.map(MapMode.READ_ONLY, 0, 64);
			boolean format32;

			switch (buffer.get(4)) {
			case 1:
				format32 = true;
				break;
			case 2:
				format32 = false;
				break;
			default:
				throw new IOException("Bad format class");
			}

			ByteOrder order;

			switch (buffer.get(5)) {
			case 1:
				order = ByteOrder.LITTLE_ENDIAN;
				break;
			case 2:
				order = ByteOrder.BIG_ENDIAN;
				break;
			default:
				throw new IOException("Bad endian flag");
			}

			buffer.order(order);

			long e_shoff;
			int e_shentsize;
			int e_shnum;
			int e_shstrndx;

			if (format32) {
				e_shoff = buffer.getInt(0x20);
				e_shentsize = buffer.getShort(0x2E);
				e_shnum = buffer.getShort(0x30);
				e_shstrndx = buffer.getShort(0x32);
			} else {
				e_shoff = buffer.getLong(0x28);
				e_shentsize = buffer.getShort(0x3A);
				e_shnum = buffer.getShort(0x3C);
				e_shstrndx = buffer.getShort(0x3E);
			}

			ByteBuffer sectDescs = channel.map(MapMode.READ_ONLY, e_shoff, e_shnum * (long) e_shentsize).order(order);
			ByteBuffer sectNames;

			{
				int sectStart = e_shstrndx * e_shentsize;
				long sectOffset;
				long sectSize;

				if (format32) {
					sectOffset = sectDescs.getInt(sectStart + 0x10);
					sectSize = sectDescs.getInt(sectStart + 0x14);
				} else {
					sectOffset = sectDescs.getLong(sectStart + 0x18);
					sectSize = sectDescs.getLong(sectStart + 0x20);
				}

				sectNames = channel.map(MapMode.READ_ONLY, sectOffset, sectSize);
			}

			for (int section = 0, sectStart = 0; section < e_shnum; section += 1, sectStart += e_shentsize) {
				int nameIndex = sectDescs.getInt(sectStart + 0x0);
				String name = getName(sectNames, nameIndex);
				ByteBuffer sectData;

				switch (name) {
				case ".debug_abbrev":
				case ".debug_addr":
				case ".debug_info":
				case ".debug_str":
					long sectOffset;
					long sectSize;

					if (format32) {
						sectOffset = sectDescs.getInt(sectStart + 0x10);
						sectSize = sectDescs.getInt(sectStart + 0x14);
					} else {
						sectOffset = sectDescs.getLong(sectStart + 0x18);
						sectSize = sectDescs.getLong(sectStart + 0x20);
					}

					sectData = channel.map(MapMode.READ_ONLY, sectOffset, sectSize).order(order);
					break;
				default:
					continue;
				}

				switch (name) {
				case ".debug_abbrev":
					this.abbrev = sectData;
					break;
				case ".debug_addr":
					this.addr = sectData;
					break;
				case ".debug_info":
					this.info = sectData;
					break;
				case ".debug_str":
					this.strings = sectData;
					break;
				default:
					break;
				}
			}
		}

	}

	private static final class MachO extends DwarfContainer {

		static final int Magic64 = 0xFEEDFACF;

		static final int Magic64Reversed = 0xCFFAEDFE;

		// struct section_64
		// {
		//  0  char sectname[16];
		// 16  char segname[16];
		// 32  uint64_t addr;
		// 40  uint64_t size;
		// 48  uint32_t offset;
		// 52  uint32_t align;
		// 56  uint32_t reloff;
		// 60  uint32_t nreloc;
		// 64  uint32_t flags;
		// 68  uint32_t reserved1;
		// 72  uint32_t reserved2;
		// 76  uint32_t reserved2;
		// };
		static final int Section64Size = 80;

		static final int Segment64Command = 0x19;

		// struct segment_command_64
		// {
		//  0  uint32_t cmd;
		//  4  uint32_t cmdsize;
		//  8  char segname[16];
		// 24  uint64_t vmaddr;
		// 32  uint64_t vmsize;
		// 40  uint64_t fileoff;
		// 48  uint64_t filesize;
		// 56  vm_prot_t maxprot;
		// 60  vm_prot_t initprot;
		// 64  uint32_t nsects;
		// 68  uint32_t flags;
		// };
		static final int Segment64Size = 72;

		private static int getMagic(ByteBuffer buffer) {
			int magic = 0;

			magic |= (buffer.get(0) & 0xFF);
			magic |= (buffer.get(1) & 0xFF) << 8;
			magic |= (buffer.get(2) & 0xFF) << 16;
			magic |= (buffer.get(3) & 0xFF) << 24;

			return magic;
		}

		static boolean isMachO(FileChannel channel) throws IOException {
			int magic = getMagic(channel.map(MapMode.READ_ONLY, 0, 4));

			return (magic == Magic64) || (magic == Magic64Reversed);
		}

		private static String toCString(byte[] data) {
			StringBuilder buffer = new StringBuilder();

			for (int index = 0; index < data.length; ++index) {
				byte ch = data[index];

				if (ch == 0) {
					break;
				}

				buffer.append((char) (ch & 0xFF));
			}

			return buffer.toString();
		}

		MachO(FileChannel channel) throws IOException {
			ByteBuffer buffer = channel.map(MapMode.READ_ONLY, 0, 64);
			int magic = getMagic(buffer);
			ByteOrder order;

			if (magic == Magic64) {
				order = ByteOrder.LITTLE_ENDIAN;
			} else if (magic == Magic64Reversed) {
				order = ByteOrder.BIG_ENDIAN;
			} else {
				throw new IllegalStateException();
			}

			buffer.order(order);

			int numCmds = checkUInt(buffer.getInt(16));
			int sizeCmds = checkUInt(buffer.getInt(20));
			ByteBuffer cmdBuffer = channel.map(MapMode.READ_ONLY, 32, sizeCmds).order(order);
			byte[] nameBuffer = new byte[16];
			int cmdIndex;
			int cmdOffset;
			int cmdSize;

			for (cmdIndex = 0, cmdOffset = 0; cmdIndex < numCmds; cmdIndex += 1, cmdOffset += cmdSize) {
				int cmd = cmdBuffer.getInt(cmdOffset);

				cmdSize = cmdBuffer.getInt(cmdOffset + 4);

				if (cmd != Segment64Command) {
					continue;
				}

				int numSections = checkUInt(cmdBuffer.getInt(cmdOffset + 64));
				int sectionIndex;
				int sectionOffset = cmdOffset + Segment64Size;

				for (sectionIndex = 0; sectionIndex < numSections; sectionIndex += 1, sectionOffset += Section64Size) {
					cmdBuffer.position(sectionOffset);
					cmdBuffer.get(nameBuffer);

					String sectionName = toCString(nameBuffer);
					ByteBuffer sectData;

					switch (sectionName) {
					case "__debug_abbrev":
					case "__debug_addr":
					case "__debug_info":
					case "__debug_str":
						long sectOffset = cmdBuffer.getLong(sectionOffset + 48);
						long sectSize = cmdBuffer.getLong(sectionOffset + 40);

						System.out.format("@ 0x%012x len 0x%08x %s%n", sectOffset, sectSize, sectionName);

						sectData = channel.map(MapMode.READ_ONLY, sectOffset, sectSize).order(order);
						break;
					default:
						continue;
					}

					switch (sectionName) {
					case "__debug_abbrev":
						this.abbrev = sectData;
						break;
					case "__debug_addr":
						this.addr = sectData;
						break;
					case "__debug_info":
						this.info = sectData;
						break;
					case "__debug_str":
						this.strings = sectData;
						break;
					default:
						break;
					}
				}
			}
		}

	}

	/*
	 * https://www.ibm.com/docs/en/aix/7.2?topic=formats-xcoff-object-file-format
	 */
	private static final class XCOFF extends DwarfContainer {

		private static final int FileHeaderSize = 24;

		private static final int SectionHeaderSize = 72;

		private static int getMagic(ByteBuffer buffer) {
			int magic = 0;

			magic |= (buffer.get(0) & 0xFF) << 8;
			magic |= (buffer.get(1) & 0xFF);

			return magic;
		}

		static boolean isXCOFF(FileChannel channel) throws IOException {
			int magic = getMagic(channel.map(MapMode.READ_ONLY, 0, 2));

			return magic == 0x01f7;
		}

		private static String toCString(byte[] data) {
			StringBuilder buffer = new StringBuilder();

			for (int index = 0; index < data.length; ++index) {
				byte ch = data[index];

				if (ch == 0) {
					break;
				}

				buffer.append((char) (ch & 0xFF));
			}

			return buffer.toString();
		}

		XCOFF(FileChannel channel) throws IOException {
			super();

			// XCOFF is used only on AIX and z/OS which are both big-endian platforms.
			ByteOrder order = ByteOrder.BIG_ENDIAN;
			ByteBuffer buffer = channel.map(MapMode.READ_ONLY, 0, 20).order(order);

			int nscns = buffer.getShort(2) & 0xFFFF;
			int firstSectionOffset = FileHeaderSize + (buffer.getShort(16) & 0xFFFF);

			ByteBuffer sectDescs = channel.map(MapMode.READ_ONLY, //
					firstSectionOffset, nscns * (long) SectionHeaderSize).order(order);
			byte[] nameBuffer = new byte[16];

			for (int sectionNo = 0; sectionNo < nscns; ++sectionNo) {
				int sectionOffset = sectionNo * SectionHeaderSize;

				sectDescs.position(sectionOffset);
				sectDescs.get(nameBuffer);

				String sectionName = toCString(nameBuffer);
				ByteBuffer sectData;

				switch (sectionName) {
				case ".debug": // stabs, not DWARF
					long sectSize = sectDescs.getLong(sectionOffset + 24);
					long sectOffset = sectDescs.getLong(sectionOffset + 32);

					if (sectOffset == 0) {
						continue;
					}

					System.out.format("@ 0x%012x len 0x%08x %s%n", sectOffset, sectSize, sectionName);

					sectData = channel.map(MapMode.READ_ONLY, sectOffset, sectSize).order(order);
					break;
				default:
					continue;
				}

				// TODO scan STABS format, translate to DWARF concepts
			}
		}

	}

	public static final int VERSION_MAXIMUM = 5;

	public static final int VERSION_MINIMUM = 2;

	static int checkUInt(long value) {
		if (0 <= value && value <= Integer.MAX_VALUE) {
			return (int) value;
		}

		throw new IllegalArgumentException("Not U4: " + value);
	}

	private final DataSource abbrevSection;

	private final AddressTable addresses;

	private final DataSource infoSection;

	private final LongFunction<String> stringAccessor;

	public DwarfScanner(String fileName) throws IOException {
		super();

		DwarfContainer dwarf;

		try (FileChannel channel = FileChannel.open(Paths.get(fileName))) {
			if (ELF.isELF(channel)) {
				dwarf = new ELF(channel);
			} else if (MachO.isMachO(channel)) {
				dwarf = new MachO(channel);
			} else if (XCOFF.isXCOFF(channel)) {
				dwarf = new XCOFF(channel);
			} else {
				throw new IOException("Unrecognized file format");
			}
		}

		Map<Long, String> stringCache = new HashMap<>();
		DataSource stringData = new DataSource(dwarf.strings);
		Function<Long, String> stringReader = offset -> stringData.position(offset.longValue()).getString();

		this.abbrevSection = new DataSource(dwarf.abbrev);
		this.addresses = new AddressTable(new DataSource(dwarf.addr));
		this.infoSection = new DataSource(dwarf.info);
		this.stringAccessor = offset -> stringCache.computeIfAbsent(Long.valueOf(offset), stringReader);
	}

	private void scanTags(DwarfRequestor requestor, DataSource data, LongFunction<Abbreviation> abbreviations) {
		Stack<Abbreviation> tagStack = new Stack<>();

		while (data.hasRemaining()) {
			long tagOffset = data.position();
			long code = data.getUDATA();

			if (code != 0) {
				Abbreviation entry = abbreviations.apply(code);

				if (entry != null) {
					if ((entry.tag == DwarfAttribute.DW_AT_addr_base) && tagStack.isEmpty()) {
						// TODO remember offset
						addresses.setAddressBase(0);
					} else {
						requestor.beginTag(entry.tag, tagOffset, entry.hasChildren);

						entry.readAttributes(requestor, data, addresses);

						if (entry.hasChildren) {
							tagStack.push(entry);
						} else {
							requestor.endTag(entry.tag, entry.hasChildren);
						}
					}
				}
			} else {
				if (!tagStack.isEmpty()) {
					Abbreviation entry = tagStack.pop();

					requestor.endTag(entry.tag, entry.hasChildren);
				}
			}
		}

		while (!tagStack.isEmpty()) {
			Abbreviation entry = tagStack.pop();

			requestor.endTag(entry.tag, entry.hasChildren);
		}
	}

	public void scanUnits(DwarfRequestor requestor) {
		DataSource data = infoSection.duplicate();

		while (data.hasRemaining()) {
			DataSource unit = data.duplicate();
			long unitOffset = unit.position();
			long unitLength = unit.getU4();
			int offsetSize = 4;
			long abbrevOffset;

			if (unitLength == 0 || unitLength == 0xFFFFFFFFL) {
				unitLength = unit.getU8();
				offsetSize = 8;
			}

			long nextUnit = unit.position() + unitLength;

			unit.limit(nextUnit);
			data.position(nextUnit);

			int version = unit.getU2();

			if (version < VERSION_MINIMUM || version > VERSION_MAXIMUM) {
				throw new IllegalArgumentException("version=" + version);
			}

			int unitType;
			int addressSize;

			/*
			 * in version 5
			 * + the unitType field is added
			 * + the addressSize and abbrevOffset fields are reversed
			 */
			if (version < 5) {
				unitType = DwarfUnit.DW_UT_compile;
				abbrevOffset = (offsetSize == 8) ? unit.getU8() : unit.getU4();
				addressSize = unit.getU1();
			} else {
				unitType = unit.getU1();
				addressSize = unit.getU1();
				abbrevOffset = (offsetSize == 8) ? unit.getU8() : unit.getU4();
			}

			requestor.enterCompilationUnit(unitOffset, unitType);

			DataSource abbrevs = abbrevSection.position(abbrevOffset);
			LongFunction<Abbreviation> abbreviations = Abbreviation.readFrom(abbrevs);
			DataSource source = new DataSource(unit, addressSize, offsetSize, stringAccessor);

			scanTags(requestor, source, abbreviations);

			requestor.exitCompilationUnit(unitOffset, unitType);
		}
	}

}

/*******************************************************************************
 * Copyright (c) 2022, 2022 IBM Corp. and others
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

/**
 * Dwarf unit types.
 *
 * Source: http://www.dwarfstd.org/doc/DWARF5.pdf
 */
public interface DwarfUnit {

	int DW_UT_compile = 0x01;
	int DW_UT_type = 0x02;
	int DW_UT_partial = 0x03;
	int DW_UT_skeleton = 0x04;
	int DW_UT_split_compile = 0x05;
	int DW_UT_split_type = 0x06;

	int DW_UT_lo_user = 0x80;
	int DW_UT_hi_user = 0xFF;

}

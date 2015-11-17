/*
 * Copyright (c) 2015, the IRMA Team
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the IRMA project nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.irmacard.idemix.util;

import java.io.Serializable;

import net.sf.scuba.util.Hex;

public class CardVersion implements Comparable<CardVersion>, Serializable {

	private static final long serialVersionUID = 3887160109187109660L;

	public enum Type { BUILD, DEBUG, REV, ALPHA, BETA, CANDIDATE, RELEASE };

	private int major = 0;
	private int minor = 0;
	private Integer maint = null;
	private Integer build = null;

	private String extra = null;
	private Integer count = null;
	private byte[] data = null;


	/**
	 * Constructor which gets all elements as separate variables.
	 *
	 * @param majresponse
	 * @param min
	 * @param mnt
	 * @param bld
	 * @param ext
	 * @param cnt
	 */
	public CardVersion(int maj, int min, Integer mnt, Integer bld, String ext, Integer cnt) {
		major = maj;
		minor = min;
		maint = mnt;
		build = bld;
		extra = ext;
		count = cnt;
	}

	/**
	 * Constructor which gets all elements as an ASN.1 encoded bytearray.
	 *
	 * @param version
	 */
	public CardVersion(byte[] version) {
		// 0.6.1 or older had no versioning
		if (version == null || version.length == 0) {
            major = 0;
            minor = 6;
            maint = 1;
            extra = "or older";

        // 0.6.2 - 0.7.2
        } else if (version.length == 4) {
            major = version[1];
            minor = version[2];
            maint = (int) version[3];

        // 0.8 and newer
        } else {
			int i = 6;

			// Major
			major = version[i++];

			// Minor
			if (i < version.length && version[i] == 0x02) {
				i += 2;
				minor = version[i++];
			}

			// Maintenance
			if (i < version.length && version[i] == 0x02) {
				i += 2;
				maint = (int) version[i++];
			}

			// Build
			if (i < version.length && version[i] == 0x02) {
				i += 2;
				build = (int) version[i++];
			}

			// Extra
			if (i < version.length && version[i++] == 0x10) {
				i += 2;
				int length = version[i++];
				byte[] str = new byte[length];
				System.arraycopy(version, i, str, 0, length);
				try {
					extra = new String(str, "UTF-8");
				} catch (java.io.UnsupportedEncodingException e) {
					System.err.println(e.getMessage());
					System.err.println("Apparently UTF-8 is not supported, trying system default charset.");
					extra = new String(str);
				}
				i += length;

				// Counter
				if (i < version.length && version[i] == 0x02) {
					i += 2;
					count = (int) version[i++];
				}

				// Extra data
				if (i < version.length && version[i] == 0x04) {
					length = version[i++];
					data = new byte[length];
					System.arraycopy(version, i, data, 0, length);
				}
			}
        }
	}

	// Convenience constructors
	public CardVersion(int maj, int min) {
		this(maj, min, null, null, null, null);
	}
	public CardVersion(int maj, int min, Integer mnt) {
		this(maj, min, mnt, null, null, null);
	}
	public CardVersion(int maj, int min, Integer mnt, Integer bld) {
		this(maj, min, mnt, bld, null, null);
	}
	public CardVersion(int maj, int min, String ext) {
		this(maj, min, null, null, ext, null);
	}
	public CardVersion(int maj, int min, String ext, Integer cnt) {
		this(maj, min, null, null, ext, cnt);
	}
	public CardVersion(int maj, int min, Integer mnt, String ext) {
		this(maj, min, mnt, null, ext, null);
	}
	public CardVersion(int maj, int min, Integer mnt, String ext, Integer cnt) {
		this(maj, min, mnt, null, ext, cnt);
	}
	public CardVersion(int maj, int min, Integer mnt, Integer bld, String ext) {
		this(maj, min, mnt, bld, ext, null);
	}

	// Getters
	public int getMajor() {
		return major;
	}
	public int getMinor() {
		return minor;
	}
	public Integer getMaintenance() {
		return maint;
	}
	public Integer getBuild() {
		return build;
	}
	public Integer getCounter() {
		return count;
	}

	public String getExtra() {
		String version = extra;

		if (count != null) {
			version += count;
		}
		if (data != null && data.length > 0) {
			version += " " + Hex.toHexString(data);
		}

		return version;
	}

	public Type getType() {
		Type type = Type.RELEASE;

		if (extra != null) {
			if (extra.contains("build")) {
				type = Type.BUILD;
			}
			if (extra.contains("rev") || extra.contains("revision") || extra.contains("r")) {
				type = Type.REV;
			}
			if (extra.contains("alpha")) {
				type = Type.ALPHA;
			}
			if (extra.contains("beta")) {
				type = Type.BETA;
			}
			if (extra.contains("rc") || extra.contains("candidate")) {
				type = Type.CANDIDATE;
			}
			if (extra.contains("debug")) {
				type = Type.DEBUG;
			}
		}

		return type;
	}

	public int compareTo(CardVersion c) {
		int comp = major - c.major;
		if (comp != 0) return comp;

		comp = minor - c.minor;
		if (comp != 0) return comp;

		comp = compareInteger(maint, c.maint);
		if (comp != 0) return comp;

		comp = compareInteger(build, c.build);
		if (comp != 0) return comp;

		comp = getType().compareTo(c.getType());
		if (comp != 0) return comp;

		comp = compareInteger(count, c.count);
		if (comp != 0) return comp;

		return 0;
	}

	private int compareInteger(Integer a, Integer b) {
		if (a == null && b == null) {
			return 0;
		} else if (a == null && b != null) {
			return -1;
		} else 	if (a != null && b == null) {
			return 1;
		} else {
			return a.compareTo(b);
		}
	}

	public boolean newer(CardVersion c) {
		return compareTo(c) > 0;
	}

	public boolean older(CardVersion c) {
		return compareTo(c) < 0;
	}

	public String toString() {
		String version = major + "." + minor;

		if (maint != null) {
			version += "." + maint;
			if (build != null) {
				version += "." + build;
			}
		}

		if (extra != null) {
			version += " " + getExtra();
		}

		return version;
	}
}

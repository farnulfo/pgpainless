// SPDX-FileCopyrightText: 2020 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.key.generation.type.xdh;

import javax.annotation.Nonnull;

public enum XDHSpec {
    _X25519("X25519", "Curve25519", 256),
    ;

    final String name;
    final String curveName;
    final int bitStrength;

    XDHSpec(@Nonnull String name, @Nonnull String curveName, int bitStrength) {
        this.name = name;
        this.curveName = curveName;
        this.bitStrength = bitStrength;
    }

    public String getName() {
        return name;
    }

    public String getCurveName() {
        return curveName;
    }

    public int getBitStrength() {
        return bitStrength;
    }
}

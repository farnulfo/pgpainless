// SPDX-FileCopyrightText: 2023 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.wot.dijkstra.sq;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;

public final class RegexSet {

    private final Set<String> regexStrings;

    private RegexSet(Set<String> regexStrings) {
        this.regexStrings = regexStrings;
    }

    public static RegexSet fromExpressionList(@Nonnull List<String> regexList) {
        Set<String> regexStringSet = new HashSet<>(regexList);
        return new RegexSet(regexStringSet);
    }

    public static RegexSet fromExpression(@Nonnull String regex) {
        return fromExpressionList(Collections.singletonList(regex));
    }

    public static RegexSet wildcard() {
        return fromExpressionList(Collections.emptyList());
    }

    public boolean matches(String string) {
        if (regexStrings.isEmpty()) {
            return true;
        }

        for (String regex : regexStrings) {
            Matcher matcher = Pattern.compile(regex).matcher(string);
            if (matcher.matches()) {
                return true;
            }
        }

        return false;
    }
}

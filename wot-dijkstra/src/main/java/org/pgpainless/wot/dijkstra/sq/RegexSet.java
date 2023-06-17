package org.pgpainless.wot.dijkstra.sq;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;

import org.bouncycastle.bcpg.sig.RegularExpression;

public class RegexSet {

    private final Set<String> regexStrings;

    private RegexSet(Set<String> regexStrings) {
        this.regexStrings = regexStrings;
    }

    public static RegexSet fromList(@Nonnull List<RegularExpression> regexList) {
        Set<String> regexStringSet = new HashSet<>();
        for (RegularExpression regex : regexList) {
            regexStringSet.add(regex.getRegex());
        }
        return new RegexSet(regexStringSet);
    }

    public static RegexSet fromRegex(@Nonnull RegularExpression regex) {
        return fromList(Collections.singletonList(regex));
    }

    public static RegexSet wildcard() {
        return fromList(Collections.emptyList());
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

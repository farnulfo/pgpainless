// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.exception;

import org.pgpainless.decryption_verification.syntax_check.InputAlphabet;
import org.pgpainless.decryption_verification.syntax_check.StackAlphabet;
import org.pgpainless.decryption_verification.syntax_check.State;

/**
 * Exception that gets thrown if the OpenPGP message is malformed.
 * Malformed messages are messages which do not follow the grammar specified in the RFC.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4880#section-11.3">RFC4880 §11.3. OpenPGP Messages</a>
 */
public class MalformedOpenPgpMessageException extends RuntimeException {

    public MalformedOpenPgpMessageException(String message) {
        super(message);
    }

    public MalformedOpenPgpMessageException(State state, InputAlphabet input, StackAlphabet stackItem) {
        this("There is no legal transition from state '" + state + "' for input '" + input + "' when '" + stackItem + "' is on top of the stack.");
    }

    public MalformedOpenPgpMessageException(String s, MalformedOpenPgpMessageException e) {
        super(s, e);
    }
}

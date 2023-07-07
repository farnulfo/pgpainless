<!--
SPDX-FileCopyrightText: 2023 Paul Schaub <info@pgpainless.org>

SPDX-License-Identifier: Apache-2.0
-->

# Command Line Interface for the Web-of-Trust

This module contains a command line interface application that acts as a front-end for
[`pgpainless-wot`](../pgpainless-wot).
The interface of the application is modelled after the [sq-wot](https://gitlab.com/sequoia-pgp/sequoia-wot/)
reference implementation.

## Build

To build the application, navigate into this subdirectory and execute the following command:
```shell
../gradlew installDist
```

A ready-to-use distributable directory can then be found in `build/install/` with an executable in `build/install/pgpainless-wot-cli/bin/`.
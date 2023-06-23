<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->
# Test Vectors

## Freshly Generated Vectors

The `freshly_generated/` directory contains freshly generated test vectors.
Those are keys and certificates without any third-party signatures.

```mermaid
graph LR;
a[Foo Bank CA &ltca&#64foobank.com&gt];
b[Foo Bank Employee &ltemployee&#64foobank.com&gt];
c[Foo Bank Admin &ltadmin&#64foobank.com&gt];

d[Customer &ltcustomer&#64example.com&gt];
e[Bar Bank CA &ltca&#64barbank.com&gt];
f[Bar Bank Employee &ltemployee&#64barbank.com&gt];
g[Foo Bank Employee &#40Attacker&#41 &ltemployee&#64foobank.com&gt];
```

## Cross Signed Vectors
The `cross_signed/` directory contains test vectors that model the following interconnectivity:

```mermaid
graph TD;
a[Foo Bank CA &ltca&#64foobank.com&gt];
b[Foo Bank Employee &ltemployee&#64foobank.com&gt];
c[Foo Bank Admin &ltadmin&#64foobank.com&gt];

d[Customer &ltcustomer&#64example.com&gt];
e[Bar Bank CA &ltca&#64barbank.com&gt];
f[Bar Bank Employee &ltemployee&#64barbank.com&gt];
g[Foo Bank Employee &#40Attacker&#41 &ltemployee&#64foobank.com&gt];

a -- generic certification --> b & c;
b & c & d == 1:120:&quot&lt&#91^&gt&#93&#43&#91&#64.&#93foobank\.com>$&quot ==> a;
e -- generic certification --> f;
c == 1:120:&quot&lt&#91^&gt&#93&#43&#91&#64.&#93barbank\.com>$&quot ==> e;
```

## Useful Resources:
* https://mateam.net/html-escape-characters/
* https://docs.sequoia-pgp.org/sequoia_openpgp/regex/index.html#caveat-emptor
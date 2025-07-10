.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 1

.. _hashes:

Additional Hash algorithms
==========================

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.2 *Message digests*.
They are used with the hash functions and multi-part operations, or combined with composite algorithms that are parameterized by a hash algorithm.

SHA-256-based hash algorithms
-----------------------------

.. macro:: PSA_ALG_SHA_256_192
    :definition: ((psa_algorithm_t)0x0200000E)

    .. summary::
        The SHA-256/192 message digest algorithm.

        .. versionadded:: 1.3

    SHA-256/192 is the first 192 bits (24 bytes) of the SHA-256 output.
    SHA-256 is defined in :cite:`FIPS180-4`.


SHAKE-based hash algorithms
---------------------------

.. macro:: PSA_ALG_SHAKE128_256
    :definition: ((psa_algorithm_t)0x02000016)

    .. summary::
        The SHAKE128/256 message digest algorithm.

        .. versionadded:: 1.3

    SHAKE128/256 is the first 256 bits (32 bytes) of the SHAKE128 output.
    SHAKE128 is defined in :cite:`FIPS202`.

    This can be used as pre-hashing for SLH-DSA (see `PSA_ALG_HASH_SLH_DSA()`).

    .. note::
        For other scenarios where a hash function based on SHA3 or SHAKE is required, SHA3-256 is recommended. SHA3-256 has the same output size, and a theoretically higher security strength.

.. comment
    Update the description of PSA_ALG_SHAKE256_512 to state:

    This is the pre-hashing for Ed448ph (see `PSA_ALG_ED448PH`), and can be used as pre-hashing for SLH-DSA (see `PSA_ALG_HASH_SLH_DSA()`).

.. macro:: PSA_ALG_SHAKE256_192
    :definition: ((psa_algorithm_t)0x02000017)

    .. summary::
        The SHAKE256/192 message digest algorithm.

        .. versionadded:: 1.3

    SHAKE256/192 is the first 192 bits (24 bytes) of the SHAKE256 output.
    SHAKE256 is defined in :cite:`FIPS202`.

.. macro:: PSA_ALG_SHAKE256_256
    :definition: ((psa_algorithm_t)0x02000018)

    .. summary::
        The SHAKE256/256 message digest algorithm.

        .. versionadded:: 1.3

    SHAKE256/256 is the first 256 bits (32 bytes) of the SHAKE256 output.
    SHAKE256 is defined in :cite:`FIPS202`.

.. SPDX-FileCopyrightText: Copyright 2018-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _algorithms:

Algorithms
==========

This specification encodes algorithms into a structured 32-bit integer value.

Algorithm identifiers are used for two purposes in the |API|:

1.  To specify a specific algorithm to use in a cryptographic operation. These are all defined in :secref:`crypto-operations`.
#.  To specify the policy for a key, identifying the permitted algorithm for use with the key. This use is described in :secref:`key-policy`.

The specific algorithm identifiers are described alongside the cryptographic operation functions to which they apply:

*   :secref:`hash-algorithms`
*   :secref:`mac-algorithms`
*   :secref:`cipher-algorithms`
*   :secref:`aead-algorithms`
*   :secref:`key-derivation-algorithms`
*   :secref:`sign`
*   :secref:`asymmetric-encryption-algorithms`
*   :secref:`key-agreement-algorithms`
*   :secref:`key-encapsulation`
*   :secref:`pake`


Algorithm encoding
------------------

.. header:: psa/crypto
    :seq: 160

.. typedef:: uint32_t psa_algorithm_t

    .. summary::
        Encoding of a cryptographic algorithm.

    This is a structured bitfield that identifies the category and type of algorithm. The range of algorithm identifier values is divided as follows:

    :code:`0x00000000`
        Reserved as an invalid algorithm identifier.
    :code:`0x00000001 - 0x7fffffff`
        Specification-defined algorithm identifiers.
        Algorithm identifiers defined by this standard always have bit 31 clear.
        Unallocated algorithm identifier values in this range are reserved for future use.
    :code:`0x80000000 - 0xffffffff`
        Implementation-defined algorithm identifiers.
        Implementations that define additional algorithms must use an encoding with bit 31 set.
        The related support macros will be easier to write if these algorithm identifier encodings also respect the bitwise structure used by standard encodings.

    For algorithms that can be applied to multiple key types, this identifier does not encode the key type. For example, for symmetric ciphers based on a block cipher, `psa_algorithm_t` encodes the block cipher mode and the padding mode while the block cipher itself is encoded via `psa_key_type_t`.

    The :secref:`appendix-encodings` appendix provides a full definition of the algorithm identifier encoding.

.. header:: psa/crypto
    :seq: 200

.. macro:: PSA_ALG_NONE
    :definition: ((psa_algorithm_t)0)

    .. summary::
        An invalid algorithm identifier value.

    Zero is not the encoding of any algorithm.

Algorithm categories
--------------------

.. macro:: PSA_ALG_IS_HASH
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a hash algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a hash algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`hash-algorithms` for a list of defined hash algorithms.

.. macro:: PSA_ALG_IS_MAC
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a MAC algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a MAC algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`mac-algorithms` for a list of defined MAC algorithms.

.. macro:: PSA_ALG_IS_CIPHER
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a symmetric cipher algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a symmetric cipher algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`cipher-algorithms` for a list of defined cipher algorithms.

.. macro:: PSA_ALG_IS_AEAD
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an authenticated encryption with associated data (AEAD) algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an AEAD algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`aead-algorithms` for a list of defined AEAD algorithms.

.. macro:: PSA_ALG_IS_KEY_DERIVATION
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a key-derivation algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a key-derivation algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`key-derivation-algorithms` for a list of defined key-derivation algorithms.

.. macro:: PSA_ALG_IS_SIGN
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an asymmetric signature algorithm, also known as public-key signature algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an asymmetric signature algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`sign` for a list of defined signature algorithms.

.. macro:: PSA_ALG_IS_ASYMMETRIC_ENCRYPTION
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is an asymmetric encryption algorithm, also known as public-key encryption algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an asymmetric encryption algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`asymmetric-encryption-algorithms` for a list of defined asymmetric encryption algorithms.

.. macro:: PSA_ALG_IS_KEY_AGREEMENT
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a key-agreement algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a key-agreement algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`key-agreement-algorithms` for a list of defined key-agreement algorithms.

.. macro:: PSA_ALG_IS_PAKE
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a password-authenticated key exchange.

        .. versionadded:: 1.1

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a password-authenticated key exchange (PAKE) algorithm, ``0`` otherwise.
        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_KEY_ENCAPSULATION
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is a key-encapsulation algorithm.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a key-encapsulation algorithm, ``0`` otherwise. This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See :secref:`key-encapsulation` for a list of defined key-encapsulation algorithms.

Support macros
--------------

.. macro:: PSA_ALG_IS_WILDCARD
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm encoding is a wildcard.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a wildcard algorithm encoding.

        ``0`` if ``alg`` is a non-wildcard algorithm encoding that is suitable for an operation.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    Wildcard algorithm values can only be used to set the permitted-algorithm field in a key policy, wildcard values cannot be used to perform an operation.

    See `PSA_ALG_ANY_HASH` for example of how a wildcard algorithm can be used in a key policy.

.. macro:: PSA_ALG_GET_HASH
    :definition: /* specification-defined value */

    .. summary::
        Get the hash used by a composite algorithm.

    .. param:: alg
        An algorithm identifier: a value of type `psa_algorithm_t`.

    .. return::
        The underlying hash algorithm if ``alg`` is a composite algorithm that uses a hash algorithm.

        `PSA_ALG_NONE` if ``alg`` is not a composite algorithm that uses a hash.

    The following composite algorithms require a hash algorithm:

    *   `PSA_ALG_DETERMINISTIC_ECDSA()`
    *   `PSA_ALG_ECDSA()`
    *   `PSA_ALG_HKDF()`
    *   `PSA_ALG_HKDF_EXPAND()`
    *   `PSA_ALG_HKDF_EXTRACT()`
    *   `PSA_ALG_HMAC()`
    *   `PSA_ALG_JPAKE()`
    *   `PSA_ALG_PBKDF2_HMAC()`
    *   `PSA_ALG_RSA_OAEP()`
    *   `PSA_ALG_RSA_PKCS1V15_SIGN()`
    *   `PSA_ALG_RSA_PSS()`
    *   `PSA_ALG_RSA_PSS_ANY_SALT()`
    *   `PSA_ALG_SP800_108_COUNTER_HMAC()`
    *   `PSA_ALG_SPAKE2P_CMAC()`
    *   `PSA_ALG_SPAKE2P_HMAC()`
    *   `PSA_ALG_TLS12_PRF()`
    *   `PSA_ALG_TLS12_PSK_TO_MS()`

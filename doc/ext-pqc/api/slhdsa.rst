.. SPDX-FileCopyrightText: Copyright 2024 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 4

.. _slh-dsa:

Stateless Hash-based signatures
===============================

.. _slh-dsa-keys:

Stateless Hash-based signature keys
-----------------------------------

The |API| supports Stateless Hash-based digital signatures (SLH-DSA), as defined in :cite-title:`FIPS205`.

.. typedef:: uint8_t psa_slh_dsa_family_t

    .. summary::
        The type of identifiers of a Stateless hash-based DSA parameter set.

        .. versionadded:: 1.3

    The parameter-set identifier is required to create an SLH-DSA key using the `PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()` or `PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY()` macros.

    The specific SLH-DSA parameter set within a family is identified by the ``key_bits`` attribute of the key.

    The range of SLH-DSA family identifier values is divided as follows:

    :code:`0x00`
        Reserved.
        Not allocated to an SLH-DSA parameter-set family.
    :code:`0x01 - 0x7f`
        SLH-DSA parameter-set family identifiers defined by this standard.
        Unallocated values in this range are reserved for future use.
    :code:`0x80 - 0xff`
        Invalid.
        Values in this range must not be used.

    The least significant bit of an SLH-DSA family identifier is a parity bit for the whole key type.
    See :secref:`slh-dsa-key-encoding` for details of the encoding of asymmetric key types.

.. macro:: PSA_KEY_TYPE_SLH_DSA_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        SLH-DSA key pair: both the private key and public key.

        .. versionadded:: 1.3

    .. param:: set
        A value of type `psa_slh_dsa_family_t` that identifies the SLH-DSA parameter-set family to be used.

    The key attribute size of of an SLH-DSA key pair is the bit-size of each component in the SLH-DSA keys defined in `[FIPS205]`.
    That is, for a parameter set with security parameter :math:`n`, the bit-size in the key attributes is :math:`8n`.
    See the documentation of each SLH-DSA parameter-set family for details.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_SLH_DSA`
            *   `PSA_ALG_HASH_SLH_DSA`
            *   `PSA_ALG_DETERMINISTIC_SLH_DSA`
            *   `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for SHL-DSA public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SLHDSA`.

            The current proposed format is based on the expected outcome of that process.

        A SLH-DSA key pair is defined in `[FIPS205]` §9.1 as the four :math:`n`\ -byte values, :math:`SK\text{.seed}`, :math:`SK\text{.prf}`, :math:`PK\text{.seed}`, and :math:`PK\text{.root}`, where :math:`n` is the security parameter.

        The data format for import and export of the key pair is the concatenation of the four octet strings:

        .. math::

            SK\text{.seed}\ ||\ SK\text{.prf}\ ||\ PK\text{.seed}\ ||\ PK\text{.root}

        See `PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY` for the data format used when exporting the public key with :code:`psa_export_public_key()`.

    .. subsection:: Key derivation

        A call to :code:`psa_key_derivation_output_key()` will draw output bytes as follows:

        *   32 bytes are drawn as :math:`SK\text{.seed}`.
        *   32 bytes are drawn as :math:`SK\text{.prf}`.
        *   32 bytes are drawn as :math:`PK\text{.seed}`.

        The private key :math:`(SK\text{.seed},SK\text{.prf},PK\text{.seed},PK\text{.root})` is generated from these values as defined by ``slh_keygen_internal()`` in `[FIPS205]` §9.1.

.. macro:: PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        SLH-DSA public key.

        .. versionadded:: 1.3

    .. param:: set
        A value of type `psa_slh_dsa_family_t` that identifies the SLH-DSA parameter-set family to be used.

    The key attribute size of an SLH-DSA public key is the same as the corresponding private key.
    See `PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()` and the documentation of each SLH-DSA parameter-set family for details.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_SLH_DSA`
            *   `PSA_ALG_HASH_SLH_DSA`
            *   `PSA_ALG_DETERMINISTIC_SLH_DSA`
            *   `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for SHL-DSA public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SLHDSA`.

            The current proposed format is based on the expected outcome of that process.

        A SLH-DSA public key is defined in `[FIPS205]` §9.1 as two :math:`n`\ -byte values, :math:`PK\text{.seed}` and :math:`PK\text{.root}`, where :math:`n` is the security parameter.

        The data format for export of the public key is the concatenation of the two octet strings:

        .. math::

            PK\text{.seed}\ ||\ PK\text{.root}

.. macro:: PSA_SLH_DSA_FAMILY_SHA2_S
    :definition: ((psa_slh_dsa_family_t) 0x02)

    .. summary::
        SLH-DSA family for the SLH-DSA-SHA2-\ *NNN*\ s parameter sets.

        .. versionadded:: 1.3

    This family comprises the following parameter sets:

    *   SLH-DSA-SHA2-128s : ``key_bits = 128``
    *   SLH-DSA-SHA2-192s : ``key_bits = 192``
    *   SLH-DSA-SHA2-256s : ``key_bits = 256``

    They are defined in `[FIPS205]`.

.. macro:: PSA_SLH_DSA_FAMILY_SHA2_F
    :definition: ((psa_slh_dsa_family_t) 0x04)

    .. summary::
        SLH-DSA family for the SLH-DSA-SHA2-\ *NNN*\ f parameter sets.

        .. versionadded:: 1.3

    This family comprises the following parameter sets:

    *   SLH-DSA-SHA2-128f : ``key_bits = 128``
    *   SLH-DSA-SHA2-192f : ``key_bits = 192``
    *   SLH-DSA-SHA2-256f : ``key_bits = 256``

    They are defined in `[FIPS205]`.

.. macro:: PSA_SLH_DSA_FAMILY_SHAKE_S
    :definition: ((psa_slh_dsa_family_t) 0x0b)

    .. summary::
        SLH-DSA family for the SLH-DSA-SHAKE-\ *NNN*\ s parameter sets.

        .. versionadded:: 1.3

    This family comprises the following parameter sets:

    *   SLH-DSA-SHAKE-128s : ``key_bits = 128``
    *   SLH-DSA-SHAKE-192s : ``key_bits = 192``
    *   SLH-DSA-SHAKE-256s : ``key_bits = 256``

    They are defined in `[FIPS205]`.

.. macro:: PSA_SLH_DSA_FAMILY_SHAKE_F
    :definition: ((psa_slh_dsa_family_t) 0x0d)

    .. summary::
        SLH-DSA family for the SLH-DSA-SHAKE-\ *NNN*\ f parameter sets.

        .. versionadded:: 1.3

    This family comprises the following parameter sets:

    *   SLH-DSA-SHAKE-128f : ``key_bits = 128``
    *   SLH-DSA-SHAKE-192f : ``key_bits = 192``
    *   SLH-DSA-SHAKE-256f : ``key_bits = 256``

    They are defined in `[FIPS205]`.

.. macro:: PSA_KEY_TYPE_IS_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an SLH-DSA key, either a key pair or a public key.

        .. versionadded:: 1.3

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_SLH_DSA_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an SLH-DSA key pair.

        .. versionadded:: 1.3

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_SLH_DSA_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an SLH-DSA public key.

        .. versionadded:: 1.3

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_SLH_DSA_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the parameter-set family from an SLH-DSA key type.

        .. versionadded:: 1.3

    .. param:: type
        An SLH-DSA key type: a value of type :code:`psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_SLH_DSA(type)` is true.

    .. return:: psa_dh_family_t
        The SLH-DSA parameter-set family id, if ``type`` is a supported SLH-DSA key. Unspecified if ``type`` is not a supported SLH-DSA key.

.. _slh-dsa-algorithms:

Stateless Hash-based signature algorithms
-----------------------------------------

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.7 *Asymmetric signature*, for use with the signature functions.

The SLH-DSA signature and verification scheme is defined in :cite-title:`FIPS205`.
SLH-DSA has twelve parameter sets which provide differing security strengths, trade-off between signature size and computation cost, and selection between SHA2 and SHAKE-based hashing.

SLH-DSA keys are fairly compact, 32, 48, or 64 bytes for the public key, and double that for the key pair.
SLH-DSA signatures are much larger than those for RSA and Elliptic curve schemes, between 7.8kB and 49kB depending on the selected parameter set.
An SLH-DSA signature has the structure described in `[FIPS205]` §9.2, Figure 17.

See `[FIPS205]` §11 for details on the parameter sets, and the public key and generated signature sizes.

The generation of an SLH-DSA key depends on the full parameter specification.
The encoding of each parameter set into the key attributes is described in :secref:`slh-dsa-keys`.

`[FIPS205]` defines pure and pre-hashed variants of the signature scheme, which can either be hedged (randomized) or deterministic.
Four algorithms are defined to support these variants: `PSA_ALG_SLH_DSA`, `PSA_ALG_DETERMINISTIC_SLH_DSA`, `PSA_ALG_HASH_SLH_DSA()`, and `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()`.

.. _slh-dsa-deterministic-signatures:

.. rubric:: Hedged and deterministic signatures

Hedging incorporates fresh randomness in the signature computation, resulting in distinct signatures on every signing operation when given identical inputs.
Deterministic signatures do not require additional random data, and result in an identical signature for the same inputs.

Signature verification does not distinguish between a hedged and a deterministic signature.
Either hedged or deterministic algorithms can be used when verifying a signature.

When computing a signature, the key's permitted-algorithm policy must match the requested algorithm, treating hedged and deterministic versions as distinct.
When verifying a signature, the hedged and deterministic versions of each algorithm are considered equivalent when checking the key's permitted-algorithm policy.

.. note::

    The hedged version provides message secrecy and some protection against side-channels.
    `[FIPS205]` recommends that users should use the hedged version if either of these issues are a concern.
    The deterministic variant should only be used if the implementation does not include any source of randomness.

.. admonition:: Implementation note

    `[FIPS205]` recommends that implementations use an approved random number generator to provide the random value in the hedged version.
    However, it notes that use of the hedged variant with a weak RNG is generally preferable to the deterministic variant.

.. rationale::

    The use of fresh randomness, or not, when computing a signature seems like an implementation decision based on the capability of the system, and its vulnerability to specific threats, following the recommendations in `[FIPS205]`.

    However, the |API| gives distinct algorithm identifiers for the hedged and deterministic variants for the following reasons:

    *   `[FIPS205]` §9.1 recommends that SLH-DSA signing keys are only used to compute either deterministic, or hedged, signatures, but not both.
        Supporting this recommendation requires separate algorithm identifiers, and requiring an exact policy match for signature computation.
    *   Enable an application use case to require a specific variant.

.. rubric:: Pure and pre-hashed algorithms

The pre-hashed signature computation *HashSLH-DSA* generates distinct signatures to a pure signature *SLH-DSA*, with the same key and message hashing algorithm.

An SLH-DSA signature can only be verified with an SLH-DSA algorithm. A HashSLH-DSA signature can only be verified with a HashSLH-DSA algorithm.

.. rubric:: Contexts

From release 1.4.0 this specification includes functions that take non-empty contexts. 

The :code:`psa_sign_message()` and :code:`psa_verify message()` functions use an empty context string when computing or verifying ML-DSA signatures.

To use a supplid context, use :code:`psa_sign_message_with_context()` or :code:`psa_verify message_with_context()`.

.. macro:: PSA_ALG_SLH_DSA
    :definition: ((psa_algorithm_t) 0x06004000)

    .. summary::
        Stateless hash-based digital signature algorithm without pre-hashing (SLH-DSA).

        .. versionadded:: 1.3

    This algorithm can only be used with the message signature functions, for example :code:`psa_sign_message()` and :code:`psa_verify_message_with_context()` functions.

    This is the pure SLH-DSA digital signature algorithm, defined by :cite-title:`FIPS205`, using hedging.
    SLH-DSA requires an SLH-DSA key, which determines the SLH-DSA parameter set for the operation.

    This algorithm is randomized: each invocation returns a different, equally valid signature.
    See the `notes on hedged signatures <slh-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_SLH_DSA` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_SLH_DSA` as the algorithm in a call to :code:`psa_sign_message()`.
    *   `PSA_ALG_SLH_DSA` or `PSA_ALG_DETERMINISTIC_SLH_DSA` as the algorithm in a call to :code:`psa_verify_message()`.

    .. note::
        To sign or verify the pre-computed hash of a message using SLH-DSA, the HashSLH-DSA algorithms (`PSA_ALG_HASH_SLH_DSA()` and `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()`) can also be used with :code:`psa_sign_hash()` and :code:`psa_verify_hash()`.

        The signature produced by HashSLH-DSA is distinct from that produced by SLH-DSA.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()`
        | :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY()` (signature verification only)

.. macro:: PSA_ALG_DETERMINISTIC_SLH_DSA
    :definition: ((psa_algorithm_t) 0x06004100)

    .. summary::
        Deterministic stateless hash-based digital signature algorithm without pre-hashing (SLH-DSA).

        .. versionadded:: 1.3

    This algorithm can only be used with the message signature functions, for example :code:`psa_sign_message_with_context()` and :code:`psa_verify_message()` functions.

    This is the pure SLH-DSA digital signature algorithm, defined by `[FIPS205]`, without hedging.
    SLH-DSA requires an SLH-DSA key, which determines the SLH-DSA parameter set for the operation.

    This algorithm is deterministic: each invocation with the same inputs returns an identical signature.

    .. warning::
        It is recommended to use the hedged `PSA_ALG_SLH_DSA` algorithm instead, when supported by the implementation.
        See the `notes on deterministic signatures <slh-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_DETERMINISTIC_SLH_DSA` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_DETERMINISTIC_SLH_DSA` as the algorithm in a call to :code:`psa_sign_message()`.
    *   `PSA_ALG_SLH_DSA` or `PSA_ALG_DETERMINISTIC_SLH_DSA` as the algorithm in a call to :code:`psa_verify_message()`.

    .. note::
        To sign or verify the pre-computed hash of a message using SLH-DSA, the HashSLH-DSA algorithms (`PSA_ALG_HASH_SLH_DSA()` and `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()`) can also be used with :code:`psa_sign_hash()` and :code:`psa_verify_hash()`.

        The signature produced by HashSLH-DSA is distinct from that produced by SLH-DSA.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()`
        | :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY()` (signature verification only)

.. macro:: PSA_ALG_HASH_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Stateless hash-based digital signature algorithm with pre-hashing (HashSLH-DSA).

        .. versionadded:: 1.3

    .. param:: hash_alg
        A hash algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true.
        This includes :code:`PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding HashSLH-DSA signature algorithm, using ``hash_alg`` to pre-hash the message.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

    This is the pre-hashed SLH-DSA digital signature algorithm, defined by `[FIPS205]`, using hedging.
    SLH-DSA requires an SLH-DSA key, which determines the SLH-DSA parameter set for the operation.

    .. note::
        For the pre-hashing, `[FIPS205]` §10.2 recommends the use of an approved hash function with an equivalent, or better, security strength than the chosen SLH-DSA parameter set.

    This algorithm is randomized: each invocation returns a different, equally valid signature.
    See the `notes on hedged signatures <slh-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_HASH_SLH_DSA()` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_HASH_SLH_DSA()` as the algorithm in a call to :code:`psa_sign_message()` and :code:`psa_sign_hash()`.
    *   `PSA_ALG_HASH_SLH_DSA()` or `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()` as the algorithm in a call to :code:`psa_verify_message()` and :code:`psa_verify_hash()`.

    .. note::
        The signature produced by HashSLH-DSA is distinct from that produced by SLH-DSA.

    .. subsection:: Usage

        This is a hash-and-sign algorithm. To calculate a signature, use one of the following approaches:

        *   Call :code:`psa_sign_message()` or :code:`psa_sign_message_with_context()`with the message.

        *   Calculate the hash of the message with :code:`psa_hash_compute()`, or with a multi-part hash operation, using the ``hash_alg`` hash algorithm.
            Note that ``hash_alg`` can be extracted from the signature algorithm using :code:`PSA_ALG_GET_HASH(sig_alg)`.
            Then sign the calculated hash either with :code:`psa_sign_hash()` or, if the protocol requires the use of a non-empty context, with :code:`psa_sign_hash_with_context()`.

        Verifying a signature is similar, using :code:`psa_verify_message()` or :code:`psa_verify_hash()` instead of the signature function, or :code:`psa_verify_message_with_context()` or :code:`psa_verify_hash_with_context()` if a non-empty context has been used. 

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()`
        | :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY()` (signature verification only)

    .. comment
        Add this algorithm to the list in PSA_ALG_GET_HASH()

.. macro:: PSA_ALG_DETERMINISTIC_HASH_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Deterministic stateless hash-based digital signature algorithm with pre-hashing (HashSLH-DSA).

        .. versionadded:: 1.3

    .. param:: hash_alg
        A hash algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true.
        This includes :code:`PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding deterministic HashSLH-DSA signature algorithm, using ``hash_alg`` to pre-hash the message.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

    This is the pre-hashed SLH-DSA digital signature algorithm, defined by `[FIPS205]`, without hedging.
    SLH-DSA requires an SLH-DSA key, which determines the SLH-DSA parameter set for the operation.

    .. note::
        For the pre-hashing, `[FIPS205]` §10.2 recommends the use of an approved hash function with an equivalent, or better, security strength than the chosen SLH-DSA parameter set.

    This algorithm is deterministic: each invocation with the same inputs returns an identical signature.

    .. warning::
        It is recommended to use the hedged `PSA_ALG_HASH_SLH_DSA()` algorithm instead, when supported by the implementation.
        See the `notes on deterministic signatures <slh-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()` as the algorithm in a call to :code:`psa_sign_message()` and :code:`psa_sign_hash()`.
    *   `PSA_ALG_HASH_SLH_DSA()` or `PSA_ALG_DETERMINISTIC_HASH_SLH_DSA()` as the algorithm in a call to :code:`psa_verify_message()` and :code:`psa_verify_hash()`.

    .. note::
        The signature produced by HashSLH-DSA is distinct from that produced by SLH-DSA.

    .. subsection:: Usage

        See `PSA_ALG_HASH_SLH_DSA()` for example usage.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_SLH_DSA_KEY_PAIR()`
        | :code:`PSA_KEY_TYPE_SLH_DSA_PUBLIC_KEY()` (signature verification only)

    .. comment
        Add this algorithm to the list in PSA_ALG_GET_HASH()

.. macro:: PSA_ALG_IS_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is SLH-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is an SLH-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_HASH_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is HashSLH-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a HashSLH-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

.. macro:: PSA_ALG_IS_DETERMINISTIC_HASH_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is deterministic HashSLH-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a deterministic HashSLH-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_HASH_SLH_DSA()` and `PSA_ALG_IS_HEDGED_HASH_SLH_DSA()`.

.. macro:: PSA_ALG_IS_HEDGED_HASH_SLH_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is hedged HashSLH-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a hedged HashSLH-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_HASH_SLH_DSA()` and `PSA_ALG_IS_DETERMINISTIC_HASH_SLH_DSA()`.

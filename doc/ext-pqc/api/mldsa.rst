.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 3

.. _ml-dsa:

Module Lattice-based signatures
===============================

.. _ml-dsa-keys:

Module Lattice-based signature keys
-----------------------------------

The |API| supports Module Lattice-based digital signatures (ML-DSA), as defined in :cite-title:`FIPS204`.

.. macro:: PSA_KEY_TYPE_ML_DSA_KEY_PAIR
    :definition: ((psa_key_type_t)0x7002)

    .. summary::
        ML-DSA key pair: both the private and public key.

        .. versionadded:: 1.3

    The key attribute size of an ML-DSA key is a measure of the security strength of the ML-DSA parameter set in `[FIPS204]`:

    *   ML-DSA-44 : ``key_bits = 128``
    *   ML-DSA-65 : ``key_bits = 192``
    *   ML-DSA-87 : ``key_bits = 256``

    See also §4 in `[FIPS204]`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_ML_DSA`
            *   `PSA_ALG_HASH_ML_DSA`
            *   `PSA_ALG_DETERMINISTIC_ML_DSA`
            *   `PSA_ALG_DETERMINISTIC_HASH_ML_DSA`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for ML-DSA public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-MLDSA`.

            The current proposed format is based on the expected outcome of that process.

        An ML-DSA key pair is the :math:`(pk,sk)` pair of public key and secret key, which are generated from a secret 32-byte seed, :math:`\xi`. See `[FIPS204]` §5.1.

        In calls to :code:`psa_import_key()` and :code:`psa_export_key()`, the key-pair data format is the 32-byte seed :math:`\xi`.

        .. rationale::

            The IETF working group responsible for defining the format of the ML-DSA keys in *SubjectPublicKeyInfo* and *OneAsymmetricKey* structures is discussing the formats at present (September 2024), with the current consensus to using just the seed value as the private key, for the following reasons:

            *   ML-DSA key pairs are several kB in size, but can be recomputed efficiently from the initial 32-byte seed.
            *   There is no need to validate an imported ML-DSA private key --- every 32-byte seed values is valid.
            *   The public key cannot be derived from the secret key, so a key pair must store both the secret key and the public key.
                The size of the key pair depends on the ML-DSA parameter set as follows:

                .. csv-table::
                    :align: left
                    :header-rows: 1

                    Parameter set, Key-pair size in bytes
                    ML-DSA-44, 3872
                    ML-DSA-65, 5984
                    ML-DSA-87, 7488

            *   It is better for the standard to choose a single format to improve interoperability.

        See `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` for the data format used when exporting the public key with :code:`psa_export_public_key()`.

        .. admonition:: Implementation note

            An implementation can optionally compute and store the :math:`(pk,sk)` values, to accelerate operations that use the key.
            It is recommended that an implementation retains the seed :math:`\xi` with the key pair, in order to export the key, or copy the key to a different location.

    .. subsection:: Key derivation

        A call to :code:`psa_key_derivation_output_key()` will draw 32 bytes of output and use these as the 32-byte ML-DSA key-pair seed, :math:`\xi`.
        The key pair :math:`(pk, sk)` is generated from the seed as defined by ``ML-DSA.KeyGen_internal()`` in `[FIPS204]` §6.1.

        .. admonition:: Implementation note

            It is :scterm:`implementation defined` whether the seed :math:`\xi` is expanded to :math:`(pk, sk)` at the point of derivation, or only just before the key is used.

.. macro:: PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4002)

    .. summary::
        ML-DSA public key.

        .. versionadded:: 1.3

    The key attribute size of an ML-DSA public key is the same as the corresponding private key. See `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_ML_DSA`
            *   `PSA_ALG_HASH_ML_DSA`
            *   `PSA_ALG_DETERMINISTIC_ML_DSA`
            *   `PSA_ALG_DETERMINISTIC_HASH_ML_DSA`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for ML-DSA public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-MLDSA`.

            The current proposed format is based on the expected outcome of that process.

        An ML-DSA public key is the :math:`pk` output of ``ML-DSA.KeyGen()``, defined in `[FIPS204]` §5.1.

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is :math:`pk`.

        The size of the public key depends on the ML-DSA parameter set as follows:

        .. csv-table::
            :align: left
            :header-rows: 1

            Parameter set, Public-key size in bytes
            ML-DSA-44, 1312
            ML-DSA-65, 1952
            ML-DSA-87, 2592

.. macro:: PSA_KEY_TYPE_IS_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an ML-DSA key, either a key pair or a public key.

        .. versionadded:: 1.3

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.


.. _ml-dsa-algorithms:

Module Lattice-based signature algorithms
-----------------------------------------

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.7 *Asymmetric signature*, for use with the signature functions.

The ML-DSA signature and verification scheme is defined in :cite-title:`FIPS204`.
ML-DSA has three parameter sets which provide differing security strengths.

ML-DSA keys are large: 1.2--2.5kB for the public key, and triple that for the key pair.
ML-DSA signatures are much larger than those for RSA and Elliptic curve schemes, between 2.4kB and 4.6kB, depending on the selected parameter set.

See `[FIPS204]` §4 for details on the parameter sets, and the key and generated signature sizes.

The generation of an ML-DSA key depends on the full parameter specification.
The encoding of each parameter set into the key attributes is described in :secref:`ml-dsa-keys`.

`[FIPS204]` defines pure and pre-hashed variants of the signature scheme, which can either be hedged (randomized) or deterministic.
Four algorithms are defined to support these variants: `PSA_ALG_ML_DSA`, `PSA_ALG_DETERMINISTIC_ML_DSA`, `PSA_ALG_HASH_ML_DSA()`, and `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()`.

.. _ml-dsa-deterministic-signatures:

.. rubric:: Hedged and deterministic signatures

Hedging incorporates fresh randomness in the signature computation, resulting in distinct signatures on every signing operation when given identical inputs.
Deterministic signatures do not require additional random data, and result in an identical signature for the same inputs.

Signature verification does not distinguish between a hedged and a deterministic signature.
Either hedged or deterministic algorithms can be used when verifying a signature.

When computing a signature, the key's permitted-algorithm policy must match the requested algorithm, treating hedged and deterministic versions as distinct.
When verifying a signature, the hedged and deterministic versions of each algorithm are considered equivalent when checking the key's permitted-algorithm policy.

.. note::

    The hedged version provides message secrecy and some protection against side-channels.
    `[FIPS204]` recommends that users should use the hedged version if either of these issues are a concern.
    The deterministic variant should only be used if the implementation does not include any source of randomness.

.. admonition:: Implementation note

    `[FIPS204]` recommends that implementations use an approved random number generator to provide the random value in the hedged version.
    However, it notes that use of the hedged variant with a weak RNG is generally preferable to the deterministic variant.

.. rationale::

    The use of fresh randomness, or not, when computing a signature seems like an implementation decision based on the capability of the system, and its vulnerability to specific threats, following the recommendations in `[FIPS204]`.

    However, the |API| gives distinct algorithm identifiers for the hedged and deterministic variants, to enable an application use case to require a specific variant.

.. rubric:: Pure and pre-hashed algorithms

The pre-hashed signature computation *HashML-DSA* generates distinct signatures to a pure signature *ML-DSA*, with the same key and message hashing algorithm.

An ML-DSA signature can only be verified with an ML-DSA algorithm.
A HashML-DSA signature can only be verified with a HashML-DSA algorithm.

.. rubric:: Contexts

Contexts are not supported in the current version of this specification because there is no suitable signature interface that can take the context as a parameter.
A empty context string is used when computing or verifying ML-DSA signatures.

A future version of this specification may add suitable functions and extend this algorithm to support contexts.

.. macro:: PSA_ALG_ML_DSA
    :definition: ((psa_algorithm_t) 0x06004400)

    .. summary::
        Module lattice-based digital signature algorithm without pre-hashing (ML-DSA).

        .. versionadded:: 1.3

    This algorithm can only be used with the :code:`psa_sign_message()` and :code:`psa_verify_message()` functions.

    This is the pure ML-DSA digital signature algorithm, defined by :cite-title:`FIPS204`, using hedging.
    ML-DSA requires an ML-DSA key, which determines the ML-DSA parameter set for the operation.

    This algorithm is randomized: each invocation returns a different, equally valid signature.
    See the `notes on hedged signatures <ml-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_ML_DSA` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_ML_DSA` as the algorithm in a call to :code:`psa_sign_message()`.
    *   `PSA_ALG_ML_DSA` or `PSA_ALG_DETERMINISTIC_ML_DSA` as the algorithm in a call to :code:`psa_verify_message()`.

    .. note::
        To sign or verify the pre-computed hash of a message using ML-DSA, the HashML-DSA algorithms (`PSA_ALG_HASH_ML_DSA()` and `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()`) can also be used with :code:`psa_sign_hash()` and :code:`psa_verify_hash()`.

        The signature produced by HashML-DSA is distinct from that produced by ML-DSA.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`
        | `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_DETERMINISTIC_ML_DSA
    :definition: ((psa_algorithm_t) 0x06004500)

    .. summary::
        Deterministic module lattice-based digital signature algorithm without pre-hashing (ML-DSA).

        .. versionadded:: 1.3

    This algorithm can only be used with the :code:`psa_sign_message()` and :code:`psa_verify_message()` functions.

    This is the pure ML-DSA digital signature algorithm, defined by :cite-title:`FIPS204`, without hedging.
    ML-DSA requires an ML-DSA key, which determines the ML-DSA parameter set for the operation.

    This algorithm is deterministic: each invocation with the same inputs returns an identical signature.

    .. warning::
        It is recommended to use the hedged `PSA_ALG_ML_DSA` algorithm instead, when supported by the implementation.
        See the `notes on deterministic signatures <ml-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_DETERMINISTIC_ML_DSA` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_DETERMINISTIC_ML_DSA` as the algorithm in a call to :code:`psa_sign_message()`.
    *   `PSA_ALG_ML_DSA` or `PSA_ALG_DETERMINISTIC_ML_DSA` as the algorithm in a call to :code:`psa_verify_message()`.

    .. note::
        To sign or verify the pre-computed hash of a message using ML-DSA, the HashML-DSA algorithms (`PSA_ALG_HASH_ML_DSA()` and `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()`) can also be used with :code:`psa_sign_hash()` and :code:`psa_verify_hash()`.

        The signature produced by HashML-DSA is distinct from that produced by ML-DSA.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_ML_DSA_KEY_PAIR`
        | :code:`PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_HASH_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Module lattice-based digital signature algorithm with pre-hashing (HashML-DSA).

        .. versionadded:: 1.3

    .. param:: hash_alg
        A hash algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true.
        This includes :code:`PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding HashML-DSA signature algorithm, using ``hash_alg`` to pre-hash the message.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

    This is the pre-hashed ML-DSA digital signature algorithm, defined by :cite-title:`FIPS204`, using hedging.
    ML-DSA requires an ML-DSA key, which determines the ML-DSA parameter set for the operation.

    .. note::
        For the pre-hashing, `[FIPS204]` §5.4 recommends the use of an approved hash function with an equivalent, or better, security strength than the chosen ML-DSA parameter set.

    This algorithm is randomized: each invocation returns a different, equally valid signature.
    See the `notes on hedged signatures <ml-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_HASH_ML_DSA()` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_HASH_ML_DSA()` as the algorithm in a call to :code:`psa_sign_message()` and :code:`psa_sign_hash()`.
    *   `PSA_ALG_HASH_ML_DSA()` or `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()` as the algorithm in a call to :code:`psa_verify_message()` and :code:`psa_verify_hash()`.

    .. note::
        The signature produced by HashML-DSA is distinct from that produced by ML-DSA.

    .. subsection:: Usage

        This is a hash-and-sign algorithm. To calculate a signature, use one of the following approaches:

        *   Call :code:`psa_sign_message()` with the message.

        *   Calculate the hash of the message with :code:`psa_hash_compute()`, or with a multi-part hash operation, using the ``hash_alg`` hash algorithm.
            Note that ``hash_alg`` can be extracted from the signature algorithm using :code:`PSA_ALG_GET_HASH(sig_alg)`.
            Then sign the calculated hash with :code:`psa_sign_hash()`.

        Verifying a signature is similar, using :code:`psa_verify_message()` or :code:`psa_verify_hash()` instead of the signature function.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`
        | `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` (signature verification only)

    .. comment
        Add this algorithm to the list in PSA_ALG_GET_HASH()

.. macro:: PSA_ALG_DETERMINISTIC_HASH_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Deterministic module lattice-based digital signature algorithm with pre-hashing (HashML-DSA).

        .. versionadded:: 1.3

    .. param:: hash_alg
        A hash algorithm: a value of type :code:`psa_algorithm_t` such that :code:`PSA_ALG_IS_HASH(hash_alg)` is true.
        This includes :code:`PSA_ALG_ANY_HASH` when specifying the algorithm in a key policy.

    .. return::
        The corresponding deterministic HashML-DSA signature algorithm, using ``hash_alg`` to pre-hash the message.

        Unspecified if ``hash_alg`` is not a supported hash algorithm.

    This algorithm can be used with both the message and hash signature functions.

    This is the pre-hashed ML-DSA digital signature algorithm, defined by :cite-title:`FIPS204`, without hedging.
    ML-DSA requires an ML-DSA key, which determines the ML-DSA parameter set for the operation.

    .. note::
        For the pre-hashing, `[FIPS204]` §5.4 recommends the use of an approved hash function with an equivalent, or better, security strength than the chosen ML-DSA parameter set.

    This algorithm is deterministic: each invocation with the same inputs returns an identical signature.

    .. warning::
        It is recommended to use the hedged `PSA_ALG_HASH_ML_DSA()` algorithm instead, when supported by the implementation.
        See the `notes on deterministic signatures <ml-dsa-deterministic-signatures_>`_.

    When `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()` is used as a permitted algorithm in a key policy, this permits:

    *   `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()` as the algorithm in a call to :code:`psa_sign_message()` and :code:`psa_sign_hash()`.
    *   `PSA_ALG_HASH_ML_DSA()` or `PSA_ALG_DETERMINISTIC_HASH_ML_DSA()` as the algorithm in a call to :code:`psa_verify_message()` and :code:`psa_verify_hash()`.

    .. note::
        The signature produced by HashML-DSA is distinct from that produced by ML-DSA.

    .. subsection:: Usage

        See `PSA_ALG_HASH_ML_DSA()` for example usage.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_ML_DSA_KEY_PAIR`
        | `PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY` (signature verification only)

    .. comment
        Add this algorithm to the list in PSA_ALG_GET_HASH()

.. macro:: PSA_ALG_IS_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is ML-DSA, without pre-hashing.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a pure ML-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    .. note::
        Use `PSA_ALG_IS_HASH_ML_DSA()` to determine if an algorithm identifier is a HashML-DSA algorithm.

.. macro:: PSA_ALG_IS_HASH_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is HashML-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a HashML-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    .. note::
        Use `PSA_ALG_IS_ML_DSA()` to determine if an algorithm identifier is a pre-hashed ML-DSA algorithm.

.. macro:: PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is deterministic HashML-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a deterministic HashML-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_HASH_ML_DSA()` and `PSA_ALG_IS_HEDGED_HASH_ML_DSA()`.

.. macro:: PSA_ALG_IS_HEDGED_HASH_ML_DSA
    :definition: /* specification-defined value */

    .. summary::
        Whether the specified algorithm is hedged HashML-DSA.

        .. versionadded:: 1.3

    .. param:: alg
        An algorithm identifier: a value of type :code:`psa_algorithm_t`.

    .. return::
        ``1`` if ``alg`` is a hedged HashML-DSA algorithm, ``0`` otherwise.

        This macro can return either ``0`` or ``1`` if ``alg`` is not a supported algorithm identifier.

    See also `PSA_ALG_IS_HASH_ML_DSA()` and `PSA_ALG_IS_DETERMINISTIC_HASH_ML_DSA()`.

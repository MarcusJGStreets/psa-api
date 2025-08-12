.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 2

.. _ml-kem:

Module Lattice-based key encapsulation
======================================

.. _ml-kem-keys:

Module Lattice-based key-encapsulation keys
-------------------------------------------

The |API| supports Module Lattice-based key ecapsulation (ML-KEM) as defined in :cite-title:`FIPS203`.

.. macro:: PSA_KEY_TYPE_ML_KEM_KEY_PAIR
    :definition: ((psa_key_type_t)0x7004)

    .. summary::
        ML-KEM key pair: both the decapsulation and encapsulation key.

        .. versionadded:: 1.3

    The |API| treats decapsulation keys as private keys and encapsulation keys as public keys.

    The key attribute size of an ML-KEM key is specified by the numeric part of the parameter-set identifier defined in `[FIPS203]`.
    The parameter-set identifier refers to the key strength, and not to the actual size of the key.
    The following values for the ``key_bits`` key attribute are used to select a specific ML-KEM parameter set:

    *   ML-KEM-512 : ``key_bits = 512``
    *   ML-KEM-768 : ``key_bits = 768``
    *   ML-KEM-1024 : ``key_bits = 1024``

    See also §8 in `[FIPS203]`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_ML_KEM`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for ML-KEM public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-MLKEM`.

            The current proposed format is based on the expected outcome of that process.

        An ML-KEM key pair is the :math:`(ek,dk)` pair of encapsulation key and decapsulation key, which are generated from two secret 32-byte seeds, :math:`d` and :math:`z`. See `[FIPS203]` §7.1.

        In calls to :code:`psa_import_key()` and :code:`psa_export_key()`, the key-pair data format is the concatenation of the two seed values:

        .. math::

            d\ ||\ z

        .. rationale::

            The IETF working group responsible for defining the format of the ML-DSA keys in *SubjectPublicKeyInfo* and *OneAsymmetricKey* structures is discussing the formats at present (September 2024), with the current consensus to using just the seed values as the private key, for the following reasons:

            *   ML-KEM decapsulation keys are 1.5--3.0 kB in size, but can be recomputed efficiently from the initial 64-byte seed-pair.
            *   There is no need to validate an imported ML-KEM key pair --- every 64-byte pair of seed values is valid.
            *   It is better for the standard to choose a single format to improve interoperability.

        See `PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY` for the data format used when exporting the public key with :code:`psa_export_public_key()`.

        .. admonition:: Implementation note

            An implementation can optionally compute and store the :math:`dk` value, which also contains the encapsulation key :math:`ek`, to accelerate operations that use the key.
            It is recommended that an implementation retains the seed pair :math:`(d,z)` with the decapsulation key, in order to export the key, or copy the key to a different location.

    .. subsection:: Key derivation

        A call to :code:`psa_key_derivation_output_key()` will construct an ML-KEM key pair using the following process:

        1.  Draw 32 bytes of output as the seed value :math:`d`.
        #.  Draw 32 bytes of output as the seed value :math:`z`.

        The key pair :math:`(ek,dk)` is generated from the seed as defined by ``ML-KEM.KeyGen_internal()`` in `[FIPS203]` §6.1.

        .. admonition:: Implementation note

            It is :scterm:`implementation defined` whether the seed-pair :math:`(d,z)` is expanded to :math:`(ek,dk)` at the point of derivation, or only just before the key is used.

.. macro:: PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4004)

    .. summary::
        ML-KEM public (encapsulation) key.

        .. versionadded:: 1.3

    The key attribute size of an ML-KEM public key is the same as the corresponding private key. See `PSA_KEY_TYPE_ML_KEM_KEY_PAIR`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_ML_KEM` (encapsulation only)

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for ML-KEM public and private keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-MLKEM`.

            The current proposed format is based on the expected outcome of that process.

        An ML-KEM public key is the :math:`ek` output of ``ML-KEM.KeyGen()``, defined in `[FIPS203]` §7.1.

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is :math:`ek`.

        The size of the public key depends on the ML-KEM parameter set as follows:

        .. csv-table::
            :align: left
            :header-rows: 1

            Parameter set, Public-key size in bytes
            ML-KEM-512, 800
            ML-KEM-768, 1184
            ML-KEM-1024, 1568

.. macro:: PSA_KEY_TYPE_IS_ML_KEM
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an ML-DSA key, either a key pair or a public key.

        .. versionadded:: 1.3

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

Module Lattice-based key-encapsulation algorithm
------------------------------------------------

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.10 *Key encapsulation*, for use with the key-encapsulation functions.

.. note::
    The key-encapsulation functions, :code:`psa_encapsulate()` and :code:`psa_decapsulate()`, were introduced in version 1.3 of the |API|.

ML-KEM is defined in :cite-title:`FIPS203`.
ML-KEM has three parameter sets which provide differing security strengths.

The generation of an ML-KEM key depends on the full parameter specification.
The encoding of each parameter set into the key attributes is described in :secref:`ml-kem-keys`.

See `[FIPS203]` §8 for details on the parameter sets.

.. macro:: PSA_ALG_ML_KEM
    :definition: ((psa_algorithm_t)0x0c000200)

    .. summary::
        Module Lattice-based key-encapsulation mechanism (ML-KEM).

        .. versionadded:: 1.3

    This is the ML-KEM key-encapsulation algorithm, defined by `[FIPS203]`.
    ML-KEM requires an ML-KEM key, which determines the ML-KEM parameter set for the operation.

    When using ML-KEM, the size of the encapsulation data returned by a call to :code:`psa_encapsulate()` is as follows:

    .. csv-table::
        :align: left
        :header-rows: 1

        Parameter set, Encapsulation data size in bytes
        ML-KEM-512, 768
        ML-KEM-768, 1088
        ML-KEM-1024, 1568

    The 32-byte shared output key that is produced by ML-KEM is pseudorandom.
    Although it can be used directly as an encryption key, it is recommended to use the output key as an input to a key-derivation operation to produce additional cryptographic keys.

    .. subsection:: Compatible key types

        | `PSA_KEY_TYPE_ML_KEM_KEY_PAIR`
        | `PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY` (encapsulation only)

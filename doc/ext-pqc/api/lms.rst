.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 5

.. _lms:

Leighton-Micali Signatures
==========================

The |API| supports Leighton-Micali Signatures (LMS), and the multi-level Hierarchical Signature Scheme (HSS).
These schemes are defined in :rfc-title:`8554`.

For the |API| to support signature verification, it is only necessary to define a public keys for these schemes, and the default public key formats for import and export.

.. rationale::

    At present, it is not expected that the |API| will be used to generate LMS or HSS private keys, or to carry out signing operations.
    However, there is value in supporting verification of LMS and HSS signatures.
    Therefore, the |API| does not support LMS or HSS key pairs, or the associated signing operations.

.. note::
    A full set of NIST-approved parameter sets for LMS and HSS is defined in :cite-title:`SP800-208` §4, with the additional IANA identifiers defined in :cite-title:`CFRG-LMS`.

.. _lms-keys:

Leighton-Micali Signature keys
------------------------------

.. macro:: PSA_KEY_TYPE_LMS_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4007)

    .. summary::
        Leighton-Micali Signatures (LMS) public key.

        .. versionadded:: 1.3

    The parameterization of an LMS key is fully encoded in the key data.

    The key attribute size of an LMS public key is output length, in bits, of the hash function identified by the LMS parameter set.

    *   SHA-256/192, SHAKE256/192 : ``key_bits = 192``
    *   SHA-256, SHAKE256/256 : ``key_bits = 256``

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_LMS`

    .. subsection:: Key format

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is the encoded ``lms_public_key`` structure, defined in :rfc:`8554#3`.

.. macro:: PSA_KEY_TYPE_HSS_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4008)

    .. summary::
        Hierarchical Signature Scheme (HSS) public key.

        .. versionadded:: 1.3

    The parameterization of an HSS key is fully encoded in the key data.

    The key attribute size of an HSS public key is output length, in bits, of the hash function identified by the HSS parameter set.

    *   SHA-256/192, SHAKE256/192 : ``key_bits = 192``
    *   SHA-256, SHAKE256/256 : ``key_bits = 256``

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_HSS`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for HSS public keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SHBS`.

            The current proposed format is based on the expected outcome of that process.

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is the encoded ``hss_public_key`` structure, defined in :rfc:`8554#3`.


.. _lms-algorithms:

Leighton-Micali Signature algorithms
------------------------------------

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.7 *Asymmetric signature*, for use with the signature functions.

.. macro:: PSA_ALG_LMS
    :definition: ((psa_algorithm_t) 0x06004800)

    .. summary::
        Leighton-Micali Signatures (LMS) signature algorithm.

        .. versionadded:: 1.3

    This message-signature algorithm can only be used with the :code:`psa_verify_message()` function.

    This is the LMS stateful hash-based signature algorithm, defined by :rfc-title:`8554`.
    LMS requires an LMS key.
    The key and the signature must both encode the same LMS parameter set, which is used for the verification procedure.

    .. note::
        LMS signature calculation is not supported.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_LMS_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_HSS
    :definition: ((psa_algorithm_t) 0x06004900)

    .. summary::
        Hierarchical Signature Scheme (HSS) signature algorithm.

        .. versionadded:: 1.3

    This message-signature algorithm can only be used with the :code:`psa_verify_message()` function.

    This is the HSS stateful hash-based signature algorithm, defined by :rfc-title:`8554`.
    HSS requires an HSS key.
    The key and the signature must both encode the same HSS parameter set, which is used for the verification procedure.

    .. note::
        HSS signature calculation is not supported.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_HSS_PUBLIC_KEY` (signature verification only)

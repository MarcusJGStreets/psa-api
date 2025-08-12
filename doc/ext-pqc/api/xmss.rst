.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto-pqc
    :seq: 6

.. _xmss:

eXtended Merkle Signature Scheme
================================

The |API| supports eXtended Merkle Signature Scheme (XMSS), and the multi-tree variant |XMSS^MT|.
These schemes are defined in :rfc-title:`8391`.

For the |API| to support signature verification, it is only necessary to define public keys for these schemes, and the default public key formats for import and export.

.. rationale::

    At present, it is not expected that the |API| will be used to generate XMSS or |XMSS^MT| private keys, or to carry out signing operations.
    However, there is value in supporting verification of XMSS and |XMSS^MT| signatures.
    Therefore, the |API| does not support XMSS or |XMSS^MT| key pairs, or the associated signing operations.

.. note::
    A full set of NIST-approved parameter sets for XMSS or |XMSS^MT| is defined in :cite-title:`SP800-208` §5.

.. _xmss-keys:

XMSS and |XMSS^MT| keys
-----------------------

.. macro:: PSA_KEY_TYPE_XMSS_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x400B)

    .. summary::
        eXtended Merkle Signature Scheme (XMSS) public key.

        .. versionadded:: 1.3

    The parameterization of an XMSS key is fully encoded in the key data.

    The key attribute size of an XMSS public key is output length, in bits, of the hash function identified by the XMSS parameter set.

    *   SHA-256/192, SHAKE256/192 : ``key_bits = 192``
    *   SHA-256, SHAKE256/256 : ``key_bits = 256``

    .. note::
        For a multi-tree XMSS key, see `PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_XMSS`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for XMSS public keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SHBS`.

            The current proposed format is based on the expected outcome of that process.

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is the encoded ``xmss_public_key`` structure, defined in :rfc:`8391#B.3`.

.. macro:: PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x400D)

    .. summary::
        Multi-tree eXtended Merkle Signature Scheme (|XMSS^MT|) public key.

        .. versionadded:: 1.3

    The parameterization of an |XMSS^MT| key is fully encoded in the key data.

    The key attribute size of an |XMSS^MT| public key is output length, in bits, of the hash function identified by the |XMSS^MT| parameter set.

    *   SHA-256/192, SHAKE256/192 : ``key_bits = 192``
    *   SHA-256, SHAKE256/256 : ``key_bits = 256``

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_XMSS_MT`

    .. subsection:: Key format

        .. warning::

            The key format may change in a final version of this API.
            The standardization of exchange formats for |XMSS^MT| public keys is in progress, but final documents have not been published.
            See :cite-title:`LAMPS-SHBS`.

            The current proposed format is based on the expected outcome of that process.

        In calls to :code:`psa_import_key()`, :code:`psa_export_key()`, and :code:`psa_export_public_key()`, the public-key data format is the encoded ``xmssmt_public_key`` structure, defined in :rfc:`8391#C.3`.


.. _xmss-algorithms:

XMSS and |XMSS^MT| algorithms
-----------------------------

These algorithms extend those defined in :cite-title:`PSA-CRYPT` §10.7 *Asymmetric signature*, for use with the signature functions.

.. macro:: PSA_ALG_XMSS
    :definition: ((psa_algorithm_t) 0x06004A00)

    .. summary::
        eXtended Merkle Signature Scheme (XMSS) signature algorithm.

        .. versionadded:: 1.3

    This message-signature algorithm can only be used with the :code:`psa_verify_message()` function.

    This is the XMSS stateful hash-based signature algorithm, defined by :rfc-title:`8391`.
    XMSS requires an XMSS key.
    The key and the signature must both encode the same XMSS parameter set, which is used for the verification procedure.

    .. note::
        XMSS signature calculation is not supported.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_XMSS_PUBLIC_KEY` (signature verification only)

.. macro:: PSA_ALG_XMSS_MT
    :definition: ((psa_algorithm_t) 0x06004B00)

    .. summary::
        Multi-tree eXtended Merkle Signature Scheme (|XMSS^MT|) signature algorithm.

        .. versionadded:: 1.3

    This message-signature algorithm can only be used with the :code:`psa_verify_message()` function.

    This is the |XMSS^MT| stateful hash-based signature algorithm, defined by :rfc-title:`8391`.
    |XMSS^MT| requires an |XMSS^MT| key.
    The key and the signature must both encode the same |XMSS^MT| parameter set, which is used for the verification procedure.

    .. note::
        |XMSS^MT| signature calculation is not supported.

    .. subsection:: Compatible key types

        | :code:`PSA_KEY_TYPE_XMSS_MT_PUBLIC_KEY` (signature verification only)

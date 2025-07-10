.. SPDX-FileCopyrightText: Copyright 2018-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. header:: psa/crypto
    :seq: 130

.. _key-types:

Key types
=========

Key type encoding
-----------------

.. typedef:: uint16_t psa_key_type_t

    .. summary::
        Encoding of a key type.

    This is a structured bitfield that identifies the category and type of key. The range of key type values is divided as follows:

    :code:`PSA_KEY_TYPE_NONE == 0`
        Reserved as an invalid key type.
    :code:`0x0001 - 0x7fff`
        Specification-defined key types.
        Key types defined by this standard always have bit 15 clear.
        Unallocated key type values in this range are reserved for future use.
    :code:`0x8000 - 0xffff`
        Implementation-defined key types.
        Implementations that define additional key types must use an encoding with bit 15 set.
        The related support macros will be easier to write if these key encodings also respect the bitwise structure used by standard encodings.

    The :secref:`appendix-encodings` appendix provides a full definition of the key type encoding.

.. macro:: PSA_KEY_TYPE_NONE
    :definition: ((psa_key_type_t)0x0000)

    .. summary::
        An invalid key type value.

    Zero is not the encoding of any key type.

Key categories
--------------

.. macro:: PSA_KEY_TYPE_IS_UNSTRUCTURED
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an unstructured array of bytes.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

    This encompasses both symmetric keys and non-key data.

    See :secref:`symmetric-keys` for a list of symmetric key types.

.. macro:: PSA_KEY_TYPE_IS_ASYMMETRIC
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is asymmetric: either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

    See :secref:`asymmetric-keys` for a list of asymmetric key types.

.. macro:: PSA_KEY_TYPE_IS_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is the public part of a key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a key pair containing a private part and a public part.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.


.. _symmetric-keys:

Symmetric keys
--------------

.. macro:: PSA_KEY_TYPE_RAW_DATA
    :definition: ((psa_key_type_t)0x1001)

    .. summary::
        Raw data.

    A "key" of this type cannot be used for any cryptographic operation. Applications can use this type to store arbitrary data in the keystore.

    The bit size of a raw key must be a non-zero multiple of 8. The maximum size of a raw key is :scterm:`IMPLEMENTATION DEFINED`.

    .. subsection:: Compatible algorithms

        A key of this type can also be used as a non-secret input to the following key-derivation algorithms:

        .. hlist::

            *   `PSA_ALG_HKDF`
            *   `PSA_ALG_HKDF_EXPAND`
            *   `PSA_ALG_HKDF_EXTRACT`
            *   `PSA_ALG_SP800_108_COUNTER_HMAC`
            *   `PSA_ALG_SP800_108_COUNTER_CMAC`
            *   `PSA_ALG_TLS12_PRF`
            *   `PSA_ALG_TLS12_PSK_TO_MS`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_HMAC
    :definition: ((psa_key_type_t)0x1100)

    .. summary::
        HMAC key.

    HMAC keys can be used in HMAC, or HMAC-based, algorithms.
    Although HMAC is parameterized by a specific hash algorithm, for example SHA-256, the hash algorithm is not specified in the key type.
    The permitted-algorithm policy for the key must specify a particular hash algorithm.

    The bit size of an HMAC key must be a non-zero multiple of 8.
    An HMAC key is typically the same size as the output of the underlying hash algorithm.
    An HMAC key that is longer than the block size of the underlying hash algorithm will be hashed before use, see :RFC-title:`2104#2`.

    It is recommended that an application does not construct HMAC keys that are longer than the block size of the hash algorithm that will be used.
    It is :scterm:`implementation defined` whether an HMAC key that is longer than the hash block size is supported.

    If the application does not control the length of the data used to construct the HMAC key, it is recommended that the application hashes the key data, when it exceeds the hash block length, before constructing the HMAC key.

    .. note::

        :code:`PSA_HASH_LENGTH(alg)` provides the output size of hash algorithm ``alg``, in bytes.

        :code:`PSA_HASH_BLOCK_LENGTH(alg)` provides the block size of hash algorithm ``alg``, in bytes.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_HMAC`
            *   `PSA_ALG_SP800_108_COUNTER_HMAC` (secret input)

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_DERIVE
    :definition: ((psa_key_type_t)0x1200)

    .. summary::
        A secret for key derivation.

    This key type is for high-entropy secrets only. For low-entropy secrets, `PSA_KEY_TYPE_PASSWORD` should be used instead.

    These keys can be used in the `PSA_KEY_DERIVATION_INPUT_SECRET` or `PSA_KEY_DERIVATION_INPUT_PASSWORD` input step of key-derivation algorithms.

    The key policy determines which key-derivation algorithm the key can be used for.

    The bit size of a secret for key derivation must be a non-zero multiple of 8. The maximum size of a secret for key derivation is :scterm:`IMPLEMENTATION DEFINED`.

    .. subsection:: Compatible algorithms

        A key of this type can be used as the secret input to the following key-derivation algorithms:

        .. hlist::

            *   `PSA_ALG_HKDF`
            *   `PSA_ALG_HKDF_EXPAND`
            *   `PSA_ALG_HKDF_EXTRACT`
            *   `PSA_ALG_TLS12_PRF`
            *   `PSA_ALG_TLS12_PSK_TO_MS`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_PASSWORD
    :definition: ((psa_key_type_t)0x1203)

    .. summary::
        A low-entropy secret for password hashing or key derivation.

        .. versionadded:: 1.1

    This key type is suitable for passwords and passphrases which are typically intended to be memorizable by humans, and have a low entropy relative to their size.
    It can be used for randomly generated or derived keys with maximum or near-maximum entropy, but `PSA_KEY_TYPE_DERIVE` is more suitable for such keys.
    It is not suitable for passwords with extremely low entropy, such as numerical PINs.

    These keys can be used in the `PSA_KEY_DERIVATION_INPUT_PASSWORD` input step of key-derivation algorithms.
    Algorithms that accept such an input were designed to accept low-entropy secret and are known as *password hashing* or *key stretching* algorithms.

    These keys cannot be used in the `PSA_KEY_DERIVATION_INPUT_SECRET` input step of key-derivation algorithms, as the algorithms expect such an input to have high entropy.

    The key policy determines which key-derivation algorithm the key can be used for, among the permissible subset defined above.

    .. subsection:: Compatible algorithms

        A key of this type can be used as the password input to the following key-stretching algorithms:

        .. hlist::

            *   `PSA_ALG_PBKDF2_HMAC`
            *   `PSA_ALG_PBKDF2_AES_CMAC_PRF_128`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_PASSWORD_HASH
    :definition: ((psa_key_type_t)0x1205)

    .. summary::
        A secret value that can be used to verify a password hash.

        .. versionadded:: 1.1

    The key policy determines which key-derivation algorithm the key can be used for, among the same permissible subset as for `PSA_KEY_TYPE_PASSWORD`.

    .. subsection:: Compatible algorithms

        A key of this type can be used to output or verify the result of the following key-stretching algorithms:

        .. hlist::

            *   `PSA_ALG_PBKDF2_HMAC`
            *   `PSA_ALG_PBKDF2_AES_CMAC_PRF_128`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_PEPPER
    :definition: ((psa_key_type_t)0x1206)

    .. summary::
        A secret value that can be used when computing a password hash.

        .. versionadded:: 1.1

    The key policy determines which key-derivation algorithm the key can be used for, among the subset of algorithms that can use pepper.

    .. subsection:: Compatible algorithms

        A key of this type can be used as the salt input to the following key-stretching algorithms:

        .. hlist::

            *   `PSA_ALG_PBKDF2_HMAC`
            *   `PSA_ALG_PBKDF2_AES_CMAC_PRF_128`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_AES
    :definition: ((psa_key_type_t)0x2400)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the AES block cipher.

    The size of the key is related to the AES algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   AES-128 uses a 16-byte key : ``key_bits = 128``
    *   AES-192 uses a 24-byte key : ``key_bits = 192``
    *   AES-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   AES-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   AES-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   AES-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The AES block cipher is defined in :cite-title:`FIPS197`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_CBC_MAC`
            *   `PSA_ALG_CMAC`
            *   `PSA_ALG_CTR`
            *   `PSA_ALG_CFB`
            *   `PSA_ALG_OFB`
            *   `PSA_ALG_XTS`
            *   `PSA_ALG_CBC_NO_PADDING`
            *   `PSA_ALG_CBC_PKCS7`
            *   `PSA_ALG_ECB_NO_PADDING`
            *   `PSA_ALG_CCM`
            *   `PSA_ALG_GCM`
            *   `PSA_ALG_SP800_108_COUNTER_CMAC` (secret input)

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_ARIA
    :definition: ((psa_key_type_t)0x2406)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the ARIA block cipher.

        .. versionadded:: 1.1

    The size of the key is related to the ARIA algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   ARIA-128 uses a 16-byte key : ``key_bits = 128``
    *   ARIA-192 uses a 24-byte key : ``key_bits = 192``
    *   ARIA-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   ARIA-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   ARIA-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   ARIA-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The ARIA block cipher is defined in :RFC-title:`5794`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_CBC_MAC`
            *   `PSA_ALG_CMAC`
            *   `PSA_ALG_CTR`
            *   `PSA_ALG_CFB`
            *   `PSA_ALG_OFB`
            *   `PSA_ALG_XTS`
            *   `PSA_ALG_CBC_NO_PADDING`
            *   `PSA_ALG_CBC_PKCS7`
            *   `PSA_ALG_ECB_NO_PADDING`
            *   `PSA_ALG_CCM`
            *   `PSA_ALG_GCM`
            *   `PSA_ALG_SP800_108_COUNTER_CMAC` (secret input)

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_DES
    :definition: ((psa_key_type_t)0x2301)

    .. summary::
        Key for a cipher or MAC algorithm based on DES or 3DES (Triple-DES).

    The size of the key determines which DES algorithm is used:

    *   Single DES uses an 8-byte key : ``key_bits = 64``
    *   2-key 3DES uses a 16-byte key : ``key_bits = 128``
    *   3-key 3DES uses a 24-byte key : ``key_bits = 192``

    .. warning::
        Single DES and 2-key 3DES are weak and strongly deprecated and are only recommended for decrypting legacy data.

        3-key 3DES is weak and deprecated and is only recommended for use in legacy applications.

    The DES and 3DES block ciphers are defined in :cite-title:`SP800-67`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_CBC_MAC`
            *   `PSA_ALG_CMAC`
            *   `PSA_ALG_CTR`
            *   `PSA_ALG_CFB`
            *   `PSA_ALG_OFB`
            *   `PSA_ALG_XTS`
            *   `PSA_ALG_CBC_NO_PADDING`
            *   `PSA_ALG_CBC_PKCS7`
            *   `PSA_ALG_ECB_NO_PADDING`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.
        The parity bits in each 64-bit DES key element must be correct.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will construct a single 64-bit DES key using the following process:

        1.  Draw an 8-byte string.
        #.  Set/clear the parity bits in each byte.
        #.  If the result is a forbidden weak key, discard the result and return to step 1.
        #.  Output the string.

        For 2-key 3DES and 3-key 3DES, this process is repeated to derive the 2nd and 3rd keys, as required.

.. macro:: PSA_KEY_TYPE_CAMELLIA
    :definition: ((psa_key_type_t)0x2403)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the Camellia block cipher.

    The size of the key is related to the Camellia algorithm variant. For algorithms except the XTS block cipher mode, the following key sizes are used:

    *   Camellia-128 uses a 16-byte key : ``key_bits = 128``
    *   Camellia-192 uses a 24-byte key : ``key_bits = 192``
    *   Camellia-256 uses a 32-byte key : ``key_bits = 256``

    For the XTS block cipher mode (`PSA_ALG_XTS`), the following key sizes are used:

    *   Camellia-128-XTS uses two 16-byte keys : ``key_bits = 256``
    *   Camellia-192-XTS uses two 24-byte keys : ``key_bits = 384``
    *   Camellia-256-XTS uses two 32-byte keys : ``key_bits = 512``

    The Camellia block cipher is defined in :cite-title:`NTT-CAM` and also described in :RFC-title:`3713`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_CBC_MAC`
            *   `PSA_ALG_CMAC`
            *   `PSA_ALG_CTR`
            *   `PSA_ALG_CFB`
            *   `PSA_ALG_OFB`
            *   `PSA_ALG_XTS`
            *   `PSA_ALG_CBC_NO_PADDING`
            *   `PSA_ALG_CBC_PKCS7`
            *   `PSA_ALG_ECB_NO_PADDING`
            *   `PSA_ALG_CCM`
            *   `PSA_ALG_GCM`
            *   `PSA_ALG_SP800_108_COUNTER_CMAC` (secret input)

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_SM4
    :definition: ((psa_key_type_t)0x2405)

    .. summary::
        Key for a cipher, AEAD or MAC algorithm based on the SM4 block cipher.

    For algorithms except the XTS block cipher mode, the SM4 key size is 128 bits (16 bytes).

    For the XTS block cipher mode (`PSA_ALG_XTS`), the SM4 key size is 256 bits (two 16-byte keys).

    The SM4 block cipher is defined in :cite-title:`CSTC0002`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_CBC_MAC`
            *   `PSA_ALG_CMAC`
            *   `PSA_ALG_CTR`
            *   `PSA_ALG_CFB`
            *   `PSA_ALG_OFB`
            *   `PSA_ALG_XTS`
            *   `PSA_ALG_CBC_NO_PADDING`
            *   `PSA_ALG_CBC_PKCS7`
            *   `PSA_ALG_ECB_NO_PADDING`
            *   `PSA_ALG_CCM`
            *   `PSA_ALG_GCM`
            *   `PSA_ALG_SP800_108_COUNTER_CMAC` (secret input)

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_ARC4
    :definition: ((psa_key_type_t)0x2002)

    .. summary::
        Key for the ARC4 stream cipher.

    .. warning::
        The ARC4 cipher is weak and deprecated and is only recommended for use in legacy applications.

    The ARC4 cipher supports key sizes between 40 and 2048 bits, that are multiples of 8. (5 to 256 bytes)

    Use algorithm `PSA_ALG_STREAM_CIPHER` to use this key with the ARC4 cipher.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_STREAM_CIPHER`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw :math:`m/8` bytes of output and use these as the key data, where :math:`m` is the bit-size of the key.

.. macro:: PSA_KEY_TYPE_CHACHA20
    :definition: ((psa_key_type_t)0x2004)

    .. summary::
        Key for the ChaCha20 stream cipher or the ChaCha20-Poly1305 AEAD algorithm.

    The ChaCha20 key size is 256 bits (32 bytes).

    *   Use algorithm `PSA_ALG_STREAM_CIPHER` to use this key with the ChaCha20 cipher for unauthenticated encryption. See `PSA_ALG_STREAM_CIPHER` for details of this algorithm.

    *   Use algorithm `PSA_ALG_CHACHA20_POLY1305` to use this key with the ChaCha20 cipher and Poly1305 authenticator for AEAD. See `PSA_ALG_CHACHA20_POLY1305` for details of this algorithm.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_STREAM_CIPHER`
            *   `PSA_ALG_CHACHA20_POLY1305`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw 32 bytes of output and use these as the key data.

.. macro:: PSA_KEY_TYPE_XCHACHA20
    :definition: ((psa_key_type_t)0x2007)

    .. summary::
        Key for the XChaCha20 stream cipher or the XChaCha20-Poly1305 AEAD algorithm.

        .. versionadded:: 1.2

    The XChaCha20 key size is 256 bits (32 bytes).

    *   Use algorithm `PSA_ALG_STREAM_CIPHER` to use this key with the XChaCha20 cipher for unauthenticated encryption. See `PSA_ALG_STREAM_CIPHER` for details of this algorithm.

    *   Use algorithm `PSA_ALG_XCHACHA20_POLY1305` to use this key with the XChaCha20 cipher and Poly1305 authenticator for AEAD. See `PSA_ALG_XCHACHA20_POLY1305` for details of this algorithm.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_STREAM_CIPHER`
            *   `PSA_ALG_XCHACHA20_POLY1305`

    .. subsection:: Key format

        The data format for import and export of the key is the raw bytes of the key.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will draw 32 bytes of output and use these as the key data.

.. _asymmetric-keys:

Asymmetric keys
---------------

The |API| defines the following types of asymmetric key:

* :secref:`rsa-keys`
* :secref:`ecc-keys`
* :secref:`dh-keys`
* :secref:`spake2p-keys`

.. _rsa-keys:

RSA keys
--------

.. macro:: PSA_KEY_TYPE_RSA_KEY_PAIR
    :definition: ((psa_key_type_t)0x7001)

    .. summary::
        RSA key pair: both the private and public key.

    The size of an RSA key is the bit size of the modulus.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_RSA_OAEP`
            *   `PSA_ALG_RSA_PKCS1V15_CRYPT`
            *   `PSA_ALG_RSA_PKCS1V15_SIGN`
            *   `PSA_ALG_RSA_PKCS1V15_SIGN_RAW`
            *   `PSA_ALG_RSA_PSS`
            *   `PSA_ALG_RSA_PSS_ANY_SALT`

    .. subsection:: Key format

        The data format for import and export of a key-pair is the non-encrypted DER encoding of the representation defined by in :RFC-title:`8017` as ``RSAPrivateKey``, version ``0``.

        .. code-block:: none

            RSAPrivateKey ::= SEQUENCE {
                version             INTEGER,  -- must be 0
                modulus             INTEGER,  -- n
                publicExponent      INTEGER,  -- e
                privateExponent     INTEGER,  -- d
                prime1              INTEGER,  -- p
                prime2              INTEGER,  -- q
                exponent1           INTEGER,  -- d mod (p-1)
                exponent2           INTEGER,  -- d mod (q-1)
                coefficient         INTEGER,  -- (inverse of q) mod p
            }

        .. note::

            Although it is possible to define an RSA key pair or private key using a subset of these elements, the output from `psa_export_key()` for an RSA key pair must include all of these elements.

        See `PSA_KEY_TYPE_RSA_PUBLIC_KEY` for the data format used when exporting the public key with `psa_export_public_key()`.

    .. subsection:: Key generation

        A call to `psa_generate_key()` will generate an RSA key-pair with the default public exponent of ``65537``. The modulus :math:`n=pq` is a product of two probabilistic primes :math:`p\ \text{and}\ q`, where :math:`2^{r-1} \le n < 2^r` and :math:`r` is the bit size specified in the attributes.

        The exponent can be explicitly specified in non-default production parameters in a call to `psa_generate_key_custom()`. Use the following custom production parameters:

        *   The production parameters structure, ``custom``, must have ``flags`` set to zero.

        *   If ``custom_data_length == 0``, the default exponent value ``65537`` is used.

        *   The additional production parameter buffer ``custom_data`` is the public exponent, in little-endian byte order.

            The exponent must be an odd integer greater than ``1``.
            An implementation must support an exponent of ``65537``, and is recommended to support an exponent of ``3``, and can support other values.

            The maximum supported exponent value is :scterm:`implementation defined`.

    .. subsection:: Key derivation

        The method used by `psa_key_derivation_output_key()` to derive an RSA key-pair is :term:`implementation defined`.

.. macro:: PSA_KEY_TYPE_RSA_PUBLIC_KEY
    :definition: ((psa_key_type_t)0x4001)

    .. summary::
        RSA public key.

    The size of an RSA key is the bit size of the modulus.

    .. subsection:: Compatible algorithms

        .. hlist::
            :columns: 1

            *   `PSA_ALG_RSA_OAEP` (encryption only)
            *   `PSA_ALG_RSA_PKCS1V15_CRYPT` (encryption only)
            *   `PSA_ALG_RSA_PKCS1V15_SIGN` (signature verification only)
            *   `PSA_ALG_RSA_PKCS1V15_SIGN_RAW` (signature verification only)
            *   `PSA_ALG_RSA_PSS` (signature verification only)
            *   `PSA_ALG_RSA_PSS_ANY_SALT` (signature verification only)

    .. subsection:: Key format

        The data format for import and export of a public key is the DER encoding of the representation defined by :RFC-title:`3279#2.3.1` as ``RSAPublicKey``.

        .. code-block:: none

            RSAPublicKey ::= SEQUENCE {
                modulus            INTEGER,    -- n
                publicExponent     INTEGER  }  -- e

.. macro:: PSA_KEY_TYPE_IS_RSA
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an RSA key. This includes both key pairs and public keys.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. _ecc-keys:

Elliptic Curve keys
-------------------

Elliptic curve keys are grouped into families of related curves.
A keys for a specific curve is specified by a combination of the elliptic curve family and the bit-size of the key.

There are three categories of elliptic curve key, shown in :numref:`tab-ecc-groups`.
The curve type affects the key format, the key-derivation procedure, and the algorithms which the key can be used with.

.. list-table:: Types of elliptic curve key
    :name: tab-ecc-groups
    :align: left
    :widths: 1 4
    :header-rows: 1

    *   -   Curve type
        -   Curve families

    *   -   Weierstrass
        -   `PSA_ECC_FAMILY_SECP_K1`

            `PSA_ECC_FAMILY_SECP_R1`

            `PSA_ECC_FAMILY_SECP_R2`

            `PSA_ECC_FAMILY_SECT_K1`

            `PSA_ECC_FAMILY_SECT_R1`

            `PSA_ECC_FAMILY_SECT_R2`

            `PSA_ECC_FAMILY_BRAINPOOL_P_R1`

            `PSA_ECC_FAMILY_FRP`
    *   -   Montgomery
        -   `PSA_ECC_FAMILY_MONTGOMERY`
    *   -   Twisted Edwards
        -   `PSA_ECC_FAMILY_TWISTED_EDWARDS`

.. typedef:: uint8_t psa_ecc_family_t

    .. summary::
        The type of identifiers of an elliptic curve family.

    The curve identifier is required to create an ECC key using the `PSA_KEY_TYPE_ECC_KEY_PAIR()` or `PSA_KEY_TYPE_ECC_PUBLIC_KEY()` macros.

    The specific ECC curve within a family is identified by the ``key_bits`` attribute of the key.

    The range of elliptic curve family identifier values is divided as follows:

    :code:`0x00`
        Reserved.
        Not allocated to an ECC family.
    :code:`0x01 - 0x7f`
        ECC family identifiers defined by this standard.
        Unallocated values in this range are reserved for future use.
    :code:`0x80 - 0xff`
        Invalid.
        Values in this range must not be used.

    The least significant bit of a elliptic curve family identifier is a parity bit for the whole key type.
    See :secref:`asymmetric-key-encoding` for details of the encoding of asymmetric key types.

    .. admonition:: Implementation note

        To provide other elliptic curve families, it is recommended that an implementation defines a key type with bit 15 set, which indicates an :scterm:`implementation defined` key type.

.. macro:: PSA_KEY_TYPE_ECC_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Elliptic curve key pair: both the private and public key.

    .. param:: curve
        A value of type `psa_ecc_family_t` that identifies the ECC curve family to be used.

    The size of an elliptic curve key is the bit size associated with the curve, that is, the bit size of :math:`q`` for a curve over a field :math:`\mathbb{F}_q`.
    See the documentation of each elliptic curve family for details.

    .. subsection:: Compatible algorithms

        :numref:`tab-ecc-key-pair-algorithms` shows the compatible algorithms for each type of elliptic curve key-pair.

        .. list-table:: Compatible algorithms for elliptic curve key-pairs
            :name: tab-ecc-key-pair-algorithms
            :class: longtable
            :widths: 1,4
            :header-rows: 1

            *   -   Curve type
                -   Compatible algorithms
            *   -   Weierstrass
                -   Weierstrass curve key-pairs can be used in asymmetric signature, key-agreement, and key-encapsulation algorithms.

                    `PSA_ALG_DETERMINISTIC_ECDSA`

                    `PSA_ALG_ECDSA`

                    `PSA_ALG_ECDSA_ANY`

                    `PSA_ALG_ECDH`

                    `PSA_ALG_ECIES_SEC1`

            *   -   Montgomery
                -   Montgomery curve key-pairs can be used in key-agreement and key-encapsulation algorithms.

                    `PSA_ALG_ECDH`

                    `PSA_ALG_ECIES_SEC1`

            *   -   Twisted Edwards
                -   Twisted Edwards curve key-pairs can only be used in asymmetric signature algorithms.

                    `PSA_ALG_PURE_EDDSA`

                    `PSA_ALG_ED25519PH` (Edwards25519 only)

                    `PSA_ALG_ED448PH` (Edwards448 only)

    .. subsection:: Key format

        The data format for import and export of the key-pair depends on the type of elliptic curve.
        :numref:`tab-ecc-key-pair-format` shows the format for each type of elliptic curve key-pair.

        See `PSA_KEY_TYPE_ECC_PUBLIC_KEY` for the data format used when exporting the public key with `psa_export_public_key()`.

        .. list-table:: Key-pair formats for elliptic curve keys
            :name: tab-ecc-key-pair-format
            :class: longtable
            :widths: 1,4
            :header-rows: 1

            *   -   Curve type
                -   Key-pair format
            *   -   Weierstrass
                -   The key data is the content of the ``privateKey`` field of the ``ECPrivateKey`` format defined by :RFC-title:`5915`.

                    This is a :math:`\lceil{m/8}\rceil`-byte string in big-endian order, where :math:`m` is the key size in bits.

            *   -   Montgomery
                -   The key data is the scalar value of the 'private key' in little-endian order as defined by :RFC-title:`7748#6`.
                    The value must have the forced bits set to zero or one as specified by ``decodeScalar25519()`` and ``decodeScalar448()`` in :RFC:`7748#5`.

                    This is a :math:`\lceil{m/8}\rceil`-byte string where :math:`m` is the key size in bits.
                    This is 32 bytes for Curve25519, and 56 bytes for Curve448.

            *   -   Twisted Edwards
                -   The key data is the private key, as defined by :RFC-title:`8032`.

                    This is a 32-byte string for Edwards25519, and a 57-byte string for Edwards448.

    .. subsection:: Key derivation

        The key-derivation method used when calling `psa_key_derivation_output_key()` depends on the type of elliptic curve.
        :numref:`tab-ecc-key-derivation` shows the derivation method for each type of elliptic curve key.

        .. list-table:: Key derivation for elliptic curve keys
            :name: tab-ecc-key-derivation
            :class: longtable
            :widths: 1,4
            :header-rows: 1

            *   -   Curve type
                -   Key derivation
            *   -   Weierstrass
                -   A Weierstrass elliptic curve private key is :math:`d \in [1, N - 1]`, where :math:`N` is the order of the curve's base point for ECC.

                    Let :math:`m` be the bit size of :math:`N`, such that :math:`2^{m-1} \leq N < 2^m`. This function generates the private key using the following process:

                    1.  Draw a byte string of length :math:`\lceil{m/8}\rceil` bytes.
                    #.  If :math:`m` is not a multiple of 8, set the most significant :math:`8 * \lceil{m/8}\rceil - m`` bits of the first byte in the string to zero.
                    #.  Convert the string to integer :math:`k` by decoding it as a big-endian byte-string.
                    #.  If :math:`k > N-2`, discard the result and return to step 1.
                    #.  Output :math:`d = k + 1` as the private key.

                    This method allows compliance to NIST standards, specifically the methods titled *Key-Pair Generation by Testing Candidates* in :cite:`SP800-56A` §5.6.1.2.2 or :cite-title:`FIPS186-4` §B.4.2.

            *   -   Montgomery
                -   Draw a byte string whose length is determined by the curve, and set the mandatory bits accordingly.
                    That is:

                    *   Curve25519 (`PSA_ECC_FAMILY_MONTGOMERY`, 255 bits): draw a 32-byte string and process it as specified in :RFC-title:`7748#5`.
                    *   Curve448 (`PSA_ECC_FAMILY_MONTGOMERY`, 448 bits): draw a 56-byte string and process it as specified in :RFC:`7748#5`.

            *   -   Twisted Edwards
                -   Draw a byte string whose length is determined by the curve, and use this as the private key.
                    That is:

                    *   Ed25519 (`PSA_ECC_FAMILY_MONTGOMERY`, 255 bits): draw a 32-byte string.
                    *   Ed448 (`PSA_ECC_FAMILY_MONTGOMERY`, 448 bits): draw a 57-byte string.

.. macro:: PSA_KEY_TYPE_ECC_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Elliptic curve public key.

    .. param:: curve
        A value of type `psa_ecc_family_t` that identifies the ECC curve family to be used.

    The size of an elliptic curve public key is the same as the corresponding private key. See `PSA_KEY_TYPE_ECC_KEY_PAIR()` and the documentation of each elliptic curve family for details.

    .. subsection:: Compatible algorithms

        :numref:`tab-ecc-public-key-algorithms` shows the compatible algorithms for each type of elliptic curve public key.

        .. note::

            For key agreement, the public key of the peer is provided to the |API| as a buffer.
            This avoids the need to import the public-key data that is received from the peer, just to carry out the key-agreement algorithm.

        .. list-table:: Compatible algorithms for elliptic curve public keys
            :name: tab-ecc-public-key-algorithms
            :class: longtable
            :widths: 1,4
            :header-rows: 1

            *   -   Curve type
                -   Compatible algorithms
            *   -   Weierstrass
                -   Weierstrass curve public keys can be used in asymmetric signature and key-encapsulation algorithms.

                    `PSA_ALG_DETERMINISTIC_ECDSA`

                    `PSA_ALG_ECDSA`

                    `PSA_ALG_ECDSA_ANY`

                    `PSA_ALG_ECIES_SEC1`

            *   -   Montgomery
                -   Montgomery curve public keys can only be used in key-encapsulation algorithms.

                    `PSA_ALG_ECIES_SEC1`

            *   -   Twisted Edwards
                -   Twisted Edwards curve public keys can only be used in asymmetric signature algorithms.

                    `PSA_ALG_PURE_EDDSA`

                    `PSA_ALG_ED25519PH` (Edwards25519 only)

                    `PSA_ALG_ED448PH` (Edwards448 only)

    .. subsection:: Key format

        The data format for import and export of the public key depends on the type of elliptic curve.
        :numref:`tab-ecc-public-key-format` shows the format for each type of elliptic curve public key.

        .. list-table:: Public-key formats for elliptic curve keys
            :name: tab-ecc-public-key-format
            :class: longtable
            :widths: 1,4
            :header-rows: 1

            *   -   Curve type
                -   Public-key format
            *   -   Weierstrass
                -   The key data is the uncompressed representation of an elliptic curve point as an octet string defined in :cite-title:`SEC1` §2.3.3.
                    If :math:`m` is the bit size associated with the curve, i.e. the bit size of :math:`q` for a curve over :math:`\mathbb{F}_q`, then the representation of point :math:`P` consists of:

                    *   The byte ``0x04``;
                    *   :math:`x_P` as a :math:`\lceil{m/8}\rceil`-byte string, big-endian;
                    *   :math:`y_P` as a :math:`\lceil{m/8}\rceil`-byte string, big-endian.

            *   -   Montgomery
                -   The key data is the scalar value of the 'public key' in little-endian order as defined by :RFC-title:`7748#6`.
                    This is a :math:`\lceil{m/8}\rceil`-byte string where :math:`m` is the key size in bits.

                    *   This is 32 bytes for Curve25519, computed as ``X25519(private_key, 9)``.
                    *   This is 56 bytes for Curve448, computed as ``X448(private_key, 5)``.

            *   -   Twisted Edwards
                -   The key data is the public key, as defined by :RFC-title:`8032`.

                    This is a 32-byte string for Edwards25519, and a 57-byte string for Edwards448.

.. macro:: PSA_ECC_FAMILY_SECP_K1
    :definition: ((psa_ecc_family_t) 0x17)

    .. summary::
        SEC Koblitz curves over prime fields.

    This family comprises the following curves:

    *   secp192k1 : ``key_bits = 192``
    *   secp224k1 : ``key_bits = 225``
    *   secp256k1 : ``key_bits = 256``

    They are defined in :cite-title:`SEC2`.

.. macro:: PSA_ECC_FAMILY_SECP_R1
    :definition: ((psa_ecc_family_t) 0x12)

    .. summary::
        SEC random curves over prime fields.

    This family comprises the following curves:

    *   secp192r1 : ``key_bits = 192``
    *   secp224r1 : ``key_bits = 224``
    *   secp256r1 : ``key_bits = 256``
    *   secp384r1 : ``key_bits = 384``
    *   secp521r1 : ``key_bits = 521``

    They are defined in :cite:`SEC2`.

.. macro:: PSA_ECC_FAMILY_SECP_R2
    :definition: ((psa_ecc_family_t) 0x1b)

    .. summary::
        .. warning::
            This family of curves is weak and deprecated.

    This family comprises the following curves:

    *   secp160r2 : ``key_bits = 160`` *(Deprecated)*

    It is defined in the superseded :cite-title:`SEC2v1`.

.. macro:: PSA_ECC_FAMILY_SECT_K1
    :definition: ((psa_ecc_family_t) 0x27)

    .. summary::
        SEC Koblitz curves over binary fields.

    This family comprises the following curves:

    *   sect163k1 : ``key_bits = 163`` *(Deprecated)*
    *   sect233k1 : ``key_bits = 233``
    *   sect239k1 : ``key_bits = 239``
    *   sect283k1 : ``key_bits = 283``
    *   sect409k1 : ``key_bits = 409``
    *   sect571k1 : ``key_bits = 571``

    They are defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163k1 is weak and deprecated and is only recommended for use in legacy applications.

.. macro:: PSA_ECC_FAMILY_SECT_R1
    :definition: ((psa_ecc_family_t) 0x22)

    .. summary::
        SEC random curves over binary fields.

    This family comprises the following curves:

    *   sect163r1 : ``key_bits = 163`` *(Deprecated)*
    *   sect233r1 : ``key_bits = 233``
    *   sect283r1 : ``key_bits = 283``
    *   sect409r1 : ``key_bits = 409``
    *   sect571r1 : ``key_bits = 571``

    They are defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163r1 is weak and deprecated and is only recommended for use in legacy applications.

.. macro:: PSA_ECC_FAMILY_SECT_R2
    :definition: ((psa_ecc_family_t) 0x2b)

    .. summary::
        SEC additional random curves over binary fields.

    This family comprises the following curves:

    *   sect163r2 : ``key_bits = 163`` *(Deprecated)*

    It is defined in :cite:`SEC2`.

    .. warning::
        The 163-bit curve sect163r2 is weak and deprecated and is only recommended for use in legacy applications.

.. macro:: PSA_ECC_FAMILY_BRAINPOOL_P_R1
    :definition: ((psa_ecc_family_t) 0x30)

    .. summary::
        Brainpool P random curves.

    This family comprises the following curves:

    *   brainpoolP160r1 : ``key_bits = 160`` *(Deprecated)*
    *   brainpoolP192r1 : ``key_bits = 192``
    *   brainpoolP224r1 : ``key_bits = 224``
    *   brainpoolP256r1 : ``key_bits = 256``
    *   brainpoolP320r1 : ``key_bits = 320``
    *   brainpoolP384r1 : ``key_bits = 384``
    *   brainpoolP512r1 : ``key_bits = 512``

    They are defined in :rfc-title:`5639`.

    .. warning::
        The 160-bit curve brainpoolP160r1 is weak and deprecated and is only recommended for use in legacy applications.

.. macro:: PSA_ECC_FAMILY_FRP
    :definition: ((psa_ecc_family_t) 0x33)

    .. summary::
        Curve used primarily in France and elsewhere in Europe.

    This family comprises one 256-bit curve:

    *   FRP256v1 : ``key_bits = 256``

    This is defined by :cite-title:`FRP`.

.. macro:: PSA_ECC_FAMILY_MONTGOMERY
    :definition: ((psa_ecc_family_t) 0x41)

    .. summary::
        Montgomery curves.

    This family comprises the following Montgomery curves:

    *   Curve25519 : ``key_bits = 255``
    *   Curve448 : ``key_bits = 448``

    Curve25519 is defined in :cite-title:`Curve25519`. Curve448 is defined in :cite-title:`Curve448`.

.. macro:: PSA_ECC_FAMILY_TWISTED_EDWARDS
    :definition: ((psa_ecc_family_t) 0x42)

    .. summary::
        Twisted Edwards curves.

        .. versionadded:: 1.1

    This family comprises the following twisted Edwards curves:

    *   Edwards25519 : ``key_bits = 255``. This curve is birationally equivalent to Curve25519.
    *   Edwards448 : ``key_bits = 448``. This curve is birationally equivalent to Curve448.

    Edwards25519 is defined in :cite-title:`Ed25519`. Edwards448 is defined in :cite-title:`Curve448`.

.. macro:: PSA_KEY_TYPE_IS_ECC
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve key, either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_ECC_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is an elliptic curve public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_ECC_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the curve family from an elliptic curve key type.

    .. param:: type
        An elliptic curve key type: a value of type `psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_ECC(type)` is true.

    .. return:: psa_ecc_family_t
        The elliptic curve family id, if ``type`` is a supported elliptic curve key. Unspecified if ``type`` is not a supported elliptic curve key.

.. _dh-keys:

Diffie Hellman keys
-------------------

.. typedef:: uint8_t psa_dh_family_t

    .. summary::
        The type of identifiers of a finite-field Diffie-Hellman group family.

    The group family identifier is required to create a finite-field Diffie-Hellman key using the `PSA_KEY_TYPE_DH_KEY_PAIR()` or `PSA_KEY_TYPE_DH_PUBLIC_KEY()` macros.

    The specific Diffie-Hellman group within a family is identified by the ``key_bits`` attribute of the key.

    The range of Diffie-Hellman group family identifier values is divided as follows:

    :code:`0x00`
        Reserved.
        Not allocated to a DH group family.
    :code:`0x01 - 0x7f`
        DH group family identifiers defined by this standard.
        Unallocated values in this range are reserved for future use.
    :code:`0x80 - 0xff`
        Invalid.
        Values in this range must not be used.

    The least significant bit of a Diffie-Hellman group family identifier is a parity bit for the whole key type.
    See :secref:`asymmetric-key-encoding` for details of the encoding of asymmetric key types.

    .. admonition:: Implementation note

        To provide other Diffie-Hellman group families, it is recommended that an implementation defines a key type with bit 15 set, which indicates an :scterm:`implementation defined` key type.

.. macro:: PSA_KEY_TYPE_DH_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Finite-field Diffie-Hellman key pair: both the private key and public key.

    .. param:: group
        A value of type `psa_dh_family_t` that identifies the Diffie-Hellman group family to be used.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_FFDH`

    .. subsection:: Key format

        The data format for import and export of the key pair is the representation of the private key :math:`x` as a big-endian byte string.
        The length of the byte string is the private key's size in bytes, and leading zeroes are not stripped.

        See `PSA_KEY_TYPE_DH_PUBLIC_KEY` for the data format used when exporting the public key with `psa_export_public_key()`.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will use the following process, defined in *Key-Pair Generation by Testing Candidates* in :cite-title:`SP800-56A` §5.6.1.1.4.

        A Diffie-Hellman private key is :math:`x \in [1, p - 1]`, where :math:`p` is the group's prime modulus.
        Let :math:`m` be the bit size of :math:`p`, such that :math:`2^{m-1} \leq p < 2^m`.

        This function generates the private key using the following process:

        1.  Draw a byte string of length :math:`\lceil{m/8}\rceil` bytes.
        #.  If :math:`m` is not a multiple of 8, set the most significant :math:`8 * \lceil{m/8}\rceil - m`` bits of the first byte in the string to zero.
        #.  Convert the string to integer :math:`k` by decoding it as a big-endian byte-string.
        #.  If :math:`k > p-2`, discard the result and return to step 1.
        #.  Output :math:`x = k + 1` as the private key.

.. macro:: PSA_KEY_TYPE_DH_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Finite-field Diffie-Hellman public key.

    .. param:: group
        A value of type `psa_dh_family_t` that identifies the Diffie-Hellman group family to be used.

    .. subsection:: Compatible algorithms

        None: Finite-field Diffie-Hellman public keys are exported to use in a key-agreement algorithm, and the peer key is provided to the `PSA_ALG_FFDH` key-agreement algorithm as a buffer of key data.

    .. subsection:: Key format

        The data format for export of the public key is the representation of the public key :math:`y = g^x\!\mod p` as a big-endian byte string.
        The length of the byte string is the length of the base prime :math:`p` in bytes.

.. macro:: PSA_DH_FAMILY_RFC7919
    :definition: ((psa_dh_family_t) 0x03)

    .. summary::
        Finite-field Diffie-Hellman groups defined for TLS in RFC 7919.

    This family includes groups with the following key sizes (in bits): 2048, 3072, 4096, 6144, 8192.
    An implementation can support all of these sizes or only a subset.

    Keys is this group can only be used with the `PSA_ALG_FFDH` key-agreement algorithm.

    These groups are defined by :rfc-title:`7919#A`.

.. macro:: PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        The key-pair type corresponding to a public-key type.

    .. param:: type
        A public-key type or key-pair type.

    .. return::
        The corresponding key-pair type. If ``type`` is not a public key or a key pair, the return value is undefined.

    If ``type`` is a key-pair type, it will be left unchanged.

.. macro:: PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        The public-key type corresponding to a key-pair type.

    .. param:: type
        A public-key type or key-pair type.

    .. return::
        The corresponding public-key type. If ``type`` is not a public key or a key pair, the return value is undefined.

    If ``type`` is a public-key type, it will be left unchanged.

.. macro:: PSA_KEY_TYPE_IS_DH
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman key, either a key pair or a public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_DH_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman key pair.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_DH_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a Diffie-Hellman public key.

    .. param:: type
        A key type: a value of type `psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_DH_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the group family from a Diffie-Hellman key type.

    .. param:: type
        A Diffie-Hellman key type: a value of type `psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_DH(type)` is true.

    .. return:: psa_dh_family_t
        The Diffie-Hellman group family id, if ``type`` is a supported Diffie-Hellman key. Unspecified if ``type`` is not a supported Diffie-Hellman key.

.. _spake2p-keys:

SPAKE2+ keys
------------

.. macro:: PSA_KEY_TYPE_SPAKE2P_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        SPAKE2+ key pair: both the prover and verifier key.

        .. versionadded:: 1.2

    .. param:: curve
        A value of type :code:`psa_ecc_family_t` that identifies the elliptic curve family to be used.

    The bit-size of a SPAKE2+ key is the size associated with the elliptic curve group, that is, :math:`\lceil{log_2(q)}\rceil` for a curve over a field :math:`\mathbb{F}_q`.
    See :secref:`ecc-keys` for details of each elliptic curve family.

    To create a new SPAKE2+ key pair, use :code:`psa_key_derivation_output_key()` as described in :secref:`spake2p-registration`.
    The SPAKE2+ protocol recommends that a key-stretching key-derivation function, such as PBKDF2, is used to hash the SPAKE2+ password.
    This follows the recommended process described in :rfc:`9383`.

    A SPAKE2+ key pair can also be imported from a previously exported SPAKE2+ key pair.

    The corresponding public key can be exported using :code:`psa_export_public_key()`.
    See also `PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY()`.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_SPAKE2P_HMAC`
            *   `PSA_ALG_SPAKE2P_CMAC`
            *   `PSA_ALG_SPAKE2P_MATTER`

    .. subsection:: Key format

        A SPAKE2+ key pair consists of the two values :math:`w0` and :math:`w1`, which result from the SPAKE2+ registration phase, see :secref:`spake2p-registration`.
        :math:`w0` and :math:`w1` are scalars in the same range as an elliptic curve private key from the group used as the SPAKE2+ primitive group.

        The data format for import and export of the key pair is the concatenation of the formatted values for :math:`w0` and :math:`w1`, using the standard formats for elliptic curve keys used by the |API|.
        For example, for SPAKE2+ over P-256 (secp256r1), the output from :code:`psa_export_key()` would be the concatenation of:

        *   The P-256 private key :math:`w0`.
            This is a 32-byte big-endian encoding of the integer :math:`w0`.
        *   The P-256 private key :math:`w1`.
            This is a 32-byte big-endian encoding of the integer :math:`w1`.

        See `PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY` for the data format used when exporting the public key with `psa_export_public_key()`.

    .. subsection:: Key derivation

        A call to `psa_key_derivation_output_key()` will use the following process, which follows the recommendations for the registration process in :rfc-title:`9383`, and matches the specification of this process in :cite-title:`MATTER`.

        The derivation of SPAKE2+ keys extracts :math:`\lceil{log_2(p)/8}\rceil+8` bytes from the PBKDF for each of :math:`w0s` and :math:`w1s`, where :math:`p` is the prime factor of the order of the elliptic curve group.
        The following sizes are used for extracting :math:`w0s` and :math:`w1s`, depending on the elliptic curve:

        *   P-256: 40 bytes
        *   P-384: 56 bytes
        *   P-521: 74 bytes
        *   edwards25519: 40 bytes
        *   edwards448: 64 bytes

        The calculation of :math:`w0`, :math:`w1`, and :math:`L` then proceeds as described in :rfc:`9383`.

        .. admonition:: Implementation note

            The values of :math:`w0` and :math:`w1` are required as part of the SPAKE2+ key pair.

            It is :scterm:`implementation defined` whether :math:`L` is computed during key derivation, and stored as part of the key pair; or only computed when required from the key pair.

.. macro:: PSA_KEY_TYPE_SPAKE2P_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        SPAKE2+ public key: the verifier key.

        .. versionadded:: 1.2

    .. param:: curve
        A value of type :code:`psa_ecc_family_t` that identifies the elliptic curve family to be used.

    The bit-size of an SPAKE2+ public key is the same as the corresponding private key.
    See `PSA_KEY_TYPE_SPAKE2P_KEY_PAIR()` and the documentation of each elliptic curve family for details.

    To construct a SPAKE2+ public key, it must be imported.

    .. subsection:: Compatible algorithms

        .. hlist::

            *   `PSA_ALG_SPAKE2P_HMAC` (verification only)
            *   `PSA_ALG_SPAKE2P_CMAC` (verification only)
            *   `PSA_ALG_SPAKE2P_MATTER` (verification only)

    .. subsection:: Key format

        A SPAKE2+ public key consists of the two values :math:`w0` and :math:`L`, which result from the SPAKE2+ registration phase, see :secref:`spake2p-registration`.
        :math:`w0` is a scalar in the same range as a elliptic curve private key from the group used as the SPAKE2+ primitive group.
        :math:`L` is a point on the curve, similar to a public key from the same group, corresponding to the :math:`w1` value in the key pair.

        The data format for import and export of the public key is the concatenation of the formatted values for :math:`w0` and :math:`L`, using the standard formats for elliptic curve keys used by the |API|.
        For example, for SPAKE2+ over P-256 (secp256r1), the output from :code:`psa_export_public_key()` would be the concatenation of:

        *   The P-256 private key :math:`w0`.
            This is a 32-byte big-endian encoding of the integer :math:`w0`.
        *   The P-256 public key :math:`L`.
            This is a 65-byte concatenation of:

            -   The byte ``0x04``.
            -   The 32-byte big-endian encoding of the x-coordinate of :math:`L`.
            -   The 32-byte big-endian encoding of the y-coordinate of :math:`L`.

.. macro:: PSA_KEY_TYPE_IS_SPAKE2P
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a SPAKE2+ key, either a key pair or a public key.

        .. versionadded:: 1.2

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_SPAKE2P_KEY_PAIR
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a SPAKE2+ key pair.

        .. versionadded:: 1.2

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_IS_SPAKE2P_PUBLIC_KEY
    :definition: /* specification-defined value */

    .. summary::
        Whether a key type is a SPAKE2+ public key.

        .. versionadded:: 1.2

    .. param:: type
        A key type: a value of type :code:`psa_key_type_t`.

.. macro:: PSA_KEY_TYPE_SPAKE2P_GET_FAMILY
    :definition: /* specification-defined value */

    .. summary::
        Extract the curve family from a SPAKE2+ key type.

        .. versionadded:: 1.2

    .. param:: type
        A SPAKE2+ key type: a value of type :code:`psa_key_type_t` such that :code:`PSA_KEY_TYPE_IS_SPAKE2P(type)` is true.

    .. return:: psa_ecc_family_t
        The elliptic curve family id, if ``type`` is a supported SPAKE2+ key. Unspecified if ``type`` is not a supported SPAKE2+ key.

Attribute accessors
-------------------

.. function:: psa_set_key_type

    .. summary::
        Declare the type of a key.

    .. param:: psa_key_attributes_t * attributes
        The attribute object to write to.
    .. param:: psa_key_type_t type
        The key type to write. If this is `PSA_KEY_TYPE_NONE`, the key type in ``attributes`` becomes unspecified.

    .. return:: void

    This function overwrites any key type previously set in ``attributes``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_get_key_type

    .. summary::
        Retrieve the key type from key attributes.

    .. param:: const psa_key_attributes_t * attributes
        The key attribute object to query.

    .. return:: psa_key_type_t
        The key type stored in the attribute object.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_get_key_bits

    .. summary::
        Retrieve the key size from key attributes.

    .. param:: const psa_key_attributes_t * attributes
        The key attribute object to query.

    .. return:: size_t
        The key size stored in the attribute object, in bits.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.


.. function:: psa_set_key_bits

    .. summary::
        Declare the size of a key.

    .. param:: psa_key_attributes_t * attributes
        The attribute object to write to.
    .. param:: size_t bits
        The key size in bits. If this is ``0``, the key size in ``attributes`` becomes unspecified. Keys of size ``0`` are not supported.

    .. return:: void

    This function overwrites any key size previously set in ``attributes``.

    .. admonition:: Implementation note

        This is a simple accessor function that is not required to validate its inputs. It can be efficiently implemented as a ``static inline`` function or a function-like-macro.

.. SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

Changes to the API
==================

.. _changes:

Document change history
-----------------------

Changes between *Beta 0* and *Beta 1*
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Clarifications and fixes
~~~~~~~~~~~~~~~~~~~~~~~~

*   Added references from each section to the relevant APIs in :cite-title:`PSA-CRYPT`.

Beta release
^^^^^^^^^^^^

First release of the PQC Extension.

*   Added support for FIPS 203 ML-KEM key-encapsulation algorithm and keys.
    See :secref:`ml-kem`.
*   Added support for FIPS 204 ML-DSA signature algorithm and keys.
    See :secref:`ml-dsa`.
*   Added support for FIPS 205 SLH-DSA signature algorithm and keys.
    See :secref:`slh-dsa`.
*   Added support for LMS and HSS stateful hash-based signature verification and public keys.
    See :secref:`lms`.
*   Added support for XMSS and |XMSS^MT| stateful hash-based signature verification and public keys.
    See :secref:`xmss`.

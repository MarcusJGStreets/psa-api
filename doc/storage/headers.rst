.. SPDX-FileCopyrightText: Copyright 2018-2019, 2022 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _appendix-headers:

Example header files
====================

Each implementation of the |API| must provide a header file named :file:`psa/storage_common.h`, and also any of :file:`psa/internal_trusted_storage.h` and :file:`psa/protected_storage.h` for the APIs that are implemented.

This appendix provides examples of the header files with all of the API elements. This can be used as a starting point or reference for an implementation.

psa/storage_common.h
--------------------

.. insert-header:: psa/storage_common

psa/internal_trusted_storage.h
------------------------------

.. insert-header:: psa/internal_trusted_storage

psa/protected_storage.h
-----------------------

.. insert-header:: psa/protected_storage

.. SPDX-FileCopyrightText: Copyright 2018-2019, 2022-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
.. SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

.. _document-history:

Document history
================

..  list-table::
    :class: longtable
    :header-rows: 1
    :widths: 3 3 14

    * - Date
      - Release
      - Details

    * - 2019-02-25
      - *1.0 Beta 2*
      - First Release

    * - 2019-06-12
      - *1.0 Rel*
      - Final 1.0 API

        * The protected storage API now supports flags `PSA_STORAGE_FLAG_NO_CONFIDENTIALITY` and `PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION`.
        * Error values now use standard PSA error codes, which are now defined in :file:`<psa/error.h>`.
        * Input parameters are now separate from output parameters. There are no longer any in/out parameters.
        * Size types have been replaced with ``size_t`` instead of ``uint32_t``.

    * - 2022-10-17
      - *1.0.1 Rel*
      - * Relicensed the document under Attribution-ShareAlike 4.0 International with a patent license derived from Apache License 2.0. See :secref:`license`.
        * Documentation clarifications.

    * - 2023-03-23
      - *1.0.2 Rel*
      - * Clarified the protection requirements for ITS. See :secref:`its-requirements`.
        * Fixed inconsistent descriptions of :code:`PSA_ERROR_STORAGE_FAILURE` errors.
        
    * - 2023-08-1
      - *1.0.3 RC1*
      - * Ontroduced a Security Risk Assessment 

        

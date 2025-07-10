# SPDX-FileCopyrightText: Copyright 2024-2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

# PSA Certified API document configuration
#
# This is used to generate all of the sphinx configuration data and determine
# the document file name etc.

doc_info = {
    # Document template
    'template': 'psa-api-2025',

    # Document title, MANDATORY
    'title': 'PSA Certified\nCrypto API',
    'author': 'Arm Limited',

    # Document copyright date, default to year of 'date'
    'copyright_date': '2024-2025',
    'copyright': 'Arm Limited and/or its affiliates',

    # Arm document identifier, marked as open issue if not provided
    'doc_id': 'AES 0119',

    # The short X.Y version. MANDATORY
    'version': '1.3',
    'extension_doc': 'PQC Extension',

    # Arm document quality status, marked as open issue if not provided
    'quality': 'BET',
    # Arm document issue number (within that version and quality status)
    # Marked as open issue if not provided
    'issue_no': 1,
    # Identifies the sequence number of a release candidate of the same issue
    # default to None
    'release_candidate': 0,
    # Draft status - use this to indicate the document is not ready for publication
    'draft': False,

    # Arm document confidentiality. Must be either Non-confidential or Confidential
    # Marked as open issue if not provided
    'confidentiality': 'Non-confidential',

    # Id of the legal notice for this document
    # Marked as open issue if not provided
    'license': 'psa-certified-api-license',

    # Document date, default to build date
    'date': '10/06/2025',

    # Default header file for API definitions
    # default to None, and can be set in documentation source
#    'header': 'psa/crypto',

    # Doxygen annotation level of the generated header
    #    0 : None (default)
    #    1 : Primary API elements
    #    2 : Sub-elements of API - parameters, fields, values
    'header_doxygen': 2,

    # Declare a watermark for the PDF output
    #'watermark': 'DRAFT',

    # List of optional content that should be included in the build.
    # Valid options are:
    #   'rationale' : This enables output of ..rationale:: directives
    #   'banner'    : This enables output of the title page banner
    #   'todo'      : This enables output of ..todo:: directives
    'include_content': ['banner','rationale'],

    # Optional ordering of return error values
    # This list is used to create a standard ordering of return value responses
    # throughout the document, irrespective of their ordering in the source text
    # Return values that are not in the ordering are sorted above any that are in
    # the list and appear in source text order.

    'error_order': [
        'PSA_SUCCESS',
        'PSA_ERROR_BAD_STATE',
        'PSA_ERROR_INVALID_HANDLE',
        'PSA_ERROR_NOT_PERMITTED',
        'PSA_ERROR_INVALID_SIGNATURE',
        'PSA_ERROR_ALREADY_EXISTS',
        'PSA_ERROR_INSUFFICIENT_DATA',
        'PSA_ERROR_BUFFER_TOO_SMALL',
        'PSA_ERROR_INVALID_PADDING',
        'PSA_ERROR_INVALID_ARGUMENT',
        'PSA_ERROR_NOT_SUPPORTED',
        'PSA_ERROR_INSUFFICIENT_ENTROPY',
        'PSA_ERROR_INSUFFICIENT_MEMORY',
        'PSA_ERROR_INSUFFICIENT_STORAGE',
        'PSA_ERROR_COMMUNICATION_FAILURE',
        'PSA_ERROR_CORRUPTION_DETECTED',
        'PSA_ERROR_STORAGE_FAILURE',
        'PSA_ERROR_DATA_CORRUPT',
        'PSA_ERROR_DATA_INVALID'
    ],

    # Include the C Identifier index. Default to True
    'identifier_index': True,

    # Specify where to add page breaks in main/appendix
    #   'none'     : no page breaks
    #   'appendix' : just before the appendices
    #   'chapter'  : before every chapter
    # Default to 'appendix'
    'page_break': 'chapter',

    'prolog_files': ['/substitutions'],
    }

# absolute or relative path to the psa_spec material from this file
# atg_sphinx_spec_dir = '../atg-sphinx-spec'

# Set up and run the atg-sphinx-spec configuration

import os

atg_sphinx_spec_dir = os.environ.get('ATG_SPHINX_SPEC') or atg_sphinx_spec_dir
exec(compile(open(os.path.join(atg_sphinx_spec_dir,'atg-sphinx-conf.py'),
                  encoding='utf-8').read(),
             'atg-sphinx-conf.py', 'exec'))

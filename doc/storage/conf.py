# SPDX-FileCopyrightText: Copyright 2018-2019, 2022-2023 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: CC-BY-SA-4.0 AND LicenseRef-Patent-license

# PSA Certified API document configuration
#
# This is used to generate all of the sphinx configuration data and determine
# the document file name etc.

doc_info = {
    # Document template
    'template': 'psa-api-2022',

    # Document title, MANDATORY
    'title': 'PSA Certified\nSecure Storage API',
    'author': 'Arm Limited',

    # Document copyright date, default to year of 'date'
    'copyright_date': '2018-2019, 2022-2023',
    'copyright': 'Arm Limited and/or its affiliates',

    # Arm document identifier, marked as open issue if not provided
    'doc_id': 'IHI 0087',

    # The short X.Y version. MANDATORY
    'version': '1.0',
    # Arm document quality status, marked as open issue if not provided
    'quality': 'REL',
    # Arm document issue number (within that version and quality status)
    # Marked as open issue if not provided
    'issue_no': 3,
    # Identifies the sequence number of a release candidate of the same issue
    # default to None
    'release_candidate': 2,
    # Draft status - use this to indicate the document is not ready for publication
    # 'draft': True,

    # Arm document confidentiality. Must be either Non-confidential or Confidential
    # Marked as open issue if not provided
    'confidentiality': 'Non-confidential',

    # Id of the legal notice for this document
    # Marked as open issue if not provided
    'license': 'psa-certified-api-license',

    # Document date, default to build date


    # psa_spec: default header file for API definitions
    # default to None, and can be set in documentation source
    #'header': '',

    # Doxygen annotation level of the generated header
    #    0 : None (default)
    #    1 : Primary API elements
    #    2 : Sub-elements of API - parameters, fields, values
    'header_doxygen': 2,

    # Declare a watermark for the PDF output
    # 'watermark': 'DRAFT',

    # Optional ordering of return error values
    # This list is used to create a standard ordering of return value responses
    # throughout the document, irrespective of their ordering in the source text
    # Return values that are not in the ordering are sorted above any that are in
    # the list and appear in source text order.

    'error_order': [
        'PSA_SUCCESS',
        'PSA_ERROR_NOT_PERMITTED',
        'PSA_ERROR_INVALID_SIGNATURE',
        'PSA_ERROR_DOES_NOT_EXIST',
        'PSA_ERROR_INVALID_ARGUMENT',
        'PSA_ERROR_NOT_SUPPORTED',
        'PSA_ERROR_INSUFFICIENT_STORAGE',
        'PSA_ERROR_STORAGE_FAILURE',
        'PSA_ERROR_DATA_CORRUPT',
    ],

    # Include the C Identifier index. Default to True
    'identifier_index': True,

    # Specify where to add page breaks in main/appendix
    #   'none'     : no page breaks
    #   'appendix' : just before the appendices
    #   'chapter'  : before every chapter
    # Default to 'appendix'
    'page_break': 'chapter',
    }

# If the draft flag is set, then include extra content and watermark

if doc_info.get('draft'):
    doc_info.pop('date', None)                      # Remove any release date - use build date
    doc_info['include_content'] = ['rationale', 'todo', 'banner']
    doc_info['watermark'] = "DRAFT"

# If a release candidate, then include watermark

if doc_info.get('release_candidate'):
    doc_info['watermark'] = "Candidate"

# absolute or relative path to the psa_spec material from this file
# atg_sphinx_spec_dir = '../atg-sphinx-spec'

# Set up and run the atg-sphinx-spec configuration

import os

atg_sphinx_spec_dir = os.environ.get('ATG_SPHINX_SPEC') or atg_sphinx_spec_dir
exec(compile(open(os.path.join(atg_sphinx_spec_dir,'atg-sphinx-conf.py'),
                  encoding='utf-8').read(),
             'atg-sphinx-conf.py', 'exec'))

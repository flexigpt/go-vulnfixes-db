CWE_FUNCTIONAL_AREAS = {
    'Security and Access Control':
        {
            'Authorization':
                [
                    {
                        'CWE-ID': '1220',
                        'Name': 'Insufficient Granularity of Access Control',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '283',
                        'Name': 'Unverified Ownership',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '425',
                        'Name': "Direct Request ('Forced Browsing')",
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '551',
                        'Name': 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '639',
                        'Name': 'Authorization Bypass Through User-Controlled Key',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '653',
                        'Name': 'Improper Isolation or Compartmentalization',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '708',
                        'Name': 'Incorrect Ownership Assignment',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '842',
                        'Name': 'Placement of User into Incorrect Group',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '939',
                        'Name': 'Improper Authorization in Handler for Custom URL Scheme',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '656',
                        'Name': 'Reliance on Security Through Obscurity',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '501',
                        'Name': 'Trust Boundary Violation',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '360',
                        'Name': 'Trust of System Event Data',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '374',
                        'Name': 'Passing Mutable Objects to an Untrusted Method',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '375',
                        'Name': 'Returning a Mutable Object to an Untrusted Caller',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '837',
                        'Name': 'Improper Enforcement of a Single, Unique Action',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '454',
                        'Name': 'External Initialization of Trusted Variables or Data Stores',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '470',
                        'Name': "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')",
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '472',
                        'Name': 'External Control of Assumed-Immutable Web Parameter',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '807',
                        'Name': 'Reliance on Untrusted Inputs in a Security Decision',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '915',
                        'Name': 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '224',
                        'Name': 'Obscured Security-relevant Information by Alternate Name',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '1327',
                        'Name': 'Binding to an Unrestricted IP Address',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '437',
                        'Name': 'Incomplete Model of Endpoint Features',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '243',
                        'Name': 'Creation of chroot Jail Without Changing Working Directory',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '1125',
                        'Name': 'Excessive Attack Surface',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '358',
                        'Name': 'Improperly Implemented Security Check for Standard',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '829',
                        'Name': 'Inclusion of Functionality from Untrusted Control Sphere',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }, {
                        'CWE-ID': '918',
                        'Name': 'Server-Side Request Forgery (SSRF)',
                        'CWE-Category': 'Authorization Errors',
                        'CWE-Category-ID': '1212'
                    }
                ],
            'Information Management':
                [
                    {
                        'CWE-ID': '201',
                        'Name': 'Insertion of Sensitive Information Into Sent Data',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '359',
                        'Name': 'Exposure of Private Personal Information to an Unauthorized Actor',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '497',
                        'Name': 'Exposure of Sensitive System Information to an Unauthorized Control Sphere',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '766',
                        'Name': 'Critical Data Element Declared Public',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '767',
                        'Name': 'Access to Critical Private Variable via Public Method',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '403',
                        'Name': "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')",
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '1230',
                        'Name': 'Exposure of Sensitive Information Through Metadata',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '209',
                        'Name': 'Generation of Error Message Containing Sensitive Information',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '212',
                        'Name': 'Improper Removal of Sensitive Information Before Storage or Transfer',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '213',
                        'Name': 'Exposure of Sensitive Information Due to Incompatible Policies',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '214',
                        'Name': 'Invocation of Process Using Visible Sensitive Information',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '215',
                        'Name': 'Insertion of Sensitive Information Into Debugging Code',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '222',
                        'Name': 'Truncation of Security-relevant Information',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '524',
                        'Name': 'Use of Cache Containing Sensitive Information',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '538',
                        'Name': 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }, {
                        'CWE-ID': '921',
                        'Name': 'Storage of Sensitive Data in a Mechanism without Access Control',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }
                ],
            'User Interface Security':
                [
                    {
                        'CWE-ID': '204',
                        'Name': 'Observable Response Discrepancy',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '1007',
                        'Name': 'Insufficient Visual Distinction of Homoglyphs Presented to User',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '356',
                        'Name': 'Product UI does not Warn User of Unsafe Actions',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '357',
                        'Name': 'Insufficient UI Warning of Dangerous Operations',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '447',
                        'Name': 'Unimplemented or Unsupported Feature in UI',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '448',
                        'Name': 'Obsolete Feature in UI',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '449',
                        'Name': 'The UI Performs the Wrong Action',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '1021',
                        'Name': 'Improper Restriction of Rendered UI Layers or Frames',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '601',
                        'Name': "URL Redirection to Untrusted Site ('Open Redirect')",
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '618',
                        'Name': 'Exposed Unsafe ActiveX Method',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '698',
                        'Name': 'Execution After Redirect (EAR)',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '756',
                        'Name': 'Missing Custom Error Page',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }, {
                        'CWE-ID': '804',
                        'Name': 'Guessable CAPTCHA',
                        'CWE-Category': 'User Interface Security Issues',
                        'CWE-Category-ID': '355'
                    }
                ],
            'Privilege Management':
                [
                    {
                        'CWE-ID': '266',
                        'Name': 'Incorrect Privilege Assignment',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '267',
                        'Name': 'Privilege Defined With Unsafe Actions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '268',
                        'Name': 'Privilege Chaining',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '270',
                        'Name': 'Privilege Context Switching Error',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '272',
                        'Name': 'Least Privilege Violation',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '273',
                        'Name': 'Improper Check for Dropped Privileges',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '274',
                        'Name': 'Improper Handling of Insufficient Privileges',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '648',
                        'Name': 'Incorrect Use of Privileged APIs',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '250',
                        'Name': 'Execution with Unnecessary Privileges',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '276',
                        'Name': 'Incorrect Default Permissions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '277',
                        'Name': 'Insecure Inherited Permissions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '278',
                        'Name': 'Insecure Preserved Inherited Permissions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '279',
                        'Name': 'Incorrect Execution-Assigned Permissions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '280',
                        'Name': 'Improper Handling of Insufficient Permissions or Privileges',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }, {
                        'CWE-ID': '281',
                        'Name': 'Improper Preservation of Permissions',
                        'CWE-Category': 'Privilege Issues',
                        'CWE-Category-ID': '265'
                    }
                ],
            'Authentication':
                [
                    {
                        'CWE-ID': '289',
                        'Name': 'Authentication Bypass by Alternate Name',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '290',
                        'Name': 'Authentication Bypass by Spoofing',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '303',
                        'Name': 'Incorrect Implementation of Authentication Algorithm',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '305',
                        'Name': 'Authentication Bypass by Primary Weakness',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '306',
                        'Name': 'Missing Authentication for Critical Function',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '307',
                        'Name': 'Improper Restriction of Excessive Authentication Attempts',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '308',
                        'Name': 'Use of Single-factor Authentication',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '309',
                        'Name': 'Use of Password System for Primary Authentication',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '603',
                        'Name': 'Use of Client-Side Authentication',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '654',
                        'Name': 'Reliance on a Single Factor in a Security Decision',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '294',
                        'Name': 'Authentication Bypass by Capture-replay',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '295',
                        'Name': 'Improper Certificate Validation',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '301',
                        'Name': 'Reflection Attack in an Authentication Protocol',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '346',
                        'Name': 'Origin Validation Error',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }, {
                        'CWE-ID': '348',
                        'Name': 'Use of Less Trusted Source',
                        'CWE-Category': 'Authentication Errors',
                        'CWE-Category-ID': '1211'
                    }
                ],
            'Lockout Mechanisms':
                [
                    {
                        'CWE-ID': '645',
                        'Name': 'Overly Restrictive Account Lockout Mechanism',
                        'CWE-Category': 'Lockout Mechanism Errors',
                        'CWE-Category-ID': '1216'
                    }
                ],
            'Configuration Management':
                [
                    {
                        'CWE-ID': '15',
                        'Name': 'External Control of System or Configuration Setting',
                        'CWE-Category': 'Information Management Errors',
                        'CWE-Category-ID': '199'
                    }
                ],
            'Credentials Management':
                [
                    {
                        'CWE-ID': '1392',
                        'Name': 'Use of Default Credentials',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '256',
                        'Name': 'Plaintext Storage of a Password',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '257',
                        'Name': 'Storing Passwords in a Recoverable Format',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '260',
                        'Name': 'Password in Configuration File',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '261',
                        'Name': 'Weak Encoding for Password',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '262',
                        'Name': 'Not Using Password Aging',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '263',
                        'Name': 'Password Aging with Long Expiration',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '521',
                        'Name': 'Weak Password Requirements',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '523',
                        'Name': 'Unprotected Transport of Credentials',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '549',
                        'Name': 'Missing Password Field Masking',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '620',
                        'Name': 'Unverified Password Change',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '640',
                        'Name': 'Weak Password Recovery Mechanism for Forgotten Password',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '798',
                        'Name': 'Use of Hard-coded Credentials',
                        'CWE-Category': 'Credentials Management Errors',
                        'CWE-Category-ID': '255'
                    }, {
                        'CWE-ID': '836',
                        'Name': 'Use of Password Hash Instead of Password for Authentication',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }
                ],
            'Cryptographic Handling':
                [
                    {
                        'CWE-ID': '916',
                        'Name': 'Use of Password Hash With Insufficient Computational Effort',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '547',
                        'Name': 'Use of Hard-coded, Security-relevant Constants',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID':
                            '649',
                        'Name':
                            'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking',
                        'CWE-Category':
                            'Cryptographic Issues',
                        'CWE-Category-ID':
                            '310'
                    }, {
                        'CWE-ID': '319',
                        'Name': 'Cleartext Transmission of Sensitive Information',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '312',
                        'Name': 'Cleartext Storage of Sensitive Information',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }
                ],
            'User Session Management':
                [
                    {
                        'CWE-ID': '488',
                        'Name': 'Exposure of Data Element to Wrong Session',
                        'CWE-Category': 'User Session Errors',
                        'CWE-Category-ID': '1217'
                    }, {
                        'CWE-ID': '565',
                        'Name': 'Reliance on Cookies without Validation and Integrity Checking',
                        'CWE-Category': 'User Session Errors',
                        'CWE-Category-ID': '1217'
                    }, {
                        'CWE-ID': '613',
                        'Name': 'Insufficient Session Expiration',
                        'CWE-Category': 'User Session Errors',
                        'CWE-Category-ID': '1217'
                    }
                ]
        },
    'Data Management and Integrity':
        {
            'Data Validation':
                [
                    {
                        'CWE-ID': '183',
                        'Name': 'Permissive List of Allowed Inputs',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '184',
                        'Name': 'Incomplete List of Disallowed Inputs',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '115',
                        'Name': 'Misinterpretation of Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1173',
                        'Name': 'Improper Use of Validation Framework',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1284',
                        'Name': 'Improper Validation of Specified Quantity in Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1285',
                        'Name': 'Improper Validation of Specified Index, Position, or Offset in Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1286',
                        'Name': 'Improper Validation of Syntactic Correctness of Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1287',
                        'Name': 'Improper Validation of Specified Type of Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1288',
                        'Name': 'Improper Validation of Consistency within Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1289',
                        'Name': 'Improper Validation of Unsafe Equivalence in Input',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '1389',
                        'Name': 'Incorrect Parsing of Numbers with Different Radices',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '166',
                        'Name': 'Improper Handling of Missing Special Element',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '167',
                        'Name': 'Improper Handling of Additional Special Element',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '168',
                        'Name': 'Improper Handling of Inconsistent Special Elements',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '178',
                        'Name': 'Improper Handling of Case Sensitivity',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '179',
                        'Name': 'Incorrect Behavior Order: Early Validation',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '229',
                        'Name': 'Improper Handling of Values',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '233',
                        'Name': 'Improper Handling of Parameters',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }, {
                        'CWE-ID': '606',
                        'Name': 'Unchecked Input for Loop Condition',
                        'CWE-Category': 'Data Validation Issues',
                        'CWE-Category-ID': '1215'
                    }
                ],
            'Data Processing':
                [
                    {
                        'CWE-ID': '1043',
                        'Name': 'Data Element Aggregating an Excessively Large Number of Non-Primitive Elements',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1066',
                        'Name': 'Missing Serialization Control Element',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1070',
                        'Name': 'Serializable Data Element Containing non-Serializable Item Elements',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1102',
                        'Name': 'Reliance on Machine-Dependent Data Representation',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '130',
                        'Name': 'Improper Handling of Length Parameter Inconsistency',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '182',
                        'Name': 'Collapse of Data into Unsafe Value',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '237',
                        'Name': 'Improper Handling of Structural Elements',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '349',
                        'Name': 'Acceptance of Extraneous Untrusted Data With Trusted Data',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '409',
                        'Name': 'Improper Handling of Highly Compressed Data (Data Amplification)',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '502',
                        'Name': 'Deserialization of Untrusted Data',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1049',
                        'Name': 'Excessive Data Query Operations in a Large Data Table',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1057',
                        'Name': 'Data Access Operations Outside of Expected Data Manager Component',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1067',
                        'Name': 'Excessive Execution of Sequential Searches of Data Resource',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1072',
                        'Name': 'Data Resource Access without Use of Connection Pooling',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1073',
                        'Name': 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1083',
                        'Name': 'Data Access from Outside Expected Data Manager Component',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1089',
                        'Name': 'Large Data Table with Excessive Number of Indices',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1094',
                        'Name': 'Excessive Index Range Scan for a Data Resource',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '619',
                        'Name': "Dangling Database Cursor ('Cursor Injection')",
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '1060',
                        'Name': 'Excessive Number of Inefficient Server-Side Data Accesses',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }, {
                        'CWE-ID': '112',
                        'Name': 'Missing XML Validation',
                        'CWE-Category': 'Data Processing Errors',
                        'CWE-Category-ID': '19'
                    }
                ],
            'Data Neutralization':
                [
                    {
                        'CWE-ID': '1236',
                        'Name': 'Improper Neutralization of Formula Elements in a CSV File',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '89',
                        'Name': "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '791',
                        'Name': 'Incomplete Filtering of Special Elements',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '838',
                        'Name': 'Inappropriate Encoding for Output Context',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '140',
                        'Name': 'Improper Neutralization of Delimiters',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '76',
                        'Name': 'Improper Neutralization of Equivalent Special Elements',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID':
                            '78',
                        'Name':
                            "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                        'CWE-Category':
                            'Data Neutralization Issues',
                        'CWE-Category-ID':
                            '137'
                    }, {
                        'CWE-ID': '79',
                        'Name': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '88',
                        'Name': "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')",
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '93',
                        'Name': "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '117',
                        'Name': 'Improper Output Neutralization for Logs',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '134',
                        'Name': 'Use of Externally-Controlled Format String',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID': '90',
                        'Name': "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }, {
                        'CWE-ID':
                            '917',
                        'Name':
                            "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
                        'CWE-Category':
                            'Data Neutralization Issues',
                        'CWE-Category-ID':
                            '137'
                    }, {
                        'CWE-ID': '91',
                        'Name': 'XML Injection (aka Blind XPath Injection)',
                        'CWE-Category': 'Data Neutralization Issues',
                        'CWE-Category-ID': '137'
                    }
                ],
            'File Handling':
                [
                    {
                        'CWE-ID': '22',
                        'Name': "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '378',
                        'Name': 'Creation of Temporary File With Insecure Permissions',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '379',
                        'Name': 'Creation of Temporary File in Directory with Insecure Permissions',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '41',
                        'Name': 'Improper Resolution of Path Equivalence',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '434',
                        'Name': 'Unrestricted Upload of File with Dangerous Type',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '552',
                        'Name': 'Files or Directories Accessible to External Parties',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '59',
                        'Name': "Improper Link Resolution Before File Access ('Link Following')",
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '66',
                        'Name': 'Improper Handling of File Names that Identify Virtual Resources',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '73',
                        'Name': 'External Control of File Name or Path',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '426',
                        'Name': 'Untrusted Search Path',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '427',
                        'Name': 'Uncontrolled Search Path Element',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '428',
                        'Name': 'Unquoted Search Path or Element',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '641',
                        'Name': 'Improper Restriction of Names for Files and Other Resources',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '611',
                        'Name': 'Improper Restriction of XML External Entity Reference',
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }, {
                        'CWE-ID': '776',
                        'Name': "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')",
                        'CWE-Category': 'File Handling Issues',
                        'CWE-Category-ID': '1219'
                    }
                ],
            'String Handling':
                [
                    {
                        'CWE-ID': '1046',
                        'Name': 'Creation of Immutable Text Using String Concatenation',
                        'CWE-Category': 'String Errors',
                        'CWE-Category-ID': '133'
                    }, {
                        'CWE-ID': '135',
                        'Name': 'Incorrect Calculation of Multi-Byte String Length',
                        'CWE-Category': 'String Errors',
                        'CWE-Category-ID': '133'
                    }, {
                        'CWE-ID': '170',
                        'Name': 'Improper Null Termination',
                        'CWE-Category': 'String Errors',
                        'CWE-Category-ID': '133'
                    }
                ]
        },
    'Communication and Networking':
        {
            'Communication Channel Handling':
                [
                    {
                        'CWE-ID': '419',
                        'Name': 'Unprotected Primary Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID': '420',
                        'Name': 'Unprotected Alternate Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID': '421',
                        'Name': 'Race Condition During Access to Alternate Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID': '385',
                        'Name': 'Covert Timing Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID': '444',
                        'Name': "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')",
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID':
                            '924',
                        'Name':
                            'Improper Enforcement of Message Integrity During Transmission in a Communication Channel',
                        'CWE-Category':
                            'Communication Channel Errors',
                        'CWE-Category-ID':
                            '417'
                    }, {
                        'CWE-ID': '940',
                        'Name': 'Improper Verification of Source of a Communication Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }, {
                        'CWE-ID': '941',
                        'Name': 'Incorrectly Specified Destination in a Communication Channel',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }
                ],
            'MultiThreading/Concurrency':
                [
                    {
                        'CWE-ID': '208',
                        'Name': 'Observable Timing Discrepancy',
                        'CWE-Category': 'Communication Channel Errors',
                        'CWE-Category-ID': '417'
                    }
                ],
            'Signal Handling':
                [
                    {
                        'CWE-ID': '364',
                        'Name': 'Signal Handler Race Condition',
                        'CWE-Category': 'Signal Errors',
                        'CWE-Category-ID': '387'
                    }
                ]
        },
    'Numeric and Mathematical Handling':
        {
            'Arithmetic Operations':
                [
                    {
                        'CWE-ID': '128',
                        'Name': 'Wrap-around Error',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '1335',
                        'Name': 'Incorrect Bitwise Shift of Integer',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '1339',
                        'Name': 'Insufficient Precision or Accuracy of a Real Number',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '190',
                        'Name': 'Integer Overflow or Wraparound',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '191',
                        'Name': 'Integer Underflow (Wrap or Wraparound)',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '369',
                        'Name': 'Divide By Zero',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }, {
                        'CWE-ID': '839',
                        'Name': 'Numeric Range Comparison Without Minimum Check',
                        'CWE-Category': 'Numeric Errors',
                        'CWE-Category-ID': '189'
                    }
                ]
        },
    'API and Functionality Management':
        {
            'Data / Function Handling':
                [
                    {
                        'CWE-ID': '94',
                        'Name': "Improper Control of Generation of Code ('Code Injection')",
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1056',
                        'Name': 'Invokable Control Element with Variadic Parameters',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1064',
                        'Name': 'Invokable Control Element with Signature Containing an Excessive Number of Parameters',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1082',
                        'Name': 'Class Instance Self Destruction Control Element',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1101',
                        'Name': 'Reliance on Runtime Component in Generated Code',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1117',
                        'Name': 'Callable with Insufficient Behavioral Summary',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '242',
                        'Name': 'Use of Inherently Dangerous Function',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '386',
                        'Name': 'Symbolic Name not Mapping to Correct Object',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '430',
                        'Name': 'Deployment of Wrong Handler',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '431',
                        'Name': 'Missing Handler',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '474',
                        'Name': 'Use of Function with Inconsistent Implementations',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '475',
                        'Name': 'Undefined Behavior for Input to API',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '477',
                        'Name': 'Use of Obsolete Function',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '580',
                        'Name': 'clone() Method Without super.clone()',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '628',
                        'Name': 'Function Call with Incorrectly Specified Arguments',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '676',
                        'Name': 'Use of Potentially Dangerous Function',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '695',
                        'Name': 'Use of Low-Level Functionality',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '749',
                        'Name': 'Exposed Dangerous Method or Function',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '586',
                        'Name': 'Explicit Call to Finalize()',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }, {
                        'CWE-ID': '1084',
                        'Name': 'Invokable Control Element with Excessive File or Data Access Operations',
                        'CWE-Category': 'API / Function Errors',
                        'CWE-Category-ID': '1228'
                    }
                ],
            'Initialization and Cleanup':
                [
                    {
                        'CWE-ID': '1051',
                        'Name': 'Initialization with Hard-Coded Network Resource Configuration Data',
                        'CWE-Category': 'Initialization and Cleanup Errors',
                        'CWE-Category-ID': '452'
                    }, {
                        'CWE-ID': '1052',
                        'Name': 'Excessive Use of Hard-Coded Literals in Initialization',
                        'CWE-Category': 'Initialization and Cleanup Errors',
                        'CWE-Category-ID': '452'
                    }, {
                        'CWE-ID': '1188',
                        'Name': 'Initialization of a Resource with an Insecure Default',
                        'CWE-Category': 'Initialization and Cleanup Errors',
                        'CWE-Category-ID': '452'
                    }, {
                        'CWE-ID': '455',
                        'Name': 'Non-exit on Failed Initialization',
                        'CWE-Category': 'Initialization and Cleanup Errors',
                        'CWE-Category-ID': '452'
                    }, {
                        'CWE-ID': '1063',
                        'Name': 'Creation of Class Instance within a Static Code Block',
                        'CWE-Category': 'Initialization and Cleanup Errors',
                        'CWE-Category-ID': '452'
                    }
                ],
            'Type Handling':
                [
                    {
                        'CWE-ID': '1024',
                        'Name': 'Comparison of Incompatible Types',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '1025',
                        'Name': 'Comparison Using Wrong Factors',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '1235',
                        'Name': 'Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '193',
                        'Name': 'Off-by-one Error',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '241',
                        'Name': 'Improper Handling of Unexpected Data Type',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '351',
                        'Name': 'Insufficient Type Distinction',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '581',
                        'Name': 'Object Model Violation: Just One of Equals and Hashcode Defined',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '681',
                        'Name': 'Incorrect Conversion between Numeric Types',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '843',
                        'Name': "Access of Resource Using Incompatible Type ('Type Confusion')",
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }, {
                        'CWE-ID': '914',
                        'Name': 'Improper Control of Dynamically-Identified Variables',
                        'CWE-Category': 'Type Errors',
                        'CWE-Category-ID': '136'
                    }
                ],
            'Expression Issues':
                [
                    {
                        'CWE-ID': '1037',
                        'Name': 'Processor Optimization Removal or Modification of Security-critical Code',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '1075',
                        'Name': 'Unconditional Control Flow Transfer outside of Switch Block',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '1095',
                        'Name': 'Loop Condition Value Update within the Loop',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '1123',
                        'Name': 'Excessive Use of Self-Modifying Code',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '1333',
                        'Name': 'Inefficient Regular Expression Complexity',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '186',
                        'Name': 'Overly Restrictive Regular Expression',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '478',
                        'Name': 'Missing Default Case in Multiple Condition Expression',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '480',
                        'Name': 'Use of Incorrect Operator',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '483',
                        'Name': 'Incorrect Block Delimitation',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '484',
                        'Name': 'Omitted Break Statement in Switch',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '570',
                        'Name': 'Expression is Always False',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '571',
                        'Name': 'Expression is Always True',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '584',
                        'Name': 'Return Inside Finally Block',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '617',
                        'Name': 'Reachable Assertion',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '733',
                        'Name': 'Compiler Optimization Removal or Modification of Security-critical Code',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '783',
                        'Name': 'Operator Precedence Logic Error',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '835',
                        'Name': "Loop with Unreachable Exit Condition ('Infinite Loop')",
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '624',
                        'Name': 'Executable Regular Expression Error',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }, {
                        'CWE-ID': '625',
                        'Name': 'Permissive Regular Expression',
                        'CWE-Category': 'Expression Issues',
                        'CWE-Category-ID': '569'
                    }
                ]
        },
    'Concurrency and Resource Management':
        {
            'MultiThreading/Concurrency':
                [
                    {
                        'CWE-ID':
                            '1058',
                        'Name':
                            'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element',
                        'CWE-Category':
                            'Concurrency Issues',
                        'CWE-Category-ID':
                            '557'
                    }, {
                        'CWE-ID': '1265',
                        'Name': 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '1322',
                        'Name': 'Use of Blocking Code in Single-threaded, Non-blocking Context',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '366',
                        'Name': 'Race Condition within a Thread',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '367',
                        'Name': 'Time-of-check Time-of-use (TOCTOU) Race Condition',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '368',
                        'Name': 'Context Switching Race Condition',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '663',
                        'Name': 'Use of a Non-reentrant Function in a Concurrent Context',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '820',
                        'Name': 'Missing Synchronization',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }, {
                        'CWE-ID': '821',
                        'Name': 'Incorrect Synchronization',
                        'CWE-Category': 'Concurrency Issues',
                        'CWE-Category-ID': '557'
                    }
                ],
            'Resource Locking':
                [
                    {
                        'CWE-ID': '412',
                        'Name': 'Unrestricted Externally Accessible Lock',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '413',
                        'Name': 'Improper Resource Locking',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '414',
                        'Name': 'Missing Lock Check',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '609',
                        'Name': 'Double-Checked Locking',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '764',
                        'Name': 'Multiple Locks of a Critical Resource',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '765',
                        'Name': 'Multiple Unlocks of a Critical Resource',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '832',
                        'Name': 'Unlock of a Resource that is not Locked',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }, {
                        'CWE-ID': '833',
                        'Name': 'Deadlock',
                        'CWE-Category': 'Resource Locking Problems',
                        'CWE-Category-ID': '411'
                    }
                ],
            'State Management':
                [
                    {
                        'CWE-ID': '344',
                        'Name': 'Use of Invariant Value in Dynamically Changing Context',
                        'CWE-Category': 'State Issues',
                        'CWE-Category-ID': '371'
                    }, {
                        'CWE-ID': '372',
                        'Name': 'Incomplete Internal State Distinction',
                        'CWE-Category': 'State Issues',
                        'CWE-Category-ID': '371'
                    }
                ],
            'Resource Management':
                [
                    {
                        'CWE-ID': '410',
                        'Name': 'Insufficient Resource Pool',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '459',
                        'Name': 'Incomplete Cleanup',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '463',
                        'Name': 'Deletion of Data Structure Sentinel',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '464',
                        'Name': 'Addition of Data Structure Sentinel',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '1050',
                        'Name': 'Excessive Platform Resource Consumption within a Loop',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID':
                            '1065',
                        'Name':
                            'Runtime Resource Management Control Element in a Component Built to Run on Application Servers',
                        'CWE-Category':
                            'Resource Management Errors',
                        'CWE-Category-ID':
                            '399'
                    }, {
                        'CWE-ID': '1097',
                        'Name': 'Persistent Storable Data Element without Associated Comparison Control Element',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '694',
                        'Name': 'Use of Multiple Resources with Duplicate Identifier',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '605',
                        'Name': 'Multiple Binds to the Same Port',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '1341',
                        'Name': 'Multiple Releases of Same Resource or Handle',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '770',
                        'Name': 'Allocation of Resources Without Limits or Throttling',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '771',
                        'Name': 'Missing Reference to Active Allocated Resource',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '772',
                        'Name': 'Missing Release of Resource after Effective Lifetime',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '826',
                        'Name': 'Premature Release of Resource During Expected Lifetime',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '908',
                        'Name': 'Use of Uninitialized Resource',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '909',
                        'Name': 'Missing Initialization of Resource',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '910',
                        'Name': 'Use of Expired File Descriptor',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }, {
                        'CWE-ID': '920',
                        'Name': 'Improper Restriction of Power Consumption',
                        'CWE-Category': 'Resource Management Errors',
                        'CWE-Category-ID': '399'
                    }
                ],
            'Pointer Handling':
                [
                    {
                        'CWE-ID': '1098',
                        'Name': 'Data Element containing Pointer Item without Proper Copy Control Element',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '466',
                        'Name': 'Return of Pointer Value Outside of Expected Range',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '468',
                        'Name': 'Incorrect Pointer Scaling',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '469',
                        'Name': 'Use of Pointer Subtraction to Determine Size',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '476',
                        'Name': 'NULL Pointer Dereference',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '562',
                        'Name': 'Return of Stack Variable Address',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '587',
                        'Name': 'Assignment of a Fixed Address to a Pointer',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '763',
                        'Name': 'Release of Invalid Pointer or Reference',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '822',
                        'Name': 'Untrusted Pointer Dereference',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '823',
                        'Name': 'Use of Out-of-range Pointer Offset',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '824',
                        'Name': 'Access of Uninitialized Pointer',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '825',
                        'Name': 'Expired Pointer Dereference',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }, {
                        'CWE-ID': '911',
                        'Name': 'Improper Update of Reference Count',
                        'CWE-Category': 'Pointer Issues',
                        'CWE-Category-ID': '465'
                    }
                ],
            'Memory Buffer Management':
                [
                    {
                        'CWE-ID': '120',
                        'Name': "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '124',
                        'Name': "Buffer Underwrite ('Buffer Underflow')",
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '125',
                        'Name': 'Out-of-bounds Read',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '131',
                        'Name': 'Incorrect Calculation of Buffer Size',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '786',
                        'Name': 'Access of Memory Location Before Start of Buffer',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '787',
                        'Name': 'Out-of-bounds Write',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '788',
                        'Name': 'Access of Memory Location After End of Buffer',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }, {
                        'CWE-ID': '805',
                        'Name': 'Buffer Access with Incorrect Length Value',
                        'CWE-Category': 'Memory Buffer Errors',
                        'CWE-Category-ID': '1218'
                    }
                ]
        },
    'Cryptography and Key Management':
        {
            'Cryptographic Handling':
                [
                    {
                        'CWE-ID': '1204',
                        'Name': 'Generation of Weak Initialization Vector (IV)',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '1240',
                        'Name': 'Use of a Cryptographic Primitive with a Risky Implementation',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '323',
                        'Name': 'Reusing a Nonce, Key Pair in Encryption',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '325',
                        'Name': 'Missing Cryptographic Step',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '328',
                        'Name': 'Use of Weak Hash',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '331',
                        'Name': 'Insufficient Entropy',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '347',
                        'Name': 'Improper Verification of Cryptographic Signature',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '322',
                        'Name': 'Key Exchange without Entity Authentication',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '353',
                        'Name': 'Missing Support for Integrity Check',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '354',
                        'Name': 'Improper Validation of Integrity Check Value',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '494',
                        'Name': 'Download of Code Without Integrity Check',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }, {
                        'CWE-ID': '515',
                        'Name': 'Covert Storage Channel',
                        'CWE-Category': 'Cryptographic Issues',
                        'CWE-Category-ID': '310'
                    }
                ],
            'Random Number Management':
                [
                    {
                        'CWE-ID': '1241',
                        'Name': 'Use of Predictable Algorithm in Random Number Generator',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '334',
                        'Name': 'Small Space of Random Values',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '335',
                        'Name': 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '338',
                        'Name': 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '343',
                        'Name': 'Predictable Value Range from Previous Values',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '341',
                        'Name': 'Predictable from Observable State',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }, {
                        'CWE-ID': '342',
                        'Name': 'Predictable Exact Value from Previous Values',
                        'CWE-Category': 'Random Number Issues',
                        'CWE-Category-ID': '1213'
                    }
                ],
            'Key Management':
                [
                    {
                        'CWE-ID': '324',
                        'Name': 'Use of a Key Past its Expiration Date',
                        'CWE-Category': 'Key Management Errors',
                        'CWE-Category-ID': '320'
                    }
                ]
        },
    'Error and Exception Handling':
        {
            'Error Handling':
                [
                    {
                        'CWE-ID': '252',
                        'Name': 'Unchecked Return Value',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '253',
                        'Name': 'Incorrect Check of Function Return Value',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '390',
                        'Name': 'Detection of Error Condition Without Action',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '391',
                        'Name': 'Unchecked Error Condition',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '392',
                        'Name': 'Missing Report of Error Condition',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '393',
                        'Name': 'Return of Wrong Status Code',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '394',
                        'Name': 'Unexpected Status Code or Return Value',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '395',
                        'Name': 'Use of NullPointerException Catch to Detect NULL Pointer Dereference',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '396',
                        'Name': 'Declaration of Catch for Generic Exception',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '397',
                        'Name': 'Declaration of Throws for Generic Exception',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '544',
                        'Name': 'Missing Standardized Error Handling Mechanism',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }, {
                        'CWE-ID': '248',
                        'Name': 'Uncaught Exception',
                        'CWE-Category': 'Error Conditions / Return Values / Status Codes',
                        'CWE-Category-ID': '389'
                    }
                ]
        },
    'Logging and Auditing':
        {
            'Logging and Auditing':
                [
                    {
                        'CWE-ID': '223',
                        'Name': 'Omission of Security-relevant Information',
                        'CWE-Category': 'Audit / Logging Errors',
                        'CWE-Category-ID': '1210'
                    }, {
                        'CWE-ID': '778',
                        'Name': 'Insufficient Logging',
                        'CWE-Category': 'Audit / Logging Errors',
                        'CWE-Category-ID': '1210'
                    }, {
                        'CWE-ID': '779',
                        'Name': 'Logging of Excessive Data',
                        'CWE-Category': 'Audit / Logging Errors',
                        'CWE-Category-ID': '1210'
                    }
                ]
        }
}

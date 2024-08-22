FUNCTIONAL_AREAS = {
    'Configuration Management':
        [
            {
                'CWE-ID': '15',
                'Name': 'External Control of System or Configuration Setting'
            }, {
                'CWE-ID': '1051',
                'Name': 'Initialization with Hard-Coded Network Resource Configuration Data'
            }, {
                'CWE-ID': '1052',
                'Name': 'Excessive Use of Hard-Coded Literals in Initialization'
            }, {
                'CWE-ID': '1188',
                'Name': 'Initialization of a Resource with an Insecure Default'
            }
        ],
    'File Processing':
        [
            {
                'CWE-ID': '22',
                'Name': "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
            }, {
                'CWE-ID': '41',
                'Name': 'Improper Resolution of Path Equivalence'
            }, {
                'CWE-ID': '59',
                'Name': "Improper Link Resolution Before File Access ('Link Following')"
            }, {
                'CWE-ID': '66',
                'Name': 'Improper Handling of File Names that Identify Virtual Resources'
            }, {
                'CWE-ID': '73',
                'Name': 'External Control of File Name or Path'
            }, {
                'CWE-ID': '378',
                'Name': 'Creation of Temporary File With Insecure Permissions'
            }, {
                'CWE-ID': '379',
                'Name': 'Creation of Temporary File in Directory with Insecure Permissions'
            }, {
                'CWE-ID': '434',
                'Name': 'Unrestricted Upload of File with Dangerous Type'
            }, {
                'CWE-ID': '552',
                'Name': 'Files or Directories Accessible to External Parties'
            }
        ],
    'Input Processing':
        [
            {
                'CWE-ID': '76',
                'Name': 'Improper Neutralization of Equivalent Special Elements'
            }, {
                'CWE-ID': '78',
                'Name': "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')"
            }, {
                'CWE-ID': '79',
                'Name': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
            }, {
                'CWE-ID': '88',
                'Name': "Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')"
            }, {
                'CWE-ID': '93',
                'Name': "Improper Neutralization of CRLF Sequences ('CRLF Injection')"
            }, {
                'CWE-ID': '115',
                'Name': 'Misinterpretation of Input'
            }, {
                'CWE-ID': '140',
                'Name': 'Improper Neutralization of Delimiters'
            }, {
                'CWE-ID': '166',
                'Name': 'Improper Handling of Missing Special Element'
            }, {
                'CWE-ID': '167',
                'Name': 'Improper Handling of Additional Special Element'
            }, {
                'CWE-ID': '168',
                'Name': 'Improper Handling of Inconsistent Special Elements'
            }, {
                'CWE-ID': '178',
                'Name': 'Improper Handling of Case Sensitivity'
            }, {
                'CWE-ID': '179',
                'Name': 'Incorrect Behavior Order: Early Validation'
            }, {
                'CWE-ID': '229',
                'Name': 'Improper Handling of Values'
            }, {
                'CWE-ID': '233',
                'Name': 'Improper Handling of Parameters'
            }, {
                'CWE-ID': '426',
                'Name': 'Untrusted Search Path'
            }, {
                'CWE-ID': '427',
                'Name': 'Uncontrolled Search Path Element'
            }, {
                'CWE-ID': '428',
                'Name': 'Unquoted Search Path or Element'
            }, {
                'CWE-ID': '454',
                'Name': 'External Initialization of Trusted Variables or Data Stores'
            }, {
                'CWE-ID': '470',
                'Name': "Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')"
            }, {
                'CWE-ID': '472',
                'Name': 'External Control of Assumed-Immutable Web Parameter'
            }, {
                'CWE-ID': '606',
                'Name': 'Unchecked Input for Loop Condition'
            }, {
                'CWE-ID': '624',
                'Name': 'Executable Regular Expression Error'
            }, {
                'CWE-ID': '625',
                'Name': 'Permissive Regular Expression'
            }, {
                'CWE-ID': '641',
                'Name': 'Improper Restriction of Names for Files and Other Resources'
            }, {
                'CWE-ID': '649',
                'Name': 'Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking'
            }, {
                'CWE-ID': '807',
                'Name': 'Reliance on Untrusted Inputs in a Security Decision'
            }, {
                'CWE-ID': '839',
                'Name': 'Numeric Range Comparison Without Minimum Check'
            }, {
                'CWE-ID': '915',
                'Name': 'Improperly Controlled Modification of Dynamically-Determined Object Attributes'
            }, {
                'CWE-ID': '1173',
                'Name': 'Improper Use of Validation Framework'
            }, {
                'CWE-ID': '1284',
                'Name': 'Improper Validation of Specified Quantity in Input'
            }, {
                'CWE-ID': '1285',
                'Name': 'Improper Validation of Specified Index, Position, or Offset in Input'
            }, {
                'CWE-ID': '1286',
                'Name': 'Improper Validation of Syntactic Correctness of Input'
            }, {
                'CWE-ID': '1287',
                'Name': 'Improper Validation of Specified Type of Input'
            }, {
                'CWE-ID': '1288',
                'Name': 'Improper Validation of Consistency within Input'
            }, {
                'CWE-ID': '1289',
                'Name': 'Improper Validation of Unsafe Equivalence in Input'
            }, {
                'CWE-ID': '1389',
                'Name': 'Incorrect Parsing of Numbers with Different Radices'
            }
        ],
    'Database Interaction':
        [
            {
                'CWE-ID': '89',
                'Name': "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
            }, {
                'CWE-ID': '619',
                'Name': "Dangling Database Cursor ('Cursor Injection')"
            }, {
                'CWE-ID': '1049',
                'Name': 'Excessive Data Query Operations in a Large Data Table'
            }, {
                'CWE-ID': '1057',
                'Name': 'Data Access Operations Outside of Expected Data Manager Component'
            }, {
                'CWE-ID': '1067',
                'Name': 'Excessive Execution of Sequential Searches of Data Resource'
            }, {
                'CWE-ID': '1072',
                'Name': 'Data Resource Access without Use of Connection Pooling'
            }, {
                'CWE-ID': '1073',
                'Name': 'Non-SQL Invokable Control Element with Excessive Number of Data Resource Accesses'
            }, {
                'CWE-ID': '1083',
                'Name': 'Data Access from Outside Expected Data Manager Component'
            }, {
                'CWE-ID': '1089',
                'Name': 'Large Data Table with Excessive Number of Indices'
            }, {
                'CWE-ID': '1094',
                'Name': 'Excessive Index Range Scan for a Data Resource'
            }
        ],
    'Third Party Integration':
        [
            {
                'CWE-ID': '90',
                'Name': "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')"
            }, {
                'CWE-ID': '439',
                'Name': 'Behavioral Change in New Version or Environment'
            }, {
                'CWE-ID': '829',
                'Name': 'Inclusion of Functionality from Untrusted Control Sphere'
            }, {
                'CWE-ID': '1100',
                'Name': 'Insufficient Isolation of System-Dependent Functions'
            }, {
                'CWE-ID': '1103',
                'Name': 'Use of Platform-Dependent Third Party Components'
            }, {
                'CWE-ID': '1104',
                'Name': 'Use of Unmaintained Third Party Components'
            }, {
                'CWE-ID': '1105',
                'Name': 'Insufficient Encapsulation of Machine-Dependent Functionality'
            }
        ],
    'XML Processing':
        [
            {
                'CWE-ID': '91',
                'Name': 'XML Injection (aka Blind XPath Injection)'
            }, {
                'CWE-ID': '112',
                'Name': 'Missing XML Validation'
            }, {
                'CWE-ID': '611',
                'Name': 'Improper Restriction of XML External Entity Reference'
            }, {
                'CWE-ID': '776',
                'Name': "Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')"
            }
        ],
    'Code Generation': [{
        'CWE-ID': '94',
        'Name': "Improper Control of Generation of Code ('Code Injection')"
    }],
    'String Processing':
        [
            {
                'CWE-ID': '117',
                'Name': 'Improper Output Neutralization for Logs'
            }, {
                'CWE-ID': '134',
                'Name': 'Use of Externally-Controlled Format String'
            }, {
                'CWE-ID': '135',
                'Name': 'Incorrect Calculation of Multi-Byte String Length'
            }, {
                'CWE-ID': '170',
                'Name': 'Improper Null Termination'
            }, {
                'CWE-ID': '1046',
                'Name': 'Creation of Immutable Text Using String Concatenation'
            }
        ],
    'Memory Management':
        [
            {
                'CWE-ID': '120',
                'Name': "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"
            }, {
                'CWE-ID': '124',
                'Name': "Buffer Underwrite ('Buffer Underflow')"
            }, {
                'CWE-ID': '125',
                'Name': 'Out-of-bounds Read'
            }, {
                'CWE-ID': '131',
                'Name': 'Incorrect Calculation of Buffer Size'
            }, {
                'CWE-ID': '466',
                'Name': 'Return of Pointer Value Outside of Expected Range'
            }, {
                'CWE-ID': '468',
                'Name': 'Incorrect Pointer Scaling'
            }, {
                'CWE-ID': '469',
                'Name': 'Use of Pointer Subtraction to Determine Size'
            }, {
                'CWE-ID': '476',
                'Name': 'NULL Pointer Dereference'
            }, {
                'CWE-ID': '562',
                'Name': 'Return of Stack Variable Address'
            }, {
                'CWE-ID': '586',
                'Name': 'Explicit Call to Finalize()'
            }, {
                'CWE-ID': '587',
                'Name': 'Assignment of a Fixed Address to a Pointer'
            }, {
                'CWE-ID': '763',
                'Name': 'Release of Invalid Pointer or Reference'
            }, {
                'CWE-ID': '786',
                'Name': 'Access of Memory Location Before Start of Buffer'
            }, {
                'CWE-ID': '787',
                'Name': 'Out-of-bounds Write'
            }, {
                'CWE-ID': '788',
                'Name': 'Access of Memory Location After End of Buffer'
            }, {
                'CWE-ID': '805',
                'Name': 'Buffer Access with Incorrect Length Value'
            }, {
                'CWE-ID': '822',
                'Name': 'Untrusted Pointer Dereference'
            }, {
                'CWE-ID': '823',
                'Name': 'Use of Out-of-range Pointer Offset'
            }, {
                'CWE-ID': '824',
                'Name': 'Access of Uninitialized Pointer'
            }, {
                'CWE-ID': '825',
                'Name': 'Expired Pointer Dereference'
            }, {
                'CWE-ID': '911',
                'Name': 'Improper Update of Reference Count'
            }
        ],
    'Arithmetic Operations':
        [
            {
                'CWE-ID': '128',
                'Name': 'Wrap-around Error'
            }, {
                'CWE-ID': '190',
                'Name': 'Integer Overflow or Wraparound'
            }, {
                'CWE-ID': '191',
                'Name': 'Integer Underflow (Wrap or Wraparound)'
            }, {
                'CWE-ID': '1335',
                'Name': 'Incorrect Bitwise Shift of Integer'
            }, {
                'CWE-ID': '1339',
                'Name': 'Insufficient Precision or Accuracy of a Real Number'
            }
        ],
    'Data Structures Processing':
        [
            {
                'CWE-ID': '130',
                'Name': 'Improper Handling of Length Parameter Inconsistency'
            }, {
                'CWE-ID': '182',
                'Name': 'Collapse of Data into Unsafe Value'
            }, {
                'CWE-ID': '237',
                'Name': 'Improper Handling of Structural Elements'
            }, {
                'CWE-ID': '349',
                'Name': 'Acceptance of Extraneous Untrusted Data With Trusted Data'
            }, {
                'CWE-ID': '409',
                'Name': 'Improper Handling of Highly Compressed Data (Data Amplification)'
            }, {
                'CWE-ID': '410',
                'Name': 'Insufficient Resource Pool'
            }, {
                'CWE-ID': '459',
                'Name': 'Incomplete Cleanup'
            }, {
                'CWE-ID': '463',
                'Name': 'Deletion of Data Structure Sentinel'
            }, {
                'CWE-ID': '464',
                'Name': 'Addition of Data Structure Sentinel'
            }, {
                'CWE-ID': '501',
                'Name': 'Trust Boundary Violation'
            }, {
                'CWE-ID': '502',
                'Name': 'Deserialization of Untrusted Data'
            }, {
                'CWE-ID': '1043',
                'Name': 'Data Element Aggregating an Excessively Large Number of Non-Primitive Elements'
            }, {
                'CWE-ID': '1066',
                'Name': 'Missing Serialization Control Element'
            }, {
                'CWE-ID': '1070',
                'Name': 'Serializable Data Element Containing non-Serializable Item Elements'
            }, {
                'CWE-ID': '1102',
                'Name': 'Reliance on Machine-Dependent Data Representation'
            }, {
                'CWE-ID': '1236',
                'Name': 'Improper Neutralization of Formula Elements in a CSV File'
            }
        ],
    'Access Control':
        [
            {
                'CWE-ID': '183',
                'Name': 'Permissive List of Allowed Inputs'
            }, {
                'CWE-ID': '184',
                'Name': 'Incomplete List of Disallowed Inputs'
            }, {
                'CWE-ID': '201',
                'Name': 'Insertion of Sensitive Information Into Sent Data'
            }, {
                'CWE-ID': '204',
                'Name': 'Observable Response Discrepancy'
            }, {
                'CWE-ID': '205',
                'Name': 'Observable Behavioral Discrepancy'
            }, {
                'CWE-ID': '266',
                'Name': 'Incorrect Privilege Assignment'
            }, {
                'CWE-ID': '267',
                'Name': 'Privilege Defined With Unsafe Actions'
            }, {
                'CWE-ID': '268',
                'Name': 'Privilege Chaining'
            }, {
                'CWE-ID': '270',
                'Name': 'Privilege Context Switching Error'
            }, {
                'CWE-ID': '272',
                'Name': 'Least Privilege Violation'
            }, {
                'CWE-ID': '273',
                'Name': 'Improper Check for Dropped Privileges'
            }, {
                'CWE-ID': '274',
                'Name': 'Improper Handling of Insufficient Privileges'
            }, {
                'CWE-ID': '283',
                'Name': 'Unverified Ownership'
            }, {
                'CWE-ID': '289',
                'Name': 'Authentication Bypass by Alternate Name'
            }, {
                'CWE-ID': '290',
                'Name': 'Authentication Bypass by Spoofing'
            }, {
                'CWE-ID': '303',
                'Name': 'Incorrect Implementation of Authentication Algorithm'
            }, {
                'CWE-ID': '305',
                'Name': 'Authentication Bypass by Primary Weakness'
            }, {
                'CWE-ID': '306',
                'Name': 'Missing Authentication for Critical Function'
            }, {
                'CWE-ID': '307',
                'Name': 'Improper Restriction of Excessive Authentication Attempts'
            }, {
                'CWE-ID': '308',
                'Name': 'Use of Single-factor Authentication'
            }, {
                'CWE-ID': '309',
                'Name': 'Use of Password System for Primary Authentication'
            }, {
                'CWE-ID': '359',
                'Name': 'Exposure of Private Personal Information to an Unauthorized Actor'
            }, {
                'CWE-ID': '408',
                'Name': 'Incorrect Behavior Order: Early Amplification'
            }, {
                'CWE-ID': '419',
                'Name': 'Unprotected Primary Channel'
            }, {
                'CWE-ID': '420',
                'Name': 'Unprotected Alternate Channel'
            }, {
                'CWE-ID': '425',
                'Name': "Direct Request ('Forced Browsing')"
            }, {
                'CWE-ID': '497',
                'Name': 'Exposure of Sensitive System Information to an Unauthorized Control Sphere'
            }, {
                'CWE-ID': '551',
                'Name': 'Incorrect Behavior Order: Authorization Before Parsing and Canonicalization'
            }, {
                'CWE-ID': '603',
                'Name': 'Use of Client-Side Authentication'
            }, {
                'CWE-ID': '639',
                'Name': 'Authorization Bypass Through User-Controlled Key'
            }, {
                'CWE-ID': '645',
                'Name': 'Overly Restrictive Account Lockout Mechanism'
            }, {
                'CWE-ID': '653',
                'Name': 'Improper Isolation or Compartmentalization'
            }, {
                'CWE-ID': '654',
                'Name': 'Reliance on a Single Factor in a Security Decision'
            }, {
                'CWE-ID': '708',
                'Name': 'Incorrect Ownership Assignment'
            }, {
                'CWE-ID': '842',
                'Name': 'Placement of User into Incorrect Group'
            }, {
                'CWE-ID': '939',
                'Name': 'Improper Authorization in Handler for Custom URL Scheme'
            }, {
                'CWE-ID': '1220',
                'Name': 'Insufficient Granularity of Access Control'
            }
        ],
    'Generic coding':
        [
            {
                'CWE-ID': '186',
                'Name': 'Overly Restrictive Regular Expression'
            }, {
                'CWE-ID': '193',
                'Name': 'Off-by-one Error'
            }, {
                'CWE-ID': '241',
                'Name': 'Improper Handling of Unexpected Data Type'
            }, {
                'CWE-ID': '242',
                'Name': 'Use of Inherently Dangerous Function'
            }, {
                'CWE-ID': '341',
                'Name': 'Predictable from Observable State'
            }, {
                'CWE-ID': '342',
                'Name': 'Predictable Exact Value from Previous Values'
            }, {
                'CWE-ID': '351',
                'Name': 'Insufficient Type Distinction'
            }, {
                'CWE-ID': '360',
                'Name': 'Trust of System Event Data'
            }, {
                'CWE-ID': '369',
                'Name': 'Divide By Zero'
            }, {
                'CWE-ID': '372',
                'Name': 'Incomplete Internal State Distinction'
            }, {
                'CWE-ID': '374',
                'Name': 'Passing Mutable Objects to an Untrusted Method'
            }, {
                'CWE-ID': '375',
                'Name': 'Returning a Mutable Object to an Untrusted Caller'
            }, {
                'CWE-ID': '385',
                'Name': 'Covert Timing Channel'
            }, {
                'CWE-ID': '386',
                'Name': 'Symbolic Name not Mapping to Correct Object'
            }, {
                'CWE-ID': '430',
                'Name': 'Deployment of Wrong Handler'
            }, {
                'CWE-ID': '431',
                'Name': 'Missing Handler'
            }, {
                'CWE-ID': '440',
                'Name': 'Expected Behavior Violation'
            }, {
                'CWE-ID': '474',
                'Name': 'Use of Function with Inconsistent Implementations'
            }, {
                'CWE-ID': '475',
                'Name': 'Undefined Behavior for Input to API'
            }, {
                'CWE-ID': '477',
                'Name': 'Use of Obsolete Function'
            }, {
                'CWE-ID': '478',
                'Name': 'Missing Default Case in Multiple Condition Expression'
            }, {
                'CWE-ID': '480',
                'Name': 'Use of Incorrect Operator'
            }, {
                'CWE-ID': '483',
                'Name': 'Incorrect Block Delimitation'
            }, {
                'CWE-ID': '484',
                'Name': 'Omitted Break Statement in Switch'
            }, {
                'CWE-ID': '487',
                'Name': 'Reliance on Package-level Scope'
            }, {
                'CWE-ID': '489',
                'Name': 'Active Debug Code'
            }, {
                'CWE-ID': '547',
                'Name': 'Use of Hard-coded, Security-relevant Constants'
            }, {
                'CWE-ID': '561',
                'Name': 'Dead Code'
            }, {
                'CWE-ID': '563',
                'Name': 'Assignment to Variable without Use'
            }, {
                'CWE-ID': '570',
                'Name': 'Expression is Always False'
            }, {
                'CWE-ID': '571',
                'Name': 'Expression is Always True'
            }, {
                'CWE-ID': '580',
                'Name': 'clone() Method Without super.clone()'
            }, {
                'CWE-ID': '581',
                'Name': 'Object Model Violation: Just One of Equals and Hashcode Defined'
            }, {
                'CWE-ID': '584',
                'Name': 'Return Inside Finally Block'
            }, {
                'CWE-ID': '617',
                'Name': 'Reachable Assertion'
            }, {
                'CWE-ID': '628',
                'Name': 'Function Call with Incorrectly Specified Arguments'
            }, {
                'CWE-ID': '648',
                'Name': 'Incorrect Use of Privileged APIs'
            }, {
                'CWE-ID': '676',
                'Name': 'Use of Potentially Dangerous Function'
            }, {
                'CWE-ID': '681',
                'Name': 'Incorrect Conversion between Numeric Types'
            }, {
                'CWE-ID': '694',
                'Name': 'Use of Multiple Resources with Duplicate Identifier'
            }, {
                'CWE-ID': '695',
                'Name': 'Use of Low-Level Functionality'
            }, {
                'CWE-ID': '733',
                'Name': 'Compiler Optimization Removal or Modification of Security-critical Code'
            }, {
                'CWE-ID': '749',
                'Name': 'Exposed Dangerous Method or Function'
            }, {
                'CWE-ID': '766',
                'Name': 'Critical Data Element Declared Public'
            }, {
                'CWE-ID': '767',
                'Name': 'Access to Critical Private Variable via Public Method'
            }, {
                'CWE-ID': '783',
                'Name': 'Operator Precedence Logic Error'
            }, {
                'CWE-ID': '791',
                'Name': 'Incomplete Filtering of Special Elements'
            }, {
                'CWE-ID': '835',
                'Name': "Loop with Unreachable Exit Condition ('Infinite Loop')"
            }, {
                'CWE-ID': '837',
                'Name': 'Improper Enforcement of a Single, Unique Action'
            }, {
                'CWE-ID': '838',
                'Name': 'Inappropriate Encoding for Output Context'
            }, {
                'CWE-ID': '843',
                'Name': "Access of Resource Using Incompatible Type ('Type Confusion')"
            }, {
                'CWE-ID': '914',
                'Name': 'Improper Control of Dynamically-Identified Variables'
            }, {
                'CWE-ID': '1024',
                'Name': 'Comparison of Incompatible Types'
            }, {
                'CWE-ID': '1025',
                'Name': 'Comparison Using Wrong Factors'
            }, {
                'CWE-ID': '1037',
                'Name': 'Processor Optimization Removal or Modification of Security-critical Code'
            }, {
                'CWE-ID': '1041',
                'Name': 'Use of Redundant Code'
            }, {
                'CWE-ID': '1045',
                'Name': 'Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor'
            }, {
                'CWE-ID': '1050',
                'Name': 'Excessive Platform Resource Consumption within a Loop'
            }, {
                'CWE-ID': '1055',
                'Name': 'Multiple Inheritance from Concrete Classes'
            }, {
                'CWE-ID': '1056',
                'Name': 'Invokable Control Element with Variadic Parameters'
            }, {
                'CWE-ID': '1060',
                'Name': 'Excessive Number of Inefficient Server-Side Data Accesses'
            }, {
                'CWE-ID': '1062',
                'Name': 'Parent Class with References to Child Class'
            }, {
                'CWE-ID': '1063',
                'Name': 'Creation of Class Instance within a Static Code Block'
            }, {
                'CWE-ID': '1064',
                'Name': 'Invokable Control Element with Signature Containing an Excessive Number of Parameters'
            }, {
                'CWE-ID': '1065',
                'Name': 'Runtime Resource Management Control Element in a Component Built to Run on Application Servers'
            }, {
                'CWE-ID': '1071',
                'Name': 'Empty Code Block'
            }, {
                'CWE-ID': '1074',
                'Name': 'Class with Excessively Deep Inheritance'
            }, {
                'CWE-ID': '1075',
                'Name': 'Unconditional Control Flow Transfer outside of Switch Block'
            }, {
                'CWE-ID': '1079',
                'Name': 'Parent Class without Virtual Destructor Method'
            }, {
                'CWE-ID': '1080',
                'Name': 'Source Code File with Excessive Number of Lines of Code'
            }, {
                'CWE-ID': '1082',
                'Name': 'Class Instance Self Destruction Control Element'
            }, {
                'CWE-ID': '1085',
                'Name': 'Invokable Control Element with Excessive Volume of Commented-out Code'
            }, {
                'CWE-ID': '1086',
                'Name': 'Class with Excessive Number of Child Classes'
            }, {
                'CWE-ID': '1087',
                'Name': 'Class with Virtual Method without a Virtual Destructor'
            }, {
                'CWE-ID': '1090',
                'Name': 'Method Containing Access of a Member Element from Another Class'
            }, {
                'CWE-ID': '1095',
                'Name': 'Loop Condition Value Update within the Loop'
            }, {
                'CWE-ID': '1097',
                'Name': 'Persistent Storable Data Element without Associated Comparison Control Element'
            }, {
                'CWE-ID': '1098',
                'Name': 'Data Element containing Pointer Item without Proper Copy Control Element'
            }, {
                'CWE-ID': '1101',
                'Name': 'Reliance on Runtime Component in Generated Code'
            }, {
                'CWE-ID': '1106',
                'Name': 'Insufficient Use of Symbolic Constants'
            }, {
                'CWE-ID': '1107',
                'Name': 'Insufficient Isolation of Symbolic Constant Definitions'
            }, {
                'CWE-ID': '1108',
                'Name': 'Excessive Reliance on Global Variables'
            }, {
                'CWE-ID': '1109',
                'Name': 'Use of Same Variable for Multiple Purposes'
            }, {
                'CWE-ID': '1113',
                'Name': 'Inappropriate Comment Style'
            }, {
                'CWE-ID': '1114',
                'Name': 'Inappropriate Whitespace Style'
            }, {
                'CWE-ID': '1115',
                'Name': 'Source Code Element without Standard Prologue'
            }, {
                'CWE-ID': '1116',
                'Name': 'Inaccurate Comments'
            }, {
                'CWE-ID': '1117',
                'Name': 'Callable with Insufficient Behavioral Summary'
            }, {
                'CWE-ID': '1119',
                'Name': 'Excessive Use of Unconditional Branching'
            }, {
                'CWE-ID': '1121',
                'Name': 'Excessive McCabe Cyclomatic Complexity'
            }, {
                'CWE-ID': '1122',
                'Name': 'Excessive Halstead Complexity'
            }, {
                'CWE-ID': '1123',
                'Name': 'Excessive Use of Self-Modifying Code'
            }, {
                'CWE-ID': '1124',
                'Name': 'Excessively Deep Nesting'
            }, {
                'CWE-ID': '1126',
                'Name': 'Declaration of Variable with Unnecessarily Wide Scope'
            }, {
                'CWE-ID': '1127',
                'Name': 'Compilation with Insufficient Warnings or Errors'
            }, {
                'CWE-ID': '1235',
                'Name': 'Incorrect Use of Autoboxing and Unboxing for Performance Critical Operations'
            }, {
                'CWE-ID': '1333',
                'Name': 'Inefficient Regular Expression Complexity'
            }
        ],
    'Concurrency Management':
        [
            {
                'CWE-ID': '208',
                'Name': 'Observable Timing Discrepancy'
            }, {
                'CWE-ID': '364',
                'Name': 'Signal Handler Race Condition'
            }, {
                'CWE-ID': '366',
                'Name': 'Race Condition within a Thread'
            }, {
                'CWE-ID': '367',
                'Name': 'Time-of-check Time-of-use (TOCTOU) Race Condition'
            }, {
                'CWE-ID': '368',
                'Name': 'Context Switching Race Condition'
            }, {
                'CWE-ID': '412',
                'Name': 'Unrestricted Externally Accessible Lock'
            }, {
                'CWE-ID': '413',
                'Name': 'Improper Resource Locking'
            }, {
                'CWE-ID': '414',
                'Name': 'Missing Lock Check'
            }, {
                'CWE-ID': '421',
                'Name': 'Race Condition During Access to Alternate Channel'
            }, {
                'CWE-ID': '609',
                'Name': 'Double-Checked Locking'
            }, {
                'CWE-ID': '663',
                'Name': 'Use of a Non-reentrant Function in a Concurrent Context'
            }, {
                'CWE-ID': '764',
                'Name': 'Multiple Locks of a Critical Resource'
            }, {
                'CWE-ID': '765',
                'Name': 'Multiple Unlocks of a Critical Resource'
            }, {
                'CWE-ID': '820',
                'Name': 'Missing Synchronization'
            }, {
                'CWE-ID': '821',
                'Name': 'Incorrect Synchronization'
            }, {
                'CWE-ID': '832',
                'Name': 'Unlock of a Resource that is not Locked'
            }, {
                'CWE-ID': '833',
                'Name': 'Deadlock'
            }, {
                'CWE-ID':
                    '1058',
                'Name':
                    'Invokable Control Element in Multi-Thread Context with non-Final Static Storable or Member Element'
            }, {
                'CWE-ID': '1265',
                'Name': 'Unintended Reentrant Invocation of Non-reentrant Code Via Nested Calls'
            }, {
                'CWE-ID': '1322',
                'Name': 'Use of Blocking Code in Single-threaded, Non-blocking Context'
            }
        ],
    'Sensitive Data Handling':
        [
            {
                'CWE-ID': '209',
                'Name': 'Generation of Error Message Containing Sensitive Information'
            }, {
                'CWE-ID': '212',
                'Name': 'Improper Removal of Sensitive Information Before Storage or Transfer'
            }, {
                'CWE-ID': '213',
                'Name': 'Exposure of Sensitive Information Due to Incompatible Policies'
            }, {
                'CWE-ID': '214',
                'Name': 'Invocation of Process Using Visible Sensitive Information'
            }, {
                'CWE-ID': '215',
                'Name': 'Insertion of Sensitive Information Into Debugging Code'
            }, {
                'CWE-ID': '222',
                'Name': 'Truncation of Security-relevant Information'
            }, {
                'CWE-ID': '312',
                'Name': 'Cleartext Storage of Sensitive Information'
            }, {
                'CWE-ID': '524',
                'Name': 'Use of Cache Containing Sensitive Information'
            }, {
                'CWE-ID': '538',
                'Name': 'Insertion of Sensitive Information into Externally-Accessible File or Directory'
            }, {
                'CWE-ID': '921',
                'Name': 'Storage of Sensitive Data in a Mechanism without Access Control'
            }, {
                'CWE-ID': '1230',
                'Name': 'Exposure of Sensitive Information Through Metadata'
            }
        ],
    'Logging':
        [
            {
                'CWE-ID': '223',
                'Name': 'Omission of Security-relevant Information'
            }, {
                'CWE-ID': '224',
                'Name': 'Obscured Security-relevant Information by Alternate Name'
            }, {
                'CWE-ID': '778',
                'Name': 'Insufficient Logging'
            }, {
                'CWE-ID': '779',
                'Name': 'Logging of Excessive Data'
            }
        ],
    'Privilege Management':
        [
            {
                'CWE-ID': '243',
                'Name': 'Creation of chroot Jail Without Changing Working Directory'
            }, {
                'CWE-ID': '250',
                'Name': 'Execution with Unnecessary Privileges'
            }, {
                'CWE-ID': '276',
                'Name': 'Incorrect Default Permissions'
            }, {
                'CWE-ID': '277',
                'Name': 'Insecure Inherited Permissions'
            }, {
                'CWE-ID': '278',
                'Name': 'Insecure Preserved Inherited Permissions'
            }, {
                'CWE-ID': '279',
                'Name': 'Incorrect Execution-Assigned Permissions'
            }, {
                'CWE-ID': '280',
                'Name': 'Improper Handling of Insufficient Permissions or Privileges'
            }, {
                'CWE-ID': '281',
                'Name': 'Improper Preservation of Permissions'
            }
        ],
    'Error Handling':
        [
            {
                'CWE-ID': '248',
                'Name': 'Uncaught Exception'
            }, {
                'CWE-ID': '252',
                'Name': 'Unchecked Return Value'
            }, {
                'CWE-ID': '253',
                'Name': 'Incorrect Check of Function Return Value'
            }, {
                'CWE-ID': '390',
                'Name': 'Detection of Error Condition Without Action'
            }, {
                'CWE-ID': '391',
                'Name': 'Unchecked Error Condition'
            }, {
                'CWE-ID': '392',
                'Name': 'Missing Report of Error Condition'
            }, {
                'CWE-ID': '393',
                'Name': 'Return of Wrong Status Code'
            }, {
                'CWE-ID': '394',
                'Name': 'Unexpected Status Code or Return Value'
            }, {
                'CWE-ID': '395',
                'Name': 'Use of NullPointerException Catch to Detect NULL Pointer Dereference'
            }, {
                'CWE-ID': '396',
                'Name': 'Declaration of Catch for Generic Exception'
            }, {
                'CWE-ID': '397',
                'Name': 'Declaration of Throws for Generic Exception'
            }, {
                'CWE-ID': '455',
                'Name': 'Non-exit on Failed Initialization'
            }, {
                'CWE-ID': '544',
                'Name': 'Missing Standardized Error Handling Mechanism'
            }
        ],
    'Credential Management':
        [
            {
                'CWE-ID': '256',
                'Name': 'Plaintext Storage of a Password'
            }, {
                'CWE-ID': '257',
                'Name': 'Storing Passwords in a Recoverable Format'
            }, {
                'CWE-ID': '260',
                'Name': 'Password in Configuration File'
            }, {
                'CWE-ID': '261',
                'Name': 'Weak Encoding for Password'
            }, {
                'CWE-ID': '262',
                'Name': 'Not Using Password Aging'
            }, {
                'CWE-ID': '263',
                'Name': 'Password Aging with Long Expiration'
            }, {
                'CWE-ID': '521',
                'Name': 'Weak Password Requirements'
            }, {
                'CWE-ID': '523',
                'Name': 'Unprotected Transport of Credentials'
            }, {
                'CWE-ID': '549',
                'Name': 'Missing Password Field Masking'
            }, {
                'CWE-ID': '620',
                'Name': 'Unverified Password Change'
            }, {
                'CWE-ID': '640',
                'Name': 'Weak Password Recovery Mechanism for Forgotten Password'
            }, {
                'CWE-ID': '798',
                'Name': 'Use of Hard-coded Credentials'
            }, {
                'CWE-ID': '836',
                'Name': 'Use of Password Hash Instead of Password for Authentication'
            }, {
                'CWE-ID': '916',
                'Name': 'Use of Password Hash With Insufficient Computational Effort'
            }, {
                'CWE-ID': '1392',
                'Name': 'Use of Default Credentials'
            }
        ],
    'Network Communications':
        [
            {
                'CWE-ID': '294',
                'Name': 'Authentication Bypass by Capture-replay'
            }, {
                'CWE-ID': '295',
                'Name': 'Improper Certificate Validation'
            }, {
                'CWE-ID': '301',
                'Name': 'Reflection Attack in an Authentication Protocol'
            }, {
                'CWE-ID': '319',
                'Name': 'Cleartext Transmission of Sensitive Information'
            }, {
                'CWE-ID': '322',
                'Name': 'Key Exchange without Entity Authentication'
            }, {
                'CWE-ID': '346',
                'Name': 'Origin Validation Error'
            }, {
                'CWE-ID': '348',
                'Name': 'Use of Less Trusted Source'
            }, {
                'CWE-ID': '353',
                'Name': 'Missing Support for Integrity Check'
            }, {
                'CWE-ID': '354',
                'Name': 'Improper Validation of Integrity Check Value'
            }, {
                'CWE-ID': '437',
                'Name': 'Incomplete Model of Endpoint Features'
            }, {
                'CWE-ID': '444',
                'Name': "Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')"
            }, {
                'CWE-ID': '494',
                'Name': 'Download of Code Without Integrity Check'
            }, {
                'CWE-ID': '515',
                'Name': 'Covert Storage Channel'
            }, {
                'CWE-ID': '605',
                'Name': 'Multiple Binds to the Same Port'
            }, {
                'CWE-ID': '924',
                'Name': 'Improper Enforcement of Message Integrity During Transmission in a Communication Channel'
            }, {
                'CWE-ID': '940',
                'Name': 'Improper Verification of Source of a Communication Channel'
            }, {
                'CWE-ID': '941',
                'Name': 'Incorrectly Specified Destination in a Communication Channel'
            }, {
                'CWE-ID': '1327',
                'Name': 'Binding to an Unrestricted IP Address'
            }
        ],
    'Cryptography':
        [
            {
                'CWE-ID': '323',
                'Name': 'Reusing a Nonce, Key Pair in Encryption'
            }, {
                'CWE-ID': '324',
                'Name': 'Use of a Key Past its Expiration Date'
            }, {
                'CWE-ID': '325',
                'Name': 'Missing Cryptographic Step'
            }, {
                'CWE-ID': '328',
                'Name': 'Use of Weak Hash'
            }, {
                'CWE-ID': '331',
                'Name': 'Insufficient Entropy'
            }, {
                'CWE-ID': '334',
                'Name': 'Small Space of Random Values'
            }, {
                'CWE-ID': '335',
                'Name': 'Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)'
            }, {
                'CWE-ID': '338',
                'Name': 'Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)'
            }, {
                'CWE-ID': '343',
                'Name': 'Predictable Value Range from Previous Values'
            }, {
                'CWE-ID': '344',
                'Name': 'Use of Invariant Value in Dynamically Changing Context'
            }, {
                'CWE-ID': '347',
                'Name': 'Improper Verification of Cryptographic Signature'
            }, {
                'CWE-ID': '656',
                'Name': 'Reliance on Security Through Obscurity'
            }, {
                'CWE-ID': '1204',
                'Name': 'Generation of Weak Initialization Vector (IV)'
            }, {
                'CWE-ID': '1240',
                'Name': 'Use of a Cryptographic Primitive with a Risky Implementation'
            }, {
                'CWE-ID': '1241',
                'Name': 'Use of Predictable Algorithm in Random Number Generator'
            }
        ],
    'User Interface':
        [
            {
                'CWE-ID': '356',
                'Name': 'Product UI does not Warn User of Unsafe Actions'
            }, {
                'CWE-ID': '357',
                'Name': 'Insufficient UI Warning of Dangerous Operations'
            }, {
                'CWE-ID': '447',
                'Name': 'Unimplemented or Unsupported Feature in UI'
            }, {
                'CWE-ID': '448',
                'Name': 'Obsolete Feature in UI'
            }, {
                'CWE-ID': '449',
                'Name': 'The UI Performs the Wrong Action'
            }, {
                'CWE-ID': '1007',
                'Name': 'Insufficient Visual Distinction of Homoglyphs Presented to User'
            }
        ],
    'Security Protocol':
        [
            {
                'CWE-ID': '358',
                'Name': 'Improperly Implemented Security Check for Standard'
            }, {
                'CWE-ID': '1125',
                'Name': 'Excessive Attack Surface'
            }
        ],
    'Process Management':
        [
            {
                'CWE-ID': '403',
                'Name': "Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')"
            }
        ],
    'Session Management':
        [
            {
                'CWE-ID': '488',
                'Name': 'Exposure of Data Element to Wrong Session'
            }, {
                'CWE-ID': '565',
                'Name': 'Reliance on Cookies without Validation and Integrity Checking'
            }, {
                'CWE-ID': '613',
                'Name': 'Insufficient Session Expiration'
            }, {
                'CWE-ID': '841',
                'Name': 'Improper Enforcement of Behavioral Workflow'
            }
        ],
    'Web Security':
        [
            {
                'CWE-ID': '601',
                'Name': "URL Redirection to Untrusted Site ('Open Redirect')"
            }, {
                'CWE-ID': '618',
                'Name': 'Exposed Unsafe ActiveX Method'
            }, {
                'CWE-ID': '698',
                'Name': 'Execution After Redirect (EAR)'
            }, {
                'CWE-ID': '756',
                'Name': 'Missing Custom Error Page'
            }, {
                'CWE-ID': '804',
                'Name': 'Guessable CAPTCHA'
            }, {
                'CWE-ID':
                    '917',
                'Name':
                    "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')"
            }, {
                'CWE-ID': '918',
                'Name': 'Server-Side Request Forgery (SSRF)'
            }, {
                'CWE-ID': '1021',
                'Name': 'Improper Restriction of Rendered UI Layers or Frames'
            }
        ],
    'Resource Management':
        [
            {
                'CWE-ID': '770',
                'Name': 'Allocation of Resources Without Limits or Throttling'
            }, {
                'CWE-ID': '771',
                'Name': 'Missing Reference to Active Allocated Resource'
            }, {
                'CWE-ID': '772',
                'Name': 'Missing Release of Resource after Effective Lifetime'
            }, {
                'CWE-ID': '826',
                'Name': 'Premature Release of Resource During Expected Lifetime'
            }, {
                'CWE-ID': '908',
                'Name': 'Use of Uninitialized Resource'
            }, {
                'CWE-ID': '909',
                'Name': 'Missing Initialization of Resource'
            }, {
                'CWE-ID': '910',
                'Name': 'Use of Expired File Descriptor'
            }, {
                'CWE-ID': '920',
                'Name': 'Improper Restriction of Power Consumption'
            }, {
                'CWE-ID': '1084',
                'Name': 'Invokable Control Element with Excessive File or Data Access Operations'
            }, {
                'CWE-ID': '1341',
                'Name': 'Multiple Releases of Same Resource or Handle'
            }
        ],
    'Software Architecture':
        [
            {
                'CWE-ID': '1044',
                'Name': 'Architecture with Number of Horizontal Layers Outside of Expected Range'
            }, {
                'CWE-ID': '1047',
                'Name': 'Modules with Circular Dependencies'
            }, {
                'CWE-ID': '1048',
                'Name': 'Invokable Control Element with Large Number of Outward Calls'
            }, {
                'CWE-ID': '1054',
                'Name': 'Invocation of a Control Element at an Unnecessarily Deep Horizontal Layer'
            }, {
                'CWE-ID': '1068',
                'Name': 'Inconsistency Between Implementation and Documented Design'
            }, {
                'CWE-ID': '1092',
                'Name': 'Use of Same Invokable Control Element in Multiple Architectural Layers'
            }
        ],
    'Documentation':
        [
            {
                'CWE-ID': '1053',
                'Name': 'Missing Documentation for Design'
            }, {
                'CWE-ID': '1099',
                'Name': 'Inconsistent Naming Conventions for Identifiers'
            }, {
                'CWE-ID': '1110',
                'Name': 'Incomplete Design Documentation'
            }, {
                'CWE-ID': '1111',
                'Name': 'Incomplete I/O Documentation'
            }, {
                'CWE-ID': '1112',
                'Name': 'Incomplete Documentation of Program Execution'
            }, {
                'CWE-ID': '1118',
                'Name': 'Insufficient Documentation of Error Handling Techniques'
            }
        ]
}

from __future__ import annotations

import re
from re import Pattern
from typing import LiteralString, List, Tuple, Any, Dict, Set

# regex taken from https://github.com/InQuest/python-iocextract
# Reusable end punctuation regex.
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"

# Reusable regex for symbols commonly used to defang.
SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"

# Split URLs on some characters that may be valid, but may also be garbage.
URL_SPLIT_STR = r"[>\"'\),};]"

# Get basic url format, including a few obfuscation techniques, main anchor is the uri scheme.
GENERIC_URL: Pattern[Any] = re.compile(r"""
        (
            # Scheme.
            [fhstu]\S\S?[px]s?
            # One of these delimiters/defangs.
            (?:
                :\/\/|
                :\\\\|
                :?__
            )
            # Any number of defang characters.
            (?:
                \x20|
                """ + SEPARATOR_DEFANGS + r"""
            )*
            # Domain/path characters.
            \w
            \S+?
            # CISCO ESA style defangs followed by domain/path characters.
            (?:\x20[\/\.][^\.\/\s]\S*?)*
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE | re.UNICODE)

# Get some obfuscated urls, main anchor is brackets around the period.
BRACKET_URL: Pattern[Any] = re.compile(r"""
        \b
        (
            [\.\:\/\\\w\[\]\(\)-]+
            (?:
                \x20?
                [\(\[]
                \x20?
                \.
                \x20?
                [\]\)]
                \x20?
                \S*?
            )+
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE | re.UNICODE)

# Get some obfuscated urls, main anchor is backslash before a period.
BACKSLASH_URL: Pattern[Any] = re.compile(r"""
        \b
        (
            [\:\/\\\w\[\]\(\)-]+
            (?:
                \x20?
                \\?\.
                \x20?
                \S*?
            )*?
            (?:
                \x20?
                \\.
                \x20?
                \S*?
            )
            (?:
                \x20?
                \\?\.
                \x20?
                \S*?
            )*
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE | re.UNICODE)

# Get hex-encoded urls.
HEXENCODED_URL: Pattern[Any] = re.compile(r"""
        (
            [46][86]
            (?:[57]4)?
            [57]4[57]0
            (?:[57]3)?
            3a2f2f
            (?:2[356def]|3[0-9adf]|[46][0-9a-f]|[57][0-9af])+
        )
        (?:[046]0|2[0-2489a-c]|3[bce]|[57][b-e]|[8-f][0-9a-f]|0a|0d|09|[
            \x5b-\x5d\x7b\x7d\x0a\x0d\x20
        ]|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

# Get urlencoded urls.
URLENCODED_URL: Pattern[Any] = re.compile(r"""
        (s?[hf]t?tps?%3A%2F%2F\w[\w%-]*?)(?:[^\w%-]|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

# Get base64-encoded urls.
B64ENCODED_URL: Pattern[Any] = re.compile(r"""
        (
            # b64re '([hH][tT][tT][pP][sS]|[hH][tT][tT][pP]|[fF][tT][pP])://'
            # Modified to ignore whitespace.
            (?:
                [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Gm]\s*[Vd]\s*[FH]\s*[A]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*|
                [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Io]\s*[Vd]\s*[FH]\s*[R]\s*[Qw]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
                [\x2b\x2f-\x39A-Za-z]\s*[\x2b\x2f-\x39A-Za-z]\s*[\x31\x35\x39BFJNRVZdhlptx]\s*[Io]\s*[Vd]\s*[FH]\s*[R]\s*[Qw]\s*[Uc]\s*[z]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
                [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[Z]\s*[\x30U]\s*[Uc]\s*[D]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
                [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[h]\s*[\x30U]\s*[Vd]\s*[FH]\s*[A]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*|
                [\x2b\x2f-\x39A-Za-z]\s*[\x30\x32EGUWkm]\s*[h]\s*[\x30U]\s*[Vd]\s*[FH]\s*[B]\s*[Tz]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
                [RZ]\s*[ln]\s*[R]\s*[Qw]\s*[O]\s*i\s*\x38\s*v\s*[\x2b\x2f-\x39A-Za-z]\s*|
                [Sa]\s*[FH]\s*[R]\s*[\x30U]\s*[Uc]\s*[D]\s*o\s*v\s*L\s*[\x2b\x2f-\x39w-z]\s*|
                [Sa]\s*[FH]\s*[R]\s*[\x30U]\s*[Uc]\s*[FH]\s*[M]\s*\x36\s*L\s*y\s*[\x2b\x2f\x38-\x39]\s*
            )
            # Up to 260 characters (pre-encoding, reasonable URL length).
            [\w+/=\s]{1,357}
        )
        (?=[^\w+/=\s]|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

# Get some valid obfuscated ip addresses.
IPV4: Pattern[Any] = re.compile(r"""
        (?:^|
            (?![^\d\.])
        )
        (?:
            (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
            [\[\(\\]*?\.[\]\)]*?
        ){3}
        (?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])
        (?:(?=[^\d\.])|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

# Experimental IPv6 regex, will not catch everything but should be sufficent for now.
IPV6: Pattern[Any] = re.compile(r"""
        \b(?:[a-f0-9]{1,4}:|:){2,7}(?:[a-f0-9]{1,4}|:)\b
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

# Capture email addresses including common defangs.
EMAIL = re.compile(r"""
        (
            [a-z0-9_.+-]+
            [\(\[{\x20]*
            (?:@|\Wat\W)
            [\)\]}\x20]*
            [a-z0-9-]+
            (?:
                (?:
                    (?:
                        \x20*
                        """ + SEPARATOR_DEFANGS + r"""
                        \x20*
                    )*
                    \.
                    (?:
                        \x20*
                        """ + SEPARATOR_DEFANGS + r"""
                        \x20*
                    )*
                    |
                    \W+dot\W+
                )
                [a-z0-9-]+?
            )+
        )
    """ + END_PUNCTUATION + r"""
        (?=\s|$)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE | re.UNICODE)

MD5: Pattern[Any] = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)")
SHA1: Pattern[Any] = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)")
SHA256: Pattern[Any] = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)")
SHA512: Pattern[Any] = re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")

# YARA regex.
YARA_PARSE: Pattern[Any] = re.compile(r"""
        (?:^|\s)
        (
            (?:
                \s*?import\s+?"[^\r\n]*?[\r\n]+|
                \s*?include\s+?"[^\r\n]*?[\r\n]+|
                \s*?//[^\r\n]*[\r\n]+|
                \s*?/\*.*?\*/\s*?
            )*
            (?:
                \s*?private\s+|
                \s*?global\s+
            )*
            rule\s*?
            \w+\s*?
            (?:
                :[\s\w]+
            )?
            \s+\{
            .*?
            condition\s*?:
            .*?
            \s*\}
        )
        (?:$|\s)
    """, re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

CREDIT_CARD: Pattern[Any] = re.compile(r"[0-9]{4}[ ]?[-]?[0-9]{4}[ ]?[-]?[0-9]{4}[ ]?[-]?[0-9]{4}",
                                       re.MULTILINE | re.DOTALL | re.IGNORECASE | re.VERBOSE)

rintels: list[tuple[Pattern[Any], LiteralString]] = \
    [
        (GENERIC_URL, "GENERIC_URL"),
        (BRACKET_URL, "BRACKET_URL"),
        # (BACKSLASH_URL, "BACKSLASH_URL"),
        (HEXENCODED_URL, "HEX_ENCODED_URL"),
        (URLENCODED_URL, "URLENCODED_URL"),
        (B64ENCODED_URL, "B64ENCODED_URL"),
        (IPV4, "IPV4"),
        (IPV6, "IPV6"),
        (EMAIL, "EMAIL"),
        (MD5, "MD5"),
        (SHA1, "SHA1"),
        (SHA256, "SHA256"),
        (SHA512, "SHA512"),
        (YARA_PARSE, "YARA_PARSE"),
        (CREDIT_CARD, "CREDIT_CARD")
    ]

js_sercrets = {
    "URL": r'''(['"])(/[\w\./\?\[\]&=\-]+|(https?|ftp)://[\w\./\?\[\]&=\-]+)\1''',
    "URL Parameter": r"(?<=\?|\&)\w[\w\[\]]+(?=\=)",
    "Adobe Client Secret": r'''\b((p8e-)[a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60]|$)''',
    "Alibaba AccessKey ID": r"\b((LTAI)[a-z0-9]{20})(?:['|\"|\n|\r|\s|\x60]|$)",
    "Clojars API Token": r"(CLOJARS_)[a-z0-9]{60}",
    "Doppler API Token": r"(dp\.pt\.)[a-z0-9]{43}",
    "Dynatrace API Token": r"dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}",
    "EasyPost API Token": r"EZAK[a-z0-9]{54}",
    "GitLab Personal Access Token": r"glpat-[\w\-]{20}",
    "NPM Access Token": r"\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60]|$)",
    "Shopify Private APP Access Token": r"shppa_[a-fA-F0-9]{32}",
    "Shopify Shared Secret": r"shpss_[a-fA-F0-9]{32}",
    "Shopify Custom Access Token": r"shpca_[a-fA-F0-9]{32}",
    "Shopify Access Token": r"shpat_[a-fA-F0-9]{32}",
    "Asana Client ID": r"""(?:asana)(?:[\w\-\s\.]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)""",
    "Asana Client Secret": r"""(?:asana)(?:[\w\-\s\.]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)""",
    'Google API': r'AIza[\w]{35}',
    "Artifactory API Token": r'(?:\s|=|:|"|^)AKC[\w]{10,}',
    "Artifactory Password": r'(?:\s|=|:|"|^)AP[\dABCDEF][\w]{8,}',
    "Cloudinary Basic Auth": r"cloudinary://[0-9]{15}:[\w]+@[a-z]+",
    'Firebase Key': r'AAAA[\w\-]{7}:[\w\-]{140}',
    "LinkedIn Secret Key": r"""linkedin(.{0,20})?(['"])[\w]{16}\2""",
    "Mailto String": r"(?<=mailto:)[\w\.\+\-]+@[\w\-]+\.[\w\.\-]+",
    "Firebase URL": r".*firebaseio\.com",
    "PGP Private Key Block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "SSH (DSA) Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH (RSA) Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH (ssh-ed25519) Public Key": r"ssh-ed25519",
    'Google Captcha Key': r'6L[\w\-]{38}|^6[\w\-]{39}',
    "Amazon AWS Access Key ID": r"AKIA[\w]{16}",
    "Amazon MWS Auth Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Amazon AWS API Key": r"AKIA[\w]{16}",
    'Amazon AWS URL': r's3\.amazonaws.com[/\w]+|[\w\-]*\.s3\.amazonaws.com',
    "Generic API Key": r"""api[_]?key.*(['"])\w{32,45}\1""",
    "Generic Secret": r"""secret.*(['"])\w{32,45}\1""",
    'Authorization Bearer': r'bearer [\w\.=\-]+',
    'Authorization Basic': r'basic [\w=:_\+\/-]{5,100}',
    'Authorization API Key': r'api[key|_key|\s]+[\w\-]{24,100}',
    'PayPal Braintree Access Token': r'access_token\$production\$[\w]{16}\$[0-9a-f]{32}',
    'Mailgun API Key': r'key-[\w]{32}',
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
    "Heroku API Key": r"heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "JWT Token": r'ey[\w]+\.ey[\w]+\.?[\w=\-\.\+/]*',
    "Facebook Access Token": r"EAACEdEose0cBA[\w]+",
    "Facebook OAuth": r"""facebook.*(['"])[0-9a-f]{32}\1""",
    "Facebook Client ID": r"""(facebook|fb)(.{0,20})?['"][0-9]{13,17}""",
    "Google Cloud Platform API Key": r'''\b(AIza[\w\-]{35})(?:['|\"|\n|\r|\s|\x60]|$)''',
    "Google Cloud Platform OAuth": r"[0-9]+-[\w]{32}\.apps\.googleusercontent\.com",
    "Google Drive API Key": r"AIza[\w\-]{35}",
    "Google Drive OAuth": r"[0-9]+-[\w]{32}\.apps\.googleusercontent\.com",
    "Google (GCP) Service-account": r'''"type":\ "service_account"''',
    "Google Gmail API Key": r"AIza[\w\-]{35}",
    "Google Gmail OAuth": r"[0-9]+\-[\w\-]{32}\.apps\.googleusercontent\.com",
    "Google OAuth Access Token": r"ya29\.[\w\-]+",
    "Google YouTube API Key": r"AIza[\w\-]{35}",
    "Google YouTube OAuth": r"[0-9]+-[\w\-]{32}\.apps\.googleusercontent\.com",
    'GitHub Access Token': r'[\w\-]*:[\w\-]+@github\.com*',
    "GitHub Personal Access Token": r"ghp_[\w]{36}",
    "GitHub URL": r"""github.*(['"])[\w]{35,40}\1""",
    "GitHub App Token": r"(ghu|ghs)_[\w]{36}",
    "Slack Token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "Slack Webhook": r"https://hooks.slack.com/services/T\w{8}/B\w{8}/\w{24}",
    "Slack Webhook 2": r"T[\w]{8}/B[\w]{8}/[\w]{24}",
    "Slack OAuth v2 Username/Bot Access Token": r"xoxb-[0-9]{11}-[0-9]{11}-[\w]{24}",
    "Slack OAuth v2 Configuration Token": r"xoxe.xoxp-1-[\w]{166}",
    "Picatic API Key": r"sk_live_[\w]{32}",
    "Stripe API Key": r"sk_live_[\w]{24}",
    "Stripe Restricted API Key": r"rk_live_[\w]{24}",
    "Twitter Access Token": r"twitter.*[1-9][0-9]+\-\w{40}",
    "Twitter OAuth": r"""twitter.*(['"])\w{35,44}\1""",
    "Twitter Client ID": r"""twitter(.{0,20})?['"][\w]{18,25}""",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Square Access Token": r"sq0atp-[\w\-]{22}",
    "Square OAuth Secret": r"sq0csp-[\w\-]{43}"
}

secret_patterns = {
    r"""(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})""",
    r"""https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}""",
    r"""[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['"\s][0-9a-f]{32}['"\s]""",
    r"""[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['"\s][0-9a-zA-Z]{35,44}['"\s]""",
    r"""[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}""",
    r"""key-[0-9a-zA-Z]{32}""", r"""[0-9a-f]{32}-us[0-9]{1,2}""", r"""sk_live_[0-9a-z]{32}""",
    r"""[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com""", r"""AIza[0-9A-Za-z-_]{35}""",
    r"""6L[0-9A-Za-z-_]{38}""", r"""ya29\.[0-9A-Za-z\-_]+""", r"""AKIA[0-9A-Z]{16}""",
    r"""amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}""",
    r"""s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com""", r"""EAACEdEose0cBA[0-9A-Za-z]+""",
    r"""key-[0-9a-zA-Z]{32}""", r"""SK[0-9a-fA-F]{32}""", r"""AC[a-zA-Z0-9_\-]{32}""",
    r"""AP[a-zA-Z0-9_\-]{32}""", r"""access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}""",
    r"""sq0csp-[ 0-9A-Za-z\-_]{43}""", r"""sqOatp-[0-9A-Za-z\-_]{22}""", r"""sk_live_[0-9a-zA-Z]{24}""",
    r"""rk_live_[0-9a-zA-Z]{24}""", r"""[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*""",
    r"""-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END PRIVATE KEY-----""",
    r"""-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\S]{100,}-----END RSA PRIVATE KEY-----""",
    r"""(?i)["']?zopim[_-]?account[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?zhuliang[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?zensonatypepassword["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)zendesk(_api_token|_key|_token|-travis-github|_url|_username)(\s|=)""",
    r"""(?i)["']?yt[_-]?server[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?partner[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?partner[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?account[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yt[_-]?account[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yangshun[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?yangshun[_-]?gh[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?www[_-]?googleapis[_-]?com["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?ssh[_-]?connect["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?report[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?prepare[_-]?dir["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?db[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpt[_-]?db[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wporg[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wordpress[_-]?db[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wordpress[_-]?db[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wincert[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?test[_-]?server["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?fb[_-]?password[_-]?3["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?fb[_-]?password[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?fb[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?basic[_-]?password[_-]?5["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?basic[_-]?password[_-]?4["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?basic[_-]?password[_-]?3["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?basic[_-]?password[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?widget[_-]?basic[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?watson[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?watson[_-]?device[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?watson[_-]?conversation[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?wakatime[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?vscetoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?visual[_-]?recognition[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?virustotal[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?vip[_-]?github[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?v[_-]?sfdc[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?v[_-]?sfdc[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?usertravis["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?user[_-]?assets[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?user[_-]?assets[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?use[_-]?ssh["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?urban[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?urban[_-]?master[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?urban[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?unity[_-]?serial["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?unity[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twitteroauthaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twitteroauthaccesssecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twitter[_-]?consumer[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twitter[_-]?consumer[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twine[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?configuration[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?twilio[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?trex[_-]?okta[_-]?client[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?trex[_-]?client[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?secure[_-]?env[_-]?vars["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?pull[_-]?request["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?e2e[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?com[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?branch["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?travis[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?token[_-]?core[_-]?java["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?thera[_-]?oss[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?tester[_-]?keys[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?test[_-]?test["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?test[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?tesco[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?svn[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?surge[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?surge[_-]?login["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?stripe[_-]?public["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?stripe[_-]?private["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?strip[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?strip[_-]?publishable[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?stormpath[_-]?api[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?stormpath[_-]?api[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?starship[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?starship[_-]?account[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?star[_-]?test[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?star[_-]?test[_-]?location["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?star[_-]?test[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?staging[_-]?base[_-]?url[_-]?runscope["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ssmtp[_-]?config["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sshpass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?srcclr[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sqssecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sqsaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?spring[_-]?mail[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?spotify[_-]?api[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?spotify[_-]?api[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?spaces[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?spaces[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?soundcloud[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?soundcloud[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatypepassword["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?token[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?token[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?gpg[_-]?passphrase["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonatype[_-]?gpg[_-]?key[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonar[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonar[_-]?project[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sonar[_-]?organization[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?socrata[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?socrata[_-]?app[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?snyk[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?snyk[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?snoowrap[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?snoowrap[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?snoowrap[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?slate[_-]?user[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?slash[_-]?developer[_-]?space[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?slash[_-]?developer[_-]?space["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?signing[_-]?key[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?signing[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?signing[_-]?key[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?signing[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?setsecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?setdstsecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?setdstaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ses[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ses[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?service[_-]?account[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sentry[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sentry[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sentry[_-]?endpoint["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sentry[_-]?default[_-]?org["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sentry[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendwithus[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sendgrid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?selion[_-]?selenium[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?selion[_-]?log[_-]?level[_-]?dev["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?segment[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secretaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?key[_-]?base["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?9["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?8["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?7["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?6["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?5["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?4["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?3["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?11["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?10["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?1["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?secret[_-]?0["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sdr[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?scrutinizer[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sauce[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sandbox[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?salesforce[_-]?bulk[_-]?test[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sacloud[_-]?api["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sacloud[_-]?access[_-]?token[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?sacloud[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?user[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?secret[_-]?assets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?secret[_-]?app[_-]?logs["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?key[_-]?assets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?key[_-]?app[_-]?logs["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?bucket[_-]?name[_-]?assets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?bucket[_-]?name[_-]?app[_-]?logs["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?s3[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rubygems[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rtd[_-]?store[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rtd[_-]?key[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?route53[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ropsten[_-]?private[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rinkeby[_-]?private[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rest[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?repotoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?reporting[_-]?webdav[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?reporting[_-]?webdav[_-]?pwd["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?release[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?release[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?registry[_-]?secure["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?registry[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rediscloud[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?redis[_-]?stunnel[_-]?urls["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?randrmusicapiaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?rabbitmq[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?quip[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?qiita[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pypi[_-]?passowrd["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pushover[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?publish[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?publish[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?publish[_-]?access["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?project[_-]?config["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?prod[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?prod[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?prod[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?private[_-]?signing[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pring[_-]?mail[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?preferred[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?prebuild[_-]?auth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?postgresql[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?postgresql[_-]?db["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?postgres[_-]?env[_-]?postgres[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?postgres[_-]?env[_-]?postgres[_-]?db["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?plugin[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?plotly[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?places[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?places[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pg[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pg[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?personal[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?personal[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?percy[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?percy[_-]?project["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?paypal[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?passwordtravis["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?parse[_-]?js[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?pagerduty[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?packagecloud[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ossrh[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ossrh[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ossrh[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ossrh[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ossrh[_-]?jira[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?os[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?os[_-]?auth[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?org[_-]?gradle[_-]?project[_-]?sonatype[_-]?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?openwhisk[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?open[_-]?whisk[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?onesignal[_-]?user[_-]?auth[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?onesignal[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?omise[_-]?skey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?omise[_-]?pubkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?omise[_-]?pkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?omise[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?okta[_-]?oauth2[_-]?clientsecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?okta[_-]?oauth2[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?okta[_-]?client[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ofta[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ofta[_-]?region["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ofta[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?octest[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?octest[_-]?app[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?octest[_-]?app[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?oc[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?object[_-]?store[_-]?creds["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?object[_-]?store[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?object[_-]?storage[_-]?region[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?object[_-]?storage[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?oauth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?numbers[_-]?service[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nuget[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nuget[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nuget[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?npm[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?now[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?non[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?node[_-]?pre[_-]?gyp[_-]?secretaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?node[_-]?pre[_-]?gyp[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?node[_-]?pre[_-]?gyp[_-]?accesskeyid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?node[_-]?env["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ngrok[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ngrok[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nexuspassword["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?new[_-]?relic[_-]?beta[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?netlify[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?nativeevents["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysqlsecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysqlmasteruser["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?root[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?hostname["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mysql[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?my[_-]?secret[_-]?env["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?multi[_-]?workspace[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?multi[_-]?workflow[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?multi[_-]?disconnect[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?multi[_-]?connect[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?multi[_-]?bob[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?minio[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?minio[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mile[_-]?zero[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mh[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mh[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mg[_-]?public[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mg[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mapboxaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mapbox[_-]?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mapbox[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mapbox[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mapbox[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?manifest[_-]?app[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?manifest[_-]?app[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mandrill[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?managementapiaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?management[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?manage[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?manage[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?secret[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?pub[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?pub[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?priv[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailgun[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailer[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailchimp[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mailchimp[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?mail[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?magento[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?magento[_-]?auth[_-]?username ["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?magento[_-]?auth[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?store[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lottie[_-]?upload[_-]?cert[_-]?key[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lottie[_-]?s3[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lottie[_-]?happo[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lottie[_-]?happo[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?looker[_-]?test[_-]?runner[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ll[_-]?shared[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ll[_-]?publish[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?linux[_-]?signing[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?linkedin[_-]?client[_-]?secretor lottie[_-]?s3[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lighthouse[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lektor[_-]?deploy[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?lektor[_-]?deploy[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?leanplum[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kxoltsn3vogdop92m["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kubeconfig["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kubecfg[_-]?s3[_-]?path["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kovan[_-]?private[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?keystore[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kafka[_-]?rest[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kafka[_-]?instance[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?kafka[_-]?admin[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?jwt[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?jdbc:mysql["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?jdbc[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?jdbc[_-]?databaseurl["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?itest[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ios[_-]?docs[_-]?deploy[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?internal[_-]?secrets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?integration[_-]?test[_-]?appid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?integration[_-]?test[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?index[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ij[_-]?repo[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ij[_-]?repo[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hub[_-]?dxia2[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?homebrew[_-]?github[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hockeyapp[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?heroku[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?heroku[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?heroku[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hb[_-]?codesign[_-]?key[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hb[_-]?codesign[_-]?gpg[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hab[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?hab[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?grgit[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gren[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gradle[_-]?signing[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gradle[_-]?signing[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gradle[_-]?publish[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gradle[_-]?publish[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?secret[_-]?keys["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?private[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?passphrase["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?ownertrust["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?keyname["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gpg[_-]?key[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?private[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?maps[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?client[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?client[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?google[_-]?account[_-]?type["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gogs[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gitlab[_-]?user[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?tokens["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?repo["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?release[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?pwd["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?oauth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?oauth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?hunter[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?hunter[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?deployment[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?deploy[_-]?hb[_-]?doc[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?auth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?github[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?committer[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?committer[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?author[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?git[_-]?author[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ghost[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ghb[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?unstable[_-]?oauth[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?repo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?oauth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?oauth[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?next[_-]?unstable[_-]?oauth[_-]?client[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?next[_-]?oauth[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gh[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gcs[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gcr[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gcloud[_-]?service[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gcloud[_-]?project["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?gcloud[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?pw["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?login["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ftp[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?fossa[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?flickr[_-]?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?flickr[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?flask[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firefox[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firebase[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firebase[_-]?project[_-]?develop["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firebase[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firebase[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?firebase[_-]?api[_-]?json["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?file[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?exp[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?eureka[_-]?awssecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?sonatype[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?heroku[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?env[_-]?github[_-]?oauth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?end[_-]?user[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?encryption[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?elasticsearch[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?elastic[_-]?cloud[_-]?auth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dsonar[_-]?projectkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dsonar[_-]?login["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?droplet[_-]?travis[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dropbox[_-]?oauth[_-]?bearer["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?doordash[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dockerhubpassword["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dockerhub[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?postgres[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?passwd["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?docker[_-]?hub[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?digitalocean[_-]?ssh[_-]?key[_-]?ids["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?digitalocean[_-]?ssh[_-]?key[_-]?body["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?digitalocean[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?dgpg[_-]?passphrase["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?deploy[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?deploy[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?deploy[_-]?secure["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?deploy[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ddgc[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ddg[_-]?test[_-]?email[_-]?pw["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ddg[_-]?test[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?pw["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?db[_-]?connection["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?datadog[_-]?app[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?datadog[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?port["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?database[_-]?host["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?danger[_-]?github[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cypress[_-]?record[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?coverity[_-]?scan[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?coveralls[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?coveralls[_-]?repo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?coveralls[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cos[_-]?secrets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?conversation[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?conversation[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?v2[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?test[_-]?org[_-]?cma[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?php[_-]?management[_-]?test[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?management[_-]?api[_-]?access[_-]?token[_-]?new["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?management[_-]?api[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?integration[_-]?management[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?cma[_-]?test[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?contentful[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?consumerkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?consumer[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?conekta[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?coding[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?codecov[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?codeclimate[_-]?repo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?codacy[_-]?project[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cocoapods[_-]?trunk[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cocoapods[_-]?trunk[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cn[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cn[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?clu[_-]?ssh[_-]?private[_-]?key[_-]?base64["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?clu[_-]?repo[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudinary[_-]?url[_-]?staging["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudinary[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudflare[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudflare[_-]?auth[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudflare[_-]?auth[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudflare[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?service[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?processed[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?parsed[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?order[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?instance["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?audited[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloudant[_-]?archived[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cloud[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?clojars[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cli[_-]?e2e[_-]?cma[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?claimr[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?claimr[_-]?superuser["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?claimr[_-]?db["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?claimr[_-]?database["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ci[_-]?user[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ci[_-]?server[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ci[_-]?registry[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ci[_-]?project[_-]?url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ci[_-]?deploy[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?chrome[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?chrome[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cheverny[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cf[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?certificate[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?censys[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cattle[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cattle[_-]?agent[_-]?instance[_-]?auth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cattle[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cargo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?cache[_-]?s3[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bx[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bx[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bundlesize[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?built[_-]?branch[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bucketeer[_-]?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bucketeer[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?browserstack[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?browser[_-]?stack[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?brackets[_-]?repo[_-]?oauth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?pwd["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?pass[_-]?prod["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?auth["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bluemix[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintraykey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintray[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintray[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintray[_-]?gpg[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintray[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?bintray[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?b2[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?b2[_-]?app[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?awssecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?awscn[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?awscn[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?awsaccesskeyid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?ses[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?ses[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?secrets["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?config[_-]?secretaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?config[_-]?accesskeyid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aws[_-]?access["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?author[_-]?npm[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?author[_-]?email[_-]?addr["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?auth0[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?auth0[_-]?api[_-]?clientsecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?assistant[_-]?iam[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifacts[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifacts[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifacts[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifacts[_-]?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifacts[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?artifactory[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?argos[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?apple[_-]?id[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?appclientsecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?app[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?app[_-]?secrete["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?app[_-]?report[_-]?token[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?app[_-]?bucket[_-]?perm["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?apigw[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?apiary[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?api[_-]?key[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?api[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aos[_-]?sec["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?aos[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?ansible[_-]?vault[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?android[_-]?docs[_-]?deploy[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?anaconda[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?amazon[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?amazon[_-]?bucket[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?alicloud[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?alicloud[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?alias[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?search[_-]?key[_-]?1["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?search[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?search[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?api[_-]?key[_-]?search["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?api[_-]?key[_-]?mcm["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?admin[_-]?key[_-]?mcm["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?admin[_-]?key[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?algolia[_-]?admin[_-]?key[_-]?1["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?air[-_]?table[-_]?api[-_]?key["']?[=:]["']?.+["']""",
    r"""(?i)["']?adzerk[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?admin[_-]?email["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?account[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?access[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?""",
    r"""(?i)["']?access[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?"""
}

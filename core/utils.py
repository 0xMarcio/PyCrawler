import requests
import os.path
import re
import argparse
import html
import tld

from core.config import BAD_TYPES
from urllib.parse import urlparse, unquote, urldefrag


def regxy(pattern, response, suppress_regex, custom):
    """Extract a string based on regex pattern supplied by user.
    @rtype: object
    """
    try:
        matches = re.findall(r'%s' % pattern, response)
        for match in matches:
            custom.add(match)
    except:
        suppress_regex = True


def is_link(url, processed, files, host):
    """
    Determine whether a link should be crawled
    A url should not be crawled if it
        - Is a file
        - Has already been crawled

    Args:
        url: str Url to be processed
        processed: list[str] List of urls that have already been crawled

    Returns:
        bool If `url` should be crawled
    """
    if url not in processed:
        path = urlparse(url).path
        if url.startswith('#') or url.startswith('javascript:') or url in {'', ':'}:
            print('BAD URL: '+url)
            return False
        is_file = path.endswith(BAD_TYPES)
        if is_file:
            # print(f'File found in link: {url}')
            # if file.startswith()
            if host in url:
                files.add(url)
            return False
        return True
    # print(f'Link already processed: {url}')
    return False


def fix_encoding(bad_str):
    if '\\' in bad_str:
        bad_str = bad_str.replace('\\', '')
    unquoted = unquote(bad_str)
    if '\\' in unquoted:
        unquoted.replace('\\', '')
    return unquoted


def defrag_url(url):
    defragged = urldefrag(url).url
    if ' ' in defragged:
        defragged.replace(' ', '')
    if (defragged.startswith('"') and defragged.endswith('"')) or (defragged.startswith("'") and defragged.endswith("'")):
        defragged = defragged[1:-1]
    if not defragged.startswith('http'):
        print(f'Something went very wrong with URL: {url}\nValue after defrag: {defragged}')
    return defragged


def replace_query_param_values(url):
    # Define a regex pattern to match query parameters and their values
    pattern = r'(\?|&)([^=]+)=([^&]+)'

    # Function to determine whether a value is numeric or not
    def is_numeric(value):
        try:
            float(value)
            return True
        except ValueError:
            return False

    # Replace query parameter values based on their type
    def replace(match):
        param_name = match.group(2)
        param_value = match.group(3)

        if is_numeric(param_value):
            return match.group(1) + param_name + '=<int>'
        else:
            return match.group(1) + param_name + '=<str>'

    # Use re.sub() to replace parameter values
    updated_url = re.sub(pattern, replace, url)
    return updated_url


def unescape_html_in_strings(string_list):
    # Define a regex pattern to find HTML entities (e.g., &amp;, &lt;, &gt;)
    pattern = r'&[a-zA-Z]+;'

    # Function to unescape HTML entities using the html module
    def unescape(match):
        return html.unescape(match.group())

    # Iterate over the strings in the list and unescape HTML entities
    unescaped_strings = [re.sub(pattern, unescape, s) for s in string_list]

    return unescaped_strings


def remove_regex(urls, regex):
    """
    Parse a list for non-matches to a regex.

    Args:
        urls: iterable of urls
        regex: string regex to be parsed for

    Returns:
        list of strings not matching regex
    """

    if not regex:
        return urls

    # To avoid iterating over the characters of a string
    if not isinstance(urls, (list, set, tuple)):
        urls = [urls]

    try:
        non_matching_urls = [url for url in urls if not re.search(regex, url)]
    except TypeError:
        return []

    return non_matching_urls


def writer(datasets, dataset_names, output_dir):
    """Write the results."""
    for dataset, dataset_name in zip(datasets, dataset_names):
        if dataset:
            try:
                dataset = list(dataset)
                dataset.sort()
            except Exception as e:
                print(f'Failed to sort {dataset_name} with error: {e}')
            filepath = output_dir + '/' + dataset_name + '.txt'
            with open(filepath, 'w+') as out_file:
                joined = '\n'.join(dataset)
                out_file.write(str(joined.encode('utf-8').decode('utf-8')))
                out_file.write('\n')


def timer(diff, processed):
    """Return the passed time."""
    # Changes seconds into minutes and seconds
    minutes, seconds = divmod(diff, 60)
    try:
        # Finds average time taken by requests
        time_per_request = diff / float(len(processed))
    except ZeroDivisionError:
        time_per_request = 0
    return minutes, seconds, time_per_request


def entropy(string):
    """Calculates the Shannon entropy of a string"""
    import math
    # get probability of chars in string
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

    # calculate the entropy
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

    return entropy


def xml_parser(response):
    """Extract links from .xml files."""
    # Regex for extracting URLs
    return re.findall(r'<loc>(.*?)</loc>', response)


def extract_headers(headers):
    """This function extracts valid headers from interactive input."""
    sorted_headers = {}
    matches = re.findall(r'(.*):\s(.*)', headers)
    for match in matches:
        header = match[0]
        value = match[1]
        try:
            if value[-1] == ',':
                value = value[:-1]
            sorted_headers[header] = value
        except IndexError:
            pass
    return sorted_headers


def top_level(url: str, fix_protocol: bool = True) -> str:
    """Extract the top level domain from a URL."""
    ext = tld.get_tld(url, fix_protocol=fix_protocol)
    toplevel = '.'.join(urlparse(url).netloc.split('.')[-2:]).split(
        ext)[0] + ext
    return toplevel


def guess_defaults(host):
    defaults = {
        'host': '',
    }
    testreq = requests.get('http://' + host)

    redirects = 0


def is_proxy_list(v, proxies):
    if os.path.isfile(v):
        with open(v, 'r') as _file:
            for line in _file:
                line = line.strip()
                if re.match(r"((http|socks5):\/\/.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})", line) or \
                        re.match(r"((http|socks5):\/\/.)?[-\w@:%._\+~#=]{2,256}\.[a-z]{2,6}:(\d{1,5})", line):
                    proxies.append({"http": line,
                                    "https": line})
                else:
                    print("%s ignored" % line)
        if proxies:
            return True
    return False


def proxy_type(v):
    """ Match IP:PORT or DOMAIN:PORT in a losse manner """
    proxies = []
    if re.match(r"((http|socks5):\/\/.)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})", v):
        proxies.append({"http": v,
                        "https": v})
        return proxies
    elif re.match(r"((http|socks5):\/\/.)?[-\w@:%._\+~#=]{2,256}\.[a-z]{2,6}:(\d{1,5})", v):
        proxies.append({"http": v,
                        "https": v})
        return proxies
    elif is_proxy_list(v, proxies):
        return proxies
    else:
        raise argparse.ArgumentTypeError(
            "Proxy should follow IP:PORT or DOMAIN:PORT format")


def is_valid_ipv6(ipv6_str):
    # Split the IPv6 address into groups using ":"
    groups = ipv6_str.split(":")
    # IPv6 address must have exactly 8 groups
    if len(groups) not in [8, 4]:
        return False
    # Each group must be a hexadecimal number of 1 to 4 digits
    for group in groups:
        if not (1 <= len(group) <= 4 and all(c in "0123456789abcdefABCDEF" for c in group)):
            return False
    return True


def luhn(purported):
    # sum_of_digits (index * 2)
    LUHN_ODD_LOOKUP = (0, 2, 4, 6, 8, 1, 3, 5, 7, 9)

    if not isinstance(purported, str):
        purported = str(purported)
    try:
        evens = sum(int(p) for p in purported[-1::-2])
        odds = sum(LUHN_ODD_LOOKUP[int(p)] for p in purported[-2::-2])
        return (evens + odds) % 10 == 0
    except ValueError:  # Raised if an int conversion fails
        return False


def is_good_proxy(pip):
    try:
        requests.get('http://example.com', proxies=pip, timeout=3)
    except requests.exceptions.ConnectTimeout as e:
        return False
    return True

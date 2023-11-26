#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Photon main part."""
from __future__ import print_function

import argparse
import os
import random
import re
import requests
import sys
import time
import requests
from urllib.parse import urlparse, parse_qs, urldefrag
import warnings
import hashlib

from bs4 import BeautifulSoup
from rich import print

from core.config import *
from core.utils import *
from core.colors import good, info, run, green, red, end, bad
from core.flash import flash
from core.regex import rintels, js_sercrets
from core.zap import zap


# Disable SSL related warnings
warnings.filterwarnings('ignore')

# Processing command line arguments
parser = argparse.ArgumentParser()
# Options
parser.add_argument('-u', '--url', help='root url', dest='root')
parser.add_argument('-c', '--cookie', help='cookie', dest='cook')
parser.add_argument('-r', '--regex', help='regex wpattern', dest='regex')
parser.add_argument('-e', '--export', help='export format', dest='export', choices=['csv', 'json'])
parser.add_argument('-o', '--output', help='output directory', dest='output')
parser.add_argument('-l', '--level', help='levels to crawl', dest='level',
                    type=int)
parser.add_argument('-t', '--threads', help='number of threads', dest='threads',
                    type=int)
parser.add_argument('-d', '--delay', help='delay between requests',
                    dest='delay', type=float)
parser.add_argument('-v', '--verbose', help='verbose output', dest='verbose',
                    action='store_true')
parser.add_argument('-s', '--seeds', help='additional seed URLs', dest='seeds',
                    nargs="+", default=[])
parser.add_argument('--stdout', help='send variables to stdout', dest='std')
parser.add_argument('--user-agent', help='custom user agent(s)',
                    dest='user_agent')
parser.add_argument('--exclude', help='exclude URLs matching this regex',
                    dest='exclude')
parser.add_argument('--timeout', help='http request timeout', dest='timeout',
                    type=float)
parser.add_argument('-p', '--proxy', help='Proxy server IP:PORT or DOMAIN:PORT', dest='proxies',
                    type=proxy_type)

# Switches
parser.add_argument('--clone', help='clone the website locally', dest='clone',
                    action='store_true')
parser.add_argument('--headers', help='add headers', dest='headers',
                    nargs="+", default=[])
parser.add_argument('--dns', help='enumerate subdomains and DNS data',
                    dest='dns', action='store_true')
# parser.add_argument('--keys', help='find secret keys', dest='api',
#                     action='store_true')
parser.add_argument('--only-urls', help='only extract URLs', dest='only_urls',
                    action='store_true')
parser.add_argument('--wayback', help='fetch URLs from archive.org as seeds',
                    dest='archive', action='store_true')
args = parser.parse_args()

# If the user has supplied a URL
probe_success = 0
probe = None

if not args.root:
    print('\n' + parser.format_help().lower())
    quit()

if args.root.startswith('http'):
    probe_url = args.root
    parsed_root_arg = urlparse(probe_url)
else:
    probe_url = 'https://' + args.root
    parsed_root_arg = urlparse(probe_url)

try:
    probe = requests.get(probe_url)
    probe_success = 1
except Exception as e:
    print(f'First probe failed. \nError: ' + e)
    try:
        if probe_url.startswith('https'):
            probe_url = probe_url.replace('https', 'http')
        else:
            probe_url = probe_url.replace('http', 'https')

        probe = requests.get(probe_url)
        probe_success = 1
    except Exception as e2:
        print('Second probe request failed: ' + e2)

if probe_success == 0 or probe is None:
    print('Could not parse host from given target')
    quit()

probe_headers = probe.headers
header_names = str(dict(probe_headers).keys()).lower()
parsed_probe = urlparse(probe.url)
scheme = parsed_probe.scheme
schema = scheme + ':'
host = parsed_probe.netloc
main_url = scheme + '://' + host

if 'connection' in header_names:
    connection = probe.headers['connection']
else:
    connection = 'close'

headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip,deflate,br',
    'User-Agent': random.choice(USER_AGENTS),
    'Connection': connection,
}

SESSION = requests.Session()
SESSION.max_redirects = 5
SESSION.headers.update(headers)

VERBOSE = bool(args.verbose or VERBOSE)
delay = args.delay or 0.2  # Delay between requests
timeout = args.timeout or 10  # HTTP request timeout

crawl_level = args.level or 4  # Crawling level
thread_count = args.threads or 3  # Number of threads
only_urls = bool(args.only_urls)  # Only URLs mode is off by default

# Variables we are going to use later to store stuff
# keys = set()  # High entropy strings, probably secret keys
files = set()  # The pdf, css, png, etc. files.
intel = set()  # The email addresses, website accounts, AWS buckets etc.
robots = set()  # The entries of robots.txt
custom = set()  # Strings extracted by custom regex pattern
failed = set()  # URLs that photon failed to crawl
scripts = set()  # THe Javascript files
external = set()  # URLs that don't belong to the target i.e. out-of-scope
# URLs that have get params in them e.g. example.com/page.php?id=2
fuzzable = set()
secrets = set()  # URLs found from javascript files
processed: set[str] = set()  # URLs that have been crawled
notFound: set[str] = set()
# URLs that belong to the target i.e. in-scope
internal: set[str] = set()
alreadySeen = {'', '/', '#'}
alreadySeenJs = {'', '/', '#'}
alreadySeenIntel = {'', '/', '#'}
alreadySeenSecrets = {'', '/', '#'}

bad_scripts = set()  # Unclean javascript file urls
bad_intel = set()  # needed for intel filtering


def verb(kind, string):
    """Enable verbose output."""
    if VERBOSE:
        print('%s %s: %s' % (info, kind, string))


internal.add(main_url)
internal.add(probe.url)
output_dir = args.output or host
domain = top_level(main_url)
suppress_regex = False


def requester(url):
    """Handle the requests and return the response body."""
    time.sleep(delay)
    return make_request(url)


def make_request(url):
    """Default request"""
    if not url.startswith(schema):
        print('Trying to request url without http' + url)
        return f'---failed---URL:{url}  Exception: no schema supplied'

    try:
        response = SESSION.get(url, verify=False, timeout=timeout, stream=True)
        content_type = response.headers.get("Content-Type")
        res_url = response.url
    except Exception as e:
        print(f'Exception while making request to {url} \nError: {e}')
        return f'---failed---URL:{url}  Exception: {e}'

    if res_url != url:
        # verb(f"URL changed from {url} TO", response.url)
        res_url = response.url
        if res_url not in processed and res_url not in internal and host in res_url:
            verb('Response URL was not in processed/internal', res_url)
            internal.add(response.url)
    if response.status_code == 200 and len(response.text) > 0:
        if not response.history:
            content = ''
        else:
            content = REDIR_STR + response.url + REDIR_STR
        # Check if the content type is text-based
        if "html" in content_type:
            # Convert the response content to a string
            return content + response.text
        elif "xml" in content_type:
            return content + response.text.replace('\\','')
        elif "json" in content_type:
            return content + response.text.replace('\\','')
        else:
            return FAIL_STR + f'Content-type: {content_type} from URL: {url}'
    elif response.status_code == 404:
        notFound.add(url)
        if res_url != url:
            notFound.add(res_url)
        return '404'
    else:
        response.close()
        ret_text = FAIL_STR + f'URL: {url} | Status code: {response.status_code} | Content-type: {content_type} | Length: {len(response.text)}'
        if res_url != url:
            ret_text += f' | Response URL differs from request url: {res_url}'
        return ret_text


def intel_extractor(url, response):
    soup = BeautifulSoup(response, 'html.parser')
    scripts_without_src = set(element.get_text(strip=True) for element in soup.find_all('script', src=False))
    script_contets = " ".join(list(scripts_without_src))
    md5_hex = hashlib.md5(script_contets.encode('utf-8')).hexdigest()
    rintel_hex = md5_hex + '1337'
    if md5_hex not in alreadySeenIntel:
        alreadySeenIntel.add(md5_hex)
        try:
            jscanner(url, script_contets)
        except Exception as e:
            print(f'Exception occurred: {e}')

    if rintel_hex not in alreadySeenIntel:
        alreadySeenIntel.add(rintel_hex)
        for rintel in rintels:
            matches = rintel[0].findall(script_contets)
            unique_matches = set(matches) - alreadySeenIntel
            for match in unique_matches:
                verb(f'Intel {rintel[1]}', match)
                alreadySeenIntel.add(match)
                bad_intel.add((match, rintel[1], url))


def get_links(response):
    soup = BeautifulSoup(response, 'html.parser')
    usable_links = set(urldefrag(element.get('href')).url for element in soup.find_all(href=True))
    # print(f'Found {len(usable_links)} links')
    # print(f'Number of processed links are: {len(processed)}')
    return usable_links - processed


def js_extractor(response):
    soup = BeautifulSoup(response, 'html.parser')
    scripts_with_src = set(urldefrag(element.get('src')).url for element in soup.find_all('script', src=True)) - alreadySeenJs
    script_linkz = "".join(list(scripts_with_src))
    md5_hex = hashlib.md5(script_linkz.encode('utf-8')).hexdigest()
    if md5_hex not in alreadySeenJs:
        alreadySeenJs.add(md5_hex)
        for script_path in scripts_with_src:
            match = None
            if ' ' in script_path:
                script_path.replace(' ', '')

            if not script_path.endswith('.js'):
                script_path = script_path.split('.js')[0] + ".js"

            if script_path.startswith('http'):
                match = script_path

            if script_path.startswith('/') and not script_path.startswith('//'):
                match = main_url + script_path

            elif script_path.startswith(main_url):
                match = script_path

            elif script_path.startswith('//') and (schema + script_path).startswith(main_url):
                match = schema + script_path

            if match is not None:
                if match in alreadySeenJs:
                    continue
                else:
                    verb('JS file', match)
                    alreadySeenJs.add(match)
                    bad_scripts.add(match)
                    continue
            else:
                print(f"Bad script path {script_path}")


def remove_file(url):
    if url.count('/') > 2:
        replaceable = re.search(r'/[^/]*?$', url).group()
        if replaceable != '/':
            return url.replace(replaceable, '')
        else:
            return url
    else:
        return url


def extractor(unparsed_url):
    """Extract details from the response body."""
    url = defrag_url(unparsed_url)
    response = requester(url)
    processed.add(unparsed_url)
    processed.add(url)
    if response.startswith(REDIR_STR):
        redir_url = response.split(REDIR_STR)[1]
        real_response = response.split(REDIR_STR)[2]
        processed.add(redir_url)
        # verb('Redirected from URL :' + url + ' to', redir_url)
        url = redir_url
        response = real_response
    if response.startswith(FAIL_STR):
        failed_string = response.replace(FAIL_STR, '')
        verb('Failed', failed_string)
        failed.add(failed_string)
    elif response == '404':
        verb("Not found", url)
    else:
        links = get_links(response)
        for link in links:
            if link and is_link(link, processed, files, host) and len(link) > 0:
                if link[:4] == 'http':
                    if link.startswith(main_url):
                        if link not in internal:
                            verb('Internal page 1', link)
                            internal.add(link)
                    else:
                        if link not in external:
                            verb('External page', link)
                            external.add(link)
                elif link[:7] == 'mailto:':
                    if link[7:] not in alreadySeenIntel:
                        verb('Intel', link[7:])
                        alreadySeenIntel.add(link[7:])
                        bad_intel.add((link[7:], 'EMAIL', url))
                elif link[:2] == '//':
                    if host in link:
                        link = schema + link
                        if link not in internal:
                            verb('Internal page 2', link)
                            internal.add(link)
                    else:
                        if link not in external:
                            verb('External page', link)
                            external.add(link)
                elif link[:1] == '/':
                    usable_url = remove_file(url)
                    if usable_url.endswith('/') and link.startswith('/'):
                        link = usable_url[:-1] + link
                    else:
                        link = usable_url + link
                    if link not in internal:
                        verb('Internal page 3', link)
                        internal.add(link)
                else:
                    print(f'I wonder what this link is:({link})')
                    usable_url = remove_file(url)
                    if usable_url.endswith('/'):
                        if usable_url + link not in internal:
                            verb('Internal page 4', usable_url + link)
                            internal.add(usable_url + link)
                    elif link.startswith('/'):
                        if usable_url + link not in internal:
                            verb('Internal page 5', usable_url + link)
                            internal.add(usable_url + link)
                    else:
                        print(f'Trying for fix: {usable_url}/[{link}] from: {url}')
                        internal.add(usable_url + '/' + link)
        if only_urls:
            pass
        else:
            js_extractor(response)
            intel_extractor(url, response)
        if args.regex and not suppress_regex:
            regxy(args.regex, response, suppress_regex, custom)


def jscanner(url, response=None):
    """Extract secrets from JavaScript code."""
    parsed_url = urlparse(url)
    is_jsfile = bool(response is None)
    is_minified = parsed_url.path.endswith('min.js')

    if is_jsfile and not parsed_url.path.endswith(IGNORE_JS_EXT):
        response = requests.get(url).text
    if len(response) < 10:
        print(f'Response fomr {url} is only {len(response)} long')
    for key, value in js_sercrets.items():
        pattern = re.compile(r"" + value, re.IGNORECASE)
        matches = pattern.finditer(response)
        for match in matches:
            secret = match.group()
            if '\\' in secret:
                # secret = fix_encoding(secret)
                secret = secret.replace('\\', '')
            if secret not in alreadySeenSecrets and secret not in secrets:
                alreadySeenSecrets.add(secret)
                if any(keyword in secret for keyword in IGNORE_JS):
                    continue
                if secret.split('?')[0].endswith(BAD_TYPES):
                    if secret not in files:
                        verb('Secret file', secret)
                        files.add(secret)
                    continue

                if key == 'URL' and host in secret and defrag_url(secret) not in internal:
                    secret = defrag_url(secret)
                    verb(f'Crawl-able secret {key}', secret)
                    internal.add(secret)
                    continue

                if is_jsfile:
                    verb(f'Secret {key}', secret)
                    secrets.add(f"{key}: {secret} in file: {url}")
                else:
                    verb(f'Secret {key}', secret)
                    secrets.add(f"{key}: {secret} at URL: {url}")


# Records the time at which crawling started
then = time.time()

# Step 1. Extract urls from robots.txt & sitemap.xml
zap(main_url, args.archive, domain, host, internal, robots)

# This is so the level 1 emails are parsed as well
internal = set(remove_regex(internal, args.exclude))

# Step 2. Crawl recursively to the limit specified in "crawl_level"
for level in range(crawl_level):
    # Links to crawl = (all links - already crawled links) - links not to crawl
    links_list = remove_regex(internal - processed, args.exclude)
    # If links to crawl are 0 i.e. all links have been crawled
    links = set(links_list)

    if not links:
        break
    # if crawled links are somehow more than all links. Possible? ;/
    elif len(internal) <= len(processed):
        print('crawled links are somehow more than all links. Possible? ;/')

    print('%s Level %i: %i URLs' % (run, level + 1, len(links)))
    try:
        flash(extractor, links, thread_count)
    except Exception as e:
        print(f'Exception occurred: {e}')
        quit()

if not only_urls:
    for match in bad_scripts:
        if match.startswith(main_url):
            scripts.add(match)
        elif match.startswith('/') and not match.startswith('//'):
            scripts.add(main_url + match)
        elif not match.startswith('http') and not match.startswith('//'):
            scripts.add(main_url + '/' + match)
    # Step 3. Scan the JavaScript files for secrets
    print('%s Crawling %i JavaScript files' % (run, len(scripts)))
    flash(jscanner, scripts, thread_count)

    for url in internal:
        if '=' in url and 'mailto:' not in url:
            fuzzable.add(replace_query_param_values(url))
    for match, intel_name, url in bad_intel:
        if intel_name == "CREDIT_CARD" and luhn(match):
            intel.add("%s:%s:%s" % (intel_name, match, url))
        elif intel_name == "IPV6" and is_valid_ipv6(match):
            intel.add("%s:%s:%s" % (intel_name, match, url))
        elif intel_name[-4:] == "_URL":
            intel.add("%s:%s" % (intel_name, match))
        else:
            intel.add("%s:%s:%s" % (intel_name, match, url))

# Records the time at which crawling stopped
now = time.time()
# Finds total time taken
diff = (now - then)
minutes, seconds, time_per_request = timer(diff, processed)

# Step 4. Save the results
if not os.path.exists(output_dir):  # if the directory doesn't exist
    os.mkdir(output_dir)  # create a new directory
internal = internal - notFound
datasets = [files, intel, robots, custom, failed, internal, notFound, scripts,
            external, fuzzable, secrets]
dataset_names = ['files', 'intel', 'robots', 'custom', 'failed', 'internal', 'not_found',
                 'scripts', 'external', 'fuzzable', 'secrets']

writer(datasets, dataset_names, output_dir)
# Printing out results
print(('%s-%s' % (red, end)) * 50)
for dataset, dataset_name in zip(datasets, dataset_names):
    if dataset:
        print('%s %s: %s' % (good, dataset_name.capitalize(), len(dataset)))
print(('%s-%s' % (red, end)) * 50)

print('%s Total requests made: %i' % (info, len(processed)))
print('%s Total time taken: %i minutes %i seconds' % (info, minutes, seconds))
print('%s Requests per second: %i' % (info, int(len(processed) / diff)))

datasets = {
    'files': list(files), 'intel': list(intel), 'robots': list(robots),
    'custom': list(custom), 'failed': list(failed), 'internal': list(internal),
    'not_found': list(notFound) ,'scripts': list(scripts), 'external': list(external),
    'fuzzable': list(fuzzable), 'secrets': list(secrets)
}

if args.dns:
    from plugins.dnsdumpster import dnsdumpster

    print('%s Generating DNS map' % run)
    dnsdumpster(domain, output_dir)

if args.export:
    from plugins.exporter import exporter

    # exporter(directory, format, datasets)
    exporter(output_dir, args.export, datasets)

print('%s Results saved in %s%s%s directory' % (good, green, output_dir, end))

if args.std:
    for string in datasets[args.std]:
        sys.stdout.write(string + '\n')

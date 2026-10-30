from ipaddress import ip_address
from urllib.parse import urlsplit

import tldextract


# Use the bundled public suffix list: asset creation must not need network access.
_extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def classify_asset(value, asset_type=None):
    """Return the asset type and domain subtype without changing its value.

    Certificate names can also be valid hostnames, so explicit certificate
    context is preserved. Only domains and wildcard domains have a subtype;
    wildcard labels are excluded when identifying the underlying base domain.
    """
    value = value.strip()
    if asset_type == 'certificate' or value.startswith('-----BEGIN CERTIFICATE-----'):
        return 'certificate', ''

    address = value[1:-1] if value.startswith('[') and value.endswith(']') else value
    try:
        ip_address(address)
        return 'ip', ''
    except ValueError:
        pass

    # Include scheme-relative URLs and host/path values from imports.
    if any(marker in value for marker in ('://', '/', '?', '#')):
        parsed = urlsplit(value if '://' in value or value.startswith('//') else '//' + value)
        if parsed.hostname:
            return 'url', ''

    wildcard = '*' in value
    hostname = '.'.join(label for label in value.split('.') if label != '*')
    domain = _extract_domain(hostname.lower().rstrip('.'))
    subtype = 'subdomain' if domain.subdomain else 'domain'
    return ('starred_domain' if wildcard else 'domain'), subtype

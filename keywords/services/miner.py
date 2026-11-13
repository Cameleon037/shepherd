"""Keyword miner: derive candidate keywords with provenance from one seed URL.

Pure functions (plus a thin orchestrator). Nothing here ever triggers a scan: the
engines only read certificate transparency (crt.sh), RDAP/WHOIS, the project's own
DNS records and prior DomainTools imports, then hand back candidate dicts that the
orchestrator stores as Keyword rows: brand-new keyword texts DISABLED for review, new
types of an existing text inheriting that text's enabled state.

Engines:
  E1 engine_certificates   crt.sh seed -> orgs, subdomains, brand-adjacent domains
  E2 engine_tokens         zone-file/asset host corpus -> high-value brand tokens
  E3 engine_rdap           RDAP entities -> registrant emails / email domains
  E4 engine_dns_records    project DNS TXT/MX/NS of the seed -> SPF/DMARC/mail pivots
  E6 engine_internal_results prior DomainTools imports -> orgs / emails
"""

import json
import re
import time
from datetime import date
from urllib.parse import urlsplit

import requests
from django.db.models import Q

from assets.utils import _extract_domain
from assets.models import Asset
from findings.models import DNSRecord
from keywords.models import Keyword

# crt.sh retry parameters, ported from import_shodan.py's shodan_get: transient
# gateway failures (crt.sh often serves HTML on 502) are retried, the rest are not.
MAX_ATTEMPTS = 3
RETRY_BACKOFF = 5  # seconds, doubled per attempt
RETRY_STATUS = {408, 429, 500, 502, 503, 504}

# Host labels whose value is infrastructure noise, not brand signal. Seeded, not
# exhaustive: extend from dry-run output.
TOKEN_STOPWORDS = frozenset((
    'www www2 web api app apps dev dev2 dev3 stg stage staging test test1 qa uat prod '
    'production cdn cdn1 cdn2 static assets img images files media auth sso login logon '
    'vpn mail email smtp smtpout relay mx mx1 mx2 mx3 ns1 ns2 ns3 ns4 dns autodiscover '
    'outlook owa remote blog news shop store careers jobs support help docs doc portal git '
    'gitlab jira confluence ftp ssl wp wordpress admin db sql cache gateway proxy edge demo '
    'old legacy new mobile m internal intranet extranet feedback survey events event en de '
    'fr eu us apac emea latam corp group home main default redirect forward error empty '
    'secure homeoffice'
).split())

# WHOIS-privacy proxy mailbox domains: an email at one of these carries no brand signal.
PRIVACY_EMAIL_DOMAINS = frozenset({
    'domainspareplus.com', 'withemail.us', 'domainsbyproxy.com', 'privacyguardian.com',
    'contactprivacy.com', 'whoisproxy.io', 'proxy-registrar.com', 'privacy-gandi.com',
    'automattic-domains.com', 'namecheapprivacyguard.com', 'dotprivacyprotect.com',
    'privatero.com', 'spammart.com', 'mail-defender.com', 'contact-redirection.com',
})

# Substrings (case-insensitive) that mark an organization as a registrar/CA/hosting
# service rather than a brand owner.
ORG_NOISE = (
    'corporation service company', 'digicert', 'sectigo', 'comodo', "let's encrypt",
    'globalsign', 'entrust', 'identrust', 'ssl.com', 'quovadis', 'swisssign', 'amazon',
    'microsoft', 'google llc', 'cloudflare', 'akamai', 'network solutions', 'godaddy',
    'markmonitor', 'csc global', 'csc corporate', 'google trust services',
)

# Keyword types that a mined brand token feeds.
BRAND_KTYPES = [
    'crtsh_brand', 'porch-pirate_keyword', 'swaggerhub_keyword',
    'git-hound_keyword', 'shodan_keyword', 'fofa_keyword',
]

_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def crtsh_query(q, exclude_expired=True):
    """GET crt.sh JSON for query *q*.

    Returns the list of certificate rows, or None after exhausting retries. A
    non-JSON body (crt.sh serves HTML on 502) is treated as retryable.
    """
    params = {'output': 'json', 'q': q}
    if exclude_expired:
        params['exclude'] = 'expired'
    delay = RETRY_BACKOFF
    for attempt in range(1, MAX_ATTEMPTS + 1):
        retryable = False
        try:
            rsp = requests.get('https://crt.sh/', params=params, timeout=30)
        except requests.exceptions.RequestException as e:
            reason = f'request failed: {e}'
            retryable = True
        else:
            try:
                result = json.loads(rsp.text)
            except ValueError:
                reason = f'non-JSON response (HTTP {rsp.status_code}): {rsp.text[:200]}'
                retryable = True
            else:
                if rsp.status_code != 200:
                    reason = f'HTTP {rsp.status_code}: {rsp.text[:200]}'
                    retryable = rsp.status_code in RETRY_STATUS
                elif not isinstance(result, list):
                    reason = f'unexpected payload: {str(result)[:200]}'
                else:
                    return result
        if retryable and attempt < MAX_ATTEMPTS:
            print(f'[!] crt.sh q={q}: {reason}; retrying in {delay}s '
                  f'(attempt {attempt}/{MAX_ATTEMPTS})')
            time.sleep(delay)
            delay *= 2
        else:
            print(f'[-] crt.sh q={q}: {reason}')
            return None
    return None


def split_name_value(row):
    """Split one crt.sh row into (hosts, orgs).

    Every line of name_value plus the common_name is classified. A line is a host
    when it parses as a domain whose labels are all valid host labels; otherwise, if
    it has a space and is not a street-address tail (last token numeric), it is an
    organization string, kept in its original case. issuer_name is never read.
    """
    hosts, orgs = set(), set()
    seen = set()
    for field in (row.get('name_value') or '', row.get('common_name') or ''):
        for raw in str(field).split('\n'):
            if raw in seen:
                continue
            seen.add(raw)
            line = raw.strip()
            if not line or '@' in line or '://' in line:
                continue
            low = line.lower().lstrip('*.').strip()
            if not low:
                continue
            ed = _extract_domain(low)
            if (ed.domain and ed.suffix and ed.suffix.split('.')[-1].isalpha()
                    and all(_LABEL_RE.match(lbl) for lbl in low.split('.'))):
                hosts.add(low)
                continue
            if ' ' in low and len(low) >= 4:
                tokens = low.split()
                if tokens and tokens[-1].isdigit():
                    continue
                orgs.add(line)  # preserve original case for downstream search
    return hosts, orgs


def registrable_domain(host):
    """Registrable (PSL-aware) base domain for *host*, or '' when invalid."""
    ed = _extract_domain(host)
    return '.'.join(filter(None, (ed.domain, ed.suffix)))


def seed_domain(url):
    """Registrable base domain derived from a seed URL or bare domain ('' on failure)."""
    url = (url or '').strip()
    if not url:
        return ''
    host = urlsplit(url).hostname if (':' in url or '//' in url) else url
    if not host:
        return ''
    return registrable_domain(host.lower())


def tokenize(host):
    """Brand-relevant tokens from a host: labels minus the public suffix, split on
    '-', with pure-numeric, short, and stopword tokens dropped."""
    h = (host or '').strip().lower().rstrip('.')
    out = set()
    ed = _extract_domain(h)
    suffix_labels = set(ed.suffix.split('.')) if ed.suffix else set()
    for label in h.split('.'):
        if not label or label.startswith('*'):
            continue
        if label in suffix_labels:
            continue
        for tok in label.split('-'):
            if not tok or re.match(r'^\d+$', tok) or len(tok) < 3:
                continue
            if tok in TOKEN_STOPWORDS:
                continue
            out.add(tok)
    return out


def rdap_emails(domain):
    """Best-effort RDAP registrant emails for *domain* ([] when unreachable/error)."""
    emails = []
    try:
        rsp = requests.get(f'https://rdap.org/domain/{domain}',
                           headers={'Accept': 'application/json'}, timeout=20)
    except requests.exceptions.RequestException as e:
        print(f'[!] rdap {domain}: request failed: {e}')
        return emails
    if rsp.status_code != 200:
        return emails
    try:
        data = rsp.json()
    except ValueError:
        return emails
    if not isinstance(data, dict):
        return emails
    for entity in data.get('entities', []):
        vcard = (entity.get('vcardArray') or [None, []])[1]
        for entry in vcard:
            if len(entry) >= 4 and entry[0] == 'email' and entry[3]:
                emails.append(str(entry[3]).lower())
    return emails


# --------------------------------------------------------------------------- #
# Engines (each returns a list of candidate dicts)
# --------------------------------------------------------------------------- #

def engine_certificates(seed):
    """E1: crt.sh seed -> org + brand candidates.

    Returns (candidates, discovered_hosts, discovered_domains).
    """
    rows = crtsh_query(seed)
    if rows is None:
        print('[!] crt.sh unavailable')
        return [], set(), set()

    hosts = set()
    org_counts = {}  # lower-cased org -> {'n': count, 'display': original-case}
    for row in rows:
        row_hosts, row_orgs = split_name_value(row)
        hosts |= row_hosts
        for org in row_orgs:
            rec = org_counts.setdefault(org.lower(), {'n': 0, 'display': org})
            rec['n'] += 1

    # Drop registrar/CA noise, keep the ten most-attested organizations.
    orgs = {k: v for k, v in org_counts.items() if not any(n in k for n in ORG_NOISE)}
    top = sorted(orgs.items(), key=lambda kv: (-kv[1]['n'], kv[0]))[:10]

    domains = {registrable_domain(h) for h in hosts}
    domains.discard('')

    # Second query per kept org merges in additional hosts/domains for that brand.
    for _key, rec in top:
        rows2 = crtsh_query(f'"{rec["display"]}"')
        if not rows2:
            continue
        for row in rows2:
            h2, _ = split_name_value(row)
            hosts |= h2
            for h in h2:
                d = registrable_domain(h)
                if d:
                    domains.add(d)

    candidates = []
    for _key, rec in top:
        ev = f'crt.sh q={seed}: {rec["display"]} (n={rec["n"]})'
        for ktype in ('crtsh_brand', 'domaintools_registrant_org'):
            candidates.append({'keyword': rec['display'], 'ktype': ktype, 'evidence': ev,
                               'confidence': rec['n'], 'tags': '', 'engine': 'crt.sh'})

    seed_label = _extract_domain(seed).domain
    host_list = sorted(hosts)
    for d in sorted(domains):
        if d == seed:
            continue
        example = next((h for h in host_list if registrable_domain(h) == d), d)
        count = sum(1 for h in host_list if registrable_domain(h) == d)
        dlabel = _extract_domain(d).domain
        tags = ''
        if seed_label and dlabel and seed_label in dlabel and dlabel != seed_label:
            tags = ' [brand-adjacent]'
        candidates.append({'keyword': d, 'ktype': 'crtsh_domain', 'evidence': f'crt.sh: {example}',
                           'confidence': count, 'tags': tags, 'engine': 'crt.sh'})
    return candidates, hosts, domains


def engine_tokens(project, seed, extra_hosts, max_tokens=25):
    """E2: mine high-value brand tokens from the project's zone corpus plus E1 hosts."""
    corpus = set(
        Asset.objects.filter(related_project=project,
                             type__in=('domain', 'starred_domain'))
        .values_list('value', flat=True)
    ) | set(extra_hosts)

    token_zones = {}      # token -> set of registrable domains it appears under
    token_examples = {}   # token -> one corpus host that produced it
    zones = set()         # all distinct registrable domains in the corpus
    for host in corpus:
        if not host:
            continue
        d = registrable_domain(host)
        if not d:
            continue
        zones.add(d)
        for tok in tokenize(host):
            token_zones.setdefault(tok, set()).add(d)
            token_examples.setdefault(tok, host)

    total_zones = len(zones)
    cap = 0.15 * total_zones
    seed_label = _extract_domain(seed).domain

    existing_texts = {
        kw.lower() for kw in
        Keyword.objects.filter(related_project=project).values_list('keyword', flat=True)
    }

    scored = []
    for tok, zs in token_zones.items():
        n = len(zs)
        if not (2 <= n <= cap):
            continue
        if tok == seed_label:
            continue
        if tok in zones:  # whole-domain token
            continue
        if tok in existing_texts:
            continue
        scored.append((n, tok))
    scored.sort(key=lambda nt: (-nt[0], nt[1]))

    candidates = []
    for n, tok in scored[:max_tokens]:
        ev = f'token {tok}: {n} distinct zones, e.g. {token_examples.get(tok, tok)}'
        for ktype in BRAND_KTYPES:
            candidates.append({'keyword': tok, 'ktype': ktype, 'evidence': ev,
                               'confidence': n, 'tags': '', 'engine': 'token-mining'})
    return candidates


def engine_rdap(seed, discovered_domains):
    """E3: RDAP registrant emails for the seed and discovered domains."""
    candidates = []
    for d in ([seed] + sorted(discovered_domains))[:30]:
        for email in rdap_emails(d):
            if '@' not in email:
                continue
            edom = registrable_domain(email.split('@')[-1])
            if edom in PRIVACY_EMAIL_DOMAINS:
                continue
            candidates.append({'keyword': email, 'ktype': 'domaintools_registrant_email',
                               'evidence': f'rdap: {d}', 'confidence': 1, 'tags': '',
                               'engine': 'rdap'})
            if edom:
                candidates.append({'keyword': edom, 'ktype': 'domaintools_registrant_email_domain',
                                   'evidence': f'rdap: {d}', 'confidence': 1, 'tags': '',
                                   'engine': 'rdap'})
    return candidates


def engine_dns_records(project, seed):
    """E4: SPF/DMARC/MX/NS pivots from the seed's own DNS records."""
    rows = (
        DNSRecord.objects.filter(related_project=project, record_type__in=('TXT', 'MX', 'NS'))
        .filter(
            Q(related_asset__value__iexact=seed)
            | Q(related_asset__value__iexact='*.' + seed)
            | Q(related_asset__value__iexact='www.' + seed)
        )
        .values_list('record_type', 'record_value')
    )

    seed_label = _extract_domain(seed).domain
    found_domains = {}  # registrable domain -> record type
    found_emails = {}   # email -> record type
    for rtype, value in rows:
        value = (value or '').strip()
        if not value:
            continue
        if rtype == 'TXT':
            if 'v=spf1' in value:
                for mech in re.findall(r'\b(?:include|a|mx):([A-Za-z0-9._-]+)', value):
                    mech = re.sub(r'/[0-9]{0,3}$', '', mech).rstrip('.')
                    d = registrable_domain(mech)
                    if d:
                        found_domains.setdefault(d, 'TXT')
            if 'v=DMARC1' in value:
                for addr in re.findall(r'\br(?:ua|uf)=([^;,\s]+)', value, flags=re.I):
                    addr = addr.replace('mailto:', '').strip().rstrip(',;')
                    if '@' in addr:
                        found_emails.setdefault(addr.lower(), 'TXT')
        elif rtype in ('MX', 'NS'):
            host = re.sub(r'^\d+\s+', '', value) if rtype == 'MX' else value
            d = registrable_domain(host.rstrip('.'))
            if d:
                found_domains.setdefault(d, rtype)

    candidates = []
    for d, rt in found_domains.items():
        if d == seed:
            continue
        dlabel = _extract_domain(d).domain
        tags = '' if (seed_label and dlabel and seed_label in dlabel) else ' [third-party]'
        candidates.append({'keyword': d, 'ktype': 'crtsh_domain', 'evidence': f'DNS {rt} of {seed}',
                           'confidence': 1, 'tags': tags, 'engine': 'dns-records'})
    for email, rt in found_emails.items():
        edom = registrable_domain(email.split('@')[-1]) if '@' in email else ''
        if edom in PRIVACY_EMAIL_DOMAINS:
            continue
        candidates.append({'keyword': email, 'ktype': 'domaintools_registrant_email',
                           'evidence': f'DNS {rt} of {seed}', 'confidence': 1, 'tags': '',
                           'engine': 'dns-records'})
        if edom:
            elabel = _extract_domain(edom).domain
            etags = '' if (seed_label and elabel and seed_label in elabel) else ' [third-party]'
            candidates.append({'keyword': edom, 'ktype': 'domaintools_registrant_email_domain',
                               'evidence': f'DNS {rt} of {seed}', 'confidence': 1, 'tags': etags,
                               'engine': 'dns-records'})
    return candidates


def engine_internal_results(project):
    """E6: orgs/emails already present in prior DomainTools imports."""
    orgs, emails = {}, {}  # display -> evidence
    for value, description, raw in (
        Asset.objects.filter(related_project=project, source__icontains='domaintools')
        .values_list('value', 'description', 'raw')
    ):
        asset_org = None
        asset_emails = []
        if isinstance(raw, dict):
            ro = raw.get('registrant_org')
            if isinstance(ro, dict) and ro.get('value'):
                asset_org = str(ro['value']).strip()
            rc = raw.get('registrant_contact', {})
            if isinstance(rc, dict):
                for e in (rc.get('email') or []):
                    if isinstance(e, dict) and e.get('value'):
                        asset_emails.append(str(e['value']).strip().lower())
        desc = description or ''
        if not asset_org:
            m = re.search(r'Registrant Org:\s*([^,]+)', desc)
            if m:
                asset_org = m.group(1).strip()
        if not asset_emails:
            m = re.search(r'Registrant Emails:\s*(.+)', desc)
            if m:
                asset_emails = [x.strip().lower() for x in m.group(1).split(',') if x.strip()]
        ev = f'previous domaintools import for {value}'
        if asset_org:
            orgs.setdefault(asset_org.lower(), {'display': asset_org, 'evidence': ev})
        for em in asset_emails:
            emails.setdefault(em, ev)

    candidates = []
    for _key, rec in orgs.items():
        if any(n in _key for n in ORG_NOISE):
            continue
        candidates.append({'keyword': rec['display'], 'ktype': 'domaintools_registrant_org',
                           'evidence': rec['evidence'], 'confidence': 1, 'tags': '',
                           'engine': 'internal-results'})
    for email, ev in emails.items():
        edom = registrable_domain(email.split('@')[-1]) if '@' in email else ''
        if edom in PRIVACY_EMAIL_DOMAINS:
            continue
        candidates.append({'keyword': email, 'ktype': 'domaintools_registrant_email',
                           'evidence': ev, 'confidence': 1, 'tags': '', 'engine': 'internal-results'})
        if edom:
            candidates.append({'keyword': edom, 'ktype': 'domaintools_registrant_email_domain',
                               'evidence': ev, 'confidence': 1, 'tags': '', 'engine': 'internal-results'})
    return candidates


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #

def live_keyword_texts(project):
    """Lower-cased keyword texts that already have at least one enabled row.

    Keyword enable/disable is text-level everywhere in the UI (Enabled column, bulk
    bar, Manage modal all write every type of a text), so a new *type* for a text that
    is already live must inherit that state: a per-row mix is a state no control can
    express, and the Keywords list would report the whole text as Disabled while its
    other types keep scanning.
    """
    return {text.lower() for text, enabled in
            Keyword.objects.filter(related_project=project).values_list('keyword', 'enabled')
            if enabled}


def mine(project, seed, max_tokens=25, dry_run=False):
    """Run every engine, dedup, and store the survivors as keyword rows.

    Returns (created, skipped, suggested, report_lines). Nothing is created when
    dry_run is set. Brand-new keyword texts are stored DISABLED - that is the review
    mechanism (the control-center picker filters enabled=True, and scan commands skip
    disabled keywords). A new type of an already-known text inherits that text's state
    (see live_keyword_texts) so the text never ends up in a mixed state.
    """
    created = skipped = 0
    report = []
    suggestions = []

    def run(name, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            print(f'[!] engine {name} failed: {e}')
            return None

    c1, hosts, domains = run('crt.sh', engine_certificates, seed) or ([], set(), set())
    c2 = run('token-mining', engine_tokens, project, seed, hosts, max_tokens) or []
    c6 = run('internal-results', engine_internal_results, project) or []
    c3 = run('rdap', engine_rdap, seed, domains) or []
    c4 = run('dns-records', engine_dns_records, project, seed) or []

    today = date.today()
    seen = set()
    live_texts = live_keyword_texts(project)
    for cand in c1 + c2 + c6 + c3 + c4:
        key = (cand['keyword'].lower(), cand['ktype'])
        if key in seen:
            continue
        seen.add(key)
        if Keyword.objects.filter(related_project=project, keyword__iexact=cand['keyword'],
                                  ktype=cand['ktype']).exists():
            report.append(f'skip existing: {cand["ktype"]}:{cand["keyword"]}')
            skipped += 1
            continue
        suggestions.append(cand)
        if not dry_run:
            inherited = cand['keyword'].lower() in live_texts
            desc = (f'MINED {today:%Y-%m-%d} from {seed} via {cand["engine"]}: '
                    f'{cand["evidence"]}{cand.get("tags", "")} (n={cand["confidence"]})')
            Keyword.objects.create(related_project=project, keyword=cand['keyword'],
                                   ktype=cand['ktype'], enabled=inherited, description=desc)
            if inherited:
                report.append(f'enabled with existing keyword: {cand["ktype"]}:{cand["keyword"]}')
            created += 1

    for cand in sorted(suggestions, key=lambda c: (c['ktype'], c['keyword'])):
        report.append(f'{cand["ktype"]}: {cand["keyword"]}{cand.get("tags", "")} '
                      f'(n={cand["confidence"]}) via {cand["engine"]} - {cand["evidence"]}')
    return created, skipped, len(suggestions), report

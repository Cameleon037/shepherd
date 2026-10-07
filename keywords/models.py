from django.db import models

KTYPE_CHOICES = [
    ('domaintools_registrant_org', 'DomainTools - Registrant Organization'),
    ('domaintools_registrant_email', 'DomainTools - Registrant Email'),
    ('domaintools_registrant_email_domain', 'DomainTools - Registrant Email Domain'),
    ('crtsh_domain', 'CRTSH - Domain'),
    ('shodan_keyword', 'Shodan - query keyword'),
    ('porch-pirate_keyword', 'Porch-pirate - query keyword'),
    ('swaggerhub_keyword', 'SwaggerHub - query keyword'),
    ('ai_scribd_keyword', 'ShepherdAI - Scribd search'),
    ('git-hound_keyword', 'GitHound - query keyword'),
    ('fofa_keyword', 'FOFA - query keyword'),
]

# Labels are "<tool> - <type>"; order the types by tool, then by label.
KTYPE_CHOICES.sort(key=lambda choice: (choice[1].split(' - ')[0], choice[1]))

# Mini-sections for the keyword pickers, split by what the type feeds:
# asset/domain scanners (crtsh, domaintools, shodan, fofa) or data-leakage scanners
# (scribd, git-hound/ghleaks, porch-pirate, swaggerhub) that create findings.
KTYPE_SECTIONS = [
    ('Asset & domain discovery', ['crtsh_domain', 'domaintools_registrant_org',
                                  'domaintools_registrant_email',
                                  'domaintools_registrant_email_domain',
                                  'fofa_keyword', 'shodan_keyword']),
    ('Data-leakage findings', ['ai_scribd_keyword', 'git-hound_keyword',
                               'porch-pirate_keyword', 'swaggerhub_keyword']),
]


def ktype_picker_sections():
    """KTYPE_CHOICES grouped for the pickers: [{'name': str, 'types': [(value, label)]}].

    Types missing from KTYPE_SECTIONS go into a trailing 'Other' section so a new
    keyword type is never silently dropped from the picker.
    """
    sections = [{'name': name, 'types': [c for c in KTYPE_CHOICES if c[0] in values]}
                for name, values in KTYPE_SECTIONS]
    grouped = {value for _name, values in KTYPE_SECTIONS for value in values}
    other = [c for c in KTYPE_CHOICES if c[0] not in grouped]
    if other:
        sections.append({'name': 'Other', 'types': other})
    return sections


class Keyword(models.Model):
    """Keyword describing a company (can be the name)
    """
    related_project = models.ForeignKey("project.Project", on_delete=models.CASCADE)  # relation to the project
    keyword = models.CharField(max_length=1024)  # keyword to use as a starting point
    description = models.TextField(default='')
    enabled = models.BooleanField(default=True)  # disable keywords that should not be used
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    ktype = models.CharField(max_length=1024, default='registrant_org')  # what type of keyword, e.g. name, domain, ...

    class Meta:
        db_table = 'project_keyword'

    def __str__(self):
        return "%s" % (self.keyword)


def group_keywords_by_text(queryset):
    """Group Keyword rows sharing the same keyword text, preserving queryset order.

    Returns one dict per keyword text: id (primary row), keyword, ktypes,
    type_ids (ktype -> row id), ids, id_csv, enabled (all rows), description
    (first non-empty), creation_time (earliest, ISO string).
    """
    groups = []
    by_text = {}
    for kw in queryset:
        group = by_text.get(kw.keyword)
        if group is None:
            group = {
                'id': kw.id,
                'keyword': kw.keyword,
                'ktypes': [],
                'type_ids': {},
                'ids': [],
                'enabled': True,
                'description': '',
                'creation_time': kw.creation_time,
            }
            by_text[kw.keyword] = group
            groups.append(group)
        group['ktypes'].append(kw.ktype)
        group['type_ids'][kw.ktype] = kw.id
        group['ids'].append(kw.id)
        group['enabled'] = group['enabled'] and bool(kw.enabled)
        if kw.description and not group['description']:
            group['description'] = kw.description
        if kw.creation_time < group['creation_time']:
            group['creation_time'] = kw.creation_time
    for group in groups:
        group['id_csv'] = ','.join(str(i) for i in group['ids'])
        group['creation_time'] = group['creation_time'].isoformat()
    return groups

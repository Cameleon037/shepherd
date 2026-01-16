import django.forms.fields
from django import forms
from django.forms import ModelForm
from project.models import Keyword

class AddKeywordForm(ModelForm):
    KTYPE_CHOICES = [
        ('domaintools_registrant_org', 'DomainTools - Registrant Organization'),
        ('domaintools_registrant_email', 'DomainTools - Registrant Email'),
        ('domaintools_registrant_email_domain', 'DomainTools - Registrant Email Domain'),
        ('crtsh_domain', 'CRTSH - Domain'),
        ('shodan_keyword', 'Shodan - query keyword'),
        ('porch-pirate_keyword', 'Porch-pirate - query keyword'),
        ('swaggerhub_keyword', 'SwaggerHub - query keyword'),
        ('ai_scribd_keyword', 'ShepherdAI - Enable the ai search against Scribd for the given keyword'),
        ('git-hound_keyword', 'GitHound - query keyword'),

    ]

    ktype = forms.ChoiceField(choices=KTYPE_CHOICES, required=True, label="Keyword type")
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Keyword
        fields = ['keyword', 'ktype', 'description']

    def __init__(self, *args, **kwargs):
        super(AddKeywordForm, self).__init__(*args, **kwargs)
        self.fields['keyword'].widget.attrs.update({'class': 'form-control'})
        self.fields['ktype'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})

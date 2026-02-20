import django.forms.fields
from django import forms
from django.forms import ModelForm

from project.models import Project, Asset


class AddAssetForm(ModelForm):
    description = forms.CharField(required=False, widget=forms.Textarea)
    type = forms.ChoiceField(
        choices=[('domain', 'domain'), ('starred_domain', 'starred_domain'), ('ip', 'ip')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    subtype = forms.ChoiceField(
        choices=[('domain', 'domain'), ('subdomain', 'subdomain')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Asset
        fields = ['value', 'type', 'subtype', 'source', 'description']

    def __init__(self, *args, **kwargs):
        super(AddAssetForm, self).__init__(*args, **kwargs)
        self.fields['value'].widget.attrs.update({'class': 'form-control'})
        self.fields['source'].widget.attrs.update({
            'class': 'form-control',
            'value': 'manual',
        })
        self.fields['description'].widget.attrs.update({'class': 'form-control'})

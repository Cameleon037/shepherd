import django.forms.fields
from django import forms
from django.forms import ModelForm
from keywords.models import Keyword, KTYPE_CHOICES

class AddKeywordForm(ModelForm):
    ktypes = forms.MultipleChoiceField(
        choices=KTYPE_CHOICES, required=True, label="Keyword types",
        widget=forms.CheckboxSelectMultiple,
    )
    description = forms.CharField(required=False, widget=forms.Textarea)

    class Meta:
        model = Keyword
        fields = ['keyword', 'ktypes', 'description']

    def __init__(self, *args, **kwargs):
        super(AddKeywordForm, self).__init__(*args, **kwargs)
        self.fields['keyword'].widget.attrs.update({'class': 'form-control'})
        self.fields['ktypes'].widget.attrs.update({'class': 'form-control'})
        self.fields['description'].widget.attrs.update({'class': 'form-control'})

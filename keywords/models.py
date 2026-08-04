from django.db import models


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

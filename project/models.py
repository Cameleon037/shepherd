from django.db import models


class Project(models.Model):
    """Class describes a project or company that we want to monitor
    """
    projectname = models.CharField(max_length=1024, unique=True)
    description = models.TextField(default='')
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "%s" % (self.projectname)

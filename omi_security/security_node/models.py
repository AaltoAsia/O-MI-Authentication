from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Registered_Users(models.Model):
    username = models.CharField(max_length=200, unique=True)
    email = models.EmailField(max_length=200, unique=True)


class Group(models.Model):
    group_name = models.CharField(max_length=200, unique=True)


class User_Group_Relation(models.Model):
    user_id = models.ForeignKey(Registered_Users, on_delete=models.CASCADE)
    group_id = models.ForeignKey(Group, on_delete=models.CASCADE)

class Rule(models.Model):
    group_id = models.ForeignKey(Group, on_delete=models.CASCADE)
    hierarchy_id = models.CharField(max_length=200)
    write_permissions = models.BooleanField(default=False)
    object_rule = models.BooleanField(default=False)


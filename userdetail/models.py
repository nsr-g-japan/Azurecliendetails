from django.db import models

# Create your models here.

class Employee(models.Model):

    employee= models.CharField(max_length=255)
    employee_role=models.CharField(max_length=225)



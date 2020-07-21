from django.db import models

# Create your models here.
class category(models.Model):
    title = models.CharField(max_length=20)

class post(models.Model):
    title=models.CharField(max_length=100)
    overview=models.TextField()
    timestamp=models.DateTimeField(auto_now=True)
    comment_count=models.IntegerField(default=0)
    author=models.EmailField()
    image=models.ImageField()
    categories= models.ManyToManyField(category)
    featured= models.BooleanField(default=True)
    
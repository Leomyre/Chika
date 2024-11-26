from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    encrypted_content = models.TextField()  # Message chiffré
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)  # Indique si le message a été lu

    def __str__(self):
        return f'Message from {self.sender.username} to {self.receiver.username} at {self.timestamp}'

    class Meta:
        indexes = [
            models.Index(fields=['sender', 'receiver', 'timestamp']),
        ]

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    photo = models.ImageField(upload_to='profile_photos/', null=True, blank=True)

    def __str__(self):
        return self.user.username
    

# Signal pour créer un profil utilisateur si nécessaire
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        # Si l'utilisateur a été créé et qu'il n'a pas de profil, créez-en un
        if not hasattr(instance, 'profile'):
            UserProfile.objects.create(user=instance)

# Signal pour sauvegarder le profil après une mise à jour de l'utilisateur
@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    # Sauvegarde du profil après mise à jour de l'utilisateur
    if hasattr(instance, 'profile'):
        instance.profile.save()

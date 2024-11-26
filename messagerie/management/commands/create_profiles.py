from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from messagerie.models import UserProfile

class Command(BaseCommand):
    help = 'Créer les profils manquants pour les utilisateurs existants'

    def handle(self, *args, **kwargs):
        users_without_profile = User.objects.filter(profile__isnull=True)
        for user in users_without_profile:
            UserProfile.objects.create(user=user)
            self.stdout.write(self.style.SUCCESS(f"Profil créé pour l'utilisateur {user.username}"))
        self.stdout.write(self.style.SUCCESS("Tous les profils manquants ont été créés."))

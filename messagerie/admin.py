from django.contrib import admin
from .models import AboutInfo

@admin.register(AboutInfo)
class AboutInfoAdmin(admin.ModelAdmin):
    list_display = ('id', 'app_description', 'contact_info')  # Afficher ces champs dans l'admin
    search_fields = ('app_description', 'contact_info')  # Permettre la recherche sur ces champs

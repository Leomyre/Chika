# urls.py
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.inbox, name='inbox'),  # Boîte de réception
    path('conversation/<int:user_id>/', views.conversation, name='conversation'),  # Conversation avec un utilisateur
    path('send-message/', views.send_message, name='send_message'),  # Envoyer un nouveau message
    path('conversation/delete/<int:user_id>/', views.delete_conversation, name='delete_conversation'),
    path('manage-account/', views.manage_account, name='manage_account'),  # Gérer le compte utilisateur
    path('about/', views.about, name='about'),
    path('signup/', views.signup, name='signup'),  # Inscription
    path('logout/', views.logout_view, name='logout'),  # Déconnexion
    path('login/', auth_views.LoginView.as_view(template_name='messagerie/login.html'), name='login'),  # Connexion

]

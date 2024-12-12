from django import forms
from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Message
from django.contrib import messages
from .utils import decrypt_message, encrypt_message
from django.contrib.auth.forms import UserCreationForm
from django.core.files.storage import FileSystemStorage
from django.contrib.auth.hashers import make_password
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from django.db.models import Q
from .models import UserProfile

@login_required
def inbox(request):
    # Récupérer les utilisateurs ayant une conversation avec l'utilisateur connecté
    conversations = Message.objects.filter(
        Q(sender=request.user) | Q(receiver=request.user)
    ).select_related('sender', 'receiver').distinct()

    users = set()
    for msg in conversations:
        users.add(msg.sender)
        users.add(msg.receiver)
    users.discard(request.user)  # Retirer l'utilisateur connecté

    return render(request, 'messagerie/inbox.html', {'users': users})


@login_required
def conversation(request, user_id):
    receiver = get_object_or_404(User, id=user_id)

    # Assurez-vous que l'utilisateur connecté a un profil
    if not hasattr(request.user, 'profile'):
        UserProfile.objects.create(user=request.user)

    # Récupération et traitement des messages
    messages_list = Message.objects.filter(
        Q(sender=request.user, receiver=receiver) | Q(sender=receiver, receiver=request.user)
    ).order_by('timestamp')

    if request.method == 'POST':
        plain_text_message = request.POST['message']
        key = request.user.profile.token  # Utiliser le token de l'expéditeur comme clé de chiffrement

        # Chiffrement et sauvegarde du message
        encrypted_content = encrypt_message(plain_text_message, key)
        Message.objects.create(sender=request.user, receiver=receiver, encrypted_content=encrypted_content, key=key)
        messages.success(request, 'Message envoyé avec succès!')
        return redirect('conversation', user_id=user_id)

    # Décryptage des messages
    decrypted_messages = []
    for message in messages_list:
        try:
            decrypted_content = decrypt_message(message.encrypted_content, message.key)
            decrypted_messages.append({
                'sender': message.sender.username,
                'content': decrypted_content,
                'timestamp': message.timestamp
            })
        except Exception:
            decrypted_messages.append({
                'sender': message.sender.username,
                'content': "[Message illisible]",
                'timestamp': message.timestamp
            })

    return render(request, 'messagerie/conversation.html', {
        'receiver': receiver,
        'messages': decrypted_messages,
    })



@login_required
def send_message(request):
    users = User.objects.exclude(id=request.user.id)

    # Assurez-vous que l'utilisateur connecté a un profil
    if not hasattr(request.user, 'profile'):
        UserProfile.objects.create(user=request.user)

    if request.method == 'POST':
        receiver_id = request.POST.get('receiver')
        message_content = request.POST.get('message')
        key = request.user.profile.token  # Utiliser le token de l'utilisateur comme clé de chiffrement

        if receiver_id and message_content:
            receiver = get_object_or_404(User, id=receiver_id)
            encrypted_content = encrypt_message(message_content, key)

            # Créez le message avec le contenu chiffré
            Message.objects.create(
                sender=request.user,
                receiver=receiver,
                encrypted_content=encrypted_content,
                key=key
            )
            messages.success(request, f'Message envoyé à {receiver.username}!')
            return redirect('conversation', user_id=receiver.id)

        # Message d'erreur si le formulaire est incomplet
        messages.error(request, 'Veuillez sélectionner un destinataire et écrire un message.')

    return render(request, 'messagerie/send_message.html', {'users': users})



@login_required
def delete_conversation(request, user_id):
    # Récupérer tous les messages entre l'utilisateur actuel et l'autre utilisateur
    messages_to_delete = Message.objects.filter(
        (Q(sender=request.user) & Q(receiver__id=user_id)) | 
        (Q(receiver=request.user) & Q(sender__id=user_id))
    )
    # Supprimer les messages
    messages_to_delete.delete()
    
    return redirect('inbox')



def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('inbox')
    else:
        form = UserCreationForm()
    return render(request, 'messagerie/signup.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        
        # Vérifiez d'abord si l'utilisateur existe
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Vérifiez si l'utilisateur a un profil
            if hasattr(user, 'profile'):
                # Si le profil existe, connectez l'utilisateur
                login(request, user)
                messages.success(request, 'Vous êtes connecté avec succès.')
                return redirect('inbox')
            else:
                # Si le profil n'existe pas, affichez un message d'erreur
                messages.error(request, 'Compte non trouvé. Veuillez compléter votre profil.')
                return redirect('login')  # Redirige vers la page de connexion
        else:
            # Si l'utilisateur ou le mot de passe est incorrect
            messages.error(request, 'Nom d’utilisateur ou mot de passe invalide.')
    return render(request, 'messagerie/login.html')


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'Vous avez été déconnecté avec succès.')
    return redirect('login')

@login_required
def manage_account(request):
    if request.method == 'POST':
        # Récupérer les données du formulaire
        username = request.POST.get('username')
        #email = request.POST.get('email')  # Décommentez cette ligne si vous voulez permettre la modification de l'email
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        photo = request.FILES.get('photo')

        # Validation des champs
        if password and password != confirm_password:
            messages.error(request, "Les mots de passe ne correspondent pas.")
            return redirect('manage_account')

        # Mettre à jour l'utilisateur
        user = request.user
        if username:
            user.username = username
        # Si vous souhaitez permettre la modification de l'email, décommentez et utilisez la ligne ci-dessous :
        # if email:
        #    user.email = email

        if password:
            # Hacher le mot de passe avant de le sauvegarder
            user.password = make_password(password)
            update_session_auth_hash(request, user)  # Empêcher la déconnexion après changement de mot de passe

        # Gérer la photo de profil
        if photo:
            # Vérifier si l'utilisateur a un profil, sinon, en créer un
            if not hasattr(user, 'profile'):
                UserProfile.objects.create(user=user)

            # Sauvegarder la photo de profil
            fs = FileSystemStorage(location='media/profile_photos')
            filename = fs.save(photo.name, photo)
            user.profile.photo = f"profile_photos/{filename}"

        user.save()  # Sauvegarder l'utilisateur avec les nouvelles informations
        messages.success(request, "Profil mis à jour avec succès.")
        return redirect('manage_account')  # Rediriger après la mise à jour

    return render(request, 'messagerie/manage_account.html', {'user': request.user})

@login_required
def about(request):
    # Informations dynamiques ou fixes pour l'application et les informations de contact
    context = {
        'app_description': (
            "Bienvenue sur **Chika**, une application de messagerie moderne, sécurisée et intuitive. Conçue pour offrir "
            "la meilleure expérience utilisateur, Chika met l'accent sur la confidentialité et la simplicité.\n\n"
            "### Fonctionnalités principales :\n"
            "- **Messagerie cryptée** : Tous les messages sont chiffrés de bout en bout pour garantir une confidentialité totale.\n"
            "- **Suppression facile** : Vous pouvez supprimer vos messages ou conversations à tout moment, selon vos besoins.\n"
            "- **Gestion de profil** : Personnalisez votre expérience en modifiant votre pseudo, votre mot de passe ou votre photo de profil.\n"
            "- **Interface conviviale** : Une interface intuitive et rapide pour une navigation fluide.\n"
            "- **Mode sombre** : Alternez entre un thème clair et sombre pour un meilleur confort visuel.\n\n"
            "Chika a été créée pour simplifier la communication tout en respectant vos données personnelles. Nous croyons en un monde "
            "où la confidentialité n'est pas un luxe mais une priorité."
        ),
        'contact_info': (
            "### À propos de l'administrateur\n"
            "**Akari**, l'administrateur de l'application, s'engage à garantir une expérience utilisateur optimale. Si vous avez des questions, "
            "des suggestions ou des retours, n'hésitez pas à le contacter directement.\n\n"
            "- **Nom** : Akari\n"
            "- **Email** : ghleomyre@gmail.com\n\n"
            "Akari est disponible pour :\n"
            "- Vous aider à résoudre vos problèmes techniques.\n"
            "- Répondre à vos questions sur l'utilisation de l'application.\n"
            "- Recevoir vos suggestions pour améliorer Chika.\n\n"
            "Nous travaillons en permanence pour améliorer Chika et nous sommes ravis de recevoir vos retours !"
        ),
    }
    return render(request, 'messagerie/about.html', context)


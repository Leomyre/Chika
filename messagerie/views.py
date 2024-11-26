from django.shortcuts import get_object_or_404, render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .models import Message
from django.contrib import messages
from .utils import decrypt_message, encrypt_message
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login, authenticate, logout

@login_required
def inbox(request):
    users = User.objects.exclude(id=request.user.id)  # Tous les utilisateurs sauf l'utilisateur courant
    return render(request, 'messagerie/inbox.html', {'users': users})

@login_required
def conversation(request, user_id):
    receiver = get_object_or_404(User, id=user_id)
    messages_sent = Message.objects.filter(sender=request.user, receiver=receiver)
    messages_received = Message.objects.filter(sender=receiver, receiver=request.user)
    
    messages_list = list(messages_sent) + list(messages_received)
    messages_list.sort(key=lambda x: x.timestamp)  # Trier les messages par date

    if request.method == 'POST':
        plain_text_message = request.POST['message']  # Le message saisi par l'utilisateur
        password = receiver.username  # Utiliser le nom d'utilisateur du destinataire comme clé de chiffrement

        # Encrypt the message using the sender's username
        encrypted_content = encrypt_message(plain_text_message, request.user.username)

        Message.objects.create(sender=request.user, receiver=receiver, encrypted_content=encrypted_content)
        messages.success(request, 'Message envoyé avec succès!')  # Ajouter un message de succès
        return redirect('conversation', user_id=user_id)  # Rediriger vers la conversation avec ce destinataire

    decrypted_messages = []
    for message in messages_list:
        try:
            # Utiliser le nom d'utilisateur de l'expéditeur pour le décryptage
            decrypted_content = decrypt_message(message.encrypted_content, message.sender.username)
            decrypted_messages.append({
                'sender': message.sender.username,
                'content': decrypted_content,
                'timestamp': message.timestamp
            })
        except Exception as e:
            decrypted_messages.append({
                'sender': message.sender.username,
                'content': "Erreur lors du déchiffrement.",
                'timestamp': message.timestamp
            })

    return render(request, 'messagerie/conversation.html', {
        'receiver': receiver,
        'messages': decrypted_messages,
    })


def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Connexion automatique après l'inscription
            return redirect('inbox')
    else:
        form = UserCreationForm()
    return render(request, 'messagerie/signup.html', {'form': form})

@login_required
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, 'Vous êtes connecté avec succès.')
            return redirect('inbox')  # Redirige vers la boîte de réception après connexion
        else:
            messages.error(request, 'Nom d’utilisateur ou mot de passe invalide.')
    return render(request, 'messagerie/login.html')  # Assurez-vous d'avoir ce template


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'Vous avez été déconnecté avec succès.')
    return redirect('login')

# Create your views here.
from django.http import HttpResponse, JsonResponse
from security_node.models import Group, User_Group_Relation, Rule
from django.contrib.auth.models import User
from security_node.form import UserForm, GroupForm, SuperuserForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_protect
from oauth2_provider.views.generic import ProtectedResourceView
from oauthlib.oauth2 import RequestValidator
import json
import jwt
import time

TOKEN_EXPIRY = 900  # Unit is seconds so it makes 15minutes



#class ApiEndpoint(ProtectedResourceView):
#  def get(self, request, *args, **kwargs):
#    #self.get_validator_class().validate_bearer_token(token, scopes, request)
#        if self.get_validator_class().validate_bearer_token(self,token=request.GET.get('access_token'), scopes=None, request=request):
#            reply = {'message': 'Validated'}
#            return JsonResponse(reply, status=200)
#        else:
#            reply = {'message': 'Not Validated'}
#            return JsonResponse(reply, status=400)

protectedResourceView = ProtectedResourceView()

#OAuth2 Class Validator for validating access token 


#for validating JWT tokens
def token_validator(request):
    token = request.COOKIES.get('token')
    try:
        jwt.decode(token, 'MySecretKey', algorithm=['HS256'])
        return True
    except jwt.ExpiredSignature:
        return False


@login_required
def home(request):
    """
    View used for home page
    """
    if not token_validator(request):
        return redirect('logout')
    return render(request, "home.html")


@login_required
def about(request):
    """
    View used for about page
    """
    if not token_validator(request):
        return redirect('logout')

    token = request.COOKIES.get('token')
    token_decoded = jwt.decode(token, 'MySecretKey', algorithm=['HS256'])
    return render(request, "about.html", {'token_decoded': token_decoded, 'token': token})


@login_required
def create_oauth_token(request):
    """
    View used for creating token
    """
    response = redirect('home')
    exp = time.time() + TOKEN_EXPIRY
    token = jwt.encode({'email': request.user.email, 'is_superuser': request.user.is_superuser, "exp": exp},
                       'MySecretKey', algorithm='HS256').decode('utf-8')
    response.set_cookie("token", token)
    return response


@login_required
@csrf_protect
def authmodule(request):
    """
    View used for adding groups and users in groups
    """
    if not token_validator(request):
        return redirect('logout')

    if request.user.is_superuser:  # only super user can access the webclient
        message = ''
        if request.method == 'POST':
            users_added = request.POST.getlist('users_ingroup')
            action = request.POST['action']
            if action == 'addgroup':
                form = GroupForm(request.POST)  # GroupForm defined in forms.py
                if form.is_valid():
                    form.save()
                else:
                    message = form.errors['group_name'].as_text()
                group_added_id = Group.objects.get(group_name=request.POST["group_name"])
                for user in users_added:
                    instance = User_Group_Relation()
                    instance.user_id = User.objects.get(id=int(user))
                    instance.group_id = group_added_id
                    instance.save()
        users = User.objects.filter(is_superuser=False)
        registered_groups = Group.objects.all()
        return render(request, "authmodule.html",
                      {"list_users": users, "list_groups": registered_groups, 'errormessage': message})
    else:
        return redirect('home')


def logout(request):
    """
    View used for logging out of the service
    """
    if request.user.is_authenticated:
        auth_logout(request)
        response = redirect('home')
        response.delete_cookie('token')
        return response
    return redirect('home')


def login(request):
    """
    View used for logging in to the service
    """
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = AuthenticationForm(data=request.POST)  # django.contrib.auth provides AuthenticationForm
            if form.is_valid():
                username = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password')
                user = authenticate(username=username, password=raw_password)
                auth_login(request, user)  # built-in login function
                return redirect('create_oauth_token')
        else:
            form = AuthenticationForm()
        return render(request, "login.html", {'form': form})
    else:
        return redirect('home')


def signup(request):
    """
    View used for sign-up in to the service
    """
    if request.method == 'POST':
        form = UserForm(request.POST)  # UserForm defined in forms.py
        if form.is_valid():
            form.save()
            return redirect('home')
    else:
        form = UserForm()
    return render(request, 'signup.html', {'form': form})


def omi_authquery(request):
    """
    View used for getting details of the user or returns error if token is invalid or email address does not exists in database
    """

    email = request.GET.get('email')
    token = request.GET.get('token')
    if not token: token = request.GET.get('access_token')

    user = None

    if token:
        try:
            decoded_token = jwt.decode(token, 'MySecretKey', algorithm=['HS256'])
            decoded_email = decoded_token['email']
            user = User.objects.get(email=decoded_email)
        except:
            try:
                if protectedResourceView.get_validator_class().validate_bearer_token(token=token, scopes=None, request=request):
                    user = request.user
                    print(user)
                    print(user.__dir__())
            except:
                reply = {'message': 'Invalid Token or No user Exists'}
                return JsonResponse(reply, status=400)
    elif email:
        try:
            user = User.objects.get(email=email)
        except:
            reply = json.dumps({'message': 'No User Exist with this email address'})
            return HttpResponse(reply)
        
    reply = {'email': user.email, 'isAdmin': user.is_superuser}
    return JsonResponse(reply)
   


@login_required()
def secret_page(request, *args, **kwargs):
    return HttpResponse('Secret contents!', status=200)

@login_required
@csrf_protect
def superusers_panel(request):
    if not token_validator(request):
        return redirect('logout')

    if request.user.is_superuser:
        if request.method == 'POST':
            form = SuperuserForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('home')
        else:
            form = SuperuserForm()
        users = User.objects.all()
        return render(request, 'superusers_panel.html', {'form': form, "list_users": users})
    else:
        return redirect('home')


@login_required
@csrf_protect
def userRole(request, user_id):
    if not token_validator(request):
        return redirect('logout')

    user = User.objects.get(id=user_id)
    modify_user = request.POST.get('user_superuser')
    user.is_superuser = False if modify_user == "superuser" else True
    user.save()
    return redirect('superusers_panel')

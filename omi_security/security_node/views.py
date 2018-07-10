from django.shortcuts import render

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
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_protect
import json
import jwt
import time

TOKEN_EXPIRY = 900   # Unit is seconds so it makes 15minutes


def token_validator(request):
    token = request.COOKIES.get('token')
    try:
        jwt.decode(token, 'MySecretKey', algorithm=['HS256'])                                 #decode the token
        return True
    except jwt.ExpiredSignature:
        return False


@login_required                                                                                           #check first if user is logged in or not
def home(request):
    """
    View used for home page
    """
    if not token_validator(request):
        return redirect('logout')
    return render(request, "home.html")


@login_required
def about(request):                                                                                       #now when user tries to access/request the "about" page, the token is send by client
    """
    View used for about page
    """
    if not token_validator(request):
        return redirect('logout')

    token = request.COOKIES.get('token')
    token_decoded = jwt.decode(token, 'MySecretKey', algorithm=['HS256'])                                 #decode the token
    return render(request, "about.html",{'token_decoded':token_decoded,'token':token})                    #send the decoded token to about page


@login_required
def create_oauth_token(request):
    """
    View used for about page
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


    if request.user.is_superuser:                                           #only super user can access the webclient and not the normal user
        message = ''                                                        #initialize a variable "message" and make it empty
        if request.method == 'POST':
            users_added = request.POST.getlist('users_ingroup')             #get list of user ids added in the group
            action = request.POST['action']                                 #gets the save button's name = action into the "action" variable
            if action == 'addgroup':                                        #if action value is "add group"
                form = GroupForm(request.POST)                              #get the GroupForm defined in forms.py
                if form.is_valid():                                         #check validity of the GroupForm
                    form.save()                                             #save values in Group table
                else:
                    message = form.errors['group_name'].as_text()           #if validity fails, get error message as text form and save in message variable
                group_added_id = Group.objects.get(group_name=request.POST["group_name"])   #gets group object of the group just added
                for user in users_added:
                    instance = User_Group_Relation()                        #get User_Group_Relation table
                    instance.user_id = User.objects.get(id=int(user))       #get user id in User_Group_Relation table by matching user id of User table and in users-added list of user ids
                    instance.group_id = group_added_id                      #get group id in User_Group_Relation table
                    instance.save()                                         #save values in table
        users = User.objects.filter(is_superuser=False)                     #get all users who are not super users
        registered_groups = Group.objects.all()                             #get all groups
        return render(request, "authmodule.html",{"list_users":users, "list_groups":registered_groups, 'errormessage':message })    #send users, groups and error message(if any) to authmodule.html file
    else:
        return redirect('home')                                             #if user is not a superuser, redirect him to home page



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
    if not request.user.is_authenticated:                             #if user is not logged in
        if request.method == 'POST':                                  #after filling username and password fields and pressing login button, a post request is made
            form = AuthenticationForm(data=request.POST)              #django.contrib.auth provides AuthenticationForm to which requested data is send
            if form.is_valid():                                       #is_valid() method to run validation and return a boolean designating whether the data was valid
                username = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password')
                user = authenticate(username=username, password=raw_password)   # authenticate() to verify username and password
                auth_login(request, user)                             #built-in login function
                return redirect('create_oauth_token')                               #after successful login, user redirected to home page
        else:
            form = AuthenticationForm()                               #when user visiting the login page initially
        return render(request, "login.html", {'form': form})
    else:
        return redirect('home')                                       #if user is already logged in , redirect him to home page

def signup(request):
    """
    View used for sign-up in to the service
    """
    if request.method == 'POST':
        form = UserForm(request.POST)                                #UserForm is defined in forms.py
        if form.is_valid():                                          #Checks validity
            form.save()                                              #saves the credentials in database
            return redirect('home')                                  #redirected the user to home where he will be asked to login (after sign-up)
    else:
        form = UserForm()
    return render(request, 'signup.html', {'form': form})


def omi_authquery(request):
    '''
    What this function do
    :param request: request from browser
    :return: returns the details of user or return error if token is invalid or email address doesnot exists in database
    '''
    #email = request.GET.get('email')                                                    #get the email address from URL
    token = request.GET.get('token')                                                    #get the token from URL
    if not token: token = request.GET.get('access_token')

    if token:                                                                           #in case token is provided
        try:
            decoded_token = jwt.decode(token, 'MySecretKey', algorithm=['HS256'])       #decode the jwt token
            decoded_email = decoded_token['email']                                      #get email from token
            user = User.objects.get(email=decoded_email)                                # get the user from User table by matching with decoded email address
        except:
            reply = {'message': 'Invalid Token or No user Exists'}                      #if invalid token is provided, sends error message
            return JsonResponse(reply, status=400)
    #elif email:                                                                         #in case email is provided
    #    try:
    #        user = User.objects.get(email=email)                                        # get the user from User table by matching with requested email address
    #    except:
    #        reply = json.dumps({'message': 'No User Exist with this email address'})    # if invalid email is provided, sends error message
    #        return HttpResponse(reply)
    reply = {'email': user.email, 'isAdmin':user.is_superuser}                           #making json response: user email address, user exists status, his admin status
    return JsonResponse(reply)
    #{'allow': [<paths>], 'deny': [<paths>], 'isAdmin': true|false}


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








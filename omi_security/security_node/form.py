from django import forms
from django.contrib.auth.models import User

from security_node.models import Group, User_Group_Relation, Rule



class UserForm(forms.ModelForm):
    first_name = forms.CharField(label='First Name', max_length=64, widget=forms.TextInput(attrs={'placeholder': 'First name'}))
    last_name = forms.CharField(label='Last Name', max_length=64, widget=forms.TextInput(attrs={'placeholder': 'Last Name'}))
    username = forms.CharField(min_length=6, label='Username', max_length=32, widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    email = forms.EmailField(label='Email', max_length=64, widget=forms.TextInput(attrs={'placeholder': 'Email'}))
    password = forms.CharField(min_length=6, max_length=32, label='Password', widget=forms.PasswordInput)
    password1 = forms.CharField(min_length=6, max_length=32, label='Password confirmation', widget=forms.PasswordInput)
    #is_superuser = forms.BooleanField(label='Superuser', required=False)
    #superuser_secret = forms.CharField(label='superuser secret', max_length=64, required=False, widget=forms.TextInput(attrs={'placeholder': 'superuser secret'}))
    class Meta:
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'password1', 'is_superuser']
        model=User
    def clean(self):
        cleaned_data = super(UserForm, self).clean()
        password = cleaned_data.get("password")
        password1 = cleaned_data.get("password1")
        if password != password1:
            raise forms.ValidationError(
                "Password and Confirm Password does not match"
            )
        """
        if cleaned_data.get("is_superuser"):
            cleaned_data = super(UserForm, self).clean()
            superuser_secret =  cleaned_data.get("superuser_secret")
            superuser_secret2 =  "Iamsuperuser12345"
            if superuser_secret != superuser_secret2:
                raise forms.ValidationError(
                    "Please enter valid superuser secret or uncheck the superuser checkbox"
                )
                """
    def clean_email(self):
        email = self.cleaned_data.get('email')
        username = self.cleaned_data.get('username')
        if email and User.objects.filter(email=email).exclude(username=username).exists():
            raise forms.ValidationError(u'Email addresses must be unique.')
        return email
    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(UserForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user


class GroupForm(forms.ModelForm):
    group_name = forms.CharField(min_length=6, label='new_group', max_length=32, widget=forms.TextInput(attrs={'placeholder': 'new_group'}))
    class Meta:
        fields = ['group_name']
        model = Group


class SuperuserForm(forms.ModelForm):
    first_name = forms.CharField(label='First Name', max_length=64,widget=forms.TextInput(attrs={'placeholder': 'First name'}))
    last_name = forms.CharField(label='Last Name', max_length=64,widget=forms.TextInput(attrs={'placeholder': 'Last Name'}))
    username = forms.CharField(min_length=6, label='Username', max_length=32, widget=forms.TextInput(attrs={'placeholder': 'Username'}))
    email = forms.EmailField(label='Email', max_length=64, widget=forms.TextInput(attrs={'placeholder': 'Email'}))
    password = forms.CharField(min_length=6, max_length=32, label='Password', widget=forms.PasswordInput)
    password1 = forms.CharField(min_length=6, max_length=32, label='Password confirmation', widget=forms.PasswordInput)
    is_superuser = forms.BooleanField(label='Superuser', required=False)

    class Meta:
        fields = ['first_name', 'last_name', 'username', 'email', 'password', 'password1', 'is_superuser']
        model = User

    def clean(self):
        cleaned_data = super(SuperuserForm, self).clean()
        password = cleaned_data.get("password")
        password1 = cleaned_data.get("password1")
        if password != password1:
            raise forms.ValidationError(
                "Password and Confirm Password does not match"
            )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        username = self.cleaned_data.get('username')
        if email and User.objects.filter(email=email).exclude(username=username).exists():
            raise forms.ValidationError(u'Email addresses must be unique.')
        return email

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super(SuperuserForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
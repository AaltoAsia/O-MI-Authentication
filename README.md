OMI Project - Authentication module
===============================


Basic configuration
-------

1. Setup authentication settings in `omi_security/omi_security/settings.py`
2. Install O-MI Node compiled from `feature_authapiv2` branch in O-MI Node (It will be released in near-future release)
2. In O-MI Node `/etc/o-mi-node/application.conf`, set `omi-service.authAPI.v2.authentication-url` and set parameters objects as below:

```
# This example is at root level, outside of any objects
omi-service.authAPI.v2 {
  enable = true

  # Url to do authentication (checking if the consumer have valid credentials or session)
  authentication.url = "http://localhost:8000/omi_authquery"

  # Url to do authorization (checking what data a given user has permissions to read or write)
  #authorization.url = "<put authorization module url here>"
  
  # Extract variable parameters from o-mi request or the http request transfering it
  parameters.fromRequest {
      # from omiEnvelope attributes
      omiEnvelope {
        # attribute = variableName
        token = "token"
      }
      # from the Authorization header of http protocol
      authorizationHeader {
        # type = variableName
        Bearer = "token"
      }
      ## from other http headers
      #headers {
      #  # headerName = variableName
      #}
      ## from query parameters of http URI
      #query {
      #  # queryParameterName = variableName
      #  token = "token" # uncomment this if uri query parameter "token" should be allowed
      #}
  }
  # put variables into authentication request (http GET)
  parameters.toAuthentication {
      query {
        # parameterName = variableName  
        token = "token"
      }
      # authorizationHeader {}
      # headers {}
      # jsonbody {}
  }
  # extract parameters from Authentication response
  parameters.fromAuthentication {
    # same as above + jsonbody property search
    jsonbody {
      # searchWord = variableName
      email = "username"
      #isAdmin = "isadmin"
    }
  }
  
  # To make read requests to work without authenticated user and to get default permissions from authorization module:
  # we can skip authentication (othewise it will fail which will result in unauthorized error).
  # This should contain all variables that are used for authentication. Skip will happen if they all are empty.
  parameters.skipAuthenticationOnEmpty = ["token"]

  # and send empty username to authorization (authorization module should support sending of default permissions for empty username)
  parameters.initial {
    username = "" # to send empty username if username is not given by authentication
  }
  
}
```


Initial dependencies
-------

1. Install python and pip: `sudo apt-get install python3 python3-pip`
2. Install other dependencies: `sudo apt-get install libsasl2-dev python-dev libldap2-dev libssl-dev python-ldap django-auth-ldap`
1. Install python library: `pip3 install -r requirements.txt`


To configure NGINX as proxy, use the following method
------------------------------------------------

Install the nginx (if its not installed) using the following:

```bash
$ sudo apt-get install nginx
```

Next edit the default nginx settings using the following:

```bash
$ cd /etc/nginx/sites-enabled
/etc/nginx/sites-enabled$ sudo nano default
```

In the default file, comment out the following lines
```
#root /var/www/html;

# Add index.php to the list if you are using PHP
#index index.html index.htm index.nginx-debian.html;

location / {
    # First attempt to serve request as file, then
    # as directory, then fall back to displaying a 404.
    #try_files $uri $uri/ =404;

```
Inside the location section of the file add the following code and save
```
proxy_set_header        Host $host;
proxy_set_header        X-Real-IP $remote_addr;
proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header        X-Forwarded-Proto $scheme;
proxy_pass              http://127.0.0.1:8000$request_uri;
proxy_read_timeout  90;

```

Now restart the nginx using following command:

```bash
$ sudo service nginx reload
```

The front page based on django is now accessible at 127.0.0.1 on port 8000 i.e. `127.0.0.1:800`

Install and configure Openldap and phpldapadmin
-----------------------------------------------------------------

Install the ldap server (enter root password at administrator password)

```bash
sudo apt-get install slapd ldap-utils
```

After installation, go to this file and change the lines mentioned:
```bash
$ sudo gedit /etc/ldap/ldap.conf
...
BASE	dc=ldap,dc=com
URI	ldap://localhost:389
...
```

Reconfigure slapd
```bash
sudo dpkg-reconfigure slapd
```

During the reconfiguration, you need to select the following:

```
select "NO" to Omit Openldap server configuration
set domain name as: ldap.com
organization name to : ldap.com
enter root password at administrator password
select default MDB
select NO when asked "Remove the database when slapd is purged"
select YES for move old database
select NO to allow ldapv2 protocol
```

To test openldap on the command-line input the following 

```bash
sudo ldapsearch -x
```

Now install the phpLDAPadmin package and access the main configuration file:

```bash
$ sudo apt-get install phpldapadmin
$ sudo gedit /etc/phpldapadmin/config.php
```
In the `config.php` file, change the lines as:

```php
$servers->setValue('server','host','enter host IP address here');
$servers->setValue('server','base',array('dc=ldap,dc=com'));
$servers->setValue('login','bind_id','cn=admin,dc=ldap,dc=com');
```
and uncomment the following line while changing its parameter to true:

```php
$config->custom->appearance['hide_template_warning'] = true;
```

Finally start the apache2 service:

```bash
$ sudo service apache2 start
```

The `phpldapadmin` is now accessible at http://host/phpldapadmin/.

Follow this link: https://www.techrepublic.com/article/how-to-populate-an-ldap-server-with-users-and-groups-via-phpldapadmin/.
Create Organizational units ("groups" and "users"). Under "groups" create two posix groups "normal-users" and "superuser". Under "users" create generic user accounts,
for example, I made 3 users (Hassaan, Maria and Ruman). Hassaan will be superuser so I added his memberUid in superuser group and other two users in normal-users
group.

Now to add email address, you need to enter each user's profile select "Add new attribute" and add email from there. Another method from the command line is:

```bash
sudo ldapmodify -H ldap://localhost:389 -D cn=admin,dc=ldap,dc=com -x -W
Enter LDAP Password:
dn: cn=Ruman Khan,ou=users,dc=ldap,dc=com
changetype: modify
add: mail
mail: ruman@aalto.fi
```

The O-MI security module can now be launched with the following:

```bash
python3 manage.py runserver 0:8000
```

_Note:_ When you enter username and password of the user from Openldap directory, the user will be logged in and is added into the User table of Django (if not already exists).











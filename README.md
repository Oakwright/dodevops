This is essentially an experiment/prototype that got a little too big and had some potential. So it's being turned into a project.

proto.py is the original prototype.

protodeploy is the original exerimental deploy script that worked for at least two of the django apps I work on.

This project uses inquirer to get user input. As far as I know it only works on linux and mac. 
When debugging in pycharm, you may need to set the run/debug settings to use the terminal emulation.
You can find a link with more info here: https://intellij-support.jetbrains.com/hc/en-us/community/posts/360003383619-Pycharm-2019-termios-error-25-Inappropriate-ioctl-for-device-?page=1#community_comment_6589796593042 and here https://github.com/magmax/python-readchar/issues/11

## Generate DO API token

In order for this app to work it needs a valid DigitalOcean Personal Access Token. 
The token is not required after this is run, so it is okay to recyle the token when finished. 
The token can either be stored in a .env file, or it can be pasted into the app at run time. 

### To generate a new token

Go here: https://cloud.digitalocean.com/account/api/tokens

Pick whatever name you want for the token, it doesn't matter. 
Pick whatever token expiration you want depending on your personal paranoia level. 
Write permissions are required. 

Once the token is generated copy it and paste it somewhere safe like a password manager such as 1password. 
The token won't be displayed again, so if you don't get it saved somewhere safe you'll have to regenerate it.

Protect your token well. 
Anyone with access to your token has the ability to create and destroy things and incur you costs, so be careful with it. 
This is opensource so that you can read the code if you want and verify how the token is used. 
Storing the token in the .env file is convenient but it is not the most secure, so if you feel paranoid don't do that or delete the token after. 

If you want more info about DO tokens, see here: https://docs.digitalocean.com/reference/api/create-personal-access-token/

## Generate DO Spaces Key

A DO Spaces key is required for storing a media upload folder, as app platform doesn't have storage. 

### To generate an app spaces key 

Go here: https://cloud.digitalocean.com/account/api/spaces 

You can use whatever name you want for the key, it doesn't matter. 
It will display two values, a key ID and a longer access key, save both somewhere safe like a password manager. 
It won't display the access key again, so if you don't save it you'll have to regenerate it. 

You can put the values in an .env file, or enter it at runtime.

Protect the token well.

To learn more about DO spaces keys, go here: https://docs.digitalocean.com/products/spaces/how-to/manage-access/#access-keys

## Create a DO Spaces S3 bucket

You must create an S3 bucket on DO's web interface:

https://cloud.digitalocean.com/spaces/new

## Filling out .env file

A .env file isn't required, but if you store values in it then it will save effort. 
But if you feel storing values in the .env file isn't secure enough for your personal paranoia levels you can instead enter things at runtime.

The format of the env file is:

```
$DIGITALOCEAN_TOKEN=dop_v1_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
$AWS_ACCESS_KEY_ID=DOxxxxxxxxxxxxxxxxxx
$AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
$AWS_REGION=ams3
component_name=example_app
app_prefix=example
gh_repo=someuser/example-app
gh_branch=somebranch
django_user_module=core
secret_key_env_key=SECRET_KEY
allowed_hosts_env_key=ALLOWED_HOSTS
DEBUG=1
```

```shell
poetry run protodeploy
```

```shell
poetry run start
```

```shell
poetry run protocheckdb
```

```shell
poetry run protogetkeys
```

```shell
poetry run protogetdbcluster
```

```shell
poetry run protoselectcluster
```

```shell
poetry run protoselect_spaces
```


https://cloud.digitalocean.com/apps/github/install
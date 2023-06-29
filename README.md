# TLDR

This is a tool to take github repos for Django projects and put them on DigitalOcean App Spaces with managed database and DO Spaces S3 storage.

You will need:

1) Poetry installed locally to run this tool
2) DigitalOcean account https://www.digitalocean.com/?refcode=9ef6f738fd8a
3) DigitalOcean API token: https://cloud.digitalocean.com/account/api/tokens
4) DigitalOcean S3 keys: https://cloud.digitalocean.com/account/api/spaces
5) Authorize DigitalOcean to pull your github repos: https://cloud.digitalocean.com/apps/github/install
6) A DigitalOcean S3 bucket: https://cloud.digitalocean.com/spaces/new
7) A DigitalOcean PostgreSQL database cluster: https://cloud.digitalocean.com/databases
8) A database and user and connection pool configured on the database cluster
9) Manually add the app as a trusted source on the database

There are plans to integrate items 6-9 into this tool, we just haven't gotten that far yet.

To run the tool:

```shell
poetry run start
```

# What is this

This is essentially an experiment/prototype that got a little too big and had some potential. So it's being turned into a project.

proto.py is the original prototype.

This project uses inquirer to get user input. As far as I know it only works on linux and mac. 
When debugging in pycharm, you may need to set the run/debug settings to use the terminal emulation.
You can find a link with more info here: https://intellij-support.jetbrains.com/hc/en-us/community/posts/360003383619-Pycharm-2019-termios-error-25-Inappropriate-ioctl-for-device-?page=1#community_comment_6589796593042 and here https://github.com/magmax/python-readchar/issues/11

# Details

## Generating DO API token

In order for this app to work it needs a valid DigitalOcean Personal Access Token. 
The token is not required after this is run, so it is okay to recyle the token when finished. 
The token can either be stored in a .env file, or it can be pasted into the app at run time. 

### To generating a new token

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

## Generating DO Spaces Key

A DO Spaces key is required for storing a media upload folder, as app platform doesn't have storage. 

### To generating an app spaces key 

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
DIGITALOCEAN_TOKEN=dop_v1_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_ACCESS_KEY_ID=DOxxxxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# AWS_REGION=ams3
# APP_NAME=example-rest-app
# COMPONENT_NAME=example-rest
# APP_PREFIX=example
GH_REPO=xusernamex/xrepox
# GH_BRANCH=main
# DJANGO_ROOT_MODULE=example
# DJANGO_USER_MODULE=core
# SECRET_KEY_ENV_KEY=SECRET_KEY
# SECRET_KEY=change_me
# ALLOWED_HOSTS_ENV_KEY=ALLOWED_HOSTS
# DEBUG=1
# DOMAIN=rest.example.com
# PARENT_DOMAIN=example.com
# OIDC="\"-----BEGIN RSA PRIVATE KEY-----\\n_xxx_\\n-----END RSA PRIVATE KEY-----\\n\""
```

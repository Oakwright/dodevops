import json
import logging
import secrets

import boto3
from dotenv import load_dotenv
import os
import inquirer
from pydo import Client
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

load_dotenv()


def _get_env_var_from_list_or_keep_original(env_var_list, original_value=None,
                                            override=True):
    if original_value and not override:
        return original_value

    for env_var in env_var_list:
        if os.getenv(env_var):
            logger.debug("Found {} in .env".format(env_var))
            return os.getenv(env_var)
    logger.debug("No env var from list found in .env")
    return original_value


def update_app_from_app_spec(client, target_app, app_spec):
    if not target_app:
        logger.debug("No app found, aborting")
        return None
    elif not app_spec:
        logger.debug("No app spec found, aborting")
        return None
    elif not client:
        logger.debug("No client found, aborting")
        return None
    logger.debug("Preparing to update app, validating app spec")
    validate_body = {
        "app_id": target_app["id"],
        "spec": app_spec
    }
    update_body = {
        "spec": app_spec
    }
    validate_response = client.apps.validate_app_spec(validate_body)
    print(validate_response)
    answer = inquirer.prompt([inquirer.Confirm('continue',
                                               message="Do you want to continue?")])
    if not answer["continue"]:
        print("Aborting")
        return None
    response = client.apps.update(id=target_app["id"], body=update_body)
    return response


def create_app_from_app_spec(client, potential_spec):
    print(potential_spec)
    validate_body = {
        "spec": potential_spec
    }
    validate_response = client.apps.validate_app_spec(validate_body)
    print(validate_response)
    answer = inquirer.prompt([inquirer.Confirm('continue',
                                               message="Do you want to continue?")])
    if not answer["continue"]:
        print("Aborting")
        return None
    response = client.apps.create(body=validate_body)
    return response


def build_env_list(env_obj, secret_key_env_key="SECRET_KEY",
                   allowed_hosts_env_key="ALLOWED_HOSTS"):
    runtime_vars = [secret_key_env_key, allowed_hosts_env_key, "OIDC_RSA_PRIVATE_KEY",
                    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
                    "AWS_STORAGE_BUCKET_NAME", "AWS_S3_ENDPOINT_URL", "AWS_LOCATION",
                    "DATABASE_URL"]
    run_and_build_vars = ["DEBUG"]
    build_vars = ["DISABLE_COLLECTSTATIC"]

    env_list = []
    for var in runtime_vars:
        temp_obj = {
            "key": var,
            "value": env_obj[var],
            "scope": "RUN_TIME"
        }
        env_list.append(temp_obj)
    for var in run_and_build_vars:
        temp_obj = {
            "key": var,
            "value": env_obj[var],
            "scope": "RUN_AND_BUILD_TIME"
        }
        env_list.append(temp_obj)
    for var in build_vars:
        temp_obj = {
            "key": var,
            "value": env_obj[var],
            "scope": "BUILD_TIME"
        }
        env_list.append(temp_obj)

    return env_list


def start_app_spec_file(appname, region="ams"):
    app_spec = {
        "name": appname,
        "services": [],
        "databases": [],
        "domains": [],
        "region": region,
        "alerts": [],
        "ingress": {
            "rules": []
        },
    }

    return app_spec


def populate_app_spec_ingress(app_spec, component_name):
    new_rule = {
        "match": {
            "path": {
                "prefix": "/"
            }
        },
        "component": {
            "name": component_name
        }
    }
    app_spec["ingress"]["rules"].append(new_rule)
    return app_spec


def populate_app_spec_alerts(app_spec):
    alerts = [{
        "rule": "DEPLOYMENT_FAILED"
    },
        {
            "rule": "DOMAIN_FAILED"
        }]
    app_spec["alerts"] = alerts
    return app_spec


def populate_app_spec_domains(app_spec, domain, zone):
    domain_json = {
        "domain": domain,
        "type": "PRIMARY",
        "zone": zone
    }
    app_spec["domains"].append(domain_json)
    return app_spec


def populate_app_spec_databases(app_spec, database_cluster_name, database_name,
                                database_user):
    database_json = {
        "name": database_cluster_name,
        "engine": "PG",
        "version": "15",
        "production": True,
        "cluster_name": database_cluster_name,
        "db_name": database_name,
        "db_user": database_user
    }
    app_spec["databases"].append(database_json)
    return app_spec


def populate_app_spec_services(app_spec, component_name, gh_repo, gh_branch, env_list,
                               django_user_module,
                               django_root_module, deploy_on_push=True, port=8000,
                               size_slug="basic-xxs"):
    services_json = {
        "name": component_name,
        "github": {
            "repo": gh_repo,
            "branch": gh_branch,
            "deploy_on_push": deploy_on_push
        },
        "build_command": "python manage.py makemigrations\npython manage.py makemigrations {}".format(
            django_user_module),
        "run_command": "gunicorn --worker-tmp-dir /dev/shm {}.wsgi:application  --bind 0.0.0.0:{}".format(
            django_root_module, port),
        "source_dir": "/",
        "environment_slug": "python",
        "envs": env_list,
        "instance_size_slug": size_slug,
        "instance_count": 1,
        "http_port": port
    }
    app_spec["services"].append(services_json)
    return app_spec


def build_app_spec_file(env_obj):
    env_list = build_env_list(env_obj["envvars"],
                              secret_key_env_key=env_obj["secret_key_env_key"],
                              allowed_hosts_env_key=env_obj["allowed_hosts_env_key"])
    region = env_obj["region"]
    appname = env_obj["appname"]
    component_name = env_obj["component_name"]
    domain = env_obj["domain"]
    zone = env_obj["zone"]
    database_cluster_name = env_obj["database_cluster_name"]
    database_name = env_obj["database_name"]
    database_user = env_obj["database_user"]
    gh_repo = env_obj["gh_repo"]
    gh_branch = env_obj["gh_branch"]
    django_user_module = env_obj["django_user_module"]
    django_root_module = env_obj["django_root_module"]

    app_spec = start_app_spec_file(appname=appname, region=region)
    app_spec = populate_app_spec_ingress(app_spec, component_name=component_name)
    app_spec = populate_app_spec_alerts(app_spec)
    app_spec = populate_app_spec_domains(app_spec, domain=domain,
                                         zone=zone)
    app_spec = populate_app_spec_databases(app_spec,
                                           database_cluster_name=database_cluster_name,
                                           database_name=database_name,
                                           database_user=database_user)
    app_spec = populate_app_spec_services(app_spec, component_name=component_name,
                                          gh_repo=gh_repo,
                                          gh_branch=gh_branch,
                                          django_user_module=django_user_module,
                                          env_list=env_list,
                                          django_root_module=django_root_module)
    return app_spec


def get_app(client, app_name="app"):
    app_resp = client.apps.list()
    appcount = len(app_resp["apps"])
    if appcount > 0:
        options = []
        default_app = None
        for a in app_resp["apps"]:
            options.append((a["spec"]["name"], a))
            if a["spec"]["name"] == app_name:
                default_app = a
                logger.debug("Found default app")
            elif default_app is None and app_name in a["spec"]["name"]:
                default_app = a
                logger.debug("App {} contains {}".format(a["spec"]["name"], app_name))
        options.append(("* Cancel *", None))
        questions = [
            inquirer.List('app',
                          message="App List",
                          choices=options,
                          default=default_app,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['app']
        if pickedoption and pickedoption["spec"] and pickedoption["spec"]["name"]:
            logger.debug("Using app {}".format(pickedoption["spec"]["name"]))
            return pickedoption
        else:
            print("No valid app chosen")
            return None
    else:
        print("No apps found")
        return None


def get_allowed_hosts():
    logger.debug("domain name is accessible from a DO variable in app platform")
    return "${APP_DOMAIN}"


def generate_rsa_key():
    key = rsa.generate_private_key(
        backend=crypto_default_backend(), public_exponent=65537, key_size=4096
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.TraditionalOpenSSL,
        crypto_serialization.NoEncryption(),
    ).decode("utf-8")
    return private_key


def get_oidc_rsa_key():
    logger.debug("Generating RSA key")
    rsa_key_line = "\"{}\"".format(repr(generate_rsa_key())[1:-1])
    return rsa_key_line


def get_app_name(appname):
    if appname is None:
        appname = inquirer.text("What is the name of your app?")
    else:
        appname = inquirer.text("What is the name of your app?", default=appname)
    return appname


def get_aws_region(client, region_slug=None):
    if region_slug is None:
        region_slug = "ams3"
    print("Getting regions")
    reg_resp = client.regions.list()
    regioncount = len(reg_resp["regions"])
    if regioncount > 0:
        options = []
        for r in reg_resp["regions"]:
            if r["available"] and "storage" in r["features"]:
                options.append((r["name"] + " - " + r["slug"], r["slug"]))
                if r["slug"] == region_slug:
                    logger.debug("Found default region")
                    # return r["slug"]
        questions = [
            inquirer.List('region',
                          message="Which region?",
                          choices=options, default=region_slug,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['region']
        logger.debug("Using region {}".format(pickedoption))
        return pickedoption
    else:
        print("No regions found, defaulting to ams3")
        return "ams3"


def get_spaces(s3client):
    space_resp = s3client.list_buckets()
    spacecount = len(space_resp['Buckets'])
    if spacecount > 0:
        options = []
        for s in space_resp['Buckets']:
            options.append(s['Name'])
        # options.append(None)
        questions = [
            inquirer.List('space',
                          message="Which space?",
                          choices=options,
                          default=0,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['space']
        logger.debug("Using space {}".format(pickedoption))
        return pickedoption
    else:
        print("No spaces found")
        return None


def create_folder(s3client, space, component_name, parent_folder=""):
    folder_name = inquirer.text(message="Please enter a folder name", default=component_name)
    if folder_name:
        s3client.put_object(Bucket=space, Key=parent_folder + folder_name + "/")
        return folder_name


def get_root_folder(s3client, space, component_name="app"):
    return_folder = None
    while not return_folder:
        space_resp = s3client.list_objects(Bucket=space, Delimiter='/')

        if len(space_resp['CommonPrefixes']) > 0:
            options = []
            for s in space_resp['CommonPrefixes']:
                options.append(s['Prefix'][0:-1])
            options.append(("* Create new folder *", "new_folder"))
            questions = [
                inquirer.List('folder',
                              message="Which folder?",
                              choices=options,
                              default=component_name,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['folder']
            print("Using folder {}".format(pickedoption))
            return_folder = pickedoption
        else:
            print("No folders found")
            return_folder = None
        if not return_folder or return_folder == "new_folder":
            return_folder = create_folder(s3client, space, component_name)

    return return_folder


def get_media_folder(s3client, space, media_folder="media",
                     root_folder=None):
    found_folder = None
    while not found_folder:
        space_resp = s3client.list_objects(Bucket=space, Prefix=root_folder + '/',
                                           Delimiter='{}/'.format(media_folder))

        default_choice = media_folder
        if 'CommonPrefixes' in space_resp and len(space_resp['CommonPrefixes']) > 0:
            options = []
            for s in space_resp['CommonPrefixes']:
                options.append(s['Prefix'][0:-1])
                if s['Prefix'][0:-1] == root_folder + '/' + media_folder:
                    logger.debug("Found default folder {}".format(s['Prefix'][0:-1]))
                    return s['Prefix'][0:-1]
                elif media_folder in s['Prefix'][0:-1]:
                    logger.debug(
                        "Folder {} contains {}".format(s['Prefix'][0:-1], media_folder))
                    default_choice = s['Prefix'][0:-1]
            options.append(None)
            questions = [
                inquirer.List('folder',
                              message="Which folder?",
                              choices=options,
                              default=default_choice,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['folder']
            logger.debug("Using folder {}".format(pickedoption))
            found_folder = pickedoption
        else:
            print("No folders found")
            found_folder = None
        if not found_folder:
            found_folder = create_folder(s3client, space, media_folder, root_folder + '/')


def get_cluster(client, cluster_name="db-postgresql"):
    chosen_cluster = None
    while not chosen_cluster:
        db_cluster_resp = client.databases.list_clusters()
        if "databases" in db_cluster_resp and len(db_cluster_resp["databases"]) > 0:
            default_db_cluster = None
            options = []
            for c in db_cluster_resp["databases"]:
                options.append((c['name'], c))
                if c['name'] == cluster_name:
                    default_db_cluster = c
                    logger.debug(
                        "Found default cluster {}".format(default_db_cluster['name']))
                elif default_db_cluster is None and cluster_name in c['name']:
                    default_db_cluster = c
                    logger.debug("Cluster {} contains {}".format(default_db_cluster['name'],
                                                                 cluster_name))

            options.append(None)
            questions = [
                inquirer.List('cluster',
                              message="Which cluster?",
                              choices=options, default=default_db_cluster,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['cluster']
            chosen_cluster = pickedoption
        else:
            print("No clusters found")
            chosen_cluster = None
        if not chosen_cluster:
            print(
                "No cluster found, please create a postgres one here: https://cloud.digitalocean.com/databases/new")
            answer = inquirer.prompt([inquirer.Confirm('retry',
                                                       message="Do you want to retry?")])
            if not answer["retry"]:
                print("Aborting")
                return None
    return chosen_cluster


def get_pool(client, cluster, pool_name="pool"):
    chosen_pool = None
    while not chosen_pool:
        pool_default = None
        pool_resp = client.databases.list_connection_pools(cluster["id"])
        poolcount = len(pool_resp["pools"])
        if poolcount > 0:
            pooloptions = []
            for p in pool_resp["pools"]:
                pooloptions.append((p["name"], p))
                if p["name"] == pool_name:
                    pool_default = p
                    logger.debug("Found default pool {}".format(pool_default["name"]))
                elif pool_default is None and pool_name in p["name"]:
                    pool_default = p
                    logger.debug(
                        "Pool {} contains {}".format(pool_default["name"], pool_name))
            pooloptions.append(None)
            questions = [
                inquirer.List('pool',
                              message="Which pool?",
                              choices=pooloptions,
                              default=pool_default,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['pool']
            chosen_pool = pickedoption
        else:
            print("No connection pools found")
            chosen_pool = None
        if not chosen_pool:
            print(
                "No pool found, please create a pool here: https://cloud.digitalocean.com/databases/")
            answer = inquirer.prompt([inquirer.Confirm('retry',
                                                       message="Do you want to retry?")])
            if not answer["retry"]:
                print("Aborting")
                return None
    return chosen_pool


def get_root_domain(domain):
    domain_parts = domain.split(".")
    if len(domain_parts) > 2:
        zone = domain_parts[-2] + "." + domain_parts[-1]
    else:
        zone = domain
    return zone


def get_domain_info(existing_app=None, domain=None, zone=None, client=None, prefix="test"):
    logger.debug("Getting domain info")
    if not domain and client:
        result = client.domains.list()
        if "domains" in result and len(result["domains"]) > 0:
            domain = prefix + "." + result["domains"][0]["name"]
    if not zone and domain:
        zone = get_root_domain(domain)
    if existing_app is not None and existing_app["spec"]["domains"]:
        domain = existing_app["spec"]["domains"][0]["domain"]
        zone = existing_app["spec"]["domains"][0]["zone"]
        domain = inquirer.text("What domain do you want (such as test.example.com)",
                               default=domain)
        zone = inquirer.text("What zone is that domain in (such as example.com)",
                             default=zone)
        returnobj = {"domain": domain, "zone": zone}
    else:
        domain = inquirer.text("What domain do you want (such as test.example.com)",
                               default=domain)
        zone = inquirer.text("What zone is that domain in (such as example.com)",
                             default=zone)
        returnobj = {"domain": domain, "zone": zone}
    return returnobj


def get_django_root_module(module_guess=None):
    if module_guess is not None:
        root_module = inquirer.text("What is the name of your Django root module?",
                                    default=module_guess)
    else:
        root_module = inquirer.text("What is the name of your Django root module?")
    return root_module


def get_django_user_module(django_user_module="core"):
    if not django_user_module:
        django_user_module = "core"
    user_module = inquirer.text("What is the name of your Django user module?",
                                default=django_user_module)

    return user_module


def clean_debug_value(debugvalue=None):
    debugmode = False
    binarymode = True
    if debugvalue == "1":
        debugmode = True
        binarymode = True
    elif debugvalue == "0":
        debugmode = False
        binarymode = True
    elif debugvalue == "True":
        debugmode = True
        binarymode = False
    elif debugvalue == "False":
        debugmode = False
        binarymode = False
    elif debugvalue:
        debugmode = True
        binarymode = False

    debugmode = inquirer.confirm("Enable debug mode?", default=debugmode)
    binarymode = inquirer.confirm("Is debug environment variable stored as binary (0/1)?",
                                  default=binarymode)

    if not binarymode:
        if debugmode:
            return "True"
        else:
            return "False"
    else:
        if debugmode:
            return "1"
        else:
            return "0"


def clean_allowed_hosts_env_key(allowed_hosts_env_key):
    if not allowed_hosts_env_key:
        allowed_hosts_env_key = inquirer.text(
            "What environment variable holds your allowed hosts?", default="ALLOWED_HOSTS")
    return allowed_hosts_env_key


def get_gh_repo(existing_app=None, app_name=None, repo=None, branch=None):
    logger.debug("Getting github repo")

    if existing_app is not None and existing_app["spec"]["services"]:
        services = existing_app["spec"]["services"]
        for service in services:
            if service["name"] == app_name:
                repo = repo or service["github"]["repo"]
                branch = branch or service["github"]["branch"]
    if repo is None or branch is None:
        repo = repo or inquirer.text("What is the github repo for your app?")
        branch = branch or inquirer.text("What branch should we build from?", default="main")
    return {"repo": repo, "branch": branch}


class Helper:
    # DigitalOcean's connection info
    _DIGITALOCEAN_TOKEN = None
    _AWS_ACCESS_KEY_ID = None
    _AWS_SECRET_ACCESS_KEY = None
    _AWS_REGION = None
    _do_client = None

    # App info
    app_name = None
    component_name = None
    app_prefix = None
    gh_repo = None
    gh_branch = None
    _target_app = None
    _app_spec = None
    domain = None
    zone = None

    # Django info
    django_user_module = None
    django_root_module = None
    secret_key_env_key = None
    _secret_key = None
    allowed_hosts_env_key = None
    debug = False
    _oidc = None

    def __init__(self, digitalocean_token=None, aws_access_key_id=None,
                 aws_secret_access_key=None):
        self._DIGITALOCEAN_TOKEN = digitalocean_token
        self._AWS_ACCESS_KEY_ID = aws_access_key_id
        self._AWS_SECRET_ACCESS_KEY = aws_secret_access_key
        self.load_env(override=True)

    @property
    def _digitalocean_token(self):
        while not self._DIGITALOCEAN_TOKEN:
            self._DIGITALOCEAN_TOKEN = getpass.getpass("Enter your DigitalOcean token: ")
        return self._DIGITALOCEAN_TOKEN

    @property
    def do_client(self):
        while not self._do_client:
            self._do_client = Client(token=self._digitalocean_token)
        return self._do_client

    @property
    def appname_guess(self):
        if self.app_name:
            return self.app_name
        elif self.component_name:
            return self.component_name + "-app"
        elif self.app_prefix:
            return self.app_prefix + "-app"
        else:
            return "app"

    @property
    def target_app(self):
        if self._target_app:
            return self._target_app
        self._target_app = get_app(client=self.do_client, app_name=self.appname_guess)
        return self._target_app

    @property
    def app_spec(self):
        if self._app_spec:
            return self._app_spec

    def set_app_spec_from_app(self, app):
        if app and app["spec"]:
            self._app_spec = app["spec"]
        else:
            self._app_spec = None

    def _dump_vars(self):
        print(self._DIGITALOCEAN_TOKEN)
        print(self._AWS_ACCESS_KEY_ID)
        print(self._AWS_SECRET_ACCESS_KEY)
        print(self._AWS_REGION)
        print(self.component_name)
        print(self.app_prefix)
        print(self.gh_repo)
        print(self.gh_branch)
        print(self.django_user_module)
        print(self.secret_key_env_key)
        print(self.allowed_hosts_env_key)
        print(self.debug)

    def load_env(self, override=False):

        # DigitalOcean's connection info
        potential_var_names = ["$DIGITALOCEAN_TOKEN", "DIGITALOCEAN_TOKEN",
                               "digitalocean_token"]
        self._DIGITALOCEAN_TOKEN = _get_env_var_from_list_or_keep_original(
            potential_var_names, self._DIGITALOCEAN_TOKEN, override)

        potential_var_names = ["$AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID",
                               "aws_access_key_id"]
        self._AWS_ACCESS_KEY_ID = _get_env_var_from_list_or_keep_original(
            potential_var_names, self._AWS_ACCESS_KEY_ID, override)

        potential_var_names = ["$AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY",
                               "aws_secret_access_key"]
        self._AWS_SECRET_ACCESS_KEY = _get_env_var_from_list_or_keep_original(
            potential_var_names, self._AWS_SECRET_ACCESS_KEY, override)

        potential_var_names = ["$AWS_REGION", "AWS_REGION", "aws_region"]
        self._AWS_REGION = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                                   self._AWS_REGION,
                                                                   override)

        # App info
        potential_var_names = ["app_name", "APP_NAME"]
        self.app_name = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                                self.app_name,
                                                                override)

        potential_var_names = ["component_name", "COMPONENT_NAME"]
        self.component_name = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                                      self.component_name,
                                                                      override)

        potential_var_names = ["app_prefix", "prefix", "app_name", "APP_PREFIX"]
        self.app_prefix = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                                  self.app_prefix,
                                                                  override)

        potential_var_names = ["django_root_module", "DJANGO_ROOT_MODULE"]
        self.django_root_module = _get_env_var_from_list_or_keep_original(
            potential_var_names,
            self.django_root_module,
            override)

        potential_var_names = ["gh_repo", "GH_REPO"]
        self.gh_repo = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                               self.gh_repo, override)

        potential_var_names = ["gh_branch", "GH_BRANCH"]
        self.gh_branch = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                                 self.gh_branch, override)

        # Django info
        potential_var_names = ["django_user_module", "DJANGO_USER_MODULE"]
        self.django_user_module = _get_env_var_from_list_or_keep_original(
            potential_var_names, self.django_user_module, override)

        potential_var_names = ["secret_key_env_key", "SECRET_KEY_ENV_KEY"]
        self.secret_key_env_key = _get_env_var_from_list_or_keep_original(
            potential_var_names, self.secret_key_env_key, override)

        potential_var_names = ["secret_key", "SECRET_KEY", "DJANGO_SECRET_KEY",
                               "django_secret_key"]
        self._secret_key = _get_env_var_from_list_or_keep_original(
            potential_var_names, self._secret_key, override)

        potential_var_names = ["allowed_hosts_env_key", "allowed_hosts", "ALLOWED_HOSTS", "ALLOWED_HOSTS_ENV_KEY"]
        self.allowed_hosts_env_key = _get_env_var_from_list_or_keep_original(
            potential_var_names, self.allowed_hosts_env_key, override)

        potential_var_names = ["debug", "DEBUG"]
        self.debug = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                             self.debug, override)

        potential_var_names = ["domain", "DOMAIN", "subdomain", "SUBDOMAIN"]
        self.domain = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                              self.domain, override)

        potential_var_names = ["parent_domain", "PARENT_DOMAIN", "zone", "ZONE"]
        self.zone = _get_env_var_from_list_or_keep_original(potential_var_names,
                                                            self.zone, override)

    def save_app_spec_to_json_file(self, filename=None):
        if not filename:
            filename = self._app_spec["name"] + ".json"
        with open("appspecs/" + filename, "w") as f:
            json.dump(self._app_spec, f, indent=4)

    def load_app_spec_from_json_file(self, filename=None):
        with open("appspecs/" + filename, "r") as f:
            self._app_spec = json.load(f)

    def submenu_manage_apps(self):
        while True:
            options = []
            if self._app_spec:
                logger.debug("App spec found in memory")
                options.append(("Save App Spec to file from memory", "save_to_file"))
                # options.append(("Edit App Spec in memory", "edit"))
                # options.append(("Create App from App Spec in memory", "create_do_from_memory"))
                options.append(
                    ("Update App from App Spec in memory", "update_do_from_memory"))
                options.append(("Dump App Spec from memory", "dump_from_memory"))
            options.append(
                ("Load App Spec from existing app into memory", "load_from_existing_app"))
            options.append(("Load App Spec from file into memory", "load_from_file"))
            options.append(
                ("Create App Spec from scratch into memory", "load_from_user_input"))

            options.append(("Exit", "exit"))
            questions = [
                inquirer.List('whatdo',
                              message="What would you like to do?",
                              choices=options, default="update",
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers["whatdo"]
            if pickedoption == "exit":
                break
            elif pickedoption == "load_from_existing_app":
                self.set_app_spec_from_app(get_app(client=self.do_client))
            elif pickedoption == "dump_from_memory":
                print(json.dumps(self._app_spec, indent=4))
            elif pickedoption == "save_to_file":
                filename = input("Filename to save to: ")
                self.save_app_spec_to_json_file(filename=filename)
            elif pickedoption == "load_from_file":
                filename = input("Filename to load from: ") or "app-spec.json"
                self.load_app_spec_from_json_file(filename=filename)
            elif pickedoption == "update_do_from_memory":
                print("Which app would you like to update?")
                self._target_app = get_app(client=self.do_client)
                update_app_from_app_spec(client=self.do_client,
                                         target_app=self._target_app,
                                         app_spec=self._app_spec)
            elif pickedoption == "create_do_from_memory":
                create_app_from_app_spec(client=self.do_client,
                                         potential_spec=self._app_spec)
            elif pickedoption == "load_from_user_input":
                self.build_app_spec_from_user_input()

    def build_app_spec_from_user_input(self):
        allowed_hosts = get_allowed_hosts()

        if self._target_app is not None:
            appname = self._target_app["spec"]["name"]
        else:
            appname = self.appname_guess
        appname = get_app_name(appname=appname)

        if not self._oidc or inquirer.confirm("Do you want to generate a new OIDC RSA key?", default=True):
            self._oidc = get_oidc_rsa_key()
        oidc_rsa_private_key = self._oidc

        if not self.secret_key_env_key:
            self.secret_key_env_key = inquirer.text(message="What is the name of the environment variable that contains the Django secret key?", default="SECRET_KEY")
        if not self._secret_key or inquirer.confirm("Do you want to generate a new Django secret key?", default=False):
            self._secret_key = secrets.token_urlsafe()

        git_info = get_gh_repo(existing_app=self._target_app, app_name=self.component_name, repo=self.gh_repo, branch=self.gh_branch)
        self.gh_repo = git_info["repo"]
        self.gh_branch = git_info["branch"]

        if self._AWS_REGION:
            region_guess = self._AWS_REGION
        elif self._target_app and self._target_app["region"]["data_centers"][0]:
            region_guess = self._target_app["region"]["data_centers"][0]
        else:
            region_guess = None
        logger.debug("Get regions with default of {}".format(region_guess))
        aws_region = get_aws_region(client=self.do_client, region_slug=region_guess)

        logger.debug("Connecting to S3")
        session = boto3.session.Session()
        s3client = session.client('s3',
                                  endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                      aws_region),
                                  aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                  aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY)

        logger.debug("Getting spaces")
        spacename = None
        while not spacename:
            spacename = get_spaces(s3client=s3client)
            if not spacename:
                print("No spaces found, please create one here: https://cloud.digitalocean.com/spaces/new")
                answer = inquirer.prompt([inquirer.Confirm('retry',
                                                           message="Do you want to retry?")])
                if not answer["retry"]:
                    print("Aborting")
                    return None

        rootfolder = get_root_folder(s3client=s3client, space=spacename,
                                     component_name=self.component_name)
        if not rootfolder:
            return None

        get_media_folder(s3client=s3client, space=spacename,
                         root_folder=rootfolder)

        aws_s3_endpoint_url = "https://{}.{}.digitaloceanspaces.com".format(spacename,
                                                                            aws_region)

        aws_storage_bucket_name = rootfolder
        aws_location = rootfolder
        disable_collectstatic = "1"

        cluster_guess = self._target_app["spec"]["databases"][0]["cluster_name"] if \
            self._target_app and self._target_app["spec"][
                "databases"] else "db-postgresql"
        logger.debug("Get clusters with default of {}".format(cluster_guess))
        cluster = get_cluster(client=self.do_client, cluster_name=cluster_guess)

        pool_guess = self.app_prefix + "-pool" if self.app_prefix else "pool"
        logger.debug("Get pools with default of {}".format(pool_guess))
        pool = get_pool(client=self.do_client, cluster=cluster, pool_name=pool_guess)

        database_url = '${' + cluster["name"] + '.' + pool["name"] + '.DATABASE_URL}'

        domain_info = get_domain_info(existing_app=self._target_app, domain=self.domain,
                                      zone=self.zone, client=self.do_client, prefix=self.app_prefix)

        domain = domain_info["domain"]
        zone = domain_info["zone"]
        cluster_name = cluster["name"]
        database_name = pool["db"]
        database_user = pool["user"]

        rootmoduleguess = self.django_root_module or self.app_prefix
        django_root_module = get_django_root_module(module_guess=rootmoduleguess)
        self.django_user_module = get_django_user_module(
            django_user_module=self.django_user_module)

        self.debug = clean_debug_value(self.debug)
        self.allowed_hosts_env_key = clean_allowed_hosts_env_key(self.allowed_hosts_env_key)

        envvars = {
            self.secret_key_env_key: self._secret_key,
            "DEBUG": self.debug,
            self.allowed_hosts_env_key: allowed_hosts,
            "OIDC_RSA_PRIVATE_KEY": oidc_rsa_private_key,
            "AWS_ACCESS_KEY_ID": self._AWS_ACCESS_KEY_ID,
            "AWS_SECRET_ACCESS_KEY": self._AWS_SECRET_ACCESS_KEY,
            "AWS_STORAGE_BUCKET_NAME": aws_storage_bucket_name,
            "AWS_S3_ENDPOINT_URL": aws_s3_endpoint_url,
            "AWS_LOCATION": aws_location,
            "DISABLE_COLLECTSTATIC": disable_collectstatic,
            "DATABASE_URL": database_url,
        }
        spec_vars = {
            "envvars": envvars,
            "region": aws_region,
            "appname": appname,
            "component_name": self.component_name,
            "domain": domain,
            "zone": zone,
            "database_cluster_name": cluster_name,
            "database_name": database_name,
            "database_user": database_user,
            "gh_repo": self.gh_repo,
            "gh_branch": self.gh_branch,
            "django_user_module": self.django_user_module,
            "django_root_module": django_root_module,
            "secret_key_env_key": self.secret_key_env_key,
            "allowed_hosts_env_key": self.allowed_hosts_env_key,
        }
        self._app_spec = build_app_spec_file(env_obj=spec_vars)


def start():
    temphelper = Helper()
    temphelper.submenu_manage_apps()


if __name__ == '__main__':
    start()

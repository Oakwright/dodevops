import logging
from dotenv import load_dotenv
import os
import inquirer
from pydo import Client
import getpass


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

load_dotenv()


def _get_env_var_from_list_or_keep_original(env_var_list, original_value=None, override=True):
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


def build_env_list(env_obj, secret_key_env_key="SECRET_KEY", allowed_hosts_env_key="ALLOWED_HOSTS"):
    runtime_vars = [secret_key_env_key, allowed_hosts_env_key, "OIDC_RSA_PRIVATE_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_STORAGE_BUCKET_NAME", "AWS_S3_ENDPOINT_URL", "AWS_LOCATION", "DATABASE_URL"]
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


def populate_app_spec_services(app_spec, component_name, gh_repo, gh_branch, env_list, django_user_module,
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
    env_list = build_env_list(env_obj["envvars"], secret_key_env_key=env_obj["secret_key_env_key"], allowed_hosts_env_key=env_obj["allowed_hosts_env_key"])
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
                                          django_user_module=django_user_module, env_list=env_list, django_root_module=django_root_module)
    return app_spec


def list_apps(client):
    app_resp = client.apps.list()
    appcount = len(app_resp["apps"])
    if appcount > 0:
        options = []
        default_app = None
        for a in app_resp["apps"]:
            options.append((a["spec"]["name"], a))
        options.append(("* Cancel *", None))
        questions = [
            inquirer.List('app',
                          message="Here are your apps",
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
                          message="Are you rebuilding one of these apps?",
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


class Helper:
    # DigitalOcean's connection info
    _DIGITALOCEAN_TOKEN = None
    _AWS_ACCESS_KEY_ID = None
    _AWS_SECRET_ACCESS_KEY = None
    _AWS_REGION = None
    _do_client = None

    # App info
    component_name = None
    app_prefix = None
    gh_repo = None
    gh_branch = None
    _target_app = None
    _app_spec = None

    # Django info
    django_user_module = None
    secret_key_env_key = None
    allowed_hosts_env_key = None
    debug = False

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
        potential_var_names = ["$DIGITALOCEAN_TOKEN", "DIGITALOCEAN_TOKEN", "digitalocean_token"]
        self._DIGITALOCEAN_TOKEN = _get_env_var_from_list_or_keep_original(potential_var_names, self._DIGITALOCEAN_TOKEN, override)

        potential_var_names = ["$AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID", "aws_access_key_id"]
        self._AWS_ACCESS_KEY_ID = _get_env_var_from_list_or_keep_original(potential_var_names, self._AWS_ACCESS_KEY_ID, override)

        potential_var_names = ["$AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "aws_secret_access_key"]
        self._AWS_SECRET_ACCESS_KEY = _get_env_var_from_list_or_keep_original(potential_var_names, self._AWS_SECRET_ACCESS_KEY, override)

        potential_var_names = ["$AWS_REGION", "AWS_REGION", "aws_region"]
        self._AWS_REGION = _get_env_var_from_list_or_keep_original(potential_var_names, self._AWS_REGION, override)

        # App info
        potential_var_names = ["component_name"]
        self.component_name = _get_env_var_from_list_or_keep_original(potential_var_names, self.component_name, override)

        potential_var_names = ["app_prefix", "prefix", "app_name"]
        self.app_prefix = _get_env_var_from_list_or_keep_original(potential_var_names, self.app_prefix, override)

        potential_var_names = ["gh_repo"]
        self.gh_repo = _get_env_var_from_list_or_keep_original(potential_var_names, self.gh_repo, override)

        potential_var_names = ["gh_branch"]
        self.gh_branch = _get_env_var_from_list_or_keep_original(potential_var_names, self.gh_branch, override)

        # Django info
        potential_var_names = ["django_user_module"]
        self.django_user_module = _get_env_var_from_list_or_keep_original(potential_var_names, self.django_user_module, override)

        potential_var_names = ["secret_key_env_key"]
        self.secret_key_env_key = _get_env_var_from_list_or_keep_original(potential_var_names, self.secret_key_env_key, override)

        potential_var_names = ["allowed_hosts_env_key", "allowed_hosts", "ALLOWED_HOSTS"]
        self.allowed_hosts_env_key = _get_env_var_from_list_or_keep_original(potential_var_names, self.allowed_hosts_env_key, override)

        potential_var_names = ["debug", "DEBUG"]
        self.debug = _get_env_var_from_list_or_keep_original(potential_var_names, self.debug, override)

    def menu(self):
        options = [("List Apps", "list"), ("Create App", "create"), ("Update App", "update"), ("Exit", "exit")]
        questions = [
            inquirer.List('whatdo',
                          message="What would you like to do?",
                          choices=options, default="update",
                          ),
        ]
        while True:
            answers = inquirer.prompt(questions)
            pickedoption = answers["whatdo"]
            if pickedoption == "list":
                if self._target_app and self._target_app["spec"]["name"]:
                    list_apps(client=self.do_client)
                else:
                    list_apps(client=self.do_client)
            elif pickedoption == "create":
                pass
            elif pickedoption == "update":
                update_app_from_app_spec(client=self.do_client, target_app=self.target_app, app_spec=self.app_spec)
            elif pickedoption == "exit":
                break



def start():
    temphelper = Helper()
    temphelper.menu()


if __name__ == '__main__':
    start()

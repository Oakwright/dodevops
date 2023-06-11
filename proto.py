import json
import os
from pydo import Client
from dotenv import load_dotenv
import inquirer
import boto3
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


load_dotenv()


def getkeys(client):
    ssh_keys_resp = client.ssh_keys.list()
    for k in ssh_keys_resp["ssh_keys"]:
        print(f"ID: {k['id']}, NAME: {k['name']}, FINGERPRINT: {k['fingerprint']}")


def get_cluster(client, cluster_name="db-postgresql"):
    db_cluster_resp = client.databases.list_clusters()
    clustercount = len(db_cluster_resp)
    if clustercount > 0:
        default_db_cluster = None
        options = []
        for c in db_cluster_resp["databases"]:
            options.append((c['name'], c))
            if c['name'] == cluster_name:
                default_db_cluster = c
                logger.debug("Found default cluster {}".format(default_db_cluster['name']))
            elif default_db_cluster is None and cluster_name in c['name']:
                default_db_cluster = c
                logger.debug("Cluster {} contains {}".format(default_db_cluster['name'], cluster_name))

        options.append(None)
        questions = [
            inquirer.List('cluster',
                          message="Which cluster?",
                          choices=options, default=default_db_cluster,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['cluster']
        logger.debug("Using cluster {}".format(pickedoption['name']))
        return pickedoption
    else:
        print("No clusters found")
        return None


def get_database(cluster):
    if cluster:
        dbcount = len(cluster["db_names"])
        if dbcount > 0:
            options = []
            for d in cluster["db_names"]:
                options.append(d)
            options.append(None)
            questions = [
                inquirer.List('database',
                              message="Which database?",
                              choices=options,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['database']
            print("Using database {}".format(pickedoption))
            return pickedoption
        else:
            print("No databases found")
            return None


def get_pool(client, cluster, pool_name="pool"):
    if cluster:
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
                    logger.debug("Pool {} contains {}".format(pool_default["name"], pool_name))
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
            logger.debug("Using pool {}".format(pickedoption["name"]))
            return pickedoption
        else:
            print("No connection pools found")
            return None


def get_spaces(s3client):
    space_resp = s3client.list_buckets()
    spacecount = len(space_resp['Buckets'])
    if spacecount > 0:
        options = []
        for s in space_resp['Buckets']:
            options.append(s['Name'])
        options.append(None)
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


def get_root_folder(s3client, space, component_name="app"):
    space_resp = s3client.list_objects(Bucket=space, Delimiter='/')

    spacecount = len(space_resp['CommonPrefixes'])
    if spacecount > 0:
        options = []
        for s in space_resp['CommonPrefixes']:
            options.append(s['Prefix'][0:-1])
        options.append(None)
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
        return pickedoption
    else:
        print("No folders found")
        return None


def get_media_folder(s3client, space, media_folder="media",
                     root_folder=None):
    space_resp = s3client.list_objects(Bucket=space, Prefix=root_folder + '/',
                                       Delimiter='{}/'.format(media_folder))

    default_choice = media_folder
    spacecount = len(space_resp['CommonPrefixes'])
    if spacecount > 0:
        options = []
        for s in space_resp['CommonPrefixes']:
            options.append(s['Prefix'][0:-1])
            if s['Prefix'][0:-1] == root_folder + '/' + media_folder:
                logger.debug("Found default folder {}".format(s['Prefix'][0:-1]))
                return s['Prefix'][0:-1]
            elif media_folder in s['Prefix'][0:-1]:
                logger.debug("Folder {} contains {}".format(s['Prefix'][0:-1], media_folder))
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
        return pickedoption
    else:
        print("No folders found")
        return None


def get_secret_key():
    logger.debug("Getting secret key")
    if os.getenv("SECRET_KEY"):
        logger.debug("Found secret key in environment")
        return os.getenv("SECRET_KEY")
    elif os.getenv("DJANGO_SECRET_KEY"):
        logger.debug("Found django secret key in environment")
        return os.getenv("DJANGO_SECRET_KEY")
    else:
        logger.debug("Generating new secret key")
        return secrets.token_urlsafe()


def get_debug(binarymode=True):
    debugmode = False
    if os.getenv("DEBUG"):
        logger.debug("Found debug mode in environment")
        if os.getenv("DEBUG") == "1":
            debugmode = True
            binarymode = True
        elif os.getenv("DEBUG") == "0":
            debugmode = False
            binarymode = True
        elif os.getenv("DEBUG") == "True":
            debugmode = True
            binarymode = False
        elif os.getenv("DEBUG") == "False":
            debugmode = False
            binarymode = False

    debugmode = inquirer.confirm("Enable debug mode?", default=debugmode)
    binarymode = inquirer.confirm("Is debug environment variable stored as binary (0/1)?", default=binarymode)

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


def get_allowed_hosts():
    logger.debug("domain name is accessible from a DO variable in app platform")
    return "${APP_DOMAIN}"


def get_oidc_rsa_key():
    logger.debug("Generating RSA key")
    rsa_key_line = "\"{}\"".format(repr(generate_rsa_key())[1:-1])
    return rsa_key_line


def get_aws_access_key_id():
    if os.getenv("$AWS_ACCESS_KEY_ID"):
        return os.getenv("$AWS_ACCESS_KEY_ID")
    else:
        print("No AWS_ACCESS_KEY_ID found")
        print("https://cloud.digitalocean.com/account/api/spaces")
        promptentry = input(
            "Please enter your AWS_ACCESS_KEY_ID and press enter to continue: ")
        return promptentry


def get_aws_secret_access_key():
    if os.getenv("$AWS_SECRET_ACCESS_KEY"):
        return os.getenv("$AWS_SECRET_ACCESS_KEY")
    else:
        print("No AWS_SECRET_ACCESS_KEY found")
        print("https://cloud.digitalocean.com/account/api/spaces")
        promptentry = input(
            "Please enter your AWS_SECRET_ACCESS_KEY and press enter to continue: ")
        return promptentry


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


def get_aws_region(client, region_slug=None):
    if region_slug is None and os.getenv("$AWS_REGION"):
        logger.debug("No region passed, found region in environment")
        region_slug = os.getenv("$AWS_REGION")
    elif region_slug is not None and os.getenv("$AWS_REGION") and region_slug != os.getenv("$AWS_REGION"):
        logger.debug("Region passed and region in environment don't match, using passed region")
    elif region_slug is not None and os.getenv("$AWS_REGION") and region_slug == os.getenv("$AWS_REGION"):
        logger.debug("Region passed and region in environment match, using passed region")
    reg_resp = client.regions.list()
    regioncount = len(reg_resp["regions"])
    if regioncount > 0:
        options = []
        for r in reg_resp["regions"]:
            if r["available"] and "storage" in r["features"]:
                options.append((r["name"] + " - " + r["slug"], r["slug"]))
                if r["slug"] == region_slug:
                    logger.debug("Found default region")
                    return r["slug"]
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
        options.append(("* Build New App *", None))
        questions = [
            inquirer.List('app',
                          message="Are you rebuilding one of these apps?",
                          choices=options,
                          default=default_app,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['app']
        logger.debug("Using app {}".format(pickedoption["spec"]["name"]))
        return pickedoption
    else:
        print("No apps found")
        return None


def validate_app_spec(client, app_spec):
    body = {
        "spec": app_spec
    }
    response = client.apps.validate_app_spec(body)
    return response


def get_app_spec(client):
    app = get_app(client)
    return app["spec"]


def get_do_token():
    logger.debug("Checking .env for DO token")
    if os.getenv("$DIGITALOCEAN_TOKEN"):
        logger.debug("Found DO token in .env")
        return os.getenv("$DIGITALOCEAN_TOKEN")
    logger.debug("No DO token found in .env")
    return inquirer.password("Please enter your DigitalOcean API token: ")


def get_domain_info(existing_app=None):
    logger.debug("Getting domain info")
    if existing_app is not None and existing_app["spec"]["domains"]:
        domain = existing_app["spec"]["domains"][0]["domain"]
        zone = existing_app["spec"]["domains"][0]["zone"]
        domain = inquirer.text("What domain do you want (such as test.example.com", default=domain)
        zone = inquirer.text("What zone is that domain in (such as example.com)", default=zone)
        returnobj = {"domain": domain, "zone": zone}
    else:
        domain = inquirer.text("What domain do you want (such as test.example.com")
        zone = inquirer.text("What zone is that domain in (such as example.com)")
        returnobj = {"domain": domain, "zone": zone}
    return returnobj


def get_gh_repo(existing_app=None, app_name=None):
    logger.debug("Getting github repo")
    repo = None
    branch = None
    if existing_app is not None and existing_app["spec"]["services"]:
        services = existing_app["spec"]["services"]
        for service in services:
            if service["name"] == app_name:
                repo = service["github"]["repo"]
                branch = service["github"]["branch"]
    if repo is None or branch is None:
        repo = inquirer.text("What is the github repo for your app?")
        branch = inquirer.text("What branch should we build from?")
    return {"repo": repo, "branch": branch}


def get_django_user_module(django_settings_file_contents=None):
    logger.debug("Getting django user module")
    if os.getenv("django_user_module"):
        django_user_module = os.getenv("django_user_module")
    else:
        django_user_module = "core"
    if django_settings_file_contents is None:
        user_module = inquirer.text("What is the name of your Django user module?", default=django_user_module)
    else:
        user_module = None
        for line in django_settings_file_contents.splitlines():
            if "AUTH_USER_MODEL" in line:
                user_module = line.split(".")[-1].replace("'", "").replace('"', "").replace(" ", "")
        if user_module is None:
            user_module = inquirer.text("What is the name of your Django user module?", default=django_user_module)
    return user_module


def validate_app_spec_against_existing_app(client, app_spec, existing_app):
    body = {
        "app_id": existing_app["id"],
        "spec": app_spec,
    }
    response = client.apps.validate_app_spec(body)
    return response


def get_django_root_module(module_guess=None):
    if module_guess is not None:
        root_module = inquirer.text("What is the name of your Django root module?",
                                    default=module_guess)
    else:
        root_module = inquirer.text("What is the name of your Django root module?")
    return root_module


def build_or_create_app(client, app_spec, existing_app=None):
    update_app = False
    if existing_app is not None:
        update_app = inquirer.confirm("Do you want to update this app?")
    if update_app:
        logger.debug("Updating app")
        app_resp = update_app_from_json_file(client=client, potential_spec=app_spec, target_app=existing_app)
    else:
        if inquirer.confirm("Do you want to build this app?"):
            logger.debug("Building app")
            app_resp = create_app_from_json_file(client, app_spec)
        else:
            logger.debug("Not building app")
            app_resp = None
    return app_resp


def get_app_name(appname):
    if appname is None:
        appname = inquirer.text("What is the name of your app?")
    else:
        appname = inquirer.text("What is the name of your app?", default=appname)
    return appname


def get_secret_key_env_key(secret_key_env_key="SECRET_KEY"):
    if os.getenv("secret_key_env_key"):
        secret_key_env_key = os.getenv("secret_key_env_key")
    secret_key_env_key = inquirer.text("What is the name of the environment variable that contains your Django secret key?", default=secret_key_env_key)
    return secret_key_env_key


def get_allowed_hosts_env_key():
    if os.getenv("allowed_hosts_env_key"):
        allowed_hosts_env_key = os.getenv("allowed_hosts_env_key")
    else:
        allowed_hosts_env_key = "ALLOWED_HOSTS"

    allowed_hosts_env_key = inquirer.text("What is the name of the environment variable that contains your Django allowed hosts?", default=allowed_hosts_env_key)

    return allowed_hosts_env_key


def deploy_app():
    logger.debug("Starting DO client")
    do_client = Client(token=get_do_token())

    aws_access_key_id = get_aws_access_key_id()
    aws_secret_access_key = get_aws_secret_access_key()

    logger.debug("Getting component_name and app_prefix from .env to guess app name")
    if os.getenv("app_prefix"):
        app_prefix = os.getenv("app_prefix")
        logger.debug("Found app_prefix in .env")
    else:
        logger.debug("No app_prefix found in .env")
        app_prefix = None
    if os.getenv("component_name"):
        component_name = os.getenv("component_name")
        appname_guess = component_name+"-app"
        logger.debug("Found component_name in .env")
    elif app_prefix:
        component_name = app_prefix
        appname_guess = app_prefix
        logger.debug("No component_name found in .env, using app_prefix")
    else:
        appname_guess = "app"
        component_name = appname_guess
        logger.debug("No component_name or app_prefix found in .env, using 'app'")

    logger.debug("Get apps with default of {}".format(appname_guess))
    target_app = get_app(client=do_client, app_name=appname_guess)

    if target_app["region"]["data_centers"][0]:
        region_guess = target_app["region"]["data_centers"][0]
    else:
        region_guess = None
    logger.debug("Get regions with default of {}".format(region_guess))
    aws_region = get_aws_region(client=do_client, region_slug=region_guess)

    logger.debug("Starting AWS client")
    session = boto3.session.Session()
    s3client = session.client('s3',
                              endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                  aws_region),
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    logger.debug("Getting spaces")
    spacename = get_spaces(s3client=s3client)

    logger.debug("Getting root folder with default of {}".format(component_name))
    rootfolder = get_root_folder(s3client=s3client, space=spacename, component_name=component_name)

    mediafolder = get_media_folder(s3client=s3client, space=spacename, root_folder=rootfolder)

    cluster_guess = target_app["spec"]["databases"][0]["cluster_name"] if target_app["spec"]["databases"] else "db-postgresql"
    logger.debug("Get clusters with default of {}".format(cluster_guess))
    cluster = get_cluster(client=do_client, cluster_name=cluster_guess)

    pool_guess = app_prefix+"-pool" if app_prefix else "pool"
    logger.debug("Get pools with default of {}".format(pool_guess))
    pool = get_pool(client=do_client, cluster=cluster, pool_name=pool_guess)

    secret_key = get_secret_key()
    debug = get_debug()
    allowed_hosts = get_allowed_hosts()

    logger.debug("Getting OIDC key for oauthtoolkit")
    oidc_rsa_private_key = get_oidc_rsa_key()

    aws_s3_endpoint_url = "https://{}.{}.digitaloceanspaces.com".format(spacename,
                                                                        aws_region)

    aws_storage_bucket_name = rootfolder
    aws_location = rootfolder
    disable_collectstatic = "1"
    database_url = '${'+cluster["name"]+'.'+pool["name"]+'.DATABASE_URL}'

    if target_app is not None:
        appname = target_app["spec"]["name"]
    else:
        appname = appname_guess

    appname = get_app_name(appname=appname)

    domain_info = get_domain_info(existing_app=target_app)
    domain = domain_info["domain"]
    zone = domain_info["zone"]
    cluster_name = cluster["name"]
    database_name = pool["db"]
    database_user = pool["user"]
    git_info = get_gh_repo(existing_app=target_app, app_name=component_name)
    gh_repo = git_info["repo"]
    gh_branch = git_info["branch"]

    django_root_module = get_django_root_module(module_guess=app_prefix)
    django_user_module = get_django_user_module()

    secret_key_env_key = get_secret_key_env_key()
    allowed_hosts_env_key = get_allowed_hosts_env_key()

    logger.debug("Getting envvars together")
    envvars = {
        secret_key_env_key: secret_key,
        "DEBUG": debug,
        allowed_hosts_env_key: allowed_hosts,
        "OIDC_RSA_PRIVATE_KEY": oidc_rsa_private_key,
        "AWS_ACCESS_KEY_ID": aws_access_key_id,
        "AWS_SECRET_ACCESS_KEY": aws_secret_access_key,
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
        "component_name": component_name,
        "domain": domain,
        "zone": zone,
        "database_cluster_name": cluster_name,
        "database_name": database_name,
        "database_user": database_user,
        "gh_repo": gh_repo,
        "gh_branch": gh_branch,
        "django_user_module": django_user_module,
        "django_root_module": django_root_module,
        "secret_key_env_key": secret_key_env_key,
        "allowed_hosts_env_key": allowed_hosts_env_key,
    }

    logger.debug("Building app spec file")
    app_spec_file = build_app_spec_file(spec_vars)

    logger.debug("Validating app spec file")
    validcheck = validate_app_spec(client=do_client, app_spec=app_spec_file)
    rebuildvalidcheck = None

    if target_app is not None:
        logger.debug("Validating app spec file against existing app")
        rebuildvalidcheck = validate_app_spec_against_existing_app(client=do_client, app_spec=app_spec_file, existing_app=target_app)

    build_resp = None
    if validcheck is not None:
        build_resp = build_or_create_app(client=do_client, app_spec=app_spec_file, existing_app=target_app)
        logger.debug("Build response: {}".format(build_resp))

    if build_resp is not None:
        add_app_to_trusted_sources(client=do_client, database_cluster_uuid=cluster["id"], app_id=build_resp["app"]["id"])


def load_app_spec_from_json_file():
    with open("app-spec.json", "r") as f:
        app_spec = json.load(f)
    return app_spec


def save_app_spec_to_json_file(app_spec):
    with open("app-spec.json", "w") as f:
        json.dump(app_spec, f)


def validate_json_file_against_app(client):
    target_app = get_app(client)
    potential_spec = load_app_spec_from_json_file()
    body = {
        "app_id": target_app["id"],
        "spec": potential_spec
    }
    response = client.apps.validate_app_spec(body)
    return response


def update_app_from_json_file(client, target_app, potential_spec):
    logger.debug("Preparing to update app, this will trigger an app rebuild!")
    print(target_app)
    validate_body = {
        "app_id": target_app["id"],
        "spec": potential_spec
    }
    update_body = {
        "spec": potential_spec
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


def create_app_from_json_file(client, potential_spec):
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


def get_trusted_sources(client, database_cluster_uuid):
    firewall_rules = client.databases.list_firewall_rules(database_cluster_uuid)
    return firewall_rules


def add_app_to_trusted_sources(client, database_cluster_uuid, app_id):
    trusted_sources = get_trusted_sources(client, database_cluster_uuid)
    new_rule = {
        "cluster_uuid": database_cluster_uuid,
        "type": "app",
        "value": app_id,
    }
    trusted_sources["rules"].append(new_rule)
    print(trusted_sources)
    answer = inquirer.prompt([inquirer.Confirm('continue',
                                               message="Do you want to continue?")])
    if not answer["continue"]:
        print("Aborting")
        return None
    response = client.databases.update_firewall_rules(database_cluster_uuid,
                                                      trusted_sources)
    return response


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


def start():
    logger.debug("Starting")
    deploy_app()


if __name__ == '__main__':
    start()

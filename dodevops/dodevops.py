import configparser
import json
import logging
import secrets
import time
import psycopg2
from psycopg2 import sql
import requests
import boto3
from dotenv import load_dotenv
import os
import inquirer
from pydo import Client
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
import cProfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

file_handler = logging.FileHandler('debug.log')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

load_dotenv()


def s3_method(func):
    func.is_s3_method = True
    return func


def do_api_method(func):
    func.is_do_api_method = True
    return func


def _get_env_var_from_list_or_keep_original(env_var_list, original_value=None,
                                            override=True):
    if original_value and not override:
        return original_value

    for env_var in env_var_list:
        env_var_value = os.getenv(env_var)
        if env_var_value:
            logger.debug("Found {} in .env".format(env_var))
            return env_var_value
    # logger.debug("No env var from list found in .env")
    return original_value


@do_api_method
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
    if inquirer.confirm("Do you want to add the app to the db firewall?", default=True):
        add_app_to_db_firewall(client, app_name=app_spec["name"])
    print("If this is a new subdomain your browser may display SSL_ERROR_NO_CYPHER_OVERLAP error.")
    print("Domain verification can take between 5 minutes and an hour.")
    return response


@do_api_method
def create_app_from_app_spec(client, potential_spec, wait_for_migrate=False):
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
    client.apps.create(body=validate_body)
    if inquirer.confirm("Do you want to add the app to the db firewall?", default=True):
        add_app_to_db_firewall(client, app_name=potential_spec["name"])
    print("If this is a new subdomain your browser may display SSL_ERROR_NO_CYPHER_OVERLAP error.")
    print("Domain verification can take between 5 minutes and an hour.")
    if wait_for_migrate:
        print("Preparing to wait for app to migrate")
        return loop_until_migrate(client, potential_spec["name"])
    return False


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


def start_app_spec_file(appname, region="sfo"):
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
    # bonus = ""

    first_command = "python3 manage.py migrate"

    last_command = "gunicorn --worker-tmp-dir /dev/shm {}.wsgi:application  --bind 0.0.0.0:{}".format(
        django_root_module, port)

    run_command = "{}\n{}".format(
        first_command, last_command)

    services_json = {
        "name": component_name,
        "github": {
            "repo": gh_repo,
            "branch": gh_branch,
            "deploy_on_push": deploy_on_push
        },
        "build_command": "python manage.py makemigrations\npython manage.py makemigrations {}".format(
            django_user_module),
        "run_command": run_command,
        "source_dir": "/",
        "environment_slug": "python",
        "envs": env_list,
        "instance_size_slug": size_slug,
        "instance_count": 1,
        "http_port": port
    }
    app_spec["services"].append(services_json)
    return app_spec


def populate_app_spec_jobs(app_spec, gh_repo, gh_branch, env_list,
                           django_user_module, import_json, deploy_on_push=True, migrate_scripts=None):
    lines = []

    python_lines = ("from custom_storages import MediaStorage;"
                    "FileStorage = MediaStorage;"
                    "fs = FileStorage();"
                    "test = fs.open('db.json');"
                    "temp = test.read();"
                    "from django.core.files import File;"
                    "f = open('db.json', 'w');"
                    "testfile = File(f);"
                    "testfile.write(temp.decode('utf-8'));"
                    "testfile.close();"
                    "f.close()")

    lines.append("python manage.py makemigrations\n")
    lines.append("python manage.py makemigrations {}\n".format(
        django_user_module))
    lines.append("python manage.py migrate\n")

    if migrate_scripts and len(migrate_scripts) > 0:
        for command in migrate_scripts:
            lines.append("{}\n".format(command))

    # get json file from somewhere to here

    lines.append("python manage.py shell -c \"{}\"\n".format(python_lines))

    if import_json:
        # Load json file
        lines.append("python manage.py loaddata \"db.json\"\n")

    run_command = "".join(lines)

    services_json = {
        "name": "migrate",
        "kind": "PRE_DEPLOY",
        "github": {
            "repo": gh_repo,
            "branch": gh_branch,
            "deploy_on_push": deploy_on_push
        },
        "run_command": run_command,
        "source_dir": "/",
        "envs": env_list,
    }
    app_spec["jobs"] = []
    app_spec["jobs"].append(services_json)
    return app_spec


def build_app_spec_file(env_obj, import_json, migrate_task):
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

    migrate_scripts = env_obj["migrate_scripts"]

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
    if import_json or migrate_task:
        app_spec = populate_app_spec_jobs(app_spec,
                                          gh_repo=gh_repo,
                                          gh_branch=gh_branch,
                                          django_user_module=django_user_module,
                                          env_list=env_list, import_json=import_json, migrate_scripts=migrate_scripts)
        # populate_app_spec_jobs(app_spec, gh_repo, gh_branch, env_list,
        #                            django_user_module, deploy_on_push=True)
    return app_spec


@do_api_method
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
    # logger.debug("domain name is accessible from a DO variable in app platform")
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


@do_api_method
def get_region(client, region_slug=None):
    if region_slug is None:
        region_slug = "sfo3"
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
        print("No regions found, defaulting to sfo3")
        return "sfo3"


@do_api_method
def get_spaces(s3client, appname):
    pickedoption = None
    while not pickedoption:
        space_resp = s3client.list_buckets()
        spacecount = len(space_resp['Buckets'])
        print(spacecount)
        # if spacecount > 0:
        options = []
        for s in space_resp['Buckets']:
            options.append(s['Name'])
        options.append(("$$ Create New Space $$", "creates3"))
        questions = [
            inquirer.List('space',
                          message="Which space?",
                          choices=options,
                          default=appname,
                          ),
        ]
        answers = inquirer.prompt(questions)
        pickedoption = answers['space']
        if pickedoption == "creates3":
            space_name = create_s3_space(s3client=s3client,
                                         space_name="space-" + appname)
            if space_name:
                pickedoption = space_name
                while not check_space_existence(s3client, space_name):
                    print("Waiting for space creation to complete...")
                    time.sleep(10)
            else:
                pickedoption = None
        if pickedoption:
            logger.debug("Using space {}".format(pickedoption))
    return pickedoption


@s3_method
def create_folder(s3client, space, component_name, parent_folder=""):
    folder_name = inquirer.text(message="Please enter a folder name",
                                default=component_name)
    if folder_name:
        s3client.put_object(Bucket=space, Key=parent_folder + folder_name + "/")
        return folder_name


@s3_method
def get_root_folder(s3client, space, component_name=None):
    return_folder = None
    default_folder = None
    while not return_folder:
        space_resp = s3client.list_objects(Bucket=space, Delimiter='/')

        if "CommonPrefixes" in space_resp and len(space_resp['CommonPrefixes']) > 0:
            options = []
            for s in space_resp['CommonPrefixes']:
                options.append(s['Prefix'][0:-1])
            if component_name in options:
                default_folder = component_name
            options.append(("Create new folder", None))
            questions = [
                inquirer.List('folder',
                              message="Which folder?",
                              choices=options,
                              default=default_folder,
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers['folder']
            print("Using folder {}".format(pickedoption))
            return_folder = pickedoption
        else:
            print("No folders found")
            return_folder = None
        if not return_folder:
            return_folder = create_folder(s3client, space, component_name)

    return return_folder


@s3_method
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


@do_api_method
def get_cluster(client, cluster_name="db-postgresql", region=None, prefix=None):
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
                    logger.debug(
                        "Cluster {} contains {}".format(default_db_cluster['name'],
                                                        cluster_name))

            options.append(("$$ Create new cluster $$", "createcluster"))
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
        if not chosen_cluster or chosen_cluster == "createcluster":
            cluster_id = create_db_cluster(client, region=region, suffix=prefix)
            if cluster_id:
                logger.debug("Waiting for cluster to come online")
                print("This part can take about five minutes, it would be a good time to get coffee")
                while True:
                    status = check_cluster_status(cluster_id, client)

                    if status in ['creating', 'resuming', 'updating']:
                        print(f"Cluster status: {status}. Waiting...")
                        time.sleep(10)
                    elif status in ['active', 'online']:
                        print("Cluster has been created successfully!")
                        logger.debug("Cluster has been created successfully!")
                        chosen_cluster = None
                        break
                    else:
                        print(f"Cluster creation failed. Status: {status}")
                        logger.debug(f"Cluster creation failed. Status: {status}")
                        chosen_cluster = None
                        break
            else:
                chosen_cluster = None

    return chosen_cluster


@do_api_method
def create_db(client, cluster=None, database_name=None):
    if not cluster:
        cluster = get_cluster(client)
    database_name = inquirer.text("What would you like the database name to be?",
                                  default=database_name)
    body = {
        "name": database_name,
    }
    result = client.databases.add(database_cluster_uuid=cluster["id"], body=body)
    return result["db"]["name"]


@do_api_method
def get_database(client, cluster, database_name,
                 skip_defaultdb=True):
    logger.debug("Getting database")
    if cluster:
        chosen_db = None
        while not chosen_db:
            dbcount = len(cluster["db_names"])
            if dbcount > 0:
                default_db = None
                options = []
                for d in cluster["db_names"]:
                    if skip_defaultdb and d == "defaultdb":
                        continue
                    options.append(d)
                    if d == database_name:
                        logger.debug("Found default database {}".format(d))
                        default_db = d
                options.append(("Create new database", None))
                questions = [
                    inquirer.List('database',
                                  message="Which database?",
                                  choices=options, default=default_db,
                                  ),
                ]
                answers = inquirer.prompt(questions)
                pickedoption = answers['database']
                chosen_db = pickedoption
                # print("Using database {}".format(pickedoption))
                # return pickedoption
            else:
                print("No databases found")
                chosen_db = None
            if not chosen_db:
                chosen_db = create_db(client=client, cluster=cluster,
                                      database_name=database_name)
        return chosen_db


@do_api_method
def create_db_user(client, cluster=None, user_name=None, app_name=None):
    logger.debug("Creating db user")
    if not cluster:
        cluster = get_cluster(client=client)

    if not user_name and app_name:
        user_name = app_name + "-user"
    else:
        user_name = "django-user"

    user_name = inquirer.text(message="Enter database username to create: ",
                              default=user_name)

    body = {
        "name": user_name
    }
    result = client.databases.add_user(cluster["id"], body)

    return result["user"]["name"]


@do_api_method
def get_db_user(client, cluster=None, ignore_admin=True, app_name=None):
    logger.debug("Getting db user")
    user_name = None
    if not user_name and app_name:
        user_name = app_name + "-user"
    else:
        user_name = "django-user"

    if not cluster:
        cluster = get_cluster(client=client)
    choice = None
    while not choice:

        user_list = client.databases.list_users(cluster["id"])

        if ignore_admin:
            user_list = [u["name"] for u in user_list["users"] if u["name"] != "doadmin"]
        if user_name in user_list:
            default_user = user_name
        else:
            default_user = None
        user_list.append(("Create new user", None))

        choice = inquirer.list_input("Choose a user",
                                     choices=user_list, default=default_user)

        if not choice:
            choice = create_db_user(client=client, cluster=cluster, app_name=app_name)

    return choice


@do_api_method
def create_db_pool(client, cluster=None, app_name=None, project_name=None, region=None):
    if not cluster:
        cluster = get_cluster(client, region=region, prefix=project_name)

    database = get_database(client, cluster, database_name=app_name)
    user = get_db_user(client=client, cluster=cluster, app_name=app_name)

    pool_name = inquirer.text(message="Enter connection pool name to create: ",
                              default=app_name + "-pool")

    body = {
        "name": pool_name,
        "mode": "transaction",
        "size": 3,
        "db": database,
        "user": user
    }

    result = client.databases.add_connection_pool(cluster["id"], body)

    grant_db_rights_to_django_user(client=client, cluster=cluster, database=database,
                                   user=user)

    return result["pool"]


def get_doadmin_connection_string(database, cluster):
    connection_string = "postgresql://{}:{}@{}:{}/{}?sslmode=require"
    connection_string = connection_string.format(
        cluster["connection"]["user"],
        cluster["connection"]["password"],
        cluster["connection"]["host"],
        cluster["connection"]["port"],
        database
    )
    return connection_string


@do_api_method
def grant_db_rights_to_django_user(client, app_name=None, cluster=None, user=None,
                                   database=None):
    logger.debug("Granting db rights to django user")
    if not cluster:
        cluster = get_cluster(client=client)
    if not user:
        user = get_db_user(client=client, cluster=cluster, app_name=app_name)
    if not database:
        database = get_database(client=client, cluster=cluster, database_name=app_name)

    print("The public IP address of this machine will be added to the database firewall temporarily.")
    if inquirer.confirm(
            "Continue?",
            default=True):
        add_local_ip_to_db_firewall(client, cluster=cluster)
        connection_string = get_doadmin_connection_string(database=database,
                                                          cluster=cluster)
        connection = psycopg2.connect(connection_string)

        with connection.cursor() as cursor:
            cursor.execute(sql.SQL("ALTER ROLE {} SET client_encoding TO 'utf8';").format(
                sql.Identifier(user)))
            cursor.execute(sql.SQL(
                "ALTER ROLE {} SET default_transaction_isolation TO 'read committed';").format(
                sql.Identifier(user)))
            cursor.execute(sql.SQL("ALTER ROLE {} SET timezone TO 'UTC';").format(
                sql.Identifier(user)))

            cursor.execute(sql.SQL("GRANT ALL PRIVILEGES ON DATABASE {} TO {};").format(
                sql.Identifier(database), sql.Identifier(user)))

            cursor.execute(sql.SQL("GRANT CREATE ON DATABASE {} TO {};").format(
                sql.Identifier(database), sql.Identifier(user)))
            cursor.execute(sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {};").format(
                sql.Identifier(user)))
            cursor.execute(sql.SQL(
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {};").format(
                sql.Identifier(user)))
            cursor.execute(sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {};").format(
                sql.Identifier(user)))

            cursor.execute(
                sql.SQL("ALTER USER {} CREATEDB;").format(sql.Identifier(user)))

            cursor.execute(sql.SQL("ALTER DATABASE {} OWNER TO {};").format(
                sql.Identifier(database), sql.Identifier(user)))

            connection.commit()

        print("The public IP address of this machine can now be removed from the database firewall.")
        if inquirer.confirm(
                "Continue?",
                default=True):
            remove_local_ip_from_db_firewall(client, cluster=cluster)
        remove_local_ip_from_db_firewall(client, cluster=cluster)


@do_api_method
def get_pool(client, cluster, pool_name="pool", app_name=None, project_name=None):
    logger.debug("Getting pool")
    chosen_pool = None
    while not chosen_pool:
        pool_default = None
        pool_resp = client.databases.list_connection_pools(cluster["id"])
        if "pools" in pool_resp and len(pool_resp["pools"]) > 0:
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
            pooloptions.append(("Create new pool", None))
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
            chosen_pool = create_db_pool(client, cluster, app_name=app_name, project_name=project_name)
    return chosen_pool


def get_root_domain(domain):
    domain_parts = domain.split(".")
    if len(domain_parts) > 2:
        zone = domain_parts[-2] + "." + domain_parts[-1]
    else:
        zone = domain
    return zone


@do_api_method
def get_domain_info(existing_app=None, domain=None, zone=None, client=None,
                    prefix="test"):
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


def extract_project_name(repo):
    parts = repo.split('/')
    project_name = parts[-1]
    return project_name


def extract_prefix(component):
    parts = component.split('-')
    prefix = parts[0]
    return prefix


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
            "What environment variable holds your allowed hosts?",
            default="ALLOWED_HOSTS")
    return allowed_hosts_env_key


def find_git_config_file_and_repo(base_path):

    git_config_files = []
    logger.debug("Looking for git config files in {}".format(base_path))
    for root, dirs, files in os.walk(base_path):
        for d in dirs:
            if d == ".git":
                git_config_files.append(os.path.join(root, d, "config"))
                logger.debug("Found git config file {}".format(git_config_files[-1]))

    logger.debug("Found {} git config files".format(len(git_config_files)))
    if len(git_config_files) == 0:
        logger.debug("No git config files found")
        return None, None
    else:
        logger.debug("Begin parsing first git config file found")
        config = configparser.ConfigParser()
        config.read(git_config_files[0])
        try:
            remote_url = config.get('remote "origin"', 'url')
            logger.debug("Remote URL is {}".format(remote_url))
            if "github.com:" in remote_url:
                relative_path = remote_url.split("github.com:")[1]
                relative_path = relative_path.split(".git")[0]
                logger.debug("Relative path is {}".format(relative_path))
            elif "github.com/" in remote_url:
                relative_path = remote_url.split("github.com/")[1]
                relative_path = relative_path.split(".git")[0]
                logger.debug("Relative path is {}".format(relative_path))
            else:
                relative_path = None
            return git_config_files[0], relative_path
        except (configparser.NoSectionError, configparser.NoOptionError, IndexError):
            return None, None


def get_active_branch_from_head(head_file_path):
    try:
        with open(head_file_path, 'r') as head_file:
            ref = head_file.read().strip()
            if ref.startswith("ref: refs/heads/"):
                branch_name = ref.split("ref: refs/heads/")[1]
                print("Found branch {}".format(branch_name))
                return branch_name
    except FileNotFoundError:
        return None


def get_gh_repo(existing_app=None, app_name=None, repo=None, branch=None):
    logger.debug("Getting github repo")

    default_repo = None
    default_branch = "main"

    if existing_app is not None and existing_app["spec"]["services"]:
        services = existing_app["spec"]["services"]
        for service in services:
            if service["name"] == app_name:
                repo = repo or service["github"]["repo"]
                branch = branch or service["github"]["branch"]
    if repo is None or branch is None:
        logger.debug("Looking for GitHub repo in current directory")
        current_directory = os.getcwd()
        logger.debug("Current directory is {}".format(current_directory))
        config_path, relative_path = find_git_config_file_and_repo(current_directory)
        if relative_path:
            default_repo = relative_path
            print("GitHub repository found:")
            print(config_path)

            head_file = os.path.join(os.path.dirname(config_path), "HEAD")
            if head_file:
                default_branch = get_active_branch_from_head(head_file)

        else:
            print(
                "No GitHub repositories found in the current directory or its subdirectories.")

        repo = repo or inquirer.text("What is the github repo for your app?", default=default_repo)
        branch = branch or inquirer.text("What branch should we build from?",
                                         default=default_branch)
    return {"repo": repo, "branch": branch}


def get_aws_access_key_id():
    if os.getenv("$AWS_ACCESS_KEY_ID"):
        return os.getenv("$AWS_ACCESS_KEY_ID")
    else:
        print("No AWS_ACCESS_KEY_ID found")
        print("This tool uses DigitalOcean's s3 Spaces API to create and manage resources")
        print("You can create a new access key here:")
        print("https://cloud.digitalocean.com/account/api/spaces")
        print("You can save effort when running this tool by setting the key id in the environment variable AWS_ACCESS_KEY_ID")
        promptentry = inquirer.password(message="AWS_ACCESS_KEY_ID: ")
        return promptentry


def get_aws_secret_access_key():
    if os.getenv("$AWS_SECRET_ACCESS_KEY"):
        return os.getenv("$AWS_SECRET_ACCESS_KEY")
    else:
        print("No AWS_SECRET_ACCESS_KEY found")
        print("This tool uses DigitalOcean's s3 Spaces API to create and manage resources")
        print("You can create a new access key here:")
        print("https://cloud.digitalocean.com/account/api/spaces")
        print("You can save effort when running this tool by setting the key in the environment variable AWS_SECRET_ACCESS_KEY")
        print("Please enter your AWS_SECRET_ACCESS_KEY to continue")
        promptentry = inquirer.password(message="AWS_SECRET_ACCESS_KEY: ")
        return promptentry


@do_api_method
def check_cluster_status(cluster_id, client):
    # Get the current status of the cluster
    cluster = client.databases.get_cluster(cluster_id)
    print(cluster)
    return cluster['database']['status']


@do_api_method
def create_db_cluster(client, cluster_name=None, region=None, suffix=None):
    if not region:
        region = get_region(client)
    if not cluster_name and suffix:
        cluster_name = "db-postgresql-" + region + "-" + suffix
    else:
        cluster_name = "db-postgresql-" + region + "-shared"
    print(
        "A database cluster can contain multiple databases and can be shared across multiple apps")
    print(
        "If you plan on sharing the cluster across multiple apps, you may want to name it something generic")
    cluster_name = inquirer.text("What would you like the cluster name to be?",
                                 default=cluster_name)

    body = {
        "name": cluster_name,
        "engine": "pg",
        "version": "15",
        "region": region,
        "size": "db-s-1vcpu-1gb",
        "num_nodes": 1,
    }

    print("Warning! Continuing will incur a cost on your DigitalOcean account")
    confirm = inquirer.confirm(
        "Continue?",
        default=False)
    if confirm:
        logger.debug("Creating database cluster")
        cluster = client.databases.create_cluster(body=body)
        cluster_id = cluster['database']['id']
        return cluster_id
    else:
        return None


@do_api_method
def add_app_to_db_firewall(client, app_name=None):
    app = get_app(client, app_name)
    cluster = get_cluster(client)

    get_resp = client.databases.list_firewall_rules(database_cluster_uuid=cluster["id"])

    firewall_rules = get_resp["rules"]
    app_uuid = app["id"]

    # Check if app is already in firewall rules
    for rule in firewall_rules:
        if rule["type"] == "app" and rule["value"] == app_uuid:
            print("App already in firewall rules")
            return

    firewall_rules.append({
        "type": "app",
        "value": app_uuid,
    })
    client.databases.update_firewall_rules(
        database_cluster_uuid=cluster["id"], body=get_resp)


def get_local_ip():
    ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return ip


@do_api_method
def add_local_ip_to_db_firewall(client, cluster=None):
    if not cluster:
        cluster = get_cluster(client)
    get_resp = client.databases.list_firewall_rules(database_cluster_uuid=cluster["id"])

    firewall_rules = get_resp["rules"]
    local_ip = get_local_ip()

    # Check if IP is already in firewall rules
    for rule in firewall_rules:
        if rule["type"] == "ip_addr" and rule["value"] == local_ip:
            print("IP already in firewall rules")
            return
    firewall_rules.append({
        "type": "ip_addr",
        "value": local_ip,
    })
    client.databases.update_firewall_rules(
        database_cluster_uuid=cluster["id"], body=get_resp)


@do_api_method
def remove_local_ip_from_db_firewall(client, cluster=None):
    if not cluster:
        cluster = get_cluster(client)
    get_resp = client.databases.list_firewall_rules(database_cluster_uuid=cluster["id"])

    firewall_rules = get_resp["rules"]
    local_ip = get_local_ip()

    new_firewall_rules = []
    for rule in firewall_rules:
        if rule["type"] == "ip_addr" and rule["value"] == local_ip:
            continue
        new_firewall_rules.append(rule)
    get_resp["rules"] = new_firewall_rules
    client.databases.update_firewall_rules(
        database_cluster_uuid=cluster["id"], body=get_resp)


@s3_method
def create_s3_space(aws_access_key_id=None, aws_secret_access_key=None, aws_region=None,
                    space_name=None, s3client=None):
    session = boto3.session.Session()
    if not s3client:
        s3client = session.client('s3',
                                  endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                      aws_region),
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)
    space_name = inquirer.text("What would you like to name your space?",
                               default=space_name)
    print("Warning! Continuing will incur a cost on your DigitalOcean account")
    if inquirer.confirm(
            "Continue?"):
        logger.debug("Creating space {}".format(space_name))
        s3client.create_bucket(Bucket=space_name)

        return space_name
    else:
        return None


def get_local_db_json_file(base_path=os.getcwd()):
    dbfile = None
    filename = "db.json"

    logger.debug("Looking for db.json in {}".format(base_path))
    for root, dirs, files in os.walk(base_path):
        if filename in files:
            dbfile = os.path.join(root, filename)
            break

    if not dbfile:
        logger.debug("No db.json found")
        return None
    return dbfile


@s3_method
def upload_db_json_to_s3_space(aws_access_key_id=None, aws_secret_access_key=None,
                               aws_region=None,
                               appname=None, space_name=None, rootfolder=None,
                               mediafolder=None):
    logger.debug("Uploading db.json to space {}".format(space_name))
    session = boto3.session.Session()
    s3client = session.client('s3',
                              endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                  aws_region),
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    if not space_name:
        space_name = get_spaces(s3client=s3client, appname=appname)

    if not rootfolder:
        rootfolder = get_root_folder(s3client=s3client, space=space_name,
                                     component_name=appname)

    if not mediafolder:
        mediafolder = get_media_folder(s3client=s3client, space=space_name,
                                       root_folder=rootfolder)

    dbfile = get_local_db_json_file()

    while not dbfile:
        if not inquirer.confirm("No db.json found. Please create one and try again.", default=True):
            print("Continuing without uploading db.json")
            logger.debug("Continuing without uploading db.json")
            return
        dbfile = get_local_db_json_file()

    with open(dbfile, "r") as f:
        dbdump = json.load(f)

    s3client.put_object(Bucket=space_name,
                        Key=mediafolder + '/db.json',
                        Body=json.dumps(dbdump))

    logger.debug("Uploaded db.json to space {}".format(space_name))


@s3_method
def remove_db_json_from_s3_space(aws_access_key_id=None, aws_secret_access_key=None,
                                 aws_region=None,
                                 appname=None):
    session = boto3.session.Session()
    s3client = session.client('s3',
                              endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                  aws_region),
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)

    space_name = get_spaces(s3client=s3client, appname=appname)

    rootfolder = get_root_folder(s3client=s3client, space=space_name,
                                 component_name=appname)

    mediafolder = get_media_folder(s3client=s3client, space=space_name,
                                   root_folder=rootfolder)

    s3client.delete_object(Bucket=space_name,
                           Key=mediafolder + '/db.json')


@s3_method
def upload_media_to_s3_space(aws_access_key_id, aws_secret_access_key, aws_region,
                             appname):
    session = boto3.session.Session()
    s3client = session.client('s3',
                              endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                  aws_region),
                              aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key)
    spacename = get_spaces(s3client=s3client, appname=appname)
    rootfolder = get_root_folder(s3client=s3client, space=spacename,
                                 component_name=appname)
    mediafolder = get_media_folder(s3client=s3client, space=spacename,
                                   root_folder=rootfolder)

    local_media_folder = os.path.join(os.getcwd(), "media")

    if os.path.exists(local_media_folder):
        for root, dirs, files in os.walk(local_media_folder):
            for file in files:
                local_path = os.path.join(root, file)
                relative_path = os.path.relpath(local_path, local_media_folder)
                s3_path = os.path.join(mediafolder, relative_path)
                print("Uploading {} to {}".format(local_path, s3_path))
                s3client.upload_file(local_path, spacename, s3_path)


@do_api_method
def list_deployments(client, app_name=None):
    app_name = get_app(client, app_name)
    get_resp = client.apps.list_deployments(app_id=app_name["id"])
    print(get_resp)


@do_api_method
def loop_until_migrate(client, app_name=None):
    app_name = get_app(client, app_name)
    finished = False
    error = False
    while not finished:
        print("Checking if migrate has finished")
        get_resp = client.apps.list_deployments(app_id=app_name["id"])

        migrate_deployments = []
        if "deployments" in get_resp:
            for deployment in get_resp["deployments"]:
                if "jobs" in deployment:
                    for job in deployment["jobs"]:
                        if "name" in job and job["name"] == "migrate":
                            migrate_deployments.append(deployment)

        if len(migrate_deployments) > 0:
            for deployment in migrate_deployments:
                if "phase" in deployment:
                    print(deployment["phase"])
                    if deployment["phase"] == "ERROR":
                        print("Migrate appears to have errored")
                        error = True
                if "progress" in deployment and "steps" in deployment["progress"]:
                    for step in deployment["progress"]["steps"]:
                        if "name" in step and step["name"] == "deploy" and "status" in step and step["status"] == "SUCCESS" and "steps" in step:
                            for innerstep in step["steps"]:
                                if "name" in innerstep and innerstep["name"] == "finalize" and innerstep["status"] == "SUCCESS":
                                    finished = True
                                    print("Migrate appears to have finished")
                                    return finished
        if error:
            return finished
        print("Migrate has not finished, waiting 10 seconds")
        time.sleep(10)


@do_api_method
def remove_job_from_app(client, app_name, job_name="migrate"):
    app = get_app(client, app_name)
    if app and app["spec"]:
        app_spec = app["spec"]
        # remove job from app spec
        if "jobs" in app_spec:
            jobs = app_spec["jobs"]
            new_jobs = []
            for job in jobs:
                if "name" in job and job["name"] == job_name:
                    continue
                new_jobs.append(job)
            app_spec["jobs"] = new_jobs
            update_app_from_app_spec(client, app, app_spec)


@do_api_method
def check_space_existence(client, space_name):
    logger.debug("Checking if space {} exists".format(space_name))
    try:
        client.head_bucket(Bucket=space_name)
        logger.debug("Space {} exists".format(space_name))
        return True
    except client.exceptions.NoSuchBucket:
        logger.debug("Space {} does not exist yet".format(space_name))
        return False


def get_secret_key_env_key_from_env(env_var_list):
    for var_name in env_var_list:
        env_var_value = os.getenv(var_name)
        if env_var_value and len(env_var_value) > 0:
            return var_name
    return None


def save_app_spec_to_json_file(app_spec, filename=None):
    if not filename:
        filename = app_spec["name"] + ".json"
    with open("appspecs/" + filename, "w") as f:
        json.dump(app_spec, f, indent=4)


def load_app_spec_from_json_file(filename=None):
    with open("appspecs/" + filename, "r") as f:
        app_spec = json.load(f)
        return app_spec


def get_digitalocean_token():
    print("No DIGITALOCEAN_TOKEN found")
    print("This tool uses DigitalOcean's API to create and manage resources")
    print("You can create a token here: ")
    print("https://cloud.digitalocean.com/account/api/tokens")
    print("You can save effort when running this tool by setting the token")
    print("in the environment variable DIGITALOCEAN_API_TOKEN")
    return inquirer.password(message="DO token: ")


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
    migrate_scripts = []
    _wait_for_migrate = False

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
    @do_api_method
    def do_client(self):
        while not self._do_client:
            if not self._DIGITALOCEAN_TOKEN:
                self._DIGITALOCEAN_TOKEN = get_digitalocean_token()
            self._do_client = Client(token=self._DIGITALOCEAN_TOKEN)
        return self._do_client

    @property
    def appname_guess(self):
        logger.debug("Guessing app name")
        if self.app_name:
            logger.debug("App name already set to {}".format(self.app_name))
            return self.app_name
        elif self.component_name:
            logger.debug("Guessing app name from component name {}".format(self.component_name))
            return self.component_name + "-app"
        elif self.gh_repo:
            logger.debug("Guessing app name from github repo {}".format(self.gh_repo))
            return extract_project_name(self.gh_repo) + "-app"
        elif self.app_prefix:
            logger.debug("Guessing app name from app prefix {}".format(self.app_prefix))
            return self.app_prefix + "-app"
        else:
            logger.debug("Can't guess app name")
            return "app"

    @property
    @do_api_method
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
                               "digitalocean_token", "DIGITALOCEAN_API_TOKEN"]
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
        if not self.secret_key_env_key:
            self.secret_key_env_key = get_secret_key_env_key_from_env(potential_var_names)

        potential_var_names = ["allowed_hosts_env_key", "allowed_hosts", "ALLOWED_HOSTS",
                               "ALLOWED_HOSTS_ENV_KEY"]
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

        script_var_prefix = "MIGRATE_SCRIPT_"
        i = 1
        while os.getenv(f"{script_var_prefix}{i}"):
            logger.debug("Found {} in .env".format(f"{script_var_prefix}{i}"))
            self.migrate_scripts.append(os.getenv(f"{script_var_prefix}{i}"))
            i += 1

    @do_api_method
    @s3_method
    def main_menu(self):
        if not self._DIGITALOCEAN_TOKEN:
            self._DIGITALOCEAN_TOKEN = get_digitalocean_token()
        if not self._AWS_ACCESS_KEY_ID:
            self._AWS_ACCESS_KEY_ID = get_aws_access_key_id()
        if not self._AWS_SECRET_ACCESS_KEY:
            self._AWS_SECRET_ACCESS_KEY = get_aws_secret_access_key()
        while True:
            options = [
                ("$$$ Create Full Stack Django App $$$", "create_full_stack_django_app"),
                (" - Submenu Manage Apps", "submenu_manage_apps"),
                (" - Submenu Manage Spaces", "submenu_manage_spaces"),
                (" - Submenu Manage Databases", "submenu_manage_db"), ("Exit", "exit")]

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
            elif pickedoption == "create_full_stack_django_app":
                logger.debug("User chose to create a full stack django app")
                self.create_full_stack_django_app()
            elif pickedoption == "submenu_manage_apps":
                self.submenu_manage_apps()
            elif pickedoption == "submenu_manage_spaces":
                self.submenu_manage_spaces()
            elif pickedoption == "submenu_manage_db":
                self.submenu_manage_db()

    @do_api_method
    @s3_method
    def submenu_manage_spaces(self):
        do_client = self.do_client
        appname_guess = self.appname_guess
        while True:
            options = [("$$ Create S3 Space $$", "create_s3_space"),
                       ("-- Upload db.json to Spaces", "upload_db_json_to_s3_space"),
                       ("-- Remove db.json from Spaces", "remove_db_json_from_s3_space"),
                       ("-- Upload local media folder to s3 space", "upload_media"),
                       ("Go Back", "goback")]
            questions = [
                inquirer.List('whatdo',
                              message="What would you like to do?",
                              choices=options, default="update",
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers["whatdo"]

            if pickedoption == "create_s3_space":
                if not self._AWS_REGION:
                    self._AWS_REGION = get_region(client=do_client)
                space_name = create_s3_space(self._AWS_ACCESS_KEY_ID,
                                             self._AWS_SECRET_ACCESS_KEY,
                                             aws_region=self._AWS_REGION,
                                             space_name="space-" + appname_guess)
                session = boto3.session.Session()
                s3client = session.client('s3',
                                          endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                              self._AWS_REGION),
                                          aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                          aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY)
                while not check_space_existence(s3client, space_name):
                    print("Waiting for space creation to complete...")
                    time.sleep(5)
            elif pickedoption == "upload_db_json_to_s3_space":
                if not self._AWS_REGION:
                    self._AWS_REGION = get_region(client=do_client)
                upload_db_json_to_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                           aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                           aws_region=self._AWS_REGION,
                                           appname=appname_guess)
            elif pickedoption == "remove_db_json_from_s3_space":
                if not self._AWS_REGION:
                    self._AWS_REGION = get_region(client=do_client)
                remove_db_json_from_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                             aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                             aws_region=self._AWS_REGION,
                                             appname=appname_guess)
            elif pickedoption == "upload_media":
                if not self._AWS_REGION:
                    self._AWS_REGION = get_region(client=do_client)
                upload_media_to_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                         aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                         aws_region=self._AWS_REGION,
                                         appname=appname_guess)
            elif pickedoption == "goback":
                break

    @do_api_method
    def submenu_manage_db(self):
        do_client = self.do_client
        appname_guess = self.appname_guess
        while True:
            options = [("$$ Create Database Cluster $$", "create_db_cluster"),
                       ("-- Create Database Connection Pool", "create_db_pool"),
                       ("-- Create Database User", "create_db_user"),
                       ("-- Create Database", "create_db"),
                       ("-- Grant DB permissions to DB user", "grant_user"),
                       ("-- Add App to DB Firewall", "add_app_to_db_firewall"),
                       ("-- Add local IP to DB Firewall", "add_local_ip_to_db_firewall"),
                       ("-- Remove local IP from DB Firewall",
                        "remove_local_ip_from_db_firewall"), ("Go Back", "goback")]
            questions = [
                inquirer.List('whatdo',
                              message="What would you like to do?",
                              choices=options, default="update",
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers["whatdo"]
            if pickedoption == "create_db_cluster":
                cluster_id = create_db_cluster(client=do_client,
                                               region=self._AWS_REGION,
                                               suffix=self.app_prefix)
                while True:
                    temp_client = do_client
                    status = check_cluster_status(cluster_id, client=temp_client)

                    if status in ['creating', 'resuming', 'updating']:
                        print(f"Cluster status: {status}. Waiting...")
                        time.sleep(10)
                    elif status == 'active':
                        print("Cluster has been created successfully!")
                        break
                    else:
                        print(f"Cluster creation failed. Status: {status}")
                        break
            if pickedoption == "create_db_pool":
                create_db_pool(client=do_client, region=self._AWS_REGION,
                               app_name=appname_guess,
                               project_name=self.component_name)
            elif pickedoption == "create_db_user":
                create_db_user(client=do_client, app_name=appname_guess)
            elif pickedoption == "create_db":
                create_db(client=do_client, database_name=appname_guess)
            elif pickedoption == "grant_user":
                grant_db_rights_to_django_user(client=do_client,
                                               app_name=appname_guess)
            elif pickedoption == "add_app_to_db_firewall":
                add_app_to_db_firewall(client=do_client)
            elif pickedoption == "add_local_ip_to_db_firewall":
                add_local_ip_to_db_firewall(client=do_client)
            elif pickedoption == "remove_local_ip_from_db_firewall":
                remove_local_ip_from_db_firewall(client=do_client)
            elif pickedoption == "goback":
                break

    @do_api_method
    @s3_method
    def submenu_manage_apps(self):
        do_client = self.do_client
        appname_guess = self.appname_guess
        while True:
            options = []
            if self._app_spec:
                logger.debug("App spec found in memory")

                options.append(
                    ("-- $ Create App from loaded App Spec $", "create_do_from_memory"))
                options.append(
                    ("-- $ Update App from loaded App Spec $", "update_do_from_memory"))
                options.append(
                    ("-- Save App Spec from memory into json file", "save_to_file"))
            options.append(
                ("-- Load App Spec from scratch into memory", "load_from_user_input"))
            options.append(
                ("-- Load App Spec from existing app into memory",
                 "load_from_existing_app"))
            options.append(
                ("-- Load App Spec from json file into memory", "load_from_file"))

            options.append(
                ("-- Remove Job from App", "remove_job_from_app"))
            options.append(("-- List App Deployments for app", "list_deployments"))
            options.append(("Go Back", "goback"))
            questions = [
                inquirer.List('whatdo',
                              message="What would you like to do?",
                              choices=options, default="update",
                              ),
            ]
            answers = inquirer.prompt(questions)
            pickedoption = answers["whatdo"]
            if pickedoption == "goback":
                break
            elif pickedoption == "load_from_existing_app":
                self.set_app_spec_from_app(get_app(client=do_client))
            elif pickedoption == "dump_from_memory":
                print(json.dumps(self._app_spec, indent=4))
            elif pickedoption == "save_to_file":
                filename = input("Filename to save to: ")
                save_app_spec_to_json_file(self.app_spec, filename=filename)
            elif pickedoption == "load_from_file":
                filename = input("Filename to load from: ") or "app-spec.json"
                self._app_spec = load_app_spec_from_json_file(filename=filename)
            elif pickedoption == "update_do_from_memory":
                print("Which app would you like to update?")
                self._target_app = get_app(client=do_client,
                                           app_name=appname_guess)
                update_app_from_app_spec(client=do_client,
                                         target_app=self._target_app,
                                         app_spec=self._app_spec)
            elif pickedoption == "create_do_from_memory":
                migrate_finished_too = create_app_from_app_spec(client=do_client,
                                                                potential_spec=self._app_spec,
                                                                wait_for_migrate=self._wait_for_migrate)
                if self._wait_for_migrate and migrate_finished_too:
                    print("Migration appears to have succeeded.")
                    if inquirer.confirm(
                            "Do you want to remove the migration job from the app?",
                            default=True):
                        remove_job_from_app(client=do_client,
                                            app_name=appname_guess,
                                            job_name="migrate")
                        if inquirer.confirm(
                                "Now do you want to delete db.json from s3 space?",
                                default=True):
                            if not self._AWS_REGION:
                                self._AWS_REGION = get_region(client=do_client)
                            remove_db_json_from_s3_space(
                                aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                aws_region=self._AWS_REGION,
                                appname=appname_guess)

                if inquirer.confirm(
                        "Do you want to upload local media folder to DO spaces?",
                        default=True):
                    if not self._AWS_REGION:
                        self._AWS_REGION = get_region(client=do_client)
                    upload_media_to_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                             aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                             aws_region=self._AWS_REGION,
                                             appname=appname_guess)
            elif pickedoption == "load_from_user_input":
                self.build_app_spec_from_user_input()

            elif pickedoption == "remove_job_from_app":
                remove_job_from_app(client=do_client, app_name=appname_guess,
                                    job_name="migrate")
            elif pickedoption == "list_deployments":
                list_deployments(client=do_client, app_name=appname_guess)

    @do_api_method
    @s3_method
    def build_app_spec_from_user_input(self):
        do_client = self.do_client

        allowed_hosts = get_allowed_hosts()

        git_info = get_gh_repo(existing_app=self._target_app,
                               app_name=self.component_name, repo=self.gh_repo,
                               branch=self.gh_branch)
        self.gh_repo = git_info["repo"]
        self.gh_branch = git_info["branch"]

        appname_guess = self.appname_guess

        print("DigitalOcean must have access to this repo in order to deploy it")
        print("You can grant access to specific repos or entire account here:")
        print("https://cloud.digitalocean.com/apps/github/install")
        while not inquirer.confirm("Have you granted DigitalOcean access to this repo?"):
            print("DigitalOcean can't deploy repos it can't access")
            print("You can grant access to specific repos or entire account here:")
            print("https://cloud.digitalocean.com/apps/github/install")

        if self._target_app is not None:
            possible_appname = self._target_app["spec"]["name"]
        else:
            possible_appname = appname_guess
        confirmed_app_name = get_app_name(appname=possible_appname)

        if not self._oidc or inquirer.confirm(
                "Do you want to generate a new OIDC RSA key?", default=True):
            self._oidc = get_oidc_rsa_key()
        oidc_rsa_private_key = self._oidc

        default_secret_env_key = "SECRET_KEY"
        if self.secret_key_env_key:
            default_secret_env_key = self.secret_key_env_key
        self.secret_key_env_key = inquirer.text(
            message="What is the name of the env var that contains the Django secret key?",
            default=default_secret_env_key)
        if not self._secret_key or inquirer.confirm(
                "Do you want to generate a new Django secret key?", default=False):
            self._secret_key = secrets.token_urlsafe()

        if self._AWS_REGION:
            region_guess = self._AWS_REGION
        elif self._target_app and self._target_app["region"]["data_centers"][0]:
            region_guess = self._target_app["region"]["data_centers"][0]
        else:
            region_guess = None
        logger.debug("Get regions with default of {}".format(region_guess))
        confirmed_region = get_region(client=do_client, region_slug=region_guess)
        self._AWS_REGION = confirmed_region

        if not self._AWS_ACCESS_KEY_ID:
            self._AWS_ACCESS_KEY_ID = get_aws_access_key_id()
        if not self._AWS_SECRET_ACCESS_KEY:
            self._AWS_SECRET_ACCESS_KEY = get_aws_secret_access_key()

        logger.debug("Connecting to S3")
        session = boto3.session.Session()
        s3client = session.client('s3',
                                  endpoint_url='https://{}.digitaloceanspaces.com'.format(
                                      confirmed_region),
                                  aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                  aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY)

        logger.debug("Getting spaces")
        spacename = None
        while not spacename:
            spacename = get_spaces(s3client=s3client, appname=confirmed_app_name)

        if not self.component_name:
            self.component_name = extract_project_name(repo=self.gh_repo)
        if not self.app_prefix:
            self.app_prefix = extract_prefix(confirmed_app_name)

        rootfolder = get_root_folder(s3client=s3client, space=spacename,
                                     component_name=confirmed_app_name)
        if not rootfolder:
            return None

        mediafolder = get_media_folder(s3client=s3client, space=spacename,
                                       root_folder=rootfolder)

        aws_s3_endpoint_url = "https://{}.{}.digitaloceanspaces.com".format(spacename,
                                                                            confirmed_region)

        migrate_task = inquirer.confirm(
            "Do you want to include a migration job?", default=True)
        import_json = False
        if migrate_task:
            self._wait_for_migrate = True

            import_json = inquirer.confirm("Do you want to import db.json?", default=True)

            if import_json:

                if not self._AWS_REGION:
                    self._AWS_REGION = get_region(client=do_client)
                upload_db_json_to_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                           aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                           aws_region=confirmed_region,
                                           appname=confirmed_app_name, space_name=spacename, rootfolder=rootfolder, mediafolder=mediafolder)

        aws_storage_bucket_name = rootfolder
        aws_location = rootfolder
        disable_collectstatic = "1"

        cluster_guess = self._target_app["spec"]["databases"][0]["cluster_name"] if \
            self._target_app and self._target_app["spec"][
                "databases"] else "db-postgresql"
        logger.debug("Get clusters with default of {}".format(cluster_guess))
        cluster = get_cluster(client=do_client, cluster_name=cluster_guess,
                              region=confirmed_region, prefix=self.app_prefix)

        pool_guess = confirmed_app_name + "-pool" if confirmed_app_name else "pool"
        logger.debug("Get pools with default of {}".format(pool_guess))
        pool = get_pool(client=do_client, cluster=cluster, pool_name=pool_guess,
                        app_name=confirmed_app_name, project_name=self.component_name)

        database_url = '${' + cluster["name"] + '.' + pool["name"] + '.DATABASE_URL}'

        domain_info = get_domain_info(existing_app=self._target_app, domain=self.domain,
                                      zone=self.zone, client=do_client,
                                      prefix=self.app_prefix)

        domain = domain_info["domain"]
        zone = domain_info["zone"]
        cluster_name = cluster["name"]
        database_name = pool["db"]
        database_user = pool["user"]

        rootmoduleguess = self.django_root_module or extract_prefix(
            self.component_name) or self.app_prefix
        django_root_module = get_django_root_module(module_guess=rootmoduleguess)
        self.django_user_module = get_django_user_module(
            django_user_module=self.django_user_module)

        self.debug = clean_debug_value(self.debug)
        self.allowed_hosts_env_key = clean_allowed_hosts_env_key(
            self.allowed_hosts_env_key)

        if not self.migrate_scripts or len(self.migrate_scripts) == 0:
            one_line = inquirer.text("Do you want to run a command during migration?")
            if one_line and len(one_line) > 0:
                self.migrate_scripts.append(one_line)

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
            "region": confirmed_region,
            "appname": confirmed_app_name,
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
            "migrate_scripts": self.migrate_scripts,
        }
        self._app_spec = build_app_spec_file(env_obj=spec_vars, migrate_task=migrate_task, import_json=import_json)

    @do_api_method
    @s3_method
    def create_full_stack_django_app(self):
        do_client = self.do_client
        appname_guess = self.appname_guess
        logger.debug("Starting building app spec from user input")
        self.build_app_spec_from_user_input()

        migrate_finished_too = create_app_from_app_spec(client=do_client,
                                                        potential_spec=self._app_spec,
                                                        wait_for_migrate=self._wait_for_migrate)
        if self._wait_for_migrate and migrate_finished_too:
            print("Migration appears to have succeeded.")
            if inquirer.confirm(
                    "Do you want to remove the migration job from the app?",
                    default=True):
                remove_job_from_app(client=do_client,
                                    app_name=appname_guess,
                                    job_name="migrate")
                if inquirer.confirm(
                        "Now do you want to delete db.json from s3 space?",
                        default=True):
                    if not self._AWS_REGION:
                        self._AWS_REGION = get_region(client=do_client)
                    remove_db_json_from_s3_space(
                        aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                        aws_region=self._AWS_REGION,
                        appname=appname_guess)

        if inquirer.confirm(
                "Do you want to upload local media folder to DO spaces?",
                default=True):
            if not self._AWS_REGION:
                self._AWS_REGION = get_region(client=do_client)
            upload_media_to_s3_space(aws_access_key_id=self._AWS_ACCESS_KEY_ID,
                                     aws_secret_access_key=self._AWS_SECRET_ACCESS_KEY,
                                     aws_region=self._AWS_REGION,
                                     appname=appname_guess)

        if inquirer.confirm("Do you want to save a json file of the app spec?",
                            default=True):
            filename = input("Filename to save to: ")
            save_app_spec_to_json_file(self.app_spec, filename=filename)


@do_api_method
@s3_method
def main():
    temphelper = Helper()
    temphelper.main_menu()


if __name__ == '__main__':
    main()

import argparse
import ConfigParser
import os
import sys
import logging
import random
import urllib
import traceback
import datetime
import time
import requests

from requests import HTTPError
from apkfetch import apkfetch
from dbops import dbops
from urlchecker import urlchecker

def _parse_args():
    parser = argparse.ArgumentParser(description='Download apps, optionally update appcensus DB')

    parser.add_argument('credentials', help='Path to a credentials file containing Google and \
                                             database credentials. See getter.secrets.example for format')
    parser.add_argument('--db-update', '-d', action='store_true', help='Will update database if supplied')
    parser.add_argument('--force', '-F', action='store_true', help='Force download and database updates, even if the app version is the same')
    parser.add_argument('--apps', '-a', help='Comma-separated list of app package names')
    parser.add_argument('--apps-file', '-f', help='Path to a file containing app package names, one per line.')
    parser.add_argument('--apps-update', '-u', action='store_true', help='Check for udpates for apps that haven\'t been checked in 2 weeks, implies --db-update')
    parser.add_argument('--apps-update-limit', '-l', type=int, default=100, help='Maximum number of apps to check for updates if --apps-update is provided')
    parser.add_argument('--output', '-o', help='Path to an output directory. Files will be stored \
                                                in OUTPUT/<package>/<version-code>/. Defaults to \
                                                the current working directory.', default=os.getcwd())
    parser.add_argument('--ignore-existing', '-i', action='store_true', help='Ignore app package names that are already in the database, implies --db-update')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--test', action='store_true', help='Do all input parsing, checks, and authentications, but omit app downloading step, implies verbose')

    return parser.parse_args()

def _parse_config(config_file):
    config = ConfigParser.ConfigParser()
    config.read(config_file)

    # Get Google-* sections containing logins
    google_headers = [g for g in config.sections() if g.startswith('Google-')]
    assert len(google_headers) > 0, 'No Google-* sections found in %s' % config_file
    logging.info('Found Google headers %s' % str(google_headers))

    google_creds = []
    for header in google_headers:
        cred = {'email':config.get(header, 'email'), \
                'password':config.get(header, 'password'), \
                'gsfid':config.get(header, 'gsfid'), \
                'token':config.get(header, 'token')}
        google_creds.append(cred)
        logging.info('Found Google credentials for %s' % cred['email'])

    # Get the database login
    database_header = 'Database'
    db_cred = None
    if database_header in config.sections():
        db_cred = {'host':config.get(database_header, 'host'), \
                   'database':config.get(database_header, 'database'), \
                   'user':config.get(database_header, 'user'), \
                   'password':config.get(database_header, 'password')}
        logging.info('Found database credentials for host=%s, database=%s, user=%s' % (db_cred['host'], db_cred['database'], db_cred['user']))

    return (google_creds, db_cred)

def _read_apps_file(apps_file=None):
    if(apps_file is not None):
        return [app.strip() for app in open(apps_file).readlines()]
    return []

def _parse_apps_list(apps_list=None):
    if(apps_list is not None):
        return [app.strip() for app in apps_list.split(',')]
    return []

def _retrieve_app_updates(to_retrieve, limit=100):
    if(to_retrieve):
        return dbops.get_apps_to_update(limit=limit)
    return []

def _init_google(google_cred):
    apkfetch.init_api(google_cred['email'], google_cred['password'], google_cred['gsfid'], auth_sub_token=google_cred['token'])
    logging.info('Logged in to Google as %s' % google_cred['email'])

def _init_db(db_cred):
    dbops.init(db_cred['host'], db_cred['database'], db_cred['user'], db_cred['password'])
    logging.info('Logged in to database %s on host %s as user %s' % (db_cred['host'], db_cred['database'], db_cred['user']))

_init_success = False
def init(google_cred, db_cred=None):
    # Log in to DB, if specified
    if(db_cred is not None):
        _init_db(db_cred)

    # Log in to Google
    _init_google(google_cred)

    global _init_success
    _init_success = True

def _make_output(package_name, version_code, output_dir):
    assert os.path.isdir(output_dir), 'Target output directory %s does not exist' % output_dir
    out = os.path.join(output_dir, package_name, str(version_code))

    if(not os.path.isdir(out)):
        os.makedirs(out)
        logging.info('Output folder %s created' % out)
    else:
        logging.warn('Output folder %s already exists' % out)

    return out

def _download_app(package_name, version_code, icon_url, is_free, output_dir):
    downloaded = False
    save_to = _make_output(package_name, version_code, output_dir)

    # Get the icon
    icon_path = os.path.join(save_to, '%s-%d.png' % (package_name, version_code))
    urllib.urlretrieve(icon_url, icon_path)
    logging.info('Downloaded icon %s' % icon_path)

    # Get the APK if it's free
    if(is_free):
        apkfetch.get_apk(package_name, version_code=version_code, outdir=save_to)
    else:
        logging.warning('Did not download non-free app %s-%d' % (package_name, version_code))

    return downloaded

def _process_metadata(package_name):
    metadata = apkfetch.get_metadata(package_name)
    details = metadata['docV2']['details']['appDetails']
    public = metadata['public-meta']
    processed = {'company_name': details['developerName'], \
                 'company_url': details['developerWebsite'], \
                 'company_email': details['developerEmail'], \
                 'company_gdid': public['devId'], \
                 'policy_url': public['devPrivacy'], \
                 'app_name': metadata['docV2']['title'], \
                 'app_icon': public['appIcon'], \
                 'app_is_free': public['free'], \
                 'app_is_family': public['family'], \
                 'app_url': public['devSite'], \
                 'app_categories': public['categories'], \
                 'app_installs': public['installs'], \
                 'release_version_code': details['versionCode'], \
                 'release_version_string': details['versionString'], \
                 'release_timestamp_publish': public['publishTimestamp'], \
                 'release_has_ads': public['ads'], \
                 'release_has_iap': public['iap']}

    return processed

def _db_update(package_name, metadata, update_duplicate=False):
    version_code = metadata['release_version_code']

    already_db = dbops.is_app_in_db(package_name, version_code)
    if(already_db):
        logging.warning('%s-%d already in the database' % (package_name, version_code))

    to_update = update_duplicate or not already_db
    if(to_update):
        logging.info('Updating database for %s-%d' % (package_name, version_code))

        # Update the companies table
        company_name = metadata['company_name']
        company_gdid = metadata['company_gdid']

        company_key = dbops.insert_company(company_name, google_dev_id=company_gdid)
        logging.info('Updated companies table id=%d (%s)' % (company_key, company_name))

        # Update the privacyPolicies table
        policy_url = metadata['policy_url']
        policy_key = None
        if(policy_url is not None):
            link_active = urlchecker.check_url(policy_url)
            policy_key = dbops.insert_policy(policy_url, link_active)

        # Update the apps table
        app_name = metadata['app_name']
        app_url = metadata['app_url']
        app_icon = metadata['app_icon']
        app_installs = metadata['app_installs']
        app_is_family = metadata['app_is_family']

        app_key = dbops.insert_app(company_key, package_name, app_name, product_url=app_url, icon_url=app_icon, install_count=app_installs, is_family=app_is_family, policy_key=policy_key)
        logging.info('Updated apps table id=%d (%s) for version code %d' % (app_key, package_name, version_code))

        # Update the appReleases table
        release_version_string = metadata['release_version_string']
        release_publish_timestamp = metadata['release_timestamp_publish']
        release_has_iap = metadata['release_has_iap']
        release_has_ads = metadata['release_has_ads']

        release_key = dbops.insert_app_release(app_key, version_code, release_version_string, release_publish_timestamp, \
                                               timestamp_download=dbops.get_current_timestamp(), has_iap=release_has_iap, has_ads=release_has_ads)
        logging.info('Updated appReleases table id=%d (%s) for version code %d' % (release_key, package_name, version_code))

        # Update the categories tables
        app_categories = metadata['app_categories']
        if(len(app_categories) > 0):
            dbops.insert_categories(app_key, app_categories)
            logging.info('Updated categories table for app id=%d (%s) with categories %s' % (app_key, package_name, str(app_categories)))
    else:
        # Update the check time
        dbops.update_app_check_time(package_name)
        logging.info('Updated app check time for %s' % (package_name))

    return to_update

def _db_mark_not_in_store(package_name):
    dbops.update_app_in_store(package_name, in_store=False)

def _cooldown(min_seconds=10, max_seconds=20):
    assert min_seconds <= max_seconds, 'min_seconds %d must be <= max_seconds %d' % (min_seconds, max_seconds)
    assert min_seconds >= 0 and max_seconds >= 0, 'min_seconds %d and max_seconds %d must both be non-negative' % (min_seconds, max_seconds)

    cooldown_time = random.randint(min_seconds, max_seconds)
    logging.info('Starting cooldown %d seconds' % cooldown_time)
    time.sleep(cooldown_time)
    logging.info('Ending cooldown')

def get(apps_list, output_dir, db_update=False, include_paid=False, force=False, cooldown_every=100):
    global _init_success
    assert _init_success, 'Getter not initialized, must run init() first'

    failed_apps = list()
    app_counter = 0
    for app in apps_list:
        try:
            # Check for cooldown
            app_counter = app_counter + 1
            if(app_counter % cooldown_every == 0):
                _cooldown()

            # Get metadata for the app
            metadata = _process_metadata(app)

            # Only proceed if it's a free app or if the paid override is set
            if(metadata['app_is_free'] or include_paid):
                will_download = True
                version_code = metadata['release_version_code']

                # If there's a DB update, only download if there's a newer version than what's in the DB or if the APK doesn't already exist
                if(db_update):
                    expected_apk = os.path.join(output_dir, \
                                                app, \
                                                str(version_code), \
                                                '%s-%d.apk' % (app, version_code))
                    will_download = _db_update(app, metadata, update_duplicate=force) or not os.path.isfile(expected_apk)

                if(will_download):
                    _download_app(app, version_code, metadata['app_icon'], metadata['app_is_free'], output_dir)

            else:
                logging.warning('App %s is not free, skipping' % app)
                continue
        except HTTPError as e:
            logging.error('HTTPError occurred while processing app %s, skipping, marking as unavailable, and cooling down' % app)
            logging.error(traceback.format_exc())
            _cooldown(min_seconds=3, max_seconds=7)

            failed_apps.append(app)
            if(db_update):
                _db_mark_not_in_store(app)

            continue

        except Exception as e:
            logging.error('Exception occurred while processing app %s, skipping and cooling down' % app)
            logging.error(traceback.format_exc())
            _cooldown(min_seconds=3, max_seconds=7)
            
            failed_apps.append(app)

            continue

    for app in failed_apps:
        logging.warning('Failed getting package: %s' % app)

def _get_icon_url(apps_list):
    logging.warning('_get_icon_url() is for testing purposes only')
    for app in apps_list:
        try:
            metadata = apkfetch.get_public_metadata(app)
            icon_url = metadata['appIcon']

            logging.info('%s has icon URL %s' % (app, icon_url))

            dbops.update_app_icon(app, icon_url)

        except Exception as e:
            logging.error('Exception occurred while getting metadata for app %s, skipping' % app)
            logging.error(traceback.format_exc())
            continue

    assert False, 'This is a test function'

def _new_apps_only(apps_list):
    logging.info('Eliminating packages that are already in the database')
    return [x for x in apps_list if dbops.get_app_id(x) is None]

if __name__ == '__main__':
    # Get inputs and set appropriate logging level
    args = _parse_args()
    if(args.verbose or args.test):
        logging.basicConfig(level=logging.INFO)
    (google_creds, db_cred) = _parse_config(args.credentials)

    # Ensure that --apps-update and --ignore-existing are not both turned on
    assert not (args.apps_update and args.ignore_existing), '--apps-update and --ignore-existing cannot both be present'

    # Pick a random Google credential
    google_cred_count = len(google_creds)
    random_cred_idx = random.randint(0, google_cred_count - 1)
    google_cred = google_creds[random_cred_idx]
    logging.info('Randomly selected Google credentials for %s' % google_cred['email'])

    # If either --apps-update or --ignore-existing is supplied, --db-update is implied
    db_update = (args.apps_update or args.ignore_existing) or args.db_update

    # Log in to DB and (if necessary) Google
    if(db_update):
        assert db_cred is not None, 'Database update specified, but no credentials supplied'
        init(google_cred, db_cred=db_cred)
    else:
        init(google_cred)

    # Build the list of apps to get
    apps = set(_read_apps_file(args.apps_file) + _parse_apps_list(args.apps) + _retrieve_app_updates(args.apps_update, limit=args.apps_update_limit))
    if(args.ignore_existing):
        apps = _new_apps_only(apps)

    # Pre-get checks
    assert len(apps) > 0, 'No apps supplied, please use the --apps, --apps-file, and apps-update flags'
    assert os.path.isdir(args.output), 'Target output directory %s does not exist' % output 

    # Output the run parameters
    logging.info('App count: %d' % len(apps))
    logging.info('App list: %s' % str(apps))
    logging.info('Output path: %s' % args.output)
    logging.info('DB update: %s' % db_update)
    logging.info('Force download: %s' % args.force)

    if(not args.test):
        get(apps, args.output, db_update=db_update, force=args.force)

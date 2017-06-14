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

from apkfetch import apkfetch
import dbops

# TODO: uncomment if using multiple proxies
#os.environ['https_proxy'] = "52.91.167.250:8888"
#os.environ['http_proxy'] = "52.91.167.250:8888"
#os.environ['no_proxy'] = '127.0.0.1,localhost'

def _parse_args():
    parser = argparse.ArgumentParser(description='Download apps, optionally update appcensus DB')

    parser.add_argument('credentials', help='Path to a credentials file containing Google and \
                                             database credentials. See getter.secrets.example for format')
    parser.add_argument('--db-update', '-d', action='store_true', help='Will update database if supplied')
    parser.add_argument('--force', action='store_true', help='Will force download and database updates and overwrites if supplied')
    parser.add_argument('--apps-file', '-f', help='Path to a file containing app package names, one per line.')
    parser.add_argument('--apps', '-a', help='Comma-separated list of app package names')
    parser.add_argument('--output', '-o', help='Path to an output directory. Files will be stored \
                                                in OUTPUT/<package>/<version-code>/. Defaults to \
                                                the current working directory.', default=os.getcwd())

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
                'gsfid':config.get(header, 'gsfid')}
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

def _init_google(google_cred):
    apkfetch.init_api(google_cred['email'], google_cred['password'], google_cred['gsfid'])
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
                 'app_name': metadata['docV2']['title'], \
                 'app_icon': public['appIcon'], \
                 'app_is_free': public['free'], \
                 'app_url': public['devSite'], \
                 'app_categories': public['categories'], \
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

        # Update the apps table
        app_name = metadata['app_name']
        app_url = metadata['app_url']
        app_icon = metadata['app_icon']

        app_key = dbops.insert_app(company_key, package_name, app_name, product_url=app_url, icon_url=app_icon)
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

def get(apps_list, output_dir, db_update=False, include_paid=False, force=False, wait_secs=5):
    global _init_success
    assert _init_success, 'Getter not initialized, must run init() first'

    # Get metadata for all listed apps, exclude the ones that raise exceptions
    metadata = dict()
    for app in apps_list:
        try:
            metadata[app] = _process_metadata(app)

        except Exception as e:
            logging.error('Exception occurred while getting metadata for app %s, skipping, waiting %d seconds to cool down' % (app, wait_secs))
            logging.error(traceback.format_exc())
            time.sleep(wait_secs)
            continue

    # Disregard non-free apps
    apps_set = metadata.keys()
    if(not include_paid):
        non_free = [app for app in apps_set if not metadata[app]['app_is_free']]
        [apps_set.remove(app) for app in non_free]
        logging.warning('Ignored %d non-free apps specified' % len(non_free))

    # Put app metadata in DB, determine which apps have new versions that need to be downloaded
    download_set = set([app for app in apps_set if _db_update(app, metadata[app], update_duplicate=force) is True]) if db_update else apps_set
    download_set = apps_set if force else download_set

    # Download apps in the download set
    for app in download_set:
        try:
            meta = metadata[app]
            _download_app(app, meta['release_version_code'], meta['app_icon'], meta['app_is_free'], output_dir)
        except Exception as e:
            logging.error('Exception occurred for app %s, skipping, waiting %d seconds to cool down' % (app, wait_secs))
            logging.error(traceback.format_exc())
            continue

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

if __name__ == '__main__':
    logging.basicConfig(level=20)

    args = _parse_args()
    (google_creds, db_cred) = _parse_config(args.credentials)
    apps = _read_apps_file(args.apps_file) + _parse_apps_list(args.apps)
    db_update = args.db_update
    output_dir = args.output
    force = args.force

    assert len(apps) > 0, 'No apps supplied, need to use the --apps-file and/or the --apps flags'
    assert os.path.isdir(output_dir), 'Target output directory %s does not exist' % output_dir

    logging.info('%d apps to get, start=%s, end=%s' % (len(apps), apps[0], apps[-1]))
    logging.info('DB update=%s' % db_update)
    logging.info('Output dir=%s' % output_dir)

    google_cred_count = len(google_creds)
    random_cred_idx = random.randint(0, google_cred_count - 1)
    google_cred = google_creds[random_cred_idx]
    logging.info('Randomly selected Google credentials for %s' % google_cred['email'])

    if(db_update):
        assert db_cred is not None, 'Database update specified, but no credentials supplied'
        init(google_cred, db_cred=db_cred)
    else:
        init(google_cred)

    get(apps, output_dir, db_update=db_update, force=force)

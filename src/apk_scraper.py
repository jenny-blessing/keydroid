#!/usr/bin/env python

import pandas as pd
import os
import sys
import time
import signal

from google_play_scraper import app

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

import urllib3
import requests
import csv
import json
import re
import shutil
from bs4 import BeautifulSoup
http=urllib3.PoolManager()

from datetime import datetime
from pathlib import Path

import xml.etree.ElementTree as ET


ANDROZOO_API_KEY = 'e0a253a3ec84b3fbc20bacaa4295293dcbfd6095b54d43516cf8710f9e9dead2'

downloaded_apks = []
error_apks = []

sha256_name_mapping = {}

decompiled_apks = []
decompiled_empty_count = 0
error_apks = []
keystore_apks = []
missing_manifest_apks = []

apk_to_metadata = {}

ANDROID_KEYSTORE_CLASS = 'Landroid/security/keystore/'
ANDROID_KEYSTORE_REGEX = 'Landroid/security/keystore/(.+?);'
JAVA_KEYSTORE_CLASS = 'Ljava/security/KeyStore'
JAVA_KEYSTORE_REGEX = 'Ljava/security/(.+?);'

def handle_timeout(signum, frame):
	raise TimeoutError

# Run shell command to decompile using Apktool.
def decompile_apk(pkg_name, apk_path):
	global decompiled_empty_count
	try:
		os.system(f'java -jar ../apktool/apktool.jar d {apk_path}.apk -o {apk_path}')

		# Extra check that the decompiled directory is not empty:
		dir = os.listdir(apk_path)

		if len(dir) != 0:
			print(f'Successfully decompiled: {pkg_name}.')
			decompiled_apks.append(pkg_name)
			return True
		else:
			print(f'Decompiled APK is empty for: {pkg_name}.')
			decompiled_empty_count += 1
			error_apks.append(pkg_name)
			remove_old_apk(apk_path)
			return False
	except Exception as e:
		print(f'Error decompiling {pkg_name}.')
		print(e)
		error_apks.append(pkg_name)
		return False

def recompile_apk(pkg_name, apk_path):
	try:
		os.system(f'java -jar ../apktool/apktool.jar b {apk_path} -o {apk_path}_mod.apk')
		print(f'Successfully recompiled: {pkg_name}.')
		return True
	except:
		print(f'Error recompiling {pkg_name}.')
		error_apks.append(pkg_name)
		return False

# Remove decompiled directory.
def remove_apk_directory(apk_path):
	try:
		shutil.rmtree(f'{apk_path}')
		print('Removed APK directory.')
	except Exception as e:
		print(f'Error removing APK directory.')
		print(e)

# Remove .apk file.
def remove_old_apk(apk_path):
	try:
		os.remove(f'{apk_path}.apk')
		print('Removed old APK.')
	except Exception as e:
		print(f'Error removing old APK.')
		print(e)

# Remove images and other resources in /res to save space.
def remove_resources(apk_path):
	if os.path.exists(f'{apk_path}/res'):
		try:
			shutil.rmtree(f'{apk_path}/res')
		except Exception as e:
			print(e)

# Delete APK + grep files with no Keystore usage and the smali source of all apps to save space.
def remove_decompiled_apps(category):
	shutil.rmtree('../results/apks', ignore_errors=True)
	shutil.rmtree('../results/grep', ignore_errors=True)

def get_apk_path(pkg_name, size_str):
	return f'../apks/az_{size_str}/{pkg_name}'

def get_apps_to_sha(size_str):
	try:
		print('Reading in dataset metadata dataframe.')
		df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv')
		print('Finished reading in dataset metadata dataframe')
		app_list = df[df.columns[0]].to_numpy().tolist()
		print(app_list)
		sha_list = df[df.columns[12]].to_numpy().tolist()
		print(sha_list)

		apps_to_sha = {}
		for i in range(len(app_list)):
			apps_to_sha[app_list[i]] = sha_list[i]
		print('Retrieved apps_to_sha')
		return apps_to_sha, app_list
	except Exception as e:
		print(e)
		return []

def sort_freq_dict(freq_dict):
    aux = [(freq_dict[key], key) for key in freq_dict]
    aux.sort()
    aux.reverse()
    return aux

def print_method_freqs(sorted_dict):
	for method in sorted_dict:
		print(f'{method[1]} : {method[0]}')

def write_method_freqs(pkg_name, keystore_type, sorted_dict, s):
	with open(f'../results/az_{s}/{pkg_name}_{keystore_type}_method_freqs.csv', 'w') as f:
		for method in sorted_dict:
			f.write(f'{method[1][0]},{method[1][1]},{method[0]}\n')

def check_manifest_str(elem_str):
	if elem_str:
		return elem_str
	else:
		return '-'

def parse_manifest_root_tag(manifest_dict):
	manifest_metadata = []

	# Parse strings included directly in the manifest element:
	pkg_name = check_manifest_str(manifest_dict.get('package'))
	manifest_metadata.append(pkg_name)

	version_code = check_manifest_str(manifest_dict.get('{http://schemas.android.com/apk/res/android}versionCode'))
	manifest_metadata.append(version_code)

	version_name = check_manifest_str(manifest_dict.get('{http://schemas.android.com/apk/res/android}versionName'))
	manifest_metadata.append(version_name)

	compile_sdk_version = check_manifest_str(manifest_dict.get('{http://schemas.android.com/apk/res/android}compileSdkVersion'))
	manifest_metadata.append(compile_sdk_version)

	compile_sdk_version_codename = check_manifest_str(manifest_dict.get('{http://schemas.android.com/apk/res/android}compileSdkVersionCodename'))
	manifest_metadata.append(compile_sdk_version_codename)

	platform_build_version_code = check_manifest_str(manifest_dict.get('platformBuildVersionCode'))
	manifest_metadata.append(platform_build_version_code)

	platform_build_version_name = check_manifest_str(manifest_dict.get('platformBuildVersionName'))
	manifest_metadata.append(platform_build_version_name)

	return manifest_metadata

def parse_sdk_versions(root):
	sdks = root.find('uses-sdk')
	min_sdk_version = '-'
	targ_sdk_version = '-'
	max_sdk_version = '-'

	if (sdks):
		min_sdk_version = check_manifest_str(sdks.attrib.get('{http://schemas.android.com/apk/res/android}minSdkVersion'))
		targ_sdk_version = check_manifest_str(sdks.attrib.get('{http://schemas.android.com/apk/res/android}targetSdkVersion'))
		max_sdk_version = check_manifest_str(sdks.attrib.get('{http://schemas.android.com/apk/res/android}maxSdkVersion'))

	return [min_sdk_version, targ_sdk_version, max_sdk_version]

def parse_permissions(root, permission_tag_str):
	uses_permissions = root.findall(permission_tag_str)
	
	for p_elem in uses_permissions:
		p = p_elem.attrib['{http://schemas.android.com/apk/res/android}name']

		# USE_FINGERPRINT was deprecated in API level 28 in favor of USE_BIOMETRIC, so need to check both.
		biometric_permissions = ['android.permission.USE_FINGERPRINT', 'android.permission.USE_BIOMETRIC']
		if p in biometric_permissions:
			return p

	return None

def parse_features(root):
	uses_features = root.findall('uses-feature')
	
	for f_elem in uses_features:
		f = f_elem.attrib.get('{http://schemas.android.com/apk/res/android}name')

		if f == 'android.hardware.fingerprint':
			return f
	
	return None

# manifest_path, app_metadata_path
def parse_manifest (pkg_name, size_str):
	manifest_path = f'../apks/az_{size_str}/{pkg_name}/AndroidManifest.xml'

	try:
		root = ET.parse(manifest_path).getroot()
		manifest_metadata = []

		if root.tag == 'manifest':
			manifest_dict = root.attrib
			manifest_metadata = parse_manifest_root_tag(manifest_dict)

			sdks = parse_sdk_versions(root)
			manifest_metadata.extend(sdks)

			p = parse_permissions(root, 'uses-permission')
			manifest_metadata.append(check_manifest_str(p))

			p_sdk23 = parse_permissions(root, 'uses-permission-sdk-23')
			manifest_metadata.append(check_manifest_str(p))

			f = parse_features(root)
			manifest_metadata.append(check_manifest_str(f))

			apk_to_metadata[pkg_name] = manifest_metadata
			print('Finished parsing AndroidManifest.xml.')
	except Exception as e:
		print(e)
		print(f'Error parsing AndroidManifest.xml for: {pkg_name}.')
		error_apks.append(pkg_name)


def grep_str(pkg_name, s, apk_path, grep_keyword):
	print(f'Running grep on {pkg_name}.')
	os.system(f'grep -ri "{grep_keyword}" {apk_path} > ../grep/az_{s}/{pkg_name}_grep.txt')

# Parse grep line to extract the name of a Keystore method and its corresponding class.
def extract_keystore_calls(pkg_name, regexpr, line_str):
	try:
		keystore_class = re.search(regexpr, line_str).group(1)
	except AttributeError:
		print(f'Could not retrieve KeyStore class for {pkg_name}.')
		print(line_str)

	try:
		# Retrieve name of method:
		keystore_method = re.search('->(.+?)\(', line_str).group(1)
	except AttributeError:
		print(f'Could not retrieve KeyStore method for {pkg_name}')
		print(line_str)

	return keystore_class, keystore_method

# Parse grep file and return dict containing number and types of Keystore calls.
def parse_keystore_grep(pkg_name, class_str, regex, s):
	method_freqs = {}
	
	try:
		with open(f'../grep/az_{s}/{pkg_name}_grep.txt', 'r') as grep_output:
			grep_lines = grep_output.readlines()

		for line in grep_lines:
			line_halves = line.split(':')

			# First 14 characters must be invoke-virtual to indicate a method call
			if len(line_halves) > 1:
				is_method_call = (line_halves[1].strip()[:14] in ['invoke-direct', 'invoke-virtual', 'invoke-static'])
				is_keystore_method = is_method_call and class_str in line_halves[1]

				if is_keystore_method:
					keystore_class, keystore_method = extract_keystore_calls(pkg_name, regex, line_halves[1])

					if keystore_class and keystore_method:
						# Track individual method frequencies.
						method_path = tuple([keystore_class, keystore_method])
						if (method_path in method_freqs):
							method_freqs[method_path] += 1
						else:
							method_freqs[method_path] = 1
	except UnicodeDecodeError as e:
		print(f'UnicodeDecodeError on {pkg_name}.')
		error_apks.append(pkg_name)

	except FileNotFoundError as f_e:
		print(f'FileNotFoundError for {pkg_name}.')

	return method_freqs

def analyze_grep_results(pkg_name, size_str):
	# Get dictionaries of methods and frequencies for both Android Keystore and Java Keystore calls.
	android_keystore_method_freqs = parse_keystore_grep(pkg_name, ANDROID_KEYSTORE_CLASS, ANDROID_KEYSTORE_REGEX, size_str)

	# If app contains at least one Keystore call, write individual method frequencies to file.
	if android_keystore_method_freqs:
		sorted_android_dict = sort_freq_dict(android_keystore_method_freqs)
		write_method_freqs(pkg_name, 'android', sorted_android_dict, size_str)
		keystore_apks.append(pkg_name)


def run_grep_search(pkg_name, apk_path, size_str, grep_keyword):
	# Remove '.apk' suffix.
	#decompiled_path = apk_path[:-4]

	if os.path.exists(apk_path):
		# Run grep to search for 'keystore' within the smali source and write results to file.
		grep_str(pkg_name, size_str, apk_path, grep_keyword)

		analyze_grep_results(pkg_name, size_str)


def generate_category_results(results_dict, category):
	with open(f'../results/overall/{category}_keystore_results.csv', 'w') as f_results:
		for app in results_dict:
			keystore_bool = results_dict[app]
			f_results.write(f'{app} : {keystore_bool}\n')

def write_manifest_metadata(size_str, end_idx):
	with open(f'../metadata/az_{size_str}/az_{size_str}_manifest_data_{end_idx}.csv', 'w') as manifest_list:
		writer = csv.writer(manifest_list)
		headers = ['package','versionCode','versionName','compileSdkVersion','compileSdkVersionCodename','platformBuildVersionCode','platformBuildVersionName','minSdkVersion','targetSdkVersion','maxSdkVersion','bioPermission','bioPermissionSdk23','fingerprintFeature']
		writer.writerow(headers)
		for apk_elem in apk_to_metadata:
			metadata = apk_to_metadata[apk_elem]
			writer.writerow(metadata)

def write_apk_list(apk_list, list_type_str, size_str, end_idx):
	with open(f'../metadata/az_{size_str}/az_{size_str}_{list_type_str}_{end_idx}.csv', 'a') as list_f:
		for apk in apk_list:
			list_f.write(f'{apk}\n')

def print_stats():
	print('Total decompiled: ' + str(len(decompiled_apks)))
	print('Total decompiled and empty: ' + str(decompiled_empty_count))
	print('Total error APKs: ' + str(len(error_apks)))
	print('Total APKs with a Keystore reference: ' + str(len(keystore_apks)))

def sort_freq_dict(freq_dict):
    aux = [(freq_dict[key], key) for key in freq_dict]
    aux.sort()
    aux.reverse()
    return aux

def get_androzoo_df():
	print('Reading in AndroZoo csv...')
	df = pd.read_csv('../latest_with-added-date.csv')
	print('Finished reading AndroZoo file.')
	#print(df.head(1))
	#print(df.head(2))
	return df

# Download and decompile APK for each app.
def download_apk(app_name, app_sha, size_max):
	if os.path.exists(f'../apks/az_{size_max}/{app_name}.apk') or os.path.exists(f'../grep/az_{size_max}/{app_name}_grep.txt'):
		print('Already downloaded: ', app_name)
		return True
	else:
		try:
			apk = requests.get(f'https://androzoo.uni.lu/api/download?apikey={ANDROZOO_API_KEY}&sha256={app_sha}')
			open(f'../apks/az_{size_max}/{app_name}.apk', 'wb').write(apk.content)
			print(f'Downloaded: {app_name} : {app_sha}')
			downloaded_apks.append(app)
			return True
		except Exception as e:
			print(f'Error downloading: {app_name} : {app_sha}')
			error_apks.append(app)
			return False


# Return Androzoo sha and crawl date for an app for the latest version release.
def get_most_recent_apk(df, app_name):
	# Retrieve all entries in Androzoo csv file matching the app's package name.
	# NB: A single app can have many entries in the csv from different version releases, marketplace hosts, etc.
	indices = df[df['pkg_name']==app_name].index.tolist()

	sha_crawl_date_map = {}
	# If we can't find the package name in AndroZoo's CSV file, skip and print that it wasn't found.
	if indices:
		for row in indices:
			# Check that it's a Google Play Store app.
			# If so, retrieve app's sha and crawl date at this index.
			if "play.google.com" in df.iat[row, 11]:
				sha = df.iat[row, 0]
				crawl_date_with_hour = str(df.iat[row, 10])
				crawl_date = crawl_date_with_hour[:10]
				sha_crawl_date_map[sha] = crawl_date
	else:
		print(f'Couldn\'t find app package name in AndroZoo csv: {app_name}')

	# Sort to pull out the most recent version release from dict with all sha/date combinations present in Androzoo's database:
	sha_date_sorted = sort_freq_dict(sha_crawl_date_map)
	latest_sha = sha_date_sorted[0][1]
	latest_crawl_date = sha_date_sorted[0][0]

	return latest_sha, latest_crawl_date

def run_app_checks(pkg_name, app_data):
	if pkg_name == app_data['appId']:
		if app_data['realInstalls'] > 10000:
			if app_data['free'] == True:
				# Strictly speaking this check shouldn't be necessary since all apps in AZ are free. But check just in case.
				return True
	return False


# Scrape additional app data from Google Play Store and filter dataset further.
def play_filtering(app_list):
	app_to_metadata = {}
	not_found = 0

	for pkg_name in app_list:
		# Make sure we haven't already downloaded the app in a previous run.
		if pkg_name not in downloaded_apks:
			# Call Google play scraper:
			try:
				app_data = app(pkg_name, lang='en', country='us')

				if run_app_checks(pkg_name, app_data):
					print(pkg_name + ' passed checks.')
					app_to_metadata.update({pkg_name: app_data})
			except:
				not_found += 1
		else:
			print('Already downloaded (duplicate): ', pkg_name)

	return app_to_metadata, not_found


# Scan AndroZoo csv and come up with a list of candidate apps based on size and marketplace.
def prelim_az_filtering(df, size_min, size_max):
	candidate_apps = []

	for idx, row in df.iterrows():
		market = row['markets']
		if market == "play.google.com":
			size = int(row['apk_size'])
			
			if size >= size_min and size < size_max:
				pkg_name = row['pkg_name']
				print('Identified candidate app: ', pkg_name)
				candidate_apps.append(pkg_name)
	
	return candidate_apps

def prelim_az_filtering_existing(df, size_min, size_max):
	# df = pd.read_csv('../latest_with-added-date.csv')
	candidate_apps = []

	for idx, row in df.iterrows():
		market = row['markets']
		if market == "play.google.com":
			size = int(row['apk_size'])
			
			if size >= size_min and size < size_max:
				pkg_name = row['pkg_name']
				print('Identified candidate app: ', pkg_name)

				if pkg_name not in existing_app_list:
					candidate_apps.append(pkg_name)
	
	return candidate_apps

# To run after processing + analyzing APK.
def delete_apk(pkg_name, size_str):
	apk_path = get_apk_path(pkg_name, size_str)

	remove_old_apk(apk_path)

def process_apk(pkg_name, size_str):
	apk_path = get_apk_path(pkg_name, size_str)

	# APK has already been analyzed.
	if os.path.exists(f'{apk_path}_mod.apk'):
		print(f'Already analyzed: {pkg_name}')
		# APK is a keystore APK
		decompiled_apks.append(pkg_name)
		keystore_apks.append(apk_path)
		missing_manifest_apks.append(pkg_name)

		if os.path.exists(f'{apk_path}'):
			print('Decompiled directory still exists!')
			remove_apk_directory(apk_path)
			remove_old_apk(apk_path)
	elif os.path.exists(f'../grep/az_{size_str}/{pkg_name}_grep.txt'):
		print(f'Already analyzed: {pkg_name}')
		decompiled_apks.append(pkg_name)
	# APK has already been decompiled but not yet recompiled:
	elif os.path.exists(f'{apk_path}'):
		print(f'Already decompiled: {pkg_name}')
		decompiled_apks.append(pkg_name)

		# First, extract relevant metadata from the Manifest.
		parse_manifest(pkg_name, size_str)

		# Second, run grep search for keywords.
		run_grep_search(pkg_name, apk_path, size_str, grep_keyword)

		# Third, delete resource directory of APK to save space.
		#remove_resources(apk_path)

		# Finally, delete old APK. We only bother recompiling if an APK is a keystore APK.
		#if pkg_name in keystore_apks:
			#recompile_apk(pkg_name, apk_path)
		
		remove_apk_directory(apk_path)
	# APK hasn't been looked at yet since decompiled directory doesn't exist:
	elif os.path.exists(f'{apk_path}.apk'):
		print(f'Have not analyzed: {pkg_name}')
		# Returns a boolean indicating whether the APK decompiled successfully, and adds the package name to a global error list if not.
		decompiled = decompile_apk(pkg_name, apk_path)

		if decompiled:
			# First, extract relevant metadata from the Manifest.
			parse_manifest(pkg_name, size_str)

			# Second, run grep search for keywords.
			run_grep_search(pkg_name, apk_path, size_str, grep_keyword)

			# Third, delete resource directory of APK to save space.
			#remove_resources(apk_path)

			# Finally, delete old APK. We only bother recompiling if an APK is a keystore APK.
			#if pkg_name in keystore_apks:
				#recompile_apk(pkg_name, apk_path)
			
		remove_apk_directory(apk_path)
		remove_old_apk(apk_path)
	else:
		print(f'Cannot find any files for APK: {pkg_name}')
		#decompiled_apks.append(pkg_name)
		#missing_manifest_apks.append(pkg_name)

def write_dataset_metadata(apps_to_metadata, size_max):
	apk_list = apps_to_metadata.keys()

	apps_to_sha = {}

	with open(f'../metadata/az_{size_max}/apk_dataset_metadata_{size_max}.csv', 'w', newline='') as metadata_file:
		csv_out = csv.writer(metadata_file, delimiter=",")
		headers = ['app_id','title','real_installs','free','developer','developer_id','developer_email','genre','genre_id','released','version','az_sha', 'az_added']
		csv_out.writerow(headers)

		for app in apk_list:
			print('writing app metadata: ', app)

			# Make sure we download the most recently crawled APK for an app:
			sha, crawl_date = get_most_recent_apk(df, app)

			# Check that crawl date is after Keystore API release:
			if crawl_date > "2013-07-01":
				# APK has passed all checks and will be downloaded.
				try:
					app_row = apps_to_metadata[app]
					app_data = [app_row['appId'], app_row['title'], app_row['realInstalls'], app_row['free'], app_row['developer'], app_row['developerId'], app_row['developerEmail'], app_row['genre'], app_row['genreId'], app_row['released'], app_row['version'], sha, crawl_date]
					print(app_data)
					csv_out.writerow(app_data)

					apps_to_sha[app] = sha
				except Exception as e:
					print(e)
					continue
	metadata_file.close()

	return apps_to_sha

def write_dataset_metadata_existing(apps_to_metadata, size_max):
	apk_list = apps_to_metadata.keys()

	apps_to_sha = {}

	with open(f'../metadata/az_{size_max}/apk_dataset_metadata_{size_max}_mod.csv', 'a', newline='') as metadata_file:
		csv_out = csv.writer(metadata_file, delimiter=",")

		for app in apk_list:
			print('writing app metadata: ', app)

			# Make sure we download the most recently crawled APK for an app:
			sha, crawl_date = get_most_recent_apk(df, app)

			# Check that crawl date is after Keystore API release:
			if crawl_date > "2013-07-01":
				# APK has passed all checks and will be downloaded.
				try:
					app_row = apps_to_metadata[app]
					app_data = [app_row['appId'], app_row['title'], app_row['realInstalls'], app_row['free'], app_row['developer'], app_row['developerId'], app_row['developerEmail'], app_row['genre'], app_row['genreId'], app_row['released'], app_row['version'], sha, crawl_date]
					print(app_data)
					csv_out.writerow(app_data)

					apps_to_sha[app] = sha
				except Exception as e:
					print(e)
					continue
	metadata_file.close()

	return apps_to_sha

# Retrieve all APKs within range [size_min, size_max] that meet certain filtering requirements.
def get_az_range_filtered(df, filtered_list, size_max, start_idx, end_idx):
	# Now we have a finalized list of package names to download.
	retrieved = start_idx

	for app in filtered_list:
		try:
			# Retrieve APK from AZ server and update records:
			sha, crawl_date = get_most_recent_apk(df, app)
			downloaded = download_apk(app, sha, size_max)

			if downloaded:
				retrieved += 1

				process_apk(app, size_max)
			else:
				print('Error downloading APK.')

			print(f'Progress: {retrieved}/{end_idx}')
		except Exception as e:
			continue

	return retrieved - start_idx


# Retrieve all APKs within range [size_min, size_max] directly from AndroZoo.
def get_az_range_all(size_min, size_max):
	os.system(f'az -k {ANDROZOO_API_KEY} -i ../latest_with-added-date.csv -s {size_min}:{size_max} -m play.google.com')


def read_existing_downloads(list_path):
	if os.path.exists(list_path):
		with open(list_path) as master_list:
			downloaded_apks = [pkg_name.rstrip() for pkg_name in master_list]


def update_existing_downloads(list_path):
	if os.path.exists(list_path):
		with open(list_path, 'a') as master_list:
			for apk in downloaded_apks:
				master_list.write(f'{apk}\n')
	else:
		with open(list_path, 'w') as master_list:
			for apk in downloaded_apks:
				master_list.write(f'{apk}\n')

def read_candidate_apks(size_max):
	list_path = f'../metadata/az_{size_max}/az_{size_max}_candidates.csv'
	candidate_apks = []

	if os.path.exists(list_path):
		with open(list_path) as apk_list:
			candidate_apks = [pkg_name.rstrip() for pkg_name in apk_list]

	return candidate_apks


def write_candidate_apks(candidate_apps, size_max):
	list_path = f'../metadata/az_{size_max}/az_{size_max}_candidates.csv'
	with open(list_path, 'w') as app_list:
		for apk in candidate_apps:
			app_list.write(f'{apk}\n')

def write_error_apks(list_path):
	with open(list_path, 'w') as error_list:
		for apk in error_apks:
			error_list.write(f'{apk}\n')

def make_dir(sub_dir, size_max):
	dir_path = f'../{sub_dir}/az_{size_max}'
	if not os.path.exists(dir_path):
		os.makedirs(dir_path)

def filter_apks(df, size_min, size_max):
	# Get list of possible apps from AZ csv and remove duplicates before calculating total.
	candidate_apps = list(set(prelim_az_filtering(df, size_min, size_max)))
	print('Total possible: ' + str(len(candidate_apps)))

	# Do some more filtering based on number of installs, etc.
	apps_to_metadata, not_found = play_filtering(candidate_apps)

	return apps_to_metadata, not_found

def filter_apks_existing(df, size_min, size_max):
	# Get list of possible apps from AZ csv and remove duplicates before calculating total.
	candidate_apps = list(set(prelim_az_filtering_existing(df, size_min, size_max)))
	print('Total possible: ' + str(len(candidate_apps)))

	# Do some more filtering based on number of installs, etc.
	#apps_to_metadata, not_found = play_filtering(candidate_apps)

	#return apps_to_metadata, not_found

	return candidate_apps


size_min = int(sys.argv[1])
size_max = int(sys.argv[2])
start_idx = int(sys.argv[3])
end_idx = int(sys.argv[4])

if len(sys.argv) > 5:
	print('Running delete operation.')
	df = get_androzoo_df()

	apk_list = read_candidate_apks(size_max)

	if apk_list:
		for apk in apk_list:
			delete_apk(apk, size_str)
			print('Deleted APK: ' + apk)
	else:
		print('Error reading in APK list.')

else:
	list_path = '../metadata/apk_master_list.csv'
	grep_keyword = 'keystore'

	sub_directories = ['apks', 'metadata', 'grep', 'results']
	for sub_dir in sub_directories:
		make_dir(sub_dir, size_max)

	# Read Androzoo CSV database into dataframe:
	df = get_androzoo_df()
	#read_existing_downloads(list_path)

	apk_list = []
	apps_to_sha = {}
	not_found = 0
	if not os.path.exists(f'../metadata/az_{size_max}/apk_dataset_metadata_{size_max}_mod.csv'):
		apps_to_metadata, not_found = filter_apks(df, size_min, size_max)
		apps_to_sha = write_dataset_metadata(apps_to_metadata, size_max)
		
		apk_list = apps_to_metadata.keys()
		write_candidate_apks(apk_list, size_max)
	else:
		apk_list = read_candidate_apks(size_max)

		if not apk_list:
			apk_list = filter_apks_existing(df, size_min, size_max)
			write_candidate_apks(apk_list, size_max)
			#apps_to_sha = write_dataset_metadata_existing(apps_to_metadata, size_max)
		
			# apk_list = apps_to_metadata.keys()
			# Read in apks from apk_dataset_metada file instead.


	num_apps = len(apk_list)
	if end_idx == 0:
		end_idx = num_apps

	print('Number of apps: ' + str(num_apps))

	list_subset = list(apk_list)[start_idx:end_idx]

	# Download and process:

	num_downloaded = get_az_range_filtered(df, list_subset, size_max, start_idx, end_idx)


	# def delete_apk(pkg_name, size_str):

	print('Total downloaded: ' + str(num_downloaded))
	print('Not found in Google Play: ' + str(not_found))

	'''
	write_manifest_metadata(size_max, end_idx)
	write_apk_list(decompiled_apks, 'decompiled', size_max, end_idx)
	write_apk_list(keystore_apks, 'keystore', size_max, end_idx)
	write_apk_list(error_apks, 'error', size_max, end_idx)
	write_apk_list(missing_manifest_apks, 'no_manifest', size_max, end_idx)

	print_stats()

	update_existing_downloads(list_path)
	write_error_apks(f'../metadata/az_{size_max}/az_{size_max}_errored.csv')
	'''


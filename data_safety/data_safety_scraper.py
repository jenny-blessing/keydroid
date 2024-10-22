import pandas as pd
import os
import sys

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

import urllib3
import requests
import csv

from bs4 import BeautifulSoup

sensitive_apks = []
benign_apks = []
missing_safety_apks = []
error_apks = []

#size_categories = ['20000','60000','200000','600000','1000000','2000000','3000000','4000000','5000000','6000000','7000000','10000000','11000000']

size_categories = ['20000','60000', '200000','600000','1000000','2000000', '3000000']

proxies = {
	'http': 'docean4-holland2.joojooflop.uk:28288',
    'http': 'docean4-holland3.joojooflop.uk:28288'
}

def get_apk_list(size_str):
	try:
		#df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv')
		#apk_list = df[df.columns[0]].to_numpy().tolist()
		#df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv', usecols=[0])
		#apk_list = df[df.columns[0]].to_numpy().tolist()

		apk_list = []
		with open(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv') as metadata_file:
			for row in metadata_file:
				apk_list.append(row.split(',')[0])
		# Remove header 'app_id' as the first element.
		return apk_list[1:]
	except Exception as e:
		print(e)
		return []

def get_apk_list_high_mem(size_str):
	try:
		#df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv')
		#apk_list = df[df.columns[0]].to_numpy().tolist()
		df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv', usecols=[0])
		#apk_list = df[df.columns[0]].to_numpy().tolist()

		apk_list = []
		with open(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}.csv') as metadata_file:
			for row in metadata_file:
				apk_list.append(row.split(',')[0])
		# Remove header 'app_id' as the first element.
		return apk_list[1:]
	except Exception as e:
		print(e)
		return []


def get_data_safety_url(pkg_name):
	return f'https://play.google.com/store/apps/datasafety?id={pkg_name}'

def make_dir(size_max):
	dir_path = f'../data_safety/az_{size_max}'
	if not os.path.exists(dir_path):
		os.makedirs(dir_path)

def write_safety_data_to_file(pkg_name, size_str, data_shared, data_collected, security_practices):
	file_path = f'../data_safety/az_{size_str}/{pkg_name}_data_collection.csv'

	with open(file_path, 'w') as data_file:
		writer = csv.writer(data_file)
		for data_category, type_dict in data_shared.items():
			for data_type, purpose in type_dict.items():
				writer.writerow([f'data_shared',data_category,data_type,purpose])

		for data_category, type_dict in data_collected.items():
			for data_type, purpose in type_dict.items():
				writer.writerow([f'data_collected',data_category,data_type,purpose])

		for practice, desc in security_practices.items():
			writer.writerow([f'security_practice',practice,desc])


def parse_data_collected(div):
	data_dict = {}
	cat_name = ''

	for tag in div.find_all():
		data_justifications = {}
		category_tag = tag.find("h3", class_ = "aFEzEb")
		if category_tag:
			cat_name = category_tag.text

		data_tags = tag.find_all("span", class_ = "qcuwR")
		justification_tags = tag.find_all("div", class_ = "FnWDne")

		if data_tags and justification_tags:
			for i in range(len(data_tags)):
				if justification_tags[i]:
					data_name = data_tags[i].text
					justification = justification_tags[i].text
					data_justifications[data_name] = justification

			data_dict[cat_name] = data_justifications

	return data_dict

def parse_security_practices(div):
	practices = div.find_all("h3", class_ = "aFEzEb")

	security_practices = {}
	for elem in practices:
		title = elem.text
		description = elem.find_next("div", class_ = "fozKzd").text

		security_practices[title] = description

	return security_practices

def check_if_sensitive(pkg_name, data_collected, size_str):
	sensitive_categories = ["Location", "Personal info", "Financial info", "Health and fitness", "Messages",
		"Photos and videos", "Audio files", "Files and docs", "Calendar", "Contacts", "App activity", "Web browsing"]

	for data_category, type_dict in data_collected.items():
		# If there's a sensitive category:
		if data_category in sensitive_categories:
			sensitive_apks.append(pkg_name)
			write_individual_apk(pkg_name, "sensitive", size_str)
			print('Found a sensitive APK.')
			return True
	
	benign_apks.append(pkg_name)
	write_individual_apk(pkg_name, "benign", size_str)
	return False

def scrape_safety_page(pkg_name, size_str):
	url = get_data_safety_url(pkg_name)

	try:
		page = requests.get(url, proxies=proxies)
		soup = BeautifulSoup(page.content, "html.parser")
	except Exception as e:
		print(e)
		error_apks.append(pkg_name)

	divs = soup.find_all("div", class_ = "XgPdwe")
	# divs[0]: Data Shared
	# divs[1]: Data Collected
	# divs[2]: Security Practices

	if divs is not None:
		l = len(divs)
		if l == 0:
			write_individual_apk(pkg_name, "missing_safety", size_str)
			missing_safety_apks.append(pkg_name)
		elif l < 3:
			benign_apks.append(pkg_name)
			write_individual_apk(pkg_name, "benign_apks", size_str)
		else:
			data_shared = parse_data_collected(divs[0])
			data_collected = parse_data_collected(divs[1])
			security_practices = parse_security_practices(divs[2])

			check_if_sensitive(pkg_name, data_collected, size_str)

			write_safety_data_to_file(pkg_name, size_str, data_shared, data_collected, security_practices)
	else:
		error_apks.append(pkg_name)

def check_if_seen(apk_name):
	if sensitive_apks:
		if apk_name in sensitive_apks:
			return True
	if benign_apks:
		if apk_name in benign_apks:
			return True
	if missing_safety_apks:
		if apk_name in missing_safety_apks:
			return True
	if error_apks:
		if apk_name in error_apks:
			return True

	return False

def retrieve_data_safety(apk_list, size_str):
	num_apks = len(apk_list)
	apk_idx = 0
	for apk in apk_list:
		print(f'Current apk: {apk}')

		prev_seen = check_if_seen(apk)

		if prev_seen:
			print('Previously seen APK.')
		else:
			scrape_safety_page(apk, size_str)

		apk_idx += 1
		print(f'Progress: {apk_idx}/{num_apks}')


def write_individual_apk(apk_name, apk_label, size_str):
	with open(f'../data_safety/az_{size_str}/az_{size_str}_data_safety_{apk_label}.csv', 'a') as list_f:
		csv_out = csv.writer(list_f, delimiter=",")
		csv_out.writerow([apk_name])

	list_f.close()

def write_apk_list(apk_list, apk_label, size_str):
	with open(f'../data_safety/az_{size_str}/az_{size_str}_data_safety_{apk_label}.csv', 'w') as list_f:
		for apk in apk_list:
			list_f.write(f'{apk}\n')

def read_apk_list(apk_label, size_str):
	list_path = f'../data_safety/az_{size_str}/az_{size_str}_data_safety_{apk_label}.csv'
	if os.path.exists(list_path):
		try:
			df = pd.read_csv(list_path)
			apk_list = df[df.columns[0]].to_numpy().tolist()
			return apk_list
		except Exception as e:
			print(e)
			return []
	else:
		return []


for size_str in size_categories:
	make_dir(size_str)

	# Get overall APK list of APKs in Play store with 10,000+ users.
	print(f'Reading in APK list for size: {size_str}')
	apk_list = get_apk_list(size_str)

	sensitive_apks = read_apk_list('sensitive', size_str)
	benign_apks = read_apk_list('benign', size_str)
	error_apks = read_apk_list('error', size_str)
	missing_safety_apks = read_apk_list('missing_safety', size_str)

	retrieve_data_safety(apk_list, size_str)

	print('Writing lists.')
	write_apk_list(sensitive_apks, 'sensitive', size_str)
	write_apk_list(benign_apks, 'benign', size_str)
	write_apk_list(missing_safety_apks, 'missing_safety', size_str)
	write_apk_list(error_apks, 'error', size_str)

	print('Number of sensitive APKs: ', len(sensitive_apks))
	print('Number of benign apks: ', len(benign_apks))
	print('Number of apks missing data safety page: ', len(missing_safety_apks))
	print('Number of error apks: ', len(error_apks))
	print('---------------------------------------------------')



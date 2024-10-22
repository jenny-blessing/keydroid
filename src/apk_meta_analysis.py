#!/usr/bin/env python

import pandas as pd
import os
import sys
import time
import signal

import urllib3
import requests
import json
import csv
import re
import random
import itertools

ANDROZOO_API_KEY = 'e0a253a3ec84b3fbc20bacaa4295293dcbfd6095b54d43516cf8710f9e9dead2'

KEYSTORE_CLASS = "android.security.keystore.KeyGenParameterSpec$Builder"
KEYSTORE_INIT = "void <init>(java.lang.String,int)"
STRONGBOX_METHOD = "android.security.keystore.KeyGenParameterSpec$Builder setIsStrongBoxBacked(boolean)"


size_categories = ['20000','60000','200000','600000','1000000','2000000','3000000','4000000','5000000','6000000','7000000','9000000','10000000','11000000', '15000000', '25000000', '50000000', '100000000']

package_to_party = {}
apks_to_size = {}


class MetaAnalysis:
	analyzed_apk_total = 0
	grep_apk_total = 0
	keystore_apk_total = 0

	keystore_init_count = 0
	num_strongbox_calls = 0

	apk_to_developer = {}
	apk_to_safety_label = {}
	package_to_usages = {}

	apk_to_genre = {}
	apk_to_sha = {}
	apk_to_title_email = {}

	package_to_apks = {}
	apk_to_installs = {}
	grep_genre_total = {}
	genre_analyzed = {}

	keystore_api_calls = {}
	non_keystore_api_calls = {}
	list_analyzed_apks = []
	list_strongbox_apks = []

	def __init__(self, user_threshold):
		self.user_threshold = user_threshold

	def print_line(self):
		print('\n\n--------------------------------------------------------------------------------------------\n\n')

	# Given a dictionary of boolean argument parameters, returns total of calls with real parameter arguments.
	def get_num_calls_with_params(self, param_dict):
		num_param_calls = param_dict['1'] + param_dict['0']
		return num_param_calls

	def update_overall_counts(self, apk):
		if apk in self.apk_to_sha:
			self.analyzed_apk_total += 1

		# Update genre count:
		if apk in self.apk_to_genre:
			genre = self.apk_to_genre[apk]
			if genre in self.genre_analyzed:
				self.genre_analyzed[genre] += 1
			else:
				self.genre_analyzed[genre] = 1

	def get_dataset_totals(self):
		# Get overall dataset total by checking number of APKs in apk_to_sha.
		print(f'Dataset total (excluding duplicates): {len(self.apk_to_sha)}')

	def set_dataset_totals(self, grep_total, keystore_total):
		self.grep_apk_total = grep_total
		self.keystore_apk_total = keystore_total

	def calculate_percentage_total_dataset(self, apk_count):
		print(f'Dataset total: {self.grep_apk_total}')
		print(f'Keystore APK total: {self.keystore_apk_total}')
		print(f'Analyzed APK total: {self.analyzed_apk_total}')

		# General formula to account for error %:
		# % = (APK count)/(Analyzed APKs)*(Keystore APKs/Total APks)

		analysis_percentage = int(self.keystore_apk_total)/int(self.grep_apk_total)
		type_percentage = int(apk_count)/int(self.analyzed_apk_total)

		return round((type_percentage*analysis_percentage)*100, 2)

	def set_apk_to_developer(self, size_str):
		df = read_apk_metadata(user_threshold, size_str)
		df = df.reset_index()

		for index, row in df.iterrows():
			apk_name = row['app_id']
			developer_name = row['developer']
			self.apk_to_developer[apk_name] = developer_name

	def add_package_to_apks(self, package, apk_name):
		# Special edge case --- ignore any packages that were null.
		if str(package).strip() == "nan":
			return

		if package in self.package_to_apks:
			if apk_name not in self.package_to_apks[package]:
				self.package_to_apks[package].append(apk_name)
		else:
			self.package_to_apks[package] = [apk_name]

	def add_package_use(self, package_name, num_callers):
		self.package_to_usages[package_name] = num_callers

	def read_relevant_metadata(self, metadata_df):
		for index, row in metadata_df.iterrows():
			apk_name = row['app_id']
			
			apk_genre = row['genre_id']
			genre = row['genre_id']
			if genre[:4] == 'GAME':
				genre = 'GAMES'
			self.apk_to_genre[apk_name] = genre
			
			self.apk_to_installs[apk_name] = row['real_installs']
			self.apk_to_sha[apk_name] = row['az_sha']
			self.apk_to_title_email[apk_name] = (row['title'], row['developer_email'])

	def get_apks_with_userbase(self, analyzed_apks):
		threshold_apks = []
		for apk in analyzed_apks:
			try:
				if (self.apk_to_installs[apk] >= self.user_threshold):
					threshold_apks.append(apk)
			except KeyError as ke:
				continue
		return threshold_apks

	def add_apks_to_safety_dict(self, apk_list, safety_label):
		for apk in apk_list:
			self.apk_to_safety_label[apk] = safety_label

	def read_data_safety_labels(self):
		for size_str in size_categories:
			print(f'Reading in data safety labels for size: {size_str}')

			sensitive_apks = read_safety_apk_list('sensitive', size_str)
			self.add_apks_to_safety_dict(sensitive_apks, 'sensitive')
			benign_apks = read_safety_apk_list('benign', size_str)
			self.add_apks_to_safety_dict(benign_apks, 'benign')
			error_apks = read_safety_apk_list('error', size_str)
			self.add_apks_to_safety_dict(error_apks, 'error')
			missing_safety_apks = read_safety_apk_list('missing_safety', size_str)
			self.add_apks_to_safety_dict(missing_safety_apks, 'missing_safety')

			sensitive_len = len(list(dict.fromkeys(sensitive_apks)))
			print('Number of sensitive APKs: ', sensitive_len)
			benign_len = len(list(dict.fromkeys(benign_apks)))
			print('Number of benign apks: ', benign_len)
			error_len = len(list(dict.fromkeys(error_apks)))
			print('Number of error apks: ', len(error_apks))
			missing_len = len(list(dict.fromkeys(missing_safety_apks)))
			print('Number of apks missing data safety page: ', missing_len)
			print(f'Current size of data safety list: {len(self.apk_to_safety_label)}')
			print('---------------------------------------------------')

	def get_sensitive_apks(self):
		sensitive_apks = []
		print(f'Number of APKs in data safety labels: {len(self.apk_to_safety_label)}')

		page_total = 0
		missing_safety = 0

		for apk_name, safety_label in self.apk_to_safety_label.items():
			if safety_label == 'sensitive':
				sensitive_apks.append(apk_name)
			if safety_label in ['sensitive', 'benign']:
				page_total += 1
			if safety_label in ['missing_safety', 'error']:
				missing_safety += 1

		print(f'Number of APKs with valid data safety pages: {page_total}')
		print(f'Number of APKs missing data safety pages: {missing_safety}')

		return list(dict.fromkeys(sensitive_apks))
	
	def get_category_totals(self):
		grep_apks = []

		# Calculate searched, flagged, and analyzed APKs for each category by counting number of files.
		# These numbers are used only for debugging purposes (include duplicates, etc.).
		for size_str in size_categories:
			cat_grep_total = 0
			grep_file_list = os.listdir("../grep/az_" + size_str)
			for f_name in grep_file_list:
				if len(f_name) > 9:
					f_suffix = f_name[-9:]

				if (f_suffix == "_grep.txt"):
					apk_name = f_name[:len(f_name) - 9]
					grep_apks.append(apk_name)
					cat_grep_total += 1
			print("\nGrep total for size category " + size_str + "     : " + str(cat_grep_total))

			cat_keystore_total = 0
			keystore_file_list = os.listdir("../results/az_" + size_str)
			for f_name in keystore_file_list:
				if len(f_name) > 25:
					f_suffix = f_name[-25:]

				if (f_suffix == "_android_method_freqs.csv"):
					apk_name = f_name[:len(f_name) - 25]
					cat_keystore_total += 1
			print("Keystore total for size category " + size_str + " : " + str(cat_keystore_total))

			cat_analysis_total = 0
			analysis_file_list = os.listdir("../results/az_" + size_str + "/call_analysis");
			for f_name in analysis_file_list:
				if len(f_name) > 19:
					f_suffix = f_name[-19:]

				if (f_suffix == "_keystore_calls.csv"):
					apk_name = f_name[:len(f_name) - 19]
					cat_analysis_total += 1
			print("Analysis total for size category " + size_str + " : " + str(cat_analysis_total))

		# Remove duplicates before adding to grep_genre_total:
		grep_apks = list(dict.fromkeys(grep_apks))

		# Calculate genre totals based on valid analyzed APKs:
		for apk in grep_apks:
			if (apk in self.apk_to_genre) and (self.apk_to_installs[apk] > self.user_threshold):
				genre = self.apk_to_genre[apk]

				# Count genre distribution of overall dataset:
				if genre in self.grep_genre_total:
					self.grep_genre_total[genre] += 1
				else:
					self.grep_genre_total[genre] = 1
			if apk not in self.apk_to_genre:
				#print(f'Apk not in apk_to_genre: {apk_name}')
				continue

		self.grep_genre_total = clean_genre_dict(self.grep_genre_total)
		print('Size of grep_genre_total:')
		print(len(self.grep_genre_total))

	def set_apk_list(self, list_threshold_apks):
		for apk in list(dict.fromkeys(list_threshold_apks)):
			if apk in self.apk_to_sha:
				self.list_analyzed_apks.append(apk)

	def update_api_calls(self, apk_df):
		for index, row in apk_df.iterrows():
			row_class, row_method = row['class'], row['method']

			if row_class == KEYSTORE_CLASS:
				if row_method in self.keystore_api_calls:
					self.keystore_api_calls[row_method] += 1
				else:
					self.keystore_api_calls[row_method] = 1

			else:
				# Check that none of these method names could be the same but with different classes
				if row_method in self.non_keystore_api_calls:
					self.non_keystore_api_calls[row_method] += 1
				else:
					self.non_keystore_api_calls[row_method] = 1

	def get_package_party(self, pkg_name):
		if check_if_obfuscated_pkg(pkg_name) == False:
			try:	
				package_party = package_to_party[pkg_name]
				return package_party
			except KeyError as ke:
				return ''

	def sort_ciphers(self, ciphers):
		print('\nCiphers:')
		print('(purpose, key size, strongbox)')
		cipher_count = {}

		for c in ciphers:
			c_tuple = tuple(c)
			if c_tuple in cipher_count:
				cipher_count[c_tuple] += 1
			else:
				cipher_count[c_tuple] = 1

		#print(f'Cleaned cipher total key count: {cipher_keys_total}')
		return sort_dict(cipher_count)


	def analyze_standard_init(self):
		print(f'Analyzing: {KEYSTORE_INIT}\n')
		keystore_init_app_count = 0
		init_purposes = {}
		pkg_counts = {}

		keystore_first_party_pkg_count = 0
		keystore_third_party_pkg_count = 0

		keystore_nonobfuscated_init_count = 0
		keystore_nonobfuscated_app_count = 0

		ciphers = []
		first_party_app_count = 0
		third_party_app_only_count = 0

		print(f'Number of analyzed APKs: {len(self.list_analyzed_apks)}')

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
			#call_paths_df = get_call_paths_df(apk_name, apks_to_size[apk_name])
			#call_paths_df.reset_index()

			first_party_app = False
			third_party_app_only = True
			keystore_nonobfuscated_app = False

			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == KEYSTORE_INIT:

						calling_method = row['calling_method_signature']
						pkg_name = row['calling_package']

						pkg_party = self.get_package_party(pkg_name)
						if pkg_party:
							keystore_nonobfuscated_init_count += 1
							keystore_nonobfuscated_app = True

							if pkg_name in pkg_counts:
								pkg_counts[pkg_name] += 1
							else:
								pkg_counts[pkg_name] = 1

						if pkg_party == 'first':
							keystore_first_party_pkg_count += 1
							first_party_app = True
							third_party_app_only = False
						elif pkg_party == 'third':
							keystore_third_party_pkg_count += 1

						# Parameters:
						# P1: alias string
						# P2: purpose

						# Other methods called on same register:
						# Might have to just look at same method + class
						register = row['call_object']

						key_purpose = str(row['p2'])
						if key_purpose in init_purposes:
							init_purposes[key_purpose] += 1
						else:
							init_purposes[key_purpose] = 1

						if register != '-' and non_register_val(key_purpose):
							# Initialize key size and StrongBox to null at first.
							cipher = [key_purpose, '-', '-']

							for index_sub, row_sub in apk_df.iterrows():
								calling_method_sub = row_sub['calling_method_signature']
								row_method_sub = row_sub['method']

								# Check for setKeySize method on the same Keystore init object.
								if row_method_sub == 'android.security.keystore.KeyGenParameterSpec$Builder setKeySize(int)':
									if (calling_method_sub == calling_method) and (row_sub['call_object'] == register):
										key_size = row_sub['p1']
										if non_register_val(key_size):
											cipher[1] = key_size

								# Check for setStrongBoxBacked method on the same Keystore init object.
								if row_method_sub == STRONGBOX_METHOD:
									if (calling_method_sub == calling_method) and (row_sub['call_object'] == register):
										strongbox_bool = row_sub['p1']
										if non_register_val(strongbox_bool):
											cipher[2] = strongbox_bool


							ciphers.append(cipher)


			if first_party_app:
				first_party_app_count += 1
			if third_party_app_only:
				third_party_app_only_count += 1
			if keystore_nonobfuscated_app:
				keystore_nonobfuscated_app_count += 1

		
		print('Total number of Keystore init calls:')
		self.keystore_init_count = get_dict_total(init_purposes)

		print(f'Keystore init calls in non-obfuscated package: {keystore_nonobfuscated_init_count}')
		print('\nKeystore init most used packages:')
		print_top_10_dict(pkg_counts)

		# Print party stats of all Keystore init and StrongBox calls.
		print(f'\nKeystore init first-party calls: {keystore_first_party_pkg_count}')
		print(f'Percentage of Keystore init first-party calls: {round((keystore_first_party_pkg_count/keystore_nonobfuscated_init_count)*100, 2)}')
		print(f'Keystore init third-party calls: {keystore_third_party_pkg_count}')
		print(f'Percentage of Keystore init third-party calls: {round((keystore_third_party_pkg_count/keystore_nonobfuscated_init_count)*100, 2)}\n')

		# Apps that contain at least one first-party call:
		print(f'First-party Keystore apps: {first_party_app_count}\n')
		# Need to account for the fact that some apps/calls have only obfuscated calls:
		first_party_app_percentage = int(first_party_app_count)/int(keystore_nonobfuscated_app_count)
		print(f'First-party Keystore apps as % of total dataset: {self.calculate_percentage_total_dataset(first_party_app_percentage*len(self.list_analyzed_apks))}')
		third_party_app_percentage = int(third_party_app_only_count)/int(keystore_nonobfuscated_app_count)
		print(f'Third-party-only apps as a % of Keystore apps: {round(third_party_app_percentage*100, 2)}')

		print('Purposes:')
		print(sort_dict(remove_registers(init_purposes)))

		# print(f'Percentage of Keystore init calls requiring authentication: {round(((percentage_calls_enabling_auth * auth_call_count * .01)/self.keystore_init_count)*100, 2)}')

		ciphers_dict = self.sort_ciphers(ciphers)
		print(ciphers_dict)

		# Filtered ciphers:
		cleaned_ciphers = {}
		for cipher, count in ciphers_dict.items():
			if (cipher[1] != '-') and (cipher[2] != '-'):
				print(f'Cipher[1]: {cipher[1]}')
				print(f'Cipher[2]: {cipher[2]}')
				cleaned_ciphers[cipher] = count
		
		print(cleaned_ciphers)
		#self.sort_ciphers(cleaned_ciphers)

	def analyze_strongbox(self):
		print(f'Analyzing: {STRONGBOX_METHOD}\n')
		list_strongbox_apks = []
		num_strongbox_calls = 0

		strongbox_pkg_to_params = {}
		strongbox_params = {}
		pkg_counts = {}

		apks_with_nonobfuscated_call = 0
		apks_with_nonobfuscated_param = []

		strongbox_first_party_enabled_apks = []
		strongbox_first_party_disabled_apks = []
		strongbox_third_party_enabled_apks = []
		strongbox_third_party_disabled_apks = []

		strongbox_first_party_count = 0 # change to strongbox_first_party_call_count
		strongbox_third_party_count = 0

		strongbox_nonobfuscated_call_count = 0

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()

			nonobfuscated_call = False
			nonobfuscated_param = False
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == STRONGBOX_METHOD:
						num_strongbox_calls += 1
						list_strongbox_apks.append(apk_name)
						
						strongbox_bool = row['p1']
						pkg_name = row['calling_package']
						pkg_party = self.get_package_party(pkg_name)
						if pkg_party:
							strongbox_nonobfuscated_call_count += 1

							# Get pkg counts.
							if pkg_name in pkg_counts:
								pkg_counts[pkg_name] += 1
							else:
								pkg_counts[pkg_name] = 1

						if pkg_party == 'first':
							strongbox_first_party_count += 1
							nonobfuscated_call = True
							if strongbox_bool == '1':
								strongbox_first_party_enabled_apks.append(apk_name)
							if strongbox_bool == '0':
								strongbox_first_party_disabled_apks.append(apk_name)
						elif pkg_party == 'third':
							strongbox_third_party_count += 1
							nonobfuscated_call = True
							if strongbox_bool == '1':
								strongbox_third_party_enabled_apks.append(apk_name)
							if strongbox_bool == '0':
								strongbox_third_party_disabled_apks.append(apk_name)
						
						if strongbox_bool in strongbox_params:
							strongbox_params[strongbox_bool] += 1
						else:
							strongbox_params[strongbox_bool] = 1

						if strongbox_bool == '0' or strongbox_bool == '1':
							nonobfuscated_param = True


			if nonobfuscated_call:
				apks_with_nonobfuscated_call += 1
			if nonobfuscated_param:
				apks_with_nonobfuscated_param.append(apk_name)


		# Remove duplicates (shouldn't be necessary but just in case):
		strongbox_apks_filtered = list(dict.fromkeys(list_strongbox_apks))
		strongbox_first_party_enabled_apks_filtered = list(dict.fromkeys(strongbox_first_party_enabled_apks))
		strongbox_first_party_disabled_apks_filtered = list(dict.fromkeys(strongbox_first_party_disabled_apks))

		print(f'Total number of Strongbox calls: {num_strongbox_calls}')
		print(f'Number of Strongbox APKs (APKs with any Strongbox call): {len(strongbox_apks_filtered)}')
		print(f'Number of StrongBox APKs (with any call) as a % of overall dataset: {self.calculate_percentage_total_dataset(len(strongbox_apks_filtered))}')
		print('\n')

		print('\nStrongBox most used packages:')
		print_top_10_dict(pkg_counts)

		print(f'StrongBox calls in non-obfuscated packages: {strongbox_nonobfuscated_call_count}')
		print("Strongbox first-party calls: " + str(strongbox_first_party_count))
		print(f'Percentage of StrongBox first-party calls: {round((strongbox_first_party_count/strongbox_nonobfuscated_call_count)*100, 2)}')
		print("Strongbox third-party calls: " + str(strongbox_third_party_count))
		print(f'Percentage of StrongBox third-party calls: {round((strongbox_third_party_count/strongbox_nonobfuscated_call_count)*100, 2)}')
		print('\n')

		num_param_calls = strongbox_params['1'] + strongbox_params['0']
		print('\nTotal StrongBox calls with parameters retrieved: ' + str(num_param_calls))
		print(f'Percentage of StrongBox calls with parameters retrieved: {round((num_param_calls/num_strongbox_calls)*100, 2)}')
		
		print('\nStrongBox Parameters:')
		print(sort_dict(remove_registers(strongbox_params)))

		strongbox_enabled_percentage = round((strongbox_params['1']/num_param_calls)*100, 2)
		print('Percentage StrongBox enabled calls: ' + str(strongbox_enabled_percentage))
		print('Percentage StrongBox disabled calls: ' + str(round((strongbox_params['0']/num_param_calls)*100, 2)))

		strongbox_enabled_apks = strongbox_first_party_enabled_apks + strongbox_third_party_enabled_apks
		strongbox_enabled_apks_filtered = list(dict.fromkeys(strongbox_enabled_apks))
		print('\nNumber of StrongBox enabled apps: ' + str(len(strongbox_enabled_apks_filtered)))
		print(f'Estimated number of StrongBox enabled apps as a % of overall dataset: {round(strongbox_enabled_percentage*self.calculate_percentage_total_dataset(len(strongbox_apks_filtered))*.01,2)}')
		
		# {self.calculate_percentage_total_dataset(first_party_app_count)}
		strongbox_param_apks_filtered = list(dict.fromkeys(apks_with_nonobfuscated_param))
		print(f'StrongBox APKs with at least one param call: {len(strongbox_param_apks_filtered)}\n')

		print("Number of APKs with at least one non-package-obfuscated StrongBox call: " + str(apks_with_nonobfuscated_call))
		print("Strongbox first-party enabled apps (not including calls from obfuscated packages): " + str(len(strongbox_first_party_enabled_apks_filtered)))
		print("Strongbox first-party disabled apps (not including calls from obfuscated packages): " + str(len(strongbox_first_party_disabled_apks_filtered)))
		self.write_strongbox_disabled_apks(strongbox_first_party_disabled_apks_filtered)
		print('\n\n')

		self.print_strongbox_genre_stats(strongbox_apks_filtered, strongbox_param_apks_filtered, strongbox_enabled_apks_filtered)
		self.print_line()

		return strongbox_apks_filtered

	def write_strongbox_disabled_apks(self, strongbox_disabled_list):
		# Write list of APKs flagged for manual analysis to file.
		with open(f'../results/overall/strongbox_disabled.csv', 'w', newline='') as strongbox_survey_file:
			csv_out = csv.writer(strongbox_survey_file, delimiter=",")

			for apk_name in strongbox_disabled_list:
				apk_title = self.apk_to_title_email[apk_name][0]
				dev_email = self.apk_to_title_email[apk_name][1]
				csv_out.writerow([apk_name, apk_title, dev_email])

		strongbox_survey_file.close()

	# A key could use multiple modes
	def analyze_set_block_modes(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setBlockModes(java.lang.String[])'
		print(f'Analyzing: {method_sig}')
		mode_counts = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						# Technically could be multiple modes
						mode = row['p1']

						#for mode in block_modes:
						if mode in mode_counts:
							mode_counts[mode] += 1
						else:
							mode_counts[mode] = 1


		print('Block Modes:')
		get_dict_total(mode_counts)
		print(sort_dict(mode_counts))


	def analyze_set_digests(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setDigests(java.lang.String[])'
		print(f'Analyzing: {method_sig}')
		digest_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						digest = row['p1']

						#for digest in digests:
						if digest in digest_count:
							digest_count[digest] += 1
						else:
							digest_count[digest] = 1


		print('Digests:')
		get_dict_total(digest_count)
		print(sort_dict(digest_count))


	def analyze_encryption_paddings(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setEncryptionPaddings(java.lang.String[])'
		print(f'Analyzing: {method_sig}\n')
		paddings_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						padding = row['p1']

						#for padding in paddings:
						if padding in paddings_count:
							paddings_count[padding] += 1
						else:
							paddings_count[padding] = 1


		print('Encryption Paddings:')
		get_dict_total(paddings_count)
		print(sort_dict(paddings_count))


	def analyze_signature_paddings(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setSignaturePaddings(java.lang.String[])'
		print(f'Analyzing: {method_sig}\n')
		paddings_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						padding = row['p1']

						#for padding in paddings:
						if padding in paddings_count:
							paddings_count[padding] += 1
						else:
							paddings_count[padding] = 1


		print('Signature Paddings:')
		get_dict_total(paddings_count)
		print(sort_dict(paddings_count))


	def analyze_key_size(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setKeySize(int)'
		print(f'Analyzing: {method_sig}\n')
		key_size_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()

			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						key_size = row['p1']

						if key_size in key_size_count:
							key_size_count[key_size] += 1
						else:
							key_size_count[key_size] = 1

		print('Key Sizes:')
		get_dict_total(key_size_count)
		print(sort_dict(remove_registers(key_size_count)))


	def analyze_invalidated_biometric_enrollment(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setInvalidatedByBiometricEnrollment(boolean)'
		print(f'Analyzing: {method_sig}\n')
		bool_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						bool_val = row['p1']

						if bool_val in bool_count:
							bool_count[bool_val] += 1
						else:
							bool_count[bool_val] = 1

		print('Invalidated by Biometric Enrollment:')
		get_dict_total(bool_count)

		num_param_calls = bool_count['1'] + bool_count['0']
		print('Total calls with parameters retrieved: ' + str(num_param_calls))

		print(sort_dict(remove_registers(bool_count)))
		print('Percentage enabled calls: ' + str(round((bool_count['1']/num_param_calls)*100, 2)))
		print('Percentage disabled calls: ' + str(round((bool_count['0']/num_param_calls)*100, 2)))

	def analyze_randomized_encryption_required(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setRandomizedEncryptionRequired(boolean)'
		print(f'Analyzing: {method_sig}\n')
		
		bool_count = {}
		pkg_counts = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						bool_val = row['p1']

						pkg_name = row['calling_package']
						pkg_party = self.get_package_party(pkg_name)
						if pkg_party:
							# If randomized encryption is disabled, add package to dict.
							if bool_val == '0':
								if pkg_name in pkg_counts:
									pkg_counts[pkg_name] += 1
								else:
									pkg_counts[pkg_name] = 1

						if bool_val in bool_count:
							bool_count[bool_val] += 1
						else:
							bool_count[bool_val] = 1

		print('Randomized Encryption Required:')
		randomized_call_count = get_dict_total(bool_count)

		print('\nTop 10 randomized encryption libraries:')
		print_top_10_dict(pkg_counts)

		num_param_calls = bool_count['1'] + bool_count['0']
		print('Total calls with parameters retrieved: ' + str(num_param_calls))
		
		print(sort_dict(remove_registers(bool_count)))
		print('Percentage enabled calls: ' + str(round((bool_count['1']/num_param_calls)*100, 2)))
		percentage_disabling_randomized = (bool_count['0']/num_param_calls) * 100
		print('Percentage disabled calls: ' + str(round(percentage_disabling_randomized, 2)))

		print(f'Percentage of keys disabling randomized encryption: {round(((percentage_disabling_randomized * randomized_call_count * .01)/self.keystore_init_count)*100, 2)}')


	def analyze_unlocked_device_required(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setUnlockedDeviceRequired(boolean)'
		print(f'Analyzing: {method_sig}\n')
		bool_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						bool_val = row['p1']

						if bool_val in bool_count:
							bool_count[bool_val] += 1
						else:
							bool_count[bool_val] = 1

		print('Unlocked Device Required:')
		get_dict_total(bool_count)

		num_param_calls = self.get_num_calls_with_params(bool_count)
		print('Total calls with parameters retrieved: ' + str(num_param_calls))

		print(sort_dict(remove_registers(bool_count)))
		print('Percentage enabled calls: ' + str(round((bool_count['1']/num_param_calls)*100, 2)))
		print('Percentage disabled calls: ' + str(round((bool_count['0']/num_param_calls)*100, 2)))

	def analyze_attestation(self):
		method_sig = 'android.security.keystore.KeyGenParameterSpec$Builder setAttestationChallenge(byte[])'
		print(f'Analyzing: attestation\n')
		attestation_count = 0

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == method_sig:
						attestation_count += 1

		print(f'setAttestationChallenge count: {attestation_count}')
		print(f'Percentage of Keystore init calls requiring attestation: {round((attestation_count/self.keystore_init_count)*100,2)}')



	def analyze_authentication_required(self):
		print('Analyzing: android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)')
		
		auth_bools = {}
		duration_count = {}
		type_count = {}
		confirmation_bool_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == KEYSTORE_CLASS:
					if row_method == 'android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationRequired(boolean)':
						auth_bool = row['p1']

						if auth_bool in auth_bools:
							auth_bools[auth_bool] += 1
						else:
							auth_bools[auth_bool] = 1

					if row_method == 'android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationParameters(int,int)':
						duration = row['p1']
						if duration in duration_count:
							duration_count[duration] += 1
						else:
							duration_count[duration] = 1

						type_val = row['p2']
						if type_val in type_count:
							type_count[type_val] += 1
						else:
							type_count[type_val] = 1

					if row_method == 'android.security.keystore.KeyGenParameterSpec$Builder setUserAuthenticationValidityDurationSeconds(int)':
						duration = row['p1']
						if duration in duration_count:
							duration_count[duration] += 1
						else:
							duration_count[duration] = 1

					if row_method == 'android.security.keystore.KeyGenParameterSpec$Builder setUserConfirmationRequired(boolean)':
						confirmation_bool = row['p1']

						if confirmation_bool in confirmation_bool_count:
							confirmation_bool_count[confirmation_bool] += 1
						else:
							confirmation_bool_count[confirmation_bool] = 1



		print('\nUser Authentication Required:')
		auth_call_count = get_dict_total(auth_bools)

		print(sort_dict(remove_registers(auth_bools)))
		num_param_calls = self.get_num_calls_with_params(auth_bools)

		print('\nNumber of calls with retrieved parameter value: ' + str(num_param_calls))
		print('Percentage of calls with retrieved parameter value: ' + str(round((num_param_calls/auth_call_count)*100, 2)))
		
		percentage_calls_enabling_auth = (auth_bools['1']/num_param_calls) * 100
		print('\nPercentage of calls enabling user authentication: ' + str(round(percentage_calls_enabling_auth, 2)))
		print('Percentage of calls disabling user authentication: ' + str(round((auth_bools['0']/num_param_calls)*100, 2)))

		print(f'Percentage of Keystore init calls requiring authentication: {round(((percentage_calls_enabling_auth * auth_call_count * .01)/self.keystore_init_count)*100, 2)}')

		print('\nUser Authentication Duration:')
		calls_setting_duration = get_dict_total(remove_registers(duration_count))
		print(f'Number of calls setting duration with retrieved duration value: {calls_setting_duration}')
		print(sort_dict(duration_count))
		auth_always_required_count = duration_count['0'] + duration_count['-1']

		short_dur_count = 0
		for i in range (1, 4):
			try:
				short_dur_count += duration_count[str(i)]
			except:
				continue

		print(f'Percentage of duration calls that set duration to requiring authentication each time: {round((auth_always_required_count/calls_setting_duration)*100, 2)}')
		print(f'Percentage of duration calls with short duration (<=3 seconds): {round((short_dur_count/calls_setting_duration)*100, 2)}')

		print('\nUser Authentication Type:')
		set_auth_params_call_count = get_dict_total(type_count)
		filtered_dict = convert_to_int(remove_registers(type_count))
		param_type_call_count = get_dict_total(filtered_dict)
		print(sort_dict(filtered_dict))
		# '1': Device credential unlock (non-biometric)
		# '2': Biometric credential unlock
		# '3': either/both (same effect as not calling the method at all.)
		biometric_call_count = filtered_dict['2']
		print(f'Percentage of Keystore init calls requiring biometric authentication: {round((((biometric_call_count/param_type_call_count) * set_auth_params_call_count)/self.keystore_init_count)*100, 2)}')


		print('\nUser Confirmation Required:')
		get_dict_total(confirmation_bool_count)
		print(sort_dict(remove_registers(confirmation_bool_count)))


	def analyze_provider_algorithms(self):
		print('Analyzing relationship between algorithm and provider.')
		# Only analyze getInstance calls with both (algorithm, provider) parameters.

		algorithm_provider_count = {}

		for apk_name in self.list_analyzed_apks:
			apk_df = get_apk_call_df(apk_name, apks_to_size[apk_name])
			apk_df = apk_df.reset_index()
		
			for index, row in apk_df.iterrows():
				row_class, row_method = row['class'], row['method']

				if row_class == 'javax.crypto.KeyGenerator':
					if row_method == 'javax.crypto.KeyGenerator getInstance(java.lang.String,java.lang.String)':
						algorithm = row['p1']
						provider = row['p2']

						# Only include if both algorithm and provider parameters are real values.
						if non_register_val(algorithm) and non_register_val(provider):
							algorithm_provider_tuple = (provider, algorithm)

							if algorithm_provider_tuple in algorithm_provider_count:
								algorithm_provider_count[algorithm_provider_tuple] += 1
							else:
								algorithm_provider_count[algorithm_provider_tuple] = 1
				if row_class == 'javax.crypto.Cipher':
					if row_method == 'javax.crypto.Cipher getInstance(java.lang.String,java.lang.String)':
						algorithm = row['p1']
						provider = row['p2']

						# Only include if both algorithm and provider parameters are real values.
						if non_register_val(algorithm) and non_register_val(provider):
							algorithm_provider_tuple = (provider, algorithm)

							if algorithm_provider_tuple in algorithm_provider_count:
								algorithm_provider_count[algorithm_provider_tuple] += 1
							else:
								algorithm_provider_count[algorithm_provider_tuple] = 1
				if row_class == 'java.security.KeyPairGenerator':
					if row_method == 'java.security.KeyPairGenerator getInstance(java.lang.String,java.lang.String)':
						algorithm = row['p1']
						provider = row['p2']

						# Only include if both algorithm and provider parameters are real values.
						if non_register_val(algorithm) and non_register_val(provider):
							algorithm_provider_tuple = (provider, algorithm)

							if algorithm_provider_tuple in algorithm_provider_count:
								algorithm_provider_count[algorithm_provider_tuple] += 1
							else:
								algorithm_provider_count[algorithm_provider_tuple] = 1
				if row_class == 'java.security.KeyStore':
					if row_method == 'java.security.KeyStore getInstance(java.lang.String,java.lang.String)"':
						algorithm = row['p1']
						provider = row['p2']

						# Only include if both algorithm and provider parameters are real values.
						if non_register_val(algorithm) and non_register_val(provider):
							algorithm_provider_tuple = (provider, algorithm)

							if algorithm_provider_tuple in algorithm_provider_count:
								algorithm_provider_count[algorithm_provider_tuple] += 1
							else:
								algorithm_provider_count[algorithm_provider_tuple] = 1


		print('\nAlgorithm/provider combinations:')
		print_dict(sort_dict(algorithm_provider_count))
		print('\n\n')

		# Calculate Keystore frequencies specifically.
		get_provider_ciphers(algorithm_provider_count, ["AndroidKeyStore", "AndroidKeyStoreBCWorkaround"])
		print('\n')
		get_provider_ciphers(algorithm_provider_count, ["AndroidOpenSSL"])
		print('\n')
		get_provider_ciphers(algorithm_provider_count, ["BC"])
		print('\n')



	def run_summary_analysis(self, threshold_apks):
		print('\nRunning summary analysis.\n')

		for apk in threshold_apks:
			apk_df = get_apk_call_df(apk, apks_to_size[apk])
			apk_df = apk_df.reset_index()

			self.update_overall_counts(apk)
			self.update_api_calls(apk_df)

		self.set_apk_list(threshold_apks)
		self.get_category_totals()

		print('Size of genre_analyzed: ')
		print(len(self.genre_analyzed))


	def run_keystore_analysis(self):
		print('\nRunning Android Keystore API analysis.\n')

		# Remove duplicates:
		print('\nKeystore API Call Frequency:')
		sorted_calls = sort_dict(self.keystore_api_calls)
		print_dict(sorted_calls)

		self.print_line()
		self.analyze_standard_init()

		self.print_line()
		self.analyze_strongbox()
		self.print_keystore_genre_stats(self.list_analyzed_apks)

		self.print_line()
		#self.analyze_set_block_modes()
		#self.print_line()
		#self.analyze_set_digests()
		#self.print_line()
		#self.analyze_encryption_paddings()
		#self.print_line()
		#self.analyze_signature_paddings()

		#self.print_line()
		#self.analyze_key_size()
		#self.print_line()
		#self.analyze_invalidated_biometric_enrollment()
		#self.print_line()
		#self.analyze_randomized_encryption_required()
		#self.print_line()
		#self.analyze_unlocked_device_required()
		#self.print_line()
		#self.analyze_attestation()
		#self.print_line()
		#self.analyze_authentication_required()
		#self.print_line()
		#self.analyze_provider_algorithms()
		#self.print_line()



	def print_keystore_genre_stats(self, keystore_apks_all):
		keystore_genre_count = {}
		for keystore_apk in keystore_apks_all:
			apk_genre = self.apk_to_genre[keystore_apk]
			if apk_genre in keystore_genre_count:
				keystore_genre_count[apk_genre] += 1
			else:
				keystore_genre_count[apk_genre] = 1
		sorted_keystore_genres = sort_dict(keystore_genre_count)
		
		print('\n')
		print('Final Keystore Percentages:')
		print_genre_percentages(self.grep_genre_total, sorted_keystore_genres)


	def print_strongbox_genre_stats(self, strongbox_apks_all, strongbox_param_apks, strongbox_enabled_apks):
		# strongbox_apks_all: All APKs with any StrongBox call.
		# strongbox_param_apks: APKs with at least one StrongBox call where we could retrieve the parameter value.
		# strongbox_enabled_apks: APKs where the StrongBox parameter was True.

		strongbox_genre_count = {}
		for strongbox_apk in strongbox_apks_all:
			apk_genre = self.apk_to_genre[strongbox_apk]
			if apk_genre in strongbox_genre_count:
				strongbox_genre_count[apk_genre] += 1
			else:
				strongbox_genre_count[apk_genre] = 1

		# Genre totals for Strongbox API:
		strongbox_param_genre_count = {}
		for strongbox_apk in strongbox_param_apks:
			apk_genre = self.apk_to_genre[strongbox_apk]
			if apk_genre in strongbox_param_genre_count:
				strongbox_param_genre_count[apk_genre] += 1
			else:
				strongbox_param_genre_count[apk_genre] = 1

		strongbox_enabled_genre_count = {}
		for strongbox_apk in strongbox_enabled_apks:
			apk_genre = self.apk_to_genre[strongbox_apk]
			if apk_genre in strongbox_enabled_genre_count:
				strongbox_enabled_genre_count[apk_genre] += 1
			else:
				strongbox_enabled_genre_count[apk_genre] = 1
			
		strongbox_genre_apks = {}
		for genre in strongbox_enabled_genre_count:
			#print(f'genre: {genre}')
			enabled_count = strongbox_enabled_genre_count[genre]
			#print(f'enabled count: {enabled_count}')
			param_count = strongbox_param_genre_count[genre]
			#print(f'param count: {param_count}')
			percentage_strongbox_enabled = round(enabled_count/param_count, 2)
			#print(f'percentage enabled: {percentage_strongbox_enabled}')
			num_strongbox_genre = strongbox_genre_count[genre]
			#print(f'num strongbox genre: {num_strongbox_genre}')
			# Estimate number of StrongBox enabled APKs in category.
			strongbox_genre_apks[genre] = int(int(num_strongbox_genre) * float(percentage_strongbox_enabled))
			#print('-------------')


		sorted_strongbox_genres = sort_dict(strongbox_genre_apks)
		#print('\nTotal number of StrongBox enabled APKs used to calculate StrongBox percentages:')
		#get_dict_total(strongbox_enabled_genre_count)

		#print('Estimated Strongbox Category Enabled Numbers:')
		#print_dict(sorted_strongbox_genres)

		print('---------------------------------')
		print('Final StrongBox percentages:')
		print_genre_percentages(self.grep_genre_total, strongbox_genre_apks)

	def write_nonkeystore_survey_apks(self, nonkeystore_sensitive_list):
		# Write list of APKs flagged for manual analysis to file.

		print(f'Size of nonkeystore_sensitive_list: {len(nonkeystore_sensitive_list)}')

		# Filter out any APKs that aren't in apk_to_title metadata because of weird bug.
		# Also filter to use only one APK from each developer.
		nonkeystore_filtered_list = []
		developer_set = set()
		for apk in nonkeystore_sensitive_list:
			if apk in self.apk_to_title_email:
				dev_email = self.apk_to_title_email[apk][1]
				if dev_email not in developer_set:
					developer_set.add(dev_email)
					nonkeystore_filtered_list.append(apk)

		print(f'Size of nonkeystore_filtered_list: {len(nonkeystore_filtered_list)}')

		nonkeystore_sensitive_sample = random.sample(nonkeystore_filtered_list, 10000)

		with open(f'../results/overall/nonkeystore_sensitive.csv', 'w', newline='') as nonkeystore_survey_file:
			csv_out = csv.writer(nonkeystore_survey_file, delimiter=",")

			for apk_name in nonkeystore_sensitive_sample:
				apk_title = self.apk_to_title_email[apk_name][0]
				dev_email = self.apk_to_title_email[apk_name][1]
				csv_out.writerow([apk_name, apk_title, dev_email])

		nonkeystore_survey_file.close()


		



def delete_prev_pkg_analysis():
	f_name = f'../results/overall/package_analysis_overall.csv'
	if os.path.exists(f_name):
		os.remove(f_name)

def read_package_classification():
	print('Reading pre-calculated package party classification.')
	df = pd.read_csv(f'../results/overall/package_analysis_overall.csv', header=None)

	package_to_party = {}

	for index, row in df.iterrows():
		package_to_party[row[0]] = row[2]

	return package_to_party

def get_androzoo_df():
	print('Reading in AndroZoo csv...')
	df = pd.read_csv('../latest_with-added-date.csv')
	print('Finished reading AndroZoo file.')
	return df

def read_apk_metadata(user_threshold, size_str):
	metadata_cols = ['app_id', 'title', 'real_installs', 'developer', 'genre_id', 'az_sha', 'developer_email']

	try:
		df = pd.read_csv(f'../metadata/az_{size_str}/apk_dataset_metadata_{size_str}_mod.csv', usecols=metadata_cols, low_memory = True)

		print('Total number of APK candidates for ' + size_str + ' : ' + str(df.shape[0]))

		# Filter based on user_threshold
		df_filtered = df.loc[df['real_installs'] >= user_threshold]
		print('Total number of APK candidates above specified user threshold: ' + str(df_filtered.shape[0]))


		return df_filtered
	except Exception as e:
		print(e)
		return None

	metadata_file.close()

def get_top_200():
	top_df = pd.read_csv(f'top_200_april1.csv', header=None)
	ranking_to_apk_name = {}
	for index, row in top_df.iterrows():
		ranking_to_apk_name[row[2]] = row[0]
	return ranking_to_apk_name

def sort_dict(d):
	return dict(sorted(d.items(), key=lambda x:x[1], reverse=True))

def print_top_10_dict(d):
	sorted_dict = sort_dict(d)
	top_10_dict = dict(itertools.islice(sorted_dict.items(), 10))
	print_dict(top_10_dict)

# Filter out register values (e.g., $r7) from results map.
def remove_registers(d):
	filtered_dict = {}
	for key, value in d.items():
		key_char = list(str(key))
		if key_char[0] != '$' and key_char[0] != 'z':
			filtered_dict[key] = value
	return filtered_dict

def print_dict(d):
	for key, value in d.items():
		print(key, ":", value)

def get_dict_size(d):
	size = len(d)
	print(f'Dict size: {size}')
	return size

def get_dict_total(d):
	val_total = 0
	for key, value in d.items():
		val_total += value
	print('Dict total: ' + str(val_total))
	return val_total

def clean_genre_dict(d):
	filtered_dict = {'GAMES': 0}
	for key, value in d.items():
		key_prefix = key[:4]
		if key_prefix == 'GAME':
			filtered_dict['GAMES'] += value
		else:
			filtered_dict[key] = value
	return filtered_dict

def convert_to_int(d):
	filtered_dict = {}
	for key, value in d.items():
		new_key = str(int(key))
		filtered_dict[new_key] = value
	return filtered_dict

def print_genre_percentages(total_dict, sub_dict):
	for genre, total in total_dict.items():
		if genre in sub_dict:
			sub_count = sub_dict[genre]
			print(f'{genre}: ' + str(round((sub_count/total) * 100, 2)))
		else:
			print(f'{genre}: ' + str(0.0))

def non_register_val(param):
	param_chars = list(str(param))
	first_char = param_chars[0]
	if first_char != '$' and first_char != 'z':
		return True
	return False

def get_provider_ciphers(algorithm_provider_count, provider_list):
	keystore_algorithm_frequency = {}
	for key, value in algorithm_provider_count.items():
		if key[0] in provider_list:
			algorithm = key[1]
			keystore_algorithm_frequency[algorithm] = algorithm_provider_count[key]

	print(f'Ciphers for: {provider_list}')
	print_dict(sort_dict(keystore_algorithm_frequency))


# Returns True if packaged is obfuscated.
# Example package names: r1.i.c.a.y.a, o8, q1.x.a
def check_if_obfuscated_pkg(package):
	name_components = str(package).split('.')

	for c in name_components:
		# If there's a single individual component that's at least three characters, we consider it
		# to be a real (non-obfuscated) package name.
		if len(c) > 2:
			return False

	return True

def get_total_possible(df, size_min, size_max):
	candidate_apps = []

	for idx, row in df.iterrows():
		market = row['markets']
		if market == "play.google.com":

			size = int(row['apk_size'])
			if size >= size_min and size < size_max:
				pkg_name = row['pkg_name']
				candidate_apps.append(pkg_name)

	# Remove duplicates:
	candidate_apps = list(set(candidate_apps))
	return len(candidate_apps)

def get_total_error_apks():
	total_error_apks = 0
	for size_str in size_categories:
		total_error_apks += get_num_error_apks(size_str)
	return total_error_apks

def get_num_error_apks(size_str):
	file_path = "../metadata/az_" + size_str + "/az_" + size_str + "_analysis_error_apks.csv"
	num_error_apks = 0

	with open(file_path, "r") as error_file:
		error_apks = [line.rstrip() for line in error_file]

		# Convert to set to remove duplicates:
		error_apks_set = set(error_apks)

		num_errors = len(error_apks_set)
		num_error_apks += num_errors

	return num_error_apks

def get_call_paths():
	num_apks_analyzed = 0
	num_reachable_apks = 0
	num_unreachable_apks = 0

	num_unseen_packages = 0

	for size_str in size_categories:
		file_list = os.listdir("../results/az_" + size_str + "/call_analysis")

		for f_name in file_list:
			# _keystore_call_paths.csv
			# 24 characters
			if len(f_name) > 24:
				f_suffix = f_name[-24:]

			if (f_suffix == "_keystore_call_paths.csv"):
				with open(f_name) as paths_file:
					csvreader = csv.reader(paths_file, delimiter=',')
					for path in csvreader:
						path_len = row(len)
						for node in path:
							# Do string parsing to extract package:
							# 1. Get package + class combination
							path_prefix = node.split(':')[0]

							# 2. Get package from remainder.
							path_package = path_prefix[:path_prefix.rindex['.']+1]

							#3. Remove '<' prepended to package name.
							package = path_package[1:]
							print(package)

							# Check if package is in package_to_party.
							# Ignore if not.

							try:
								package_party = package_to_party[pkg_name]

								if package_party == 'first':
									num_reachable_apks += 1
								elif package_party == 'third':
									num_unreachable_apks += 1
							except Exception as e:
								print('Missing package.')




	print('Total number of APKs tested for reachability:')
	print(num_apks_analyzed)

	print('Number of reachable APKs:')
	print(num_reachable_apks)

	print('Number of unreachable APKs:')
	print(num_unreachable_apks)



#################################################### Keyword Search Analysis ##################################################



######################################################## Static Analysis ######################################################

def get_apk_call_df(apk_name, size_str):
	file_path = "../results/az_" + size_str + "/call_analysis/" + apk_name + "_keystore_calls.csv"

	if os.path.exists(file_path):
		col_names=['class','method','calling_package','calling_class','calling_method_signature','call_object','reachability','p1','p2','p3','p4']
		df = pd.read_csv(file_path, header=None, names=col_names)
		return df
	else:
		#print('Cannot find analysis file for: ' + apk_name + ' and size: ' + size_str)
		return None

def check_keystore_call_packages(meta, apk_name, size_str):
	apk_df = get_apk_call_df(apk_name, size_str)

	if apk_df is not None:
		for index, row in apk_df.iterrows():
			# This can create the same package-->APK mapping multiple times where the same APK contains multiple API calls in the same
			# (possibly internal) package. We account for this later on when we remove any duplicates.
			if row['class'] == KEYSTORE_CLASS:
				if row['method'] == KEYSTORE_INIT or row['method'] == STRONGBOX_METHOD:
					package = row['calling_package']
					meta.add_package_to_apks(package, apk_name)

def set_package_to_apks(meta, size_str):
	# Only want to analyze APKs that actually have a relevant API call.
	keystore_apks = get_keyword_search_apks_size(size_str)
		
	for k_apk in keystore_apks:
		#if k_apk not in meta.apk_to_developer:
			#print(f"Size: {size_str}, APK not in apks_to_developer: {k_apk}")
		check_keystore_call_packages(meta, k_apk, size_str)


def parse_reachability(apk_name, size_str):
	file_path = "../results/az_" + size_str + "/call_analysis/" + apk_name + "_keystore_call_paths.csv"



###################################################### Data Safety Analysis ###################################################




###############################################################################################################################

def classify_packages(meta):
	for size_str in size_categories:
		print('\n\nAnalyzing packages for size: ' + size_str)
		meta.set_apk_to_developer(size_str)

	for size_str in size_categories:
		set_package_to_apks(meta, size_str)

	print('\n\n')
	print(f'Size of apk_to_developer: {len(meta.apk_to_developer)}')
	print('\n\n')



	# write csv file of: package_name, apks_using, party
	# Want to sort before writing to file
	with open(f'../results/overall/package_analysis_overall.csv', 'a') as analysis_file:
		print('\nWriting package analysis to file...')
		csv_out = csv.writer(analysis_file, delimiter=",")

		# Rework to function that returns array to be written to csv

		print('\nTotal number of packages: ' + str(len(meta.package_to_apks)))
		obfuscated_count = 0
		first_count = 0
		third_count = 0

		for package in meta.package_to_apks:
			# Check if package name is obfuscated.
			obfuscated = check_if_obfuscated_pkg(str(package))
			
			if not obfuscated:
				# Remove any duplicate APK names:
				apk_callers_list = list(dict.fromkeys(meta.package_to_apks[package]))
				num_callers = len(apk_callers_list)

				#if package == 'com.microsoft.appcenter.utils.crypto':
					#for apk in apk_callers_list:
						#if apk not in meta.apk_to_developer:
							#print('APK not in apk_to_developer.')
							#print(f'apk: {apk}')

				#meta.add_package_use(package, num_callers)

				# If the package is called from multiple APKs developed by the same developer, we consider it first-party.
				try:
					developers_list = []
					for apk in apk_callers_list:
						if apk in meta.apk_to_developer:
							developers_list.append(meta.apk_to_developer[apk])
					developers_set = set(developers_list)
				except KeyError as ke:
					developers_set = []

				num_developers = len(developers_set)
				if num_developers > 1:
					# More than one unique developer uses this package, so the APK is third-party.
					csv_out.writerow([package, num_callers, 'third'])
					third_count += 1
				if num_developers == 1:
					# APK is first-party (only one developer uses this package).
					csv_out.writerow([package, num_callers, 'first'])
					first_count += 1
			else:
				# If the package name is obfuscated, we can't analyze it.
				obfuscated_count += 1

		print('Obfuscated packages: ' + str(obfuscated_count))
		print('Non-obfuscated packages: ' + str(len(meta.package_to_apks) - obfuscated_count))
		print('First-party packages: ' + str(first_count))
		print('Third-party packages: ' + str(third_count))

	analysis_file.close()



# Write analysis metadata to individual files for each size category.
def write_analysis_info(apk_info, size_str):
	with open(f'../metadata/az_{size_str}/az_{size_str}_analysis.csv', 'a') as analysis_file:
		csv_out = csv.writer(analysis_file, delimiter=",")
		csv_out.writerow(apk_info)

	analysis_file.close()



def read_safety_apk_list(apk_label, size_str):
	list_path = f'../data_safety/az_{size_str}/az_{size_str}_data_safety_{apk_label}.csv'
	if os.path.exists(list_path):
		try:
			df = pd.read_csv(list_path)
			apk_list = df[df.columns[0]].to_numpy().tolist()
			return apk_list
		except Exception as e:
			print(f'Label: {apk_label}')
			print(e)
			return []
	else:
		return []


# Download and decompile APK for each app.
def download_apk(app_name, app_sha):
	if os.path.exists(f'../apks/top/{app_name}.apk'):
		print('Already downloaded: ', app_name)
	else:
		try:
			apk = requests.get(f'https://androzoo.uni.lu/api/download?apikey={ANDROZOO_API_KEY}&sha256={app_sha}')
			open(f'../apks/az_{size_max}/{app_name}.apk', 'wb').write(apk.content)
			print(f'Downloaded: {app_name} : {app_sha}')
		except Exception as e:
			print(f'Error downloading: {app_name} : {app_sha}')


# ----------------------------------------------------------------------------------------------

def write_manual_apks(meta, sensitive_apks, keystore_apks, grep_apks, error_apks):
	# Need to add to analysis script ability to find apk size from apk name (and account for multiple apk sizes).
	apk_name_to_ranking = get_top_200()

	keystore_str_apks = filter_keystore_str_apks(grep_apks, error_apks)

	# Write list of APKs flagged for manual analysis to file.
	with open(f'../results/top_200_sensitive_nonkeystore.csv', 'w', newline='') as manual_file:
		csv_out = csv.writer(manual_file, delimiter=",")

		manual_apks = []
		for apk_name, ranking in apk_name_to_ranking.items():
			if apk_name in sensitive_apks:
				if (apk_name not in error_apks) and (apk_name not in keystore_apks):
					# If apk name is in grep APKs: we searched and it didn't have Keystore.
					if apk_name not in keystore_str_apks:
						manual_apks.append(apk_name)
						print(f'{ranking}: {apk_name}')
						csv_out.writerow([ranking, apk_name])
					else:
						print(f"Sensitive APK is not in Keystore APKs because of error (no grep file): {apk_name}")

	manual_file.close()

	# Download APKs.
	for apk_name in manual_apks:
		try:
			# Retrieve APK from AZ server.
			sha = meta.apk_to_sha[apk_name]
			download_apk(app, sha)
		except Exception as e:
			continue

def get_nonkeystore_sensitive(grep_apks, keystore_apks, sensitive_apks, error_apks):
	nonkeystore_sensitive_list = []

	print(f'Number of grep APKs: {len(grep_apks)}')
	print(f'Number of keystore APKs: {len(keystore_apks)}')
	print(f'Number of sensitive APKs: {len(sensitive_apks)}')

	grep_empty_count = 0
	sensitive_processed_count = 0

	keystore_str_apks = filter_keystore_str_apks(grep_apks, error_apks)

	for apk_name in sensitive_apks:
		if apk_name in grep_apks:
			if apk_name not in error_apks:
				sensitive_processed_count += 1
				if (apk_name not in keystore_str_apks) and (apk_name not in keystore_apks):
						grep_path = f'../grep/az_{apks_to_size[apk_name]}/{apk_name}_grep.txt'
						grep_size = os.path.getsize(grep_path)

						with open(grep_path) as grep_f:
							try:
								if (grep_size != 0):
									nonkeystore_sensitive_list.append(apk_name)
								else:
									grep_empty_count += 1
							except Exception as e:
								print(e)
								continue
	print(f'Number of sensitive APKs with empty grep: {grep_empty_count}')
	print(f'Number of sensitive APKs that were downloaded and decompiled: {sensitive_processed_count}')
	
	return list(dict.fromkeys(nonkeystore_sensitive_list))

# Returns list of all APKs successfully downloaded, decompiled, and searched.
def get_grep_apks():
	global apks_to_size
	grep_apk_list = []

	for size_str in size_categories:
		grep_file_list = os.listdir("../grep/az_" + size_str)
		
		for f_name in grep_file_list:
			if len(f_name) > 8:
				f_suffix = f_name[-8:]

			if (f_suffix == "grep.txt"):
				apk_name = f_name[:len(f_name) - 9]
				grep_apk_list.append(apk_name)

				apks_to_size[apk_name] = size_str

	# Remove duplicates before returning:
	return list(dict.fromkeys(grep_apk_list))

def get_error_apks():
	error_apk_set = set()

	for size_str in size_categories:
		path_str = f'../metadata/az_{size_str}'
		file_paths = os.listdir(path_str)

		for f_name in file_paths:
			if f_name == f'az_{size_str}_decompile_error.csv':
				#print(f'Found error file: {f_name}')
				# open file and read all lines into error_apk_set
				with open(path_str + '/' + f_name) as error_file:
					for pkg_name in error_file:
						error_apk_set.add(pkg_name.rstrip())
				error_file.close()
			if f_name.startswith(f'az_{size_str}_error'):
				#print(f'Found error file: {f_name}')
				# open file and read all lines into error_apk_set
				with open(path_str + '/' + f_name) as error_file:
					for pkg_name in error_file:
						error_apk_set.add(pkg_name.rstrip())
				error_file.close()

	# Convert to list before returning:
	return list(error_apk_set)


# Returns list of all APKs flagged as having a "keystore" result through keyword searching.
def get_keyword_search_apks():
	apk_list = []

	for size_str in size_categories:
		# Need to get list of apk names
		file_list = os.listdir("../results/az_" + size_str)

		for f_name in file_list:
			if len(f_name) > 24:
				f_suffix = f_name[-24:]

			if f_suffix == "android_method_freqs.csv":
				# Add APK to category list.
				apk_name = f_name[:len(f_name) - 25]	# Name includes .apk suffix; index adds one for extra _

				# Need to check if apk is in df (i.e. meets user threshold)
				# If name is in first column of dataframe
				apk_list.append(apk_name)

	return list(dict.fromkeys(apk_list))

def get_keyword_search_apks_size(size_str):
	apk_list = []
	file_list = os.listdir("../results/az_" + size_str)

	for f_name in file_list:
		if len(f_name) > 24:
			f_suffix = f_name[-24:]

		if f_suffix == "android_method_freqs.csv":
			# Add APK to category list.
			apk_name = f_name[:len(f_name) - 25]	# Name includes .apk suffix; index adds one for extra _

			# Need to check if apk is in df (i.e. meets user threshold)
			# If name is in first column of dataframe
			apk_list.append(apk_name)

	print(f"Size: {size_str}; APKS: {str(len(apk_list))}\n")
	return apk_list


# Returns list of all APKs that were analyzed using Soot.
def get_analysis_apks():
	global apks_to_size
	apk_list = []

	for size_str in size_categories:
		# Need to get list of apk names
		file_list = os.listdir("../results/az_" + size_str + "/call_analysis")

		for f_name in file_list:
			if len(f_name) > 18:
				f_suffix = f_name[-18:]

				if (f_suffix == "keystore_calls.csv"):
					#print('Found keystore call file')
					# Add APK to category list.
					apk_name = f_name[:len(f_name) - 19]	# Name includes .apk suffix

					# Need to check if apk is in df (i.e. meets user threshold)
					# If name is in first column of dataframe

					# Will replace any grep sizes with largest analysis size:
					apks_to_size[apk_name] = size_str
					apk_list.append(apk_name)

	return list(dict.fromkeys(apk_list))

# Filter out all APKs that don't have a basic _grep.txt file, indicating they were unable to be downloaded and decompiled.
def filter_grep(apk_list, grep_apks):
	print(f'Size of list before grep filtering: {len(apk_list)}')

	filtered_list = []
	for apk in apk_list:
		if apk in grep_apks:
			filtered_list.append(apk)

	print(f'Size of list after grep filtering: {len(filtered_list)}')
	return filtered_list


def filter_sensitive_apks(apk_list, sensitive_apks):
	filtered_list = []
	for apk in sensitive_apks:
		if apk in apk_list:
			filtered_list.append(apk)
	return filtered_list

def filter_keystore_str_apks(grep_apks, error_apks):
	# Filter APKs with a _grep.txt file to remove a small number of APKs referencing AndroidKeyStore only through Java's Keystore class.
	# (And so were not flagged for analysis.)
	grep_keystorestr_count = 0
	
	keystore_str_only_list = []
	for apk in grep_apks:
		apk_size = apks_to_size[apk]
		grep_path = f'../grep/az_{apk_size}/{apk}_grep.txt'

		with open(grep_path) as grep_f:
			try:
				if "AndroidKeyStore" in grep_f.read():
					grep_keystore_path = f'../results/az_{apk_size}/{apk}_android_method_freqs.csv'
					if (not os.path.exists(grep_keystore_path)) and (apk not in error_apks):
						keystore_str_only_list.append(apk)
			except Exception as e:
				continue
	
	return list(dict.fromkeys(keystore_str_only_list))


def read_all_metadata(meta, user_threshold):
	for size_str in size_categories:
		print('\n\nReading metadata for category: ' + size_str)

		# Get APK list from APK metadata for size category.
		metadata_df = read_apk_metadata(user_threshold, size_str)

		if metadata_df is None:
			return None

		# Parse general metadata csv for size category and add apk data into data structures.
		meta.read_relevant_metadata(metadata_df)
	print('Size of apk_to_genre:')
	print(len(meta.apk_to_genre))

def run_overall_analysis(meta, data_safety):
	meta.get_dataset_totals()

	grep_apks = get_grep_apks()
	print(f'\n\nAPKs downloaded and decompiled (excluding duplicates): {len(grep_apks)}\n')
	grep_error_apks = get_error_apks()

	# Returns list of all APKs flagged as having a Keystore API reference through keyword searching.
	keystore_apks = get_keyword_search_apks()
	print(f'Keystore APKs flagged through grep searching: {len(keystore_apks)}\n')
	keystore_str_apks = filter_keystore_str_apks(grep_apks, grep_error_apks)
	print(f'Number of APKs with AndroidKeystore string only in grep but not in keystore_apks (no android_method_freqs): {len(keystore_str_apks)}')
	total_keystore = len(keystore_apks) + len(keystore_str_apks)
	print(f'Total APKs flagged as Keystore by grep: {total_keystore}')
	print(f'Percentage of APKs flagged as Keystore by grep: {round((total_keystore/len(grep_apks))*100, 2)}')

	meta.set_dataset_totals(len(grep_apks), len(keystore_apks))

	# Returns list of all APKs that were analyzed using Soot.
	analyzed_apks = get_analysis_apks()
	print(f'APKs analyzed using Soot: {len(analyzed_apks)}')
	print(f'Percentage APKs successfully analyzed: {round((len(analyzed_apks)/len(keystore_apks)*100),2)}\n')

	if data_safety:
		meta.read_data_safety_labels()
		sensitive_apks = meta.get_sensitive_apks()
		print(f'Number of sensitive APKs: {len(sensitive_apks)}')

		# Determine APKs to be manually analyzed.
		meta.print_line()
		write_manual_apks(meta, sensitive_apks, keystore_apks, grep_apks, grep_error_apks)

		nonkeystore_sensitive_list = get_nonkeystore_sensitive(grep_apks, keystore_apks, sensitive_apks, grep_error_apks)
		print(f"Number of sensitive nonkeystore APKs: {len(nonkeystore_sensitive_list)}")
		meta.write_nonkeystore_survey_apks(nonkeystore_sensitive_list)

		sensitive_grep_apks = filter_grep(sensitive_apks, grep_apks)
		sensitive_keystore_apks = filter_sensitive_apks(keystore_apks, sensitive_grep_apks)
		print(f'Number of sensitive APKs flagged as Keystore: {len(sensitive_keystore_apks)}')
		sensitive_keystore_str_apks = filter_sensitive_apks(filter_keystore_str_apks(grep_apks, grep_error_apks), sensitive_grep_apks)
		print(f'Number of sensitive APKs with AndroidKeystore string only in grep but not in keystore_apks (no android_method_freqs): {len(sensitive_keystore_str_apks)}')
		total_keystore_sensitive = len(sensitive_keystore_apks) + len(sensitive_keystore_str_apks)
		print(f'Total sensitive APKs flagged as Keystore by grep: {total_keystore_sensitive}')
		print(f'Percentage of sensitive APKs flagged as Keystore by grep: {round((total_keystore_sensitive/len(sensitive_grep_apks))*100, 2)}')

		sensitive_analyzed_apks = filter_sensitive_apks(analyzed_apks, sensitive_grep_apks)

		# Can only include analyzed APKs (with _keystore_calls file):
		keystore_apks = sensitive_keystore_apks
		analyzed_apks = sensitive_analyzed_apks


	# Filter to use only APKs above given userbase threshold.
	# Included in case we want analysis results for, say, only APKs above 1M users.
	threshold_flagged_apks = meta.get_apks_with_userbase(keystore_apks)
	print(f'Keystore APKs above user threshold: {len(threshold_flagged_apks)}')
	threshold_analyzed_apks = meta.get_apks_with_userbase(analyzed_apks)
	print(f'Analyzed APKs above user threshold: {len(threshold_analyzed_apks)}')

	# Run main analysis of Keystore init function and StrongBox.
	# Prints total numbers and Keystore API frequency dict.
	meta.print_line()
	meta.run_summary_analysis(analyzed_apks)

	return analyzed_apks


def run_analysis(user_threshold, data_safety):
	global package_to_party
	meta = MetaAnalysis(user_threshold)

	# 1. Run package analysis.
	print('Running package party analysis.')
	delete_prev_pkg_analysis()
	classify_packages(meta)
	
	# 2. Run overall analysis.
	meta.print_line()
	# Get dictionary classifying each package as first or third party.
	package_to_party = read_package_classification()

	read_all_metadata(meta, user_threshold)
	analyzed_apks = run_overall_analysis(meta, data_safety)

	# 3. Run Keystore API analysis.
	meta.print_line()
	meta.run_keystore_analysis()



# Manually edit size_categories at the top.

if len(sys.argv) > 2:
	user_threshold = int(sys.argv[1])
	data_safety = bool(sys.argv[2])
else:
	print('No user threshold provided; using default value of 10,000.')
	user_threshold = 10000
	data_safety = False


run_analysis(user_threshold, data_safety)






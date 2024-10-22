import json
import os
import csv
import statistics

def average(list):
	return sum(list) / len(list)

def get_device_logs(device_name):
	with open(f'aws_logs/device_logs/{device_name}.json', 'r') as log_file:
		log_data = json.load(log_file)
	return log_data

def delete_results_file(test_name):
	# Delete previous results file if it exists:
	results_path = f'aws_logs/test_results/{test_name}_data.csv'

	if os.path.exists(results_path):
		os.remove(results_path)

def write_data_to_file(test_name, line_data):
	with open(f'aws_logs/test_results/{test_name}_data.csv', 'a') as results_file:
		writer = csv.writer(results_file, delimiter=',')
		writer.writerow(line_data)


def extract_tag_logs(log_data, goal_tag):
	payloads = []

	for json_line in log_data:
		if json_line['tag']:
			tag_name = json_line['tag']
			if tag_name.lower() == goal_tag.lower():
				payloads.append(json_line['data'])

	return payloads

# Extracts data for particular test from device logs.
def extract_info_tags(device_list):
	test_data = []
	try:
		# Read in logs for all devices.
		for device in device_list:
			print('----------------------------------------------------------------------------------------')
			print('\nInfo tags for device: ' + device)
			json_logs = get_device_logs(device)

			tag_payloads = extract_tag_logs(json_logs, "KeystoreInfoTag")

			for payload in tag_payloads:
				payload_list = [x.strip() for x in payload.split(',')]
				# Need to account for accidental inverted conditional logic.
				if payload_list[0] != "Sym key is null.":
					print(payload_list[0])

	except Exception as e:
		print(e)
		return None

# Extracts data for particular test from device logs.
def extract_test_data(test_name, device_list, test_tags):
	test_data = []
	try:
		# Read in logs for all devices.
		for device_name in device_list:
			json_logs = get_device_logs(device_name)

			for tag in test_tags:
				#print(tag)
				tag_payloads = extract_tag_logs(json_logs, tag)

				for payload in tag_payloads:
					line_data = [device_name, tag]
					payload_list = [x.strip() for x in payload.split(',')]

					# Append to list of lists of all test data points:
					full_data_point = line_data + payload_list
					test_data.append(full_data_point)
					write_data_to_file(test_name, full_data_point)
			if not test_tags:
				print('No tags for: ' + tag)

		return test_data
	except Exception as e:
		print(e)
		return None

def calculate_test_performance(test_name, test_data, device, test_tag, test_lengths):
	print('\nPerformance data for: ' + test_tag)
	length_to_times = {}
	keystore_providers = []
	
	for data_point in test_data:
		if (data_point[0] == device) and (data_point[1] == test_tag):
			provider = data_point[2]
			length = data_point[3]
			runtime = data_point[4]

			if provider not in keystore_providers:
				keystore_providers.append(provider)

			ms_runtime = round(int(runtime)/1000000)

			# Create set of timing measurements for each length tested.
			if length in test_lengths:
				if length in length_to_times:
					length_to_times[length].append(ms_runtime)
				else:
					length_to_times[length] = [ms_runtime]

	# Print providers.
	print('Providers: ' + str(keystore_providers))
	print('Tested Lengths: ' + str(list(length_to_times.keys())))

	# Now that we have a list of all timing measurements for each length, need to calculate relevant stats.
	for length in length_to_times:
		measurements_list = length_to_times[length]
		if test_name == 'message_length_encrypt' and float(length) >= 4:
			measurements_list = measurements_list[:10]

		print('Number of measurements for length ' + length + ' : ' + str(len(measurements_list)))
		#print('Measurements:')
		#print(measurements_list)

		avg = statistics.mean(measurements_list)
		measurements_list_s = [(x/1000) for x in measurements_list]
		print(measurements_list_s)
		print('Average: ' + str(avg) + ' ms')
		print('Average: ' + str(avg/1000) + ' s')
		#median = statistics.median(measurements_list)

		sampleStdDev = statistics.stdev(measurements_list)
		print('Sample standard deviation: ' + str(sampleStdDev) + ' ms')
		print('Sample standard deviation: ' + str(sampleStdDev/1000) + ' s')


def test_performance_over_time(test_name):
	print('Testing performance over time.')
	delete_results_file(test_name)

	pixel_device_list = {
		'pixel': '10/20/2016',
		'pixel2': '10/17/2017',
		'pixel3': '10/18/2018',
		'pixel4': '10/23/2019',
		'pixel5': '10/15/2020',
		'pixel6': '10/28/2021',
		'pixel7': '10/13/2022',
		'pixel8': '10/12/2023'
	}

	device_list = ['pixel', 'pixel2', 'pixel3', 'pixel4', 'pixel5', 'pixel6', 'pixel7', 'pixel8']
	test_tags = ['EncSoftwareAsymKey', 'EncKeystoreAsymKey', 'EncStrongBoxAsymKey']
	test_lengths = ['0','1']

	#extract_info_tags(device_list)

	test_data_all = extract_test_data(test_name, device_list, test_tags)

	for device in device_list:
		print('----------------------------------------------------------------------------------------')
		print('\nRunning tests for device: ' + device)
		for tag in test_tags:
			calculate_test_performance(test_name, test_data_all, device, tag, test_lengths)

# Run performance measurements for software, TEE, and SE on increasing payload length.
def test_length_enc(test_name):
	print('Running message length encryption test.')
	delete_results_file(test_name)

	device_list = ['pixel8']
	test_tags = ['EncSoftwareSymKey', 'EncKeystoreSymKey', 'EncStrongBoxSymKey']
	test_lengths = ['0.01', '0.1', '0.2', '1', '2', '4', '6', '8', '10', '12', '14', '16']

	extract_info_tags(device_list)

	# Generate new logs file list for each length.
	device_list_mod = ['pixel8_small', 'pixel8']
	for length in test_lengths[5:]:
		device_list_mod.append(device_list[0] + '_' + length)
	print(device_list_mod)

	test_data_all = extract_test_data(test_name, device_list_mod, test_tags)

	for device in device_list_mod:
		print('----------------------------------------------------------------------------------------')
		print('\nRunning tests for device: ' + device)
		
		for tag in test_tags:
			calculate_test_performance(test_name, test_data_all, device, tag, test_lengths)

# Run performance measurements for software, TEE, and SE on increasing payload length.
def test_all_devices(test_name):
	print('Testing symmetric encryption on all major devices.')
	delete_results_file(test_name)

	device_list = ['pixel8', 'galaxyA15', 'galaxyA35', 'galaxyS24', 'xiaomi13']
	test_tags = ['EncSoftwareSymKey', 'EncKeystoreSymKey', 'EncStrongBoxSymKey']
	test_lengths = ['1']

	extract_info_tags(device_list)

	test_data_all = extract_test_data(test_name, device_list, test_tags)

	for device in device_list:
		print('----------------------------------------------------------------------------------------')
		print('\nRunning tests for device: ' + device)
		
		for tag in test_tags:
			calculate_test_performance(test_name, test_data_all, device, tag, test_lengths)

def test_asym_enc(test_name):
	print('Running aymmetric encryption test.')
	delete_results_file(test_name)

	device_list = ['pixel8_asym']
	test_tags = ['EncSoftwareAsymKey', 'EncKeystoreAsymKey', 'EncStrongBoxAsymKey']
	test_lengths = ['256']

	extract_info_tags(device_list)

	test_data_all = extract_test_data(test_name, device_list, test_tags)

	for device in device_list:
		print('----------------------------------------------------------------------------------------')
		print('\nRunning tests for device: ' + device)
		
		for tag in test_tags:
			calculate_test_performance(test_name, test_data_all, device, tag, test_lengths)

def test_signing(test_name):
	print('Running signing test.')
	delete_results_file(test_name)

	device_list = ['pixel8_signing']
	test_tags = ['SignSoftwareAsymKey', 'SignKeystoreAsymKey', 'SignStrongBoxAsymKey']
	test_lengths = ['0.01', '0.1', '0.2', '1.0', '2.0', '4.0',]

	extract_info_tags(device_list)

	test_data_all = extract_test_data(test_name, device_list, test_tags)

	for device in device_list:
		print('----------------------------------------------------------------------------------------')
		print('\nRunning tests for device: ' + device)
		
		for tag in test_tags:
			calculate_test_performance(test_name, test_data_all, device, tag, test_lengths)

# Compare symmetric key encryption performance for messages of different lengths.
#test_length_enc('message_length_encrypt')

# Compare performance of three keystores in Pixel devices from 2016 - 2023 on 1 MB.
#test_performance_over_time('time_pixels')

# Compare performance of symmetric encryption across non-Pixel devices.
#test_all_devices('devices_all')

#test_asym_enc('asym_encrypt')

test_signing('signing')

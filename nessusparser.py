#!/usr/bin/python3

import os
import sys
import io
import re
import lxml.etree as ET
import argparse
import xlsxwriter


PARSER = argparse.ArgumentParser(description='Parse Nessus Files')
PARSER.add_argument('-l', '--launch_directory',
                    help="Path to Nessus File Directory", required=True)
PARSER.add_argument('-o', '--output_file',
                    help="Filename to save results as", required=True)
ARGS = PARSER.parse_args()


VULN_DATA = []
HOST_DATA = []
DEVICE_DATA = []
CPE_DATA = []
MS_PROCESS_INFO = []
PLUGIN_IDS = []
CRIT_DATA = []
HIGH_DATA = []
MED_DATA = []
LOW_DATA = []
INFO_DATA = []


def get_child_value(currelem, getchild):
    if currelem.find(getchild) is not None:
        return currelem.find(getchild).text
    return ''


def get_attrib_value(currelem, attrib):
    if currelem.get(attrib) is not None:
        return currelem.get(attrib)
    return ''


def is_match(regex, text):
    pattern = re.compile(regex, text)
    return pattern.search(text) is not None


def return_match(regex, text):
    pattern = re.compile(regex)
    return pattern.search(text).group(1)


def parse_nessus_file(context, func, *args, **kwargs):
    start_tag = None
    for event, elem in context:
        host_properties = {}
        if event == 'start' and elem.tag == 'ReportHost' and start_tag == None:
            start_tag = elem.tag
            continue
        if event == 'end' and elem.tag == start_tag:
            host_properties['name'] = get_attrib_value(elem, 'name')
            host_properties['host-ip'] = ''
            host_properties['host-fqdn'] = ''
            host_properties['netbios-name'] = ''

            # Building Host Data
            if elem.find('HostProperties') is not None:
                for child in elem.find('HostProperties'):
                    if child.get('name') in ['host-ip'] and child.text is not None:
                        host_properties['host-ip'] = child.text
                    if child.get('name') in ['host-fqdn'] and child.text is not None:
                        host_properties['host-fqdn'] = child.text
                    if child.get('name') in ['netbios-name'] and child.text is not None:
                        host_properties['netbios-name'] = child.text
                HOST_DATA.append(host_properties.copy())

            for child in elem.findall('ReportItem'):
                # Process Info
                if get_attrib_value(child, 'pluginID') in ['70329']:
                    process_properties = host_properties

                    process_info = get_child_value(child, 'plugin_output')
                    process_info = process_info.replace(
                        'Process Overview : \n', '')
                    process_info = process_info.replace(
                        'SID: Process (PID)', '')
                    process_info = re.sub(
                        'Process_Information.*', '', process_info).replace('\n\n\n', '')

                    process_properties['processes'] = process_info
                    MS_PROCESS_INFO.append(process_properties.copy())

                # CPE Info
                if child.find('cpe') is not None:
                    cpe_hash = host_properties
                    cpe_hash['pluginID'] = get_attrib_value(child, 'pluginID')
                    cpe_hash['cpe'] = get_child_value(child, 'cpe')
                    cpe_hash['pluginFamily'] = get_attrib_value(
                        child, 'pluginFamily')
                    cpe_hash['pluginName'] = get_attrib_value(
                        child, 'pluginName')
                    cpe_hash['cpe-source'] = get_attrib_value(child, 'vuln')

                    CPE_DATA.append(cpe_hash.copy())

                # CPE Info
                if get_attrib_value(child, 'pluginID') in ['45590']:
                    if get_child_value(child, 'plugin_output') is not None:
                        cpe_properties = get_child_value(
                            child, 'plugin_output').split('\n')
                    else:
                        cpe_properties = 'None'

                    for cpe_item in cpe_properties:
                        if re.search('cpe\:\/(o|a|h)', cpe_item):
                            cpe_item = cpe_item.replace('\s', '')

                            cpe_hash = host_properties
                            cpe_hash['pluginID'] = get_attrib_value(
                                child, 'pluginID')
                            cpe_hash['cpe'] = cpe_item
                            cpe_hash['pluginFamily'] = get_attrib_value(
                                child, 'pluginFamily')
                            cpe_hash['pluginName'] = get_attrib_value(
                                child, 'pluginName')
                            cpe_hash[
                                'cpe-source'] = get_attrib_value(child, 'cpe')

                            CPE_DATA.append(cpe_hash.copy())

                # Device Info
                if get_attrib_value(child, 'pluginID') in ['54615']:
                    device_properties = host_properties

                    if get_child_value(child, 'plugin_output') is not None:
                        device_info = get_child_value(
                            child, 'plugin_output').replace('\n', ' ')
                    else:
                        device_info = 'None'

                    if re.search('(?<=type : )(.*)(?=Confidence )', device_info):
                        device_properties['type'] = re.search(
                            '(?<=type : )(.*)(?=Confidence )', device_info).group(1)
                    else:
                        device_properties['type'] = ''
                    if re.search('Confidence level : (\d+)', device_info):
                        device_properties['confidenceLevel'] = re.search(
                            'Confidence level : (\d+)', device_info).group(1)
                    else:
                        device_properties['confidenceLevel'] = 0
                    DEVICE_DATA.append(device_properties.copy())
                # End

                # WiFi Info
                if get_attrib_value(child, 'pluginID') in ['11026']:
                    wifi_properties = host_properties

                    wifi_properties['mac_address'] = get_attrib_value(
                        child, 'mac_address')
                    wifi_properties[
                        'operating-system'] = get_attrib_value(child, 'operating-system')
                    wifi_properties[
                        'system-type'] = get_attrib_value(child, 'system-type')
                    wifi_properties[
                        'plugin-output'] = get_child_value(child, 'plugin-output')
                # End

                vuln_properties = host_properties
                vuln_properties['severity'] = get_attrib_value(
                    child, 'severity')
                vuln_properties['risk_factor'] = get_child_value(
                    child, 'risk_factor')
                vuln_properties['pluginFamily'] = get_attrib_value(
                    child, 'pluginFamily')
                vuln_properties['pluginID'] = get_attrib_value(
                    child, 'pluginID')
                vuln_properties['pluginName'] = get_attrib_value(
                    child, 'pluginName')
                vuln_properties['vuln_publication_date'] = get_child_value(
                    child, 'vuln_publication_date')
                vuln_properties['description'] = get_child_value(
                    child, 'description')
                vuln_properties['plugin_output'] = get_child_value(
                    child, 'plugin_output')
                vuln_properties['solution'] = get_child_value(
                    child, 'solution')
                vuln_properties['synopsis'] = get_child_value(
                    child, 'synopsis')
                vuln_properties['exploit_available'] = get_child_value(
                    child, 'exploit_available')
                vuln_properties['exploitability_ease'] = get_child_value(
                    child, 'exploitability_ease')
                vuln_properties['plugin_publication_date'] = get_child_value(
                    child, 'plugin_publication_date')
                vuln_properties['plugin_modification_date'] = get_child_value(
                    child, 'plugin_modification_date')

                VULN_DATA.append(vuln_properties.copy())
            HOST_DATA.append(host_properties.copy())
            func(elem, *args, **kwargs)
            elem.clear()
            for ancestor in elem.xpath('ancestor-or-self::*'):
                while ancestor.getprevious() is not None:
                    del ancestor.getparent()[0]
    del context


def gen_severity_data(VULN):
    for vuln in VULN:
        if not vuln['severity']:
            continue
        if int(vuln['severity']) == 0:
            CRIT_DATA.append(vuln.copy())
        elif int(vuln['severity']) == 1:
            HIGH_DATA.append(vuln.copy())
        elif int(vuln['severity']) == 2:
            MED_DATA.append(vuln.copy())
        elif int(vuln['severity']) == 3:
            LOW_DATA.append(vuln.copy())
        elif int(vuln['severity']) == 4:
            INFO_DATA.append(vuln.copy())

#############################################
#############################################
###################EXCEL#####################
#############################################
#############################################


def add_ms_process_info(PROC_INFO, THE_FILE):
    temp_cnt = 2
    ms_proc_ws = WB.add_worksheet('MS Running Process Info')
    ms_proc_ws.set_tab_color("#9ec3ff")

    ms_proc_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    ms_proc_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    ms_proc_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    ms_proc_ws.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
    ms_proc_ws.write(1, 4, 'NetBios Name', CENTER_BORDER_FORMAT)
    ms_proc_ws.write(1, 5, 'Process Name & Level', CENTER_BORDER_FORMAT)

    ms_proc_ws.freeze_panes('C3')
    ms_proc_ws.autofilter('A2:E2')
    ms_proc_ws.set_column('A:A', 10)
    ms_proc_ws.set_column('B:B', 35)
    ms_proc_ws.set_column('C:C', 15)
    ms_proc_ws.set_column('D:D', 35)
    ms_proc_ws.set_column('E:E', 25)
    ms_proc_ws.set_column('F:F', 80)

    for host in PROC_INFO:
        for proc in host['processes'].split('\n'):
            ms_proc_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 2, host['host-ip'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 3, host['host-fqdn'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 4, host['netbios-name'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 5, proc, WRAP_TEXT_FORMAT)
            temp_cnt += 1


def add_device_type(DEVICE_INFO, THE_FILE):
    temp_cnt = 2
    device_ws = WB.add_worksheet('Device Type')

    device_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    device_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    device_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    device_ws.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
    device_ws.write(1, 4, 'NetBios Name', CENTER_BORDER_FORMAT)
    device_ws.write(1, 5, 'Device Type', CENTER_BORDER_FORMAT)
    device_ws.write(1, 6, 'Confidence', CENTER_BORDER_FORMAT)

    device_ws.freeze_panes('C3')
    device_ws.autofilter('A2:E2')
    device_ws.set_column('A:A', 10)
    device_ws.set_column('B:B', 35)
    device_ws.set_column('C:C', 15)
    device_ws.set_column('D:D', 35)
    device_ws.set_column('E:E', 25)
    device_ws.set_column('F:F', 15)
    device_ws.set_column('G:G', 15)

    for host in DEVICE_INFO:
        device_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 2, host['host-ip'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 3, host['host-fqdn'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 4, host['netbios-name'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 5, host['type'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 6, int(
            host['confidenceLevel']), WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_crit_info(CRIT, THE_FILE):
    temp_cnt = 2
    crit_ws = WB.add_worksheet('Critical')
    crit_ws.set_tab_color('red')

    crit_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
    crit_ws.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)

    crit_ws.freeze_panes('C3')
    crit_ws.autofilter('A2:E2')
    crit_ws.set_column('A:A', 10)
    crit_ws.set_column('B:B', 35)
    crit_ws.set_column('C:C', 15)
    crit_ws.set_column('D:D', 25)
    crit_ws.set_column('E:E', 10)
    crit_ws.set_column('F:F', 100)
    crit_ws.set_column('G:G', 15)

    for crit in CRIT:
        crit_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 2, crit['host-ip'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 3, crit[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 4, int(crit['pluginID']), WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 5, crit['pluginName'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 6, crit['exploit_available'], WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_high_info(HIGH, THE_FILE):
    temp_cnt = 2
    high_ws = WB.add_worksheet('High')
    high_ws.set_tab_color('orange')

    high_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    high_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    high_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    high_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    high_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
    high_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
    high_ws.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)

    high_ws.freeze_panes('C3')
    high_ws.autofilter('A2:E2')
    high_ws.set_column('A:A', 10)
    high_ws.set_column('B:B', 35)
    high_ws.set_column('C:C', 15)
    high_ws.set_column('D:D', 25)
    high_ws.set_column('E:E', 10)
    high_ws.set_column('F:F', 100)
    high_ws.set_column('G:G', 15)

    for high in HIGH:
        high_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 2, high['host-ip'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 3, high[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 4, int(high['pluginID']), WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 5, high['pluginName'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 6, high['exploit_available'], WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_med_info(MED, THE_FILE):
    temp_cnt = 2
    med_ws = WB.add_worksheet('Medium')
    med_ws.set_tab_color('yellow')

    med_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    med_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    med_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    med_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    med_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
    med_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
    med_ws.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)

    med_ws.freeze_panes('C3')
    med_ws.autofilter('A2:E2')
    med_ws.set_column('A:A', 10)
    med_ws.set_column('B:B', 35)
    med_ws.set_column('C:C', 15)
    med_ws.set_column('D:D', 25)
    med_ws.set_column('E:E', 10)
    med_ws.set_column('F:F', 100)
    med_ws.set_column('G:G', 15)

    for med in MED:
        med_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 2, med['host-ip'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 3, med[
                     'vuln_publication_date'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 4, int(med['pluginID']), WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 5, med['pluginName'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 6, med['exploit_available'], WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_low_info(LOW, THE_FILE):
    temp_cnt = 2
    low_ws = WB.add_worksheet('Low')
    low_ws.set_tab_color('green')

    low_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    low_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    low_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    low_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    low_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
    low_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
    low_ws.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)

    low_ws.freeze_panes('C3')
    low_ws.autofilter('A2:E2')
    low_ws.set_column('A:A', 10)
    low_ws.set_column('B:B', 35)
    low_ws.set_column('C:C', 15)
    low_ws.set_column('D:D', 25)
    low_ws.set_column('E:E', 10)
    low_ws.set_column('F:F', 100)
    low_ws.set_column('G:G', 15)

    for low in LOW:
        low_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 2, low['host-ip'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 3, low[
        	   'vuln_publication_date'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 4, int(low['pluginID']), WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 5, low['pluginName'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 6, low['exploit_available'], WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_info_info(INFO, THE_FILE):
    temp_cnt = 2
    info_ws = WB.add_worksheet('Informational')
    info_ws.set_tab_color('blue')

    info_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    info_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    info_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    info_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    info_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
    info_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
    info_ws.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)

    info_ws.freeze_panes('C3')
    info_ws.autofilter('A2:E2')
    info_ws.set_column('A:A', 10)
    info_ws.set_column('B:B', 35)
    info_ws.set_column('C:C', 15)
    info_ws.set_column('D:D', 25)
    info_ws.set_column('E:E', 10)
    info_ws.set_column('F:F', 100)
    info_ws.set_column('G:G', 15)

    for info in INFO:
        info_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 2, info['host-ip'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 3, info[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 4, int(info['pluginID']), WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 5, info['pluginName'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 6, info['exploit_available'], WRAP_TEXT_FORMAT)
        temp_cnt += 1


def add_report_data(REPORT_DATA_LIST, THE_FILE):
    temp_cnt = 2
    report_ws = WB.add_worksheet('Full Report')

    report_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
    report_ws.write(1, 1, 'File', CENTER_BORDER_FORMAT)
    report_ws.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
    report_ws.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
    report_ws.write(1, 4, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
    report_ws.write(1, 5, 'Severity', CENTER_BORDER_FORMAT)
    report_ws.write(1, 6, 'Risk Factor', CENTER_BORDER_FORMAT)
    report_ws.write(1, 7, 'Plugin ID', CENTER_BORDER_FORMAT)
    report_ws.write(1, 8, 'Plugin Family', CENTER_BORDER_FORMAT)
    report_ws.write(1, 9, 'Plugin Name', CENTER_BORDER_FORMAT)
    report_ws.write(1, 10, 'Description', CENTER_BORDER_FORMAT)
    report_ws.write(1, 11, 'Synopsis', CENTER_BORDER_FORMAT)
    report_ws.write(1, 12, 'Plugin Output', CENTER_BORDER_FORMAT)
    report_ws.write(1, 13, 'Solution', CENTER_BORDER_FORMAT)
    report_ws.write(1, 14, 'Exploit Available', CENTER_BORDER_FORMAT)
    report_ws.write(1, 15, 'Exploitability Ease', CENTER_BORDER_FORMAT)
    report_ws.write(1, 16, 'Plugin Publication Date', CENTER_BORDER_FORMAT)
    report_ws.write(1, 17, 'Plugin Modification Date', CENTER_BORDER_FORMAT)

    report_ws.freeze_panes('C3')
    report_ws.autofilter('A2:M2')
    report_ws.set_column('A:A', 10)
    report_ws.set_column('B:B', 35)
    report_ws.set_column('C:C', 15)
    report_ws.set_column('D:D', 35)
    report_ws.set_column('E:E', 25)
    report_ws.set_column('F:F', 20)
    report_ws.set_column('G:G', 15)
    report_ws.set_column('H:H', 15)
    report_ws.set_column('I:I', 25)
    report_ws.set_column('J:J', 100)
    report_ws.set_column('K:K', 25)
    report_ws.set_column('L:L', 25)
    report_ws.set_column('M:M', 25)
    report_ws.set_column('N:N', 25)
    report_ws.set_column('O:O', 25)
    report_ws.set_column('P:P', 25)
    report_ws.set_column('Q:Q', 25)
    report_ws.set_column('R:R', 25)

    for reportitem in REPORT_DATA_LIST:
        report_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 2, reportitem[
        	   'host-ip'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 3, reportitem[
        	   'host-fqdn'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 4, reportitem[
        	   "vuln_publication_date"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 5, 
        	   int(reportitem["severity"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 6, reportitem[
        	   "risk_factor"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 7,
        	   int(reportitem["pluginID"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 8, reportitem[
        	   "pluginFamily"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 9, reportitem[
        	   "pluginName"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 10, reportitem[
        	   "description"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 11, reportitem[
        	   'synopsis'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 12, reportitem[
        	   'plugin_output'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 13, reportitem[
        	   'solution'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 14, reportitem[
        	   'exploit_available'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 15, reportitem[
        	   'exploitability_ease'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 16, reportitem[
        	   'plugin_publication_date'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 17, reportitem[
        	   'plugin_modification_date'], WRAP_TEXT_FORMAT)

        temp_cnt += 1

#############################################
#############################################
#############################################
#############################################
#############################################


def begin_parsing():
    for nessus_report in os.listdir(ARGS.launch_directory):
        if nessus_report.endswith(".nessus") or nessus_report.endswith(".xml"):
            curr_file = os.path.join(ARGS.launch_directory, nessus_report)
            print("Found %s" % nessus_report)

            context = ET.iterparse(curr_file, events=('start', 'end', ))
            context = iter(context)
            event, root = next(context)

            if root.tag in "NessusClientData_v2":
                parse_nessus_file(context, lambda elem: None)

            del context

if __name__ == "__main__":

    FILE_COUNT = len([name for name in os.listdir(
        ARGS.launch_directory) if name.endswith('.nessus')])

    if FILE_COUNT == 0:
        print("No files found")
        sys.exit()

    if FILE_COUNT > 25:
        USER_RESPONSE = input(
            'Folder contains 25+ Nessus files. Continue? [y/n]: ')[0].lower()
        if USER_RESPONSE != 'y':
            sys.exit()

    begin_parsing()
    WB = xlsxwriter.Workbook(
        '{0}.xlsx'.format(ARGS.output_file), {'strings_to_urls': False})
    CENTER_BORDER_FORMAT = WB.add_format(
        {'bold': True, 'italic': True, 'border': True})
    WRAP_TEXT_FORMAT = WB.add_format(
        {'bold': False, 'italic': False, 'border': True})
    NUMBER_FORMAT = WB.add_format(
        {'bold': False, 'italic': False, 'border': True, 'num_format': '0'})
    gen_severity_data(VULN_DATA)
    add_device_type(DEVICE_DATA, 'None')
    add_report_data(VULN_DATA, 'None')
    add_crit_info(CRIT_DATA, 'None')
    add_high_info(HIGH_DATA, 'None')
    add_med_info(MED_DATA, 'None')
    add_low_info(LOW_DATA, 'None')
    add_info_info(INFO_DATA, 'None')
    add_ms_process_info(MS_PROCESS_INFO, 'None')
    WB.close()

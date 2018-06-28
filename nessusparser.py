#!/usr/bin/python3

import os
import sys
import re
from datetime import datetime, date
import argparse
import lxml.etree as ET
import xlsxwriter


PARSER = argparse.ArgumentParser(description='Parse Nessus Files')
PARSER.add_argument('-l', '--launch_directory',
                    help="Path to Nessus File Directory", required=True)
PARSER.add_argument('-o', '--output_file',
                    help="Filename to save results as", required=True)
ARGS = PARSER.parse_args()


# Track created worksheets
WS_MAPPER = dict()
# Track current used row for worksheets
ROW_TRACKER = dict()

SINGLE_FIELDS = ['risk_factor', 'vuln_publication_date', 'description',
                 'plugin_output', 'solution', 'synopsis',
                 'exploit_available', 'exploitability_ease', 'exploited_by_malware',
                 'plugin_publication_date', 'plugin_modification_date']

ATTRIB_FIELDS = ['severity', 'pluginFamily', 'pluginID',
                 'pluginName']


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
    VULN_DATA = []
    HOST_DATA = []
    DEVICE_DATA = []
    CPE_DATA = []
    MS_PROCESS_INFO = []
    PLUGIN_IDS = []
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

            for child in elem.iter('ReportItem'):
                # CVE Per Item
                CVE_ITEM_LIST = list()
                if child.find("cve") is not None:
                    for cve in child.iter("cve"):
                        CVE_ITEM_LIST.append(cve.text)

                # MS Builiten Per Item
                BID_ITEM_LIST = list()
                if child.find("bid") is not None:
                    for bid in child.iter("bid"):
                        BID_ITEM_LIST.append(bid.text)

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

                # # CPE Info
                # if child.find('cpe') is not None:
                #     cpe_hash = host_properties
                #     cpe_hash['pluginID'] = get_attrib_value(child, 'pluginID')
                #     cpe_hash['cpe'] = get_child_value(child, 'cpe')
                #     cpe_hash['pluginFamily'] = get_attrib_value(
                #         child, 'pluginFamily')
                #     cpe_hash['pluginName'] = get_attrib_value(
                #         child, 'pluginName')
                #     cpe_hash['cpe-source'] = get_attrib_value(child, 'vuln')

                #     CPE_DATA.append(cpe_hash.copy())

                # # CPE Info
                # if get_attrib_value(child, 'pluginID') in ['45590']:
                #     if get_child_value(child, 'plugin_output') is not None:
                #         cpe_properties = get_child_value(
                #             child, 'plugin_output').split('\n')
                #     else:
                #         cpe_properties = 'None'

                #     for cpe_item in cpe_properties:
                #         if re.search('cpe\:\/(o|a|h)', cpe_item):
                #             cpe_item = cpe_item.replace('\s', '')

                #             cpe_hash = host_properties
                #             cpe_hash['pluginID'] = get_attrib_value(
                #                 child, 'pluginID')
                #             cpe_hash['cpe'] = cpe_item
                #             cpe_hash['pluginFamily'] = get_attrib_value(
                #                 child, 'pluginFamily')
                #             cpe_hash['pluginName'] = get_attrib_value(
                #                 child, 'pluginName')
                #             cpe_hash[
                #                 'cpe-source'] = get_attrib_value(child, 'cpe')

                #             CPE_DATA.append(cpe_hash.copy())

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

                # Begin aggregation of data into vuln_properties
                # prior to adding to VULN_DATA
                vuln_properties = host_properties

                for field in SINGLE_FIELDS:
                    vuln_properties[field] = get_child_value(
                        child, field)

                for field in ATTRIB_FIELDS:
                    vuln_properties[field] = get_attrib_value(
                        child, field)
                vuln_properties['bid'] = ";\n".join(CVE_ITEM_LIST)
                vuln_properties['cve'] = ";\n".join(CVE_ITEM_LIST)

                VULN_DATA.append(vuln_properties.copy())
            HOST_DATA.append(host_properties.copy())
            func(elem, *args, **kwargs)
            elem.clear()
            for ancestor in elem.xpath('ancestor-or-self::*'):
                while ancestor.getprevious() is not None:
                    del ancestor.getparent()[0]
    del context
    return VULN_DATA, DEVICE_DATA, CPE_DATA, MS_PROCESS_INFO, PLUGIN_IDS

#############################################
#############################################
###################EXCEL#####################
#############################################
#############################################


def generate_worksheets():
    """
        Generate worksheets and store them for later use
    """
    WS_NAMES = ["Full Report", "Device Type",
                "Critical", "High",
                "Medium", "Low",
                "Informational", "MS Running Process Info"]
    for sheet in WS_NAMES:
        WS_MAPPER[sheet] = WB.add_worksheet(sheet)
        ROW_TRACKER[sheet] = 2
        WS = WS_MAPPER[sheet]
        if sheet == "Full Report":
            WS.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            WS.write(1, 1, 'File', CENTER_BORDER_FORMAT)
            WS.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
            WS.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
            WS.write(1, 4, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
            WS.write(1, 5, 'Vuln Age by Days', CENTER_BORDER_FORMAT)
            WS.write(1, 6, 'Severity', CENTER_BORDER_FORMAT)
            WS.write(1, 7, 'Risk Factor', CENTER_BORDER_FORMAT)
            WS.write(1, 8, 'Plugin ID', CENTER_BORDER_FORMAT)
            WS.write(1, 9, 'Plugin Family', CENTER_BORDER_FORMAT)
            WS.write(1, 10, 'Plugin Name', CENTER_BORDER_FORMAT)
            WS.write(1, 11, 'Description', CENTER_BORDER_FORMAT)
            WS.write(1, 12, 'Synopsis', CENTER_BORDER_FORMAT)
            WS.write(1, 13, 'Plugin Output', CENTER_BORDER_FORMAT)
            WS.write(1, 14, 'Solution', CENTER_BORDER_FORMAT)
            WS.write(1, 15, 'Exploit Available', CENTER_BORDER_FORMAT)
            WS.write(1, 16, 'Exploitability Ease', CENTER_BORDER_FORMAT)
            WS.write(1, 17, 'Plugin Publication Date', CENTER_BORDER_FORMAT)
            WS.write(1, 18, 'Plugin Modification Date', CENTER_BORDER_FORMAT)
            WS.write(1, 19, 'CVE Information', CENTER_BORDER_FORMAT)

            WS.freeze_panes('C3')
            WS.autofilter('A2:T2')
            WS.set_column('A:A', 10)
            WS.set_column('B:B', 35)
            WS.set_column('C:C', 15)
            WS.set_column('D:D', 35)
            WS.set_column('E:E', 25)
            WS.set_column('F:F', 20)
            WS.set_column('G:G', 15)
            WS.set_column('H:H', 15)
            WS.set_column('I:I', 25)
            WS.set_column('J:J', 25)
            WS.set_column('K:K', 100)
            WS.set_column('L:L', 25)
            WS.set_column('M:M', 25)
            WS.set_column('N:N', 25)
            WS.set_column('O:O', 25)
            WS.set_column('P:P', 25)
            WS.set_column('Q:Q', 25)
            WS.set_column('R:R', 25)
            WS.set_column('S:S', 25)
            WS.set_column('T:T', 25)
            continue
        if sheet == 'MS Running Process Info':
            WS.set_tab_color("#9EC3FF")

            WS.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            WS.write(1, 1, 'File', CENTER_BORDER_FORMAT)
            WS.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
            WS.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
            WS.write(1, 4, 'NetBios Name', CENTER_BORDER_FORMAT)
            WS.write(1, 5, 'Process Name & Level', CENTER_BORDER_FORMAT)

            WS.freeze_panes('C3')
            WS.autofilter('A2:E2')
            WS.set_column('A:A', 10)
            WS.set_column('B:B', 35)
            WS.set_column('C:C', 15)
            WS.set_column('D:D', 35)
            WS.set_column('E:E', 25)
            WS.set_column('F:F', 80)
            continue
        if sheet == "Device Type":
            WS.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            WS.write(1, 1, 'File', CENTER_BORDER_FORMAT)
            WS.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
            WS.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
            WS.write(1, 4, 'NetBios Name', CENTER_BORDER_FORMAT)
            WS.write(1, 5, 'Device Type', CENTER_BORDER_FORMAT)
            WS.write(1, 6, 'Confidence', CENTER_BORDER_FORMAT)

            WS.freeze_panes('C3')
            WS.autofilter('A2:E2')
            WS.set_column('A:A', 10)
            WS.set_column('B:B', 35)
            WS.set_column('C:C', 15)
            WS.set_column('D:D', 35)
            WS.set_column('E:E', 25)
            WS.set_column('F:F', 15)
            WS.set_column('G:G', 15)
            continue
        if sheet == "Informational":
            WS.set_tab_color('blue')
        if sheet == "Low":
            WS.set_tab_color('green')
        if sheet == "Medium":
            WS.set_tab_color('yellow')
        if sheet == "High":
            WS.set_tab_color('orange')
        if sheet == "Critical":
            WS.set_tab_color('red')

        WS.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
        WS.write(1, 1, 'File', CENTER_BORDER_FORMAT)
        WS.write(1, 2, 'IP Address', CENTER_BORDER_FORMAT)
        WS.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
        WS.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
        WS.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
        WS.write(1, 6, 'Exploit Avaiable', CENTER_BORDER_FORMAT)
        WS.write(1, 7, 'CVE Information', CENTER_BORDER_FORMAT)

        WS.freeze_panes('C3')
        WS.autofilter('A2:E2')
        WS.set_column('A:A', 10)
        WS.set_column('B:B', 35)
        WS.set_column('C:C', 15)
        WS.set_column('D:D', 25)
        WS.set_column('E:E', 10)
        WS.set_column('F:F', 100)
        WS.set_column('G:G', 15)
        WS.set_column('H:H', 25)

    WS = None


def add_ms_process_info(PROC_INFO, THE_FILE):
    ms_proc_ws = WS_MAPPER['MS Running Process Info']
    temp_cnt = ROW_TRACKER['MS Running Process Info']
    for host in PROC_INFO:
        for proc in host['processes'].split('\n'):
            ms_proc_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 2, host['host-ip'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 3, host['host-fqdn'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 4, host[
                             'netbios-name'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 5, proc, WRAP_TEXT_FORMAT)
            temp_cnt += 1
    ROW_TRACKER['MS Running Process Info'] = temp_cnt


def add_device_type(DEVICE_INFO, THE_FILE):
    device_ws = WS_MAPPER['Device Type']
    temp_cnt = ROW_TRACKER['Device Type']
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
    ROW_TRACKER['Device Type'] = temp_cnt


def add_crit_info(CRIT, THE_FILE):
    crit_ws = WS_MAPPER['Critical']
    temp_cnt = ROW_TRACKER['Critical']
    for crit in CRIT:
        if not int(crit['severity']) == 4:
            continue
        crit_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 2, crit['host-ip'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 3, crit[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 4, int(crit['pluginID']), WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 5, crit['pluginName'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 6, crit['exploit_available'], WRAP_TEXT_FORMAT)
        crit_ws.write(temp_cnt, 6, crit['cve'], WRAP_TEXT_FORMAT)
        temp_cnt += 1
    ROW_TRACKER['Critical'] = temp_cnt


def add_high_info(HIGH, THE_FILE):
    high_ws = WS_MAPPER['High']
    temp_cnt = ROW_TRACKER['High']
    for high in HIGH:
        if not int(high['severity']) == 3:
            continue
        high_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 2, high['host-ip'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 3, high[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 4, int(high['pluginID']), WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 5, high['pluginName'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 6, high['exploit_available'], WRAP_TEXT_FORMAT)
        high_ws.write(temp_cnt, 7, high['cve'], WRAP_TEXT_FORMAT)
        temp_cnt += 1
    ROW_TRACKER['High'] = temp_cnt


def add_med_info(MED, THE_FILE):
    med_ws = WS_MAPPER['Medium']
    temp_cnt = ROW_TRACKER['Medium']
    for med in MED:
        if not int(med['severity']) == 2:
            continue
        med_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 2, med['host-ip'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 3, med[
                     'vuln_publication_date'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 4, int(med['pluginID']), WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 5, med['pluginName'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 6, med['exploit_available'], WRAP_TEXT_FORMAT)
        med_ws.write(temp_cnt, 7, med['cve'], WRAP_TEXT_FORMAT)
        temp_cnt += 1
    ROW_TRACKER['Medium'] = temp_cnt


def add_low_info(LOW, THE_FILE):
    low_ws = WS_MAPPER['Low']
    temp_cnt = ROW_TRACKER['Low']
    for low in LOW:
        if not int(low['severity']) == 1:
            continue
        low_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 2, low['host-ip'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 3, low[
            'vuln_publication_date'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 4, int(low['pluginID']), WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 5, low['pluginName'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 6, low['exploit_available'], WRAP_TEXT_FORMAT)
        low_ws.write(temp_cnt, 7, low['cve'], WRAP_TEXT_FORMAT)
        temp_cnt += 1
    ROW_TRACKER['Low'] = temp_cnt


def add_info_info(INFO, THE_FILE):
    info_ws = WS_MAPPER['Informational']
    temp_cnt = ROW_TRACKER['Informational']
    for info in INFO:
        if not int(info['severity']) == 0:
            continue
        info_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 2, info['host-ip'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 3, info[
                      'vuln_publication_date'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 4, int(info['pluginID']), WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 5, info['pluginName'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 6, info['exploit_available'], WRAP_TEXT_FORMAT)
        info_ws.write(temp_cnt, 7, info['cve'], WRAP_TEXT_FORMAT)
        temp_cnt += 1
    ROW_TRACKER['Informational'] = temp_cnt


def add_report_data(REPORT_DATA_LIST, THE_FILE):
    """
        Function responsible for inserting data into the Full Report
        worksheet
    """
    # Retrieve correct worksheet from out Worksheet tracker
    report_ws = WS_MAPPER['Full Report']
    # Resume inserting rows at our last unused row
    temp_cnt = ROW_TRACKER['Full Report']
    # Iterate over out VULN List and insert records to worksheet
    for reportitem in REPORT_DATA_LIST:
        # If we have a valid Vulnerability publication date
        # lets generate the Days old cell value
        if reportitem["vuln_publication_date"] != '':
            date_format = "%Y/%m/%d"
            date_one = datetime.strptime(
                reportitem["vuln_publication_date"], date_format)
            date_two = datetime.strptime(
                str(date.today()).replace("-", "/"), date_format)
            report_ws.write(temp_cnt, 5,
                            (date_two - date_one).days, NUMBER_FORMAT)
        else:
            report_ws.write(temp_cnt, 5,
                            reportitem["vuln_publication_date"], NUMBER_FORMAT)

        report_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 1, THE_FILE, WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 2, reportitem[
            'host-ip'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 3, reportitem[
            'host-fqdn'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 4, reportitem[
            "vuln_publication_date"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 6,
                        int(reportitem["severity"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 7, reportitem[
            "risk_factor"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 8,
                        int(reportitem["pluginID"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 9, reportitem[
            "pluginFamily"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 10, reportitem[
            "pluginName"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 11, reportitem[
            "description"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 12, reportitem[
            'synopsis'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 13, reportitem[
            'plugin_output'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 14, reportitem[
            'solution'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 15, reportitem[
            'exploit_available'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 16, reportitem[
            'exploitability_ease'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 17, reportitem[
            'plugin_publication_date'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 18, reportitem[
            'plugin_modification_date'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 19, reportitem[
            'cve'], WRAP_TEXT_FORMAT)

        temp_cnt += 1
    # Save the last unused row for use on the next Nessus file
    ROW_TRACKER['Full Report'] = temp_cnt

#############################################
#############################################
#############################################
#############################################
#############################################


def begin_parsing():
    """
        Provides the initial starting point for validating root tag
        is for a Nessus v2 File. Initiates parsing and then writes to
        the associated workbook sheets.
    """
    for nessus_report in os.listdir(ARGS.launch_directory):
        if nessus_report.endswith(".nessus") or nessus_report.endswith(".xml"):
            curr_file = os.path.join(ARGS.launch_directory, nessus_report)
            context = ET.iterparse(curr_file, events=('start', 'end', ))
            context = iter(context)
            event, root = next(context)

            if root.tag in "NessusClientData_v2":
                print("Beginning parsing of {0}".format(nessus_report))
                VULN_DATA, DEVICE_DATA, CPE_DATA, MS_PROCESS_INFO, PLUGIN_IDS = parse_nessus_file(
                    context, lambda elem: None)
                add_report_data(VULN_DATA, curr_file)
                add_device_type(DEVICE_DATA, curr_file)
                add_crit_info(VULN_DATA, curr_file)
                add_high_info(VULN_DATA, curr_file)
                add_med_info(VULN_DATA, curr_file)
                add_low_info(VULN_DATA, curr_file)
                add_info_info(VULN_DATA, curr_file)
                add_ms_process_info(MS_PROCESS_INFO, curr_file)

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

    WB = xlsxwriter.Workbook(
        '{0}.xlsx'.format(ARGS.output_file), {'strings_to_urls': False, 'constant_memory': True})
    CENTER_BORDER_FORMAT = WB.add_format(
        {'bold': True, 'italic': True, 'border': True})
    WRAP_TEXT_FORMAT = WB.add_format(
        {'border': True})
    NUMBER_FORMAT = WB.add_format(
        {'border': True, 'num_format': '0'})

    generate_worksheets()
    begin_parsing()
    WB.close()

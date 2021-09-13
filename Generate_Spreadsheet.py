import xlsxwriter
from datetime import datetime, date
from colored import fg, bg, attr
import re
from lxml import etree
import ipaddress
import struct
from socket import inet_aton

from xlsxwriter import workbook


# Track created worksheets
WorksheetMap = dict()
# Track current used row for worksheets
RowTrack = dict()
# Child Elements
ChildElements = ['risk_factor', 'vuln_publication_date', 'description',
                 'plugin_output', 'solution', 'synopsis',
                 'exploit_available', 'exploitability_ease', 'exploited_by_malware',
                 'plugin_publication_date', 'plugin_modification_date']
# Attribute Fields
Attributes = ['severity', 'pluginFamily', 'pluginID', 'pluginName']

Severities = {0: "Informational",
              1: "Low",
              2: "Medium",
              3: "High",
              4: "Critical"}
Totals = {  "Informational": 0,
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0}
UniquieSeverities = {0: 0,
                     1: 0,
                     2: 0,
                     3: 0,
                     4: 0}

IgnoreIDs = list()
UPluginNames = dict()

COMMON_CRIT = dict()
COMMON_HIGH = dict()
COMMON_MED = dict()
COMMON_LOW = dict()
COMMON_INFO = dict()
global sorted_ips2
global host_cvss
def parse_nessus_file(file):
    """
        Paring the nessus file and generating information
    """
    hostnames = []
    sorted_ips2 = []
    vuln_data = list()
    host_data = list()
    device_data = list()
    host_cvss = dict()
    cvss_scores = dict()
    ms_process_info = list()
    filepath = 'Null'
    try:
        file
    except NameError:
        print('%sPlease enter filepath%s' % (fg(1), attr(0)))
            
    else:
        fileopen = open(file, 'r')
        doc = etree.parse(file)
        lst = doc.xpath('//ReportHost')
        ipaddresscount = 0
        for i in lst:
            sorted_ips2.append(i.xpath('@name')[0])
            sorted_ips2.sort(reverse=True)
            ipaddresscount = ipaddresscount + 1
        fileopen.close

        for sort in sorted_ips2:

            try:
                if ipaddress.ip_address(sort).version:
                    value = '0'
                    while value in sorted_ips2:
                        sorted_ips2.remove(value)
                sorted_ips2 = sorted(
                    sorted_ips2, key=lambda ip: struct.unpack("!L", inet_aton(ip))[0])

            except ValueError:

                index = sorted_ips2.index(sort)
                sorted_ips2.remove(sort)
                sorted_ips2.insert(index, '0')
                hostnames.append(sort)

        hostnames.sort()

        for ip in sorted_ips2:
            path_ = '//ReportHost[@name="'+ip+'"]'
            path2 = './/HostProperties'
            path3 = './/ReportItem'

            host = doc.xpath(path_)[0]
            hostpath = host.xpath(path2)
            reportitem = host.xpath(path3)
            # CVSS Map Generation
            for i in range(0, 4):
                cvss_scores[i] = {
                    'cvss_base_score': 0, 'cvss_temporal_score': 0}

            # Building Host Data
            host_properties = {}
            host_properties['name'] = ''
            host_properties['host-ip'] = ''
            host_properties['host-fqdn'] = ''
            host_properties['netbios-name'] = ''
            if hostpath is not None:
                for it in hostpath:
                    if it.xpath('.//tag[@name="host-ip"]/text()') != []:
                            host_properties['host-ip'] = it.xpath(
                                './/tag[@name="host-ip"]/text()')[0]
                    if it.xpath('.//tag[@name="host-fqdn"]/text()') != []:
                                host_properties['host-fqdn'] = it.xpath(
                                    './/tag[@name="host-fqdn"]/text()')[0]
                    if it.xpath('.//tag[@name="netbios-name"]') != []:
                                    host_properties['netbios-name'] = it.xpath(
                                        './/tag[@name="netbios-name"]/text()')[0]
                host_data.append(host_properties.copy())

            # Iter over each item
            for it2 in reportitem:
                plugin_name = it2.xpath('@pluginName')[0]
                plugin_id = it2.xpath('@pluginID')[0]

                # Check if we ignore this Plugin ID
                if plugin_id in IgnoreIDs:
                    continue

                # Store unique plugin names and occurances
                if plugin_name not in UPluginNames:
                    UPluginNames[plugin_name] = [plugin_id, 0]
                    UPluginNames[plugin_name] = [UPluginNames[plugin_name][0],
                                                   UPluginNames[plugin_name][1] + 1]

                if it2.xpath('cvss_base_score/text()') != []:
                    base_score = it2.xpath('cvss_base_score/text()')[0]
                    base_score = round(float(base_score), 2)
                    temp_severity = it2.xpath('.//@severity')[0]
                    temp_severity = int(temp_severity)
                    cvss_scores[temp_severity]['cvss_base_score'] = round(
                        cvss_scores[temp_severity]['cvss_base_score'] + base_score, 2)

                if it2.xpath('cvss_temporal_score/text()') != []:
                    t_base_score = it2.xpath('cvss_temporal_score/text()')
                    t_base_score = round(float(t_base_score), 2)
                    t_temp_severity = it2.xpath('severity')[0]
                    t_temp_severity = int(t_temp_severity)
                    cvss_scores[t_temp_severity]['cvss_temporal_score'] = round(
                        cvss_scores[t_temp_severity]['cvss_temporal_score'] + t_base_score, 2)

                # CVE Per Item
                cve_item_list = list()
                if it2.xpath('cve/text()') != []:
                    cve_item_list = it2.xpath('cve/text()')[0]
                else:
                    cve_item_list = ''

                # Bugtraq ID Per Item
                bid_item_list = list()
                if it2.xpath('bid/text()') != []:
                    bid_item_list = it2.xpath('bid/text()')[0]
                else:
                    bid_item_list = ''

                # Process Info
                if plugin_id in ['70329']:
                    process_properties = host_properties

                    process_info = it2.xpath('plugin_output/text()')
                    process_info = process_info.replace(
                        'Process Overview : \n', '')
                    process_info = process_info.replace(
                        'SID: Process (PID)', '')
                    process_info = re.sub(
                        'Process_Information.*', '', process_info).replace('\n\n\n', '')

                    process_properties['processes'] = process_info
                    ms_process_info.append(process_properties.copy())

                # Device Info
                if plugin_id in ['54615']:
                    device_properties = host_properties

                    if it2.xpath('plugin_output/text()') != []:
                        device_info = it2.xpath(
                            'plugin_output/text()')[0].replace('\n', ' ')
                    else:
                        device_info = 'None'

                    if re.search('(?<=type : )(.*)(?=Confidence )', device_info):
                        device_properties['type'] = re.search(
                            '(?<=type : )(.*)(?=Confidence )', device_info).group(1)
                    else:
                        device_properties['type'] = ''
                    if re.search(r'Confidence level : (\d+)', device_info):
                        device_properties['confidenceLevel'] = re.search(
                            r'Confidence level : (\d+)', device_info).group(1)
                    else:
                        device_properties['confidenceLevel'] = 0
                    device_data.append(device_properties.copy())
                # End

                # # WiFi Info
                # if plugin_id in ['11026']:
                #     wifi_properties = host_properties

                #     wifi_properties['mac_address'] = get_attrib_value(
                #         child, 'mac_address')
                #     wifi_properties[
                #         'operating-system'] = get_attrib_value(child, 'operating-system')
                #     wifi_properties[
                #         'system-type'] = get_attrib_value(child, 'system-type')
                #     wifi_properties[
                #         'plugin-output'] = get_child_value(child, 'plugin-output')
                # # End

                # Begin aggregation of data into vuln_properties
                # prior to adding to vuln_data
                vuln_properties = host_properties

                for field in ChildElements:
                    vuln_properties[field] = it2.xpath(field + '/text()')
                    if vuln_properties[field] != []:
                        vuln_properties[field] = it2.xpath(field + '/text()')[0]
                    else:
                        vuln_properties[field] = ''


                for field in Attributes:
                    vuln_properties[field] = it2.xpath('@' + field)[0]

                vuln_properties['port'] = it2.xpath('@port')[0]
                vuln_properties['bid'] = bid_item_list
                vuln_properties['cve'] = cve_item_list
                if it2.xpath('cvss_base_score/text()') != []:
                    vuln_properties['cvss_base_score'] = it2.xpath(
                        'cvss_base_score/text()')[0]
                    vuln_properties['cvss_base_score'] = round(
                        float(vuln_properties['cvss_base_score']), 2)
                else:
                    vuln_properties['cvss_base_score'] = 0

                if it2.xpath('cvss_temporal_score/text()') != []:
                    vuln_properties['cvss_temporal_score'] = it2.xpath(
                        'cvss_temporal_score/text()')[0]
                    vuln_properties['cvss_temporal_score'] = round(
                        float(vuln_properties['cvss_temporal_score']), 2)
                else:
                    vuln_properties['cvss_temporal_score'] = 0

                vuln_data.append(vuln_properties.copy())
            host_data.append(host_properties.copy())
            host_cvss[host_properties['host-ip']] = cvss_scores.copy()

    return vuln_data, device_data, ms_process_info, host_cvss, ipaddresscount






def generate_worksheets(WB,DARK_FORMAT,CENTER_BORDER_FORMAT,NUMBER_FORMAT): 
    """
        Generate worksheets and store them for later use
    """
    print("\nGenerating the worksheets")
    
    ws_names = ["Overview", "Graphs", "Full Report",
                "CVSS Overview", "Device Type", "Critical",
                "High", "Medium", "Low",
                "Informational", "MS Running Process Info",
                "Plugin Counts", "Graph Data"]
    for sheet in ws_names:
        print("\tCreating {0} worksheet".format(sheet))
        WorksheetMap[sheet] = WB.add_worksheet(sheet)
        RowTrack[sheet] = 2
        active_ws = WorksheetMap[sheet]
        if sheet == "Graphs":
            continue
        if sheet == "Overview":
            active_ws.set_default_row(hide_unused_rows=True)
            active_ws.set_default_row(hide_unused_rows=True)
            active_ws.set_column('A:A', 40)
            active_ws.set_column('B:B', 40)
            active_ws.merge_range('C1:E23','', )
            active_ws.merge_range('A1:B3', '',)
            active_ws.merge_range('A4:B5', 'Overview', DARK_FORMAT)
            continue
        if sheet == "Full Report":
            active_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            active_ws.write(1, 1, 'IP Address', CENTER_BORDER_FORMAT)
            active_ws.write(1, 2, 'Port', CENTER_BORDER_FORMAT)
            active_ws.write(1, 3, 'FQDN', CENTER_BORDER_FORMAT)
            active_ws.write(1, 4, 'Vuln Publication Date',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 5, 'Vuln Age by Days', CENTER_BORDER_FORMAT)
            active_ws.write(1, 6, 'Severity', CENTER_BORDER_FORMAT)
            active_ws.write(1, 7, 'Risk Factor', CENTER_BORDER_FORMAT)
            active_ws.write(1, 8, 'Plugin ID', CENTER_BORDER_FORMAT)
            active_ws.write(1, 9, 'Plugin Family', CENTER_BORDER_FORMAT)
            active_ws.write(1, 10, 'Plugin Name', CENTER_BORDER_FORMAT)
            active_ws.write(1, 11, 'Description', CENTER_BORDER_FORMAT)
            active_ws.write(1, 12, 'Synopsis', CENTER_BORDER_FORMAT)
            active_ws.write(1, 13, 'Plugin Output', CENTER_BORDER_FORMAT)
            active_ws.write(1, 14, 'Solution', CENTER_BORDER_FORMAT)
            active_ws.write(1, 15, 'Exploit Available', CENTER_BORDER_FORMAT)
            active_ws.write(1, 16, 'Exploitability Ease', CENTER_BORDER_FORMAT)
            active_ws.write(1, 17, 'Exploited by Malware',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 18, 'Plugin Publication Date',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 19, 'Plugin Modification Date',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 20, 'CVE Information', CENTER_BORDER_FORMAT)
            active_ws.write(1, 21, 'Bugtraq ID Information',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 22, 'CVSS Base Score',
                            CENTER_BORDER_FORMAT)
            active_ws.write(1, 23, 'CVSS Temporal Score',
                            CENTER_BORDER_FORMAT)

            active_ws.freeze_panes('C3')
            active_ws.autofilter('A2:V2')
            active_ws.set_column('A:A', 10)
            active_ws.set_column('B:B', 35)
            active_ws.set_column('C:C', 15)
            active_ws.set_column('D:D', 15)
            active_ws.set_column('E:E', 25)
            active_ws.set_column('F:F', 20)
            active_ws.set_column('G:G', 15)
            active_ws.set_column('H:H', 15)
            active_ws.set_column('I:I', 25)
            active_ws.set_column('J:J', 25)
            active_ws.set_column('K:K', 25)
            active_ws.set_column('L:L', 100)
            active_ws.set_column('M:M', 25)
            active_ws.set_column('N:N', 25)
            active_ws.set_column('O:O', 25)
            active_ws.set_column('P:P', 25)
            active_ws.set_column('Q:Q', 25)
            active_ws.set_column('R:R', 25)
            active_ws.set_column('S:S', 25)
            active_ws.set_column('T:T', 25)
            active_ws.set_column('U:U', 25)
            active_ws.set_column('V:V', 25)
            active_ws.set_column('W:W', 25)
            active_ws.set_column('X:X', 25)
            active_ws.set_column('Y:Y', 25)
            continue
        if sheet == "CVSS Overview":
            RowTrack[sheet] = RowTrack[sheet] + 3
            active_ws.set_tab_color("#F3E2D3")
            active_ws.write(1, 1, 'Critical', CENTER_BORDER_FORMAT)
            active_ws.write(1, 2, 'High', CENTER_BORDER_FORMAT)
            active_ws.write(1, 3, 'Medium', CENTER_BORDER_FORMAT)
            active_ws.write(1, 4, 'Low', CENTER_BORDER_FORMAT)
            active_ws.write(1, 5, 'Informational', CENTER_BORDER_FORMAT)
            active_ws.write(2, 0, 'Multiplier', CENTER_BORDER_FORMAT)
            active_ws.write(2, 1, 1, NUMBER_FORMAT)
            active_ws.write(2, 2, 1, NUMBER_FORMAT)
            active_ws.write(2, 3, 1, NUMBER_FORMAT)
            active_ws.write(2, 4, 1, NUMBER_FORMAT)
            active_ws.write(2, 5, 1, NUMBER_FORMAT)

            active_ws.write(4, 0, 'Index', CENTER_BORDER_FORMAT)
            active_ws.write(4, 1, 'IP Address', CENTER_BORDER_FORMAT)
            active_ws.write(4, 2, 'Total', CENTER_BORDER_FORMAT)
            active_ws.write(4, 3, 'Base Total', CENTER_BORDER_FORMAT)
            active_ws.write(4, 4, 'Temporal Total', CENTER_BORDER_FORMAT)
            active_ws.write(4, 5, 'Base Critical', CENTER_BORDER_FORMAT)
            active_ws.write(4, 6, 'Temporal Critical', CENTER_BORDER_FORMAT)
            active_ws.write(4, 7, 'Base High', CENTER_BORDER_FORMAT)
            active_ws.write(4, 8, 'Temporal High', CENTER_BORDER_FORMAT)
            active_ws.write(4, 9, 'Base Medium', CENTER_BORDER_FORMAT)
            active_ws.write(4, 10, 'Temporal Medium', CENTER_BORDER_FORMAT)
            active_ws.write(4, 11, 'Base Low', CENTER_BORDER_FORMAT)
            active_ws.write(4, 12, 'Temporal Low', CENTER_BORDER_FORMAT)

            active_ws.freeze_panes('G6')
            active_ws.autofilter('A5:P5')
            active_ws.set_column('A:A', 10)
            active_ws.set_column('B:B', 35)
            active_ws.set_column('C:C', 15)
            active_ws.set_column('D:D', 15)
            active_ws.set_column('E:E', 15)
            active_ws.set_column('F:F', 15)
            active_ws.set_column('G:G', 15)
            active_ws.set_column('H:H', 15)
            active_ws.set_column('I:I', 15)
            active_ws.set_column('J:J', 15)
            active_ws.set_column('K:K', 15)
            active_ws.set_column('L:L', 15)
            active_ws.set_column('M:M', 15)
            active_ws.set_column('N:N', 15)
            active_ws.set_column('O:O', 15)
            active_ws.set_column('P:P', 15)
            continue
        if sheet == "Device Type":
            active_ws.set_tab_color("#BDE1ED")
            active_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            active_ws.write(1, 1, 'IP Address', CENTER_BORDER_FORMAT)
            active_ws.write(1, 2, 'FQDN', CENTER_BORDER_FORMAT)
            active_ws.write(1, 3, 'NetBios Name', CENTER_BORDER_FORMAT)
            active_ws.write(1, 4, 'Device Type', CENTER_BORDER_FORMAT)
            active_ws.write(1, 5, 'Confidence', CENTER_BORDER_FORMAT)

            active_ws.freeze_panes('C3')
            active_ws.autofilter('A2:G2')
            active_ws.set_column('A:A', 10)
            active_ws.set_column('B:B', 35)
            active_ws.set_column('C:C', 15)
            active_ws.set_column('D:D', 35)
            active_ws.set_column('E:E', 25)
            active_ws.set_column('F:F', 15)
            active_ws.set_column('G:G', 15)
            continue
        if sheet == 'MS Running Process Info':
            active_ws.set_tab_color("#9EC3FF")

            active_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
            active_ws.write(1, 1, 'IP Address', CENTER_BORDER_FORMAT)
            active_ws.write(1, 2, 'FQDN', CENTER_BORDER_FORMAT)
            active_ws.write(1, 3, 'NetBios Name', CENTER_BORDER_FORMAT)
            active_ws.write(1, 4, 'Process Name & Level', CENTER_BORDER_FORMAT)

            active_ws.freeze_panes('C3')
            active_ws.autofilter('A2:E2')
            active_ws.set_column('A:A', 10)
            active_ws.set_column('B:B', 35)
            active_ws.set_column('C:C', 15)
            active_ws.set_column('D:D', 35)
            active_ws.set_column('E:E', 25)
            active_ws.set_column('F:F', 80)
            continue
        if sheet == "Plugin Counts":
            active_ws.set_tab_color("#D1B7FF")
            active_ws.autofilter('A2:C2')
            active_ws.set_column('A:A', 85)
            active_ws.set_column('B:B', 15)
            active_ws.set_column('C:C', 15)
            active_ws.write(1, 0, 'Plugin Name', CENTER_BORDER_FORMAT)
            active_ws.write(1, 1, 'Plugin ID', CENTER_BORDER_FORMAT)
            active_ws.write(1, 2, 'Total', CENTER_BORDER_FORMAT)
            active_ws.freeze_panes('A3')
            continue
        if sheet == "Graph Data":
            active_ws.write(1, 0, 'Severity', CENTER_BORDER_FORMAT)
            active_ws.write(1, 1, 'Total', CENTER_BORDER_FORMAT)
            continue
        if sheet == "Informational":
            active_ws.set_tab_color('blue')
        if sheet == "Low":
            active_ws.set_tab_color('green')
        if sheet == "Medium":
            active_ws.set_tab_color('yellow')
        if sheet == "High":
            active_ws.set_tab_color('orange')
        if sheet == "Critical":
            active_ws.set_tab_color('red')

        active_ws.write(1, 0, 'Index', CENTER_BORDER_FORMAT)
        active_ws.write(1, 1, 'IP Address', CENTER_BORDER_FORMAT)
        active_ws.write(1, 2, 'Port', CENTER_BORDER_FORMAT)
        active_ws.write(1, 3, 'Vuln Publication Date', CENTER_BORDER_FORMAT)
        active_ws.write(1, 4, 'Plugin ID', CENTER_BORDER_FORMAT)
        active_ws.write(1, 5, 'Plugin Name', CENTER_BORDER_FORMAT)
        active_ws.write(1, 6, 'Exploit Available', CENTER_BORDER_FORMAT)
        active_ws.write(1, 7, 'Exploit by Malware', CENTER_BORDER_FORMAT)
        active_ws.write(1, 8, 'CVE Information', CENTER_BORDER_FORMAT)
        active_ws.write(1, 9, 'Bugtraq ID Information', CENTER_BORDER_FORMAT)

        active_ws.freeze_panes('C3')
        active_ws.autofilter('A2:J2')
        active_ws.set_column('A:A', 10)
        active_ws.set_column('B:B', 25)
        active_ws.set_column('C:C', 15)
        active_ws.set_column('D:D', 20)
        active_ws.set_column('E:E', 15)
        active_ws.set_column('F:F', 50)
        active_ws.set_column('G:G', 35)
        active_ws.set_column('H:H', 25)
        active_ws.set_column('I:I', 25)
        active_ws.set_column('J:J', 25)
        active_ws.set_column('K:K', 25)

    active_ws = None

#########################################################################

def add_overview_data(Totals,ipaddresscount,LIGHT_FORMAT,NUMBER_FORMAT,SM_DARK_FORMAT,WRAP_TEXT_FORMAT):
    """
        Generating overview
    """
    print("\nGenerating Overview worksheet")
    active_ws = WorksheetMap['Overview']
    active_ws.insert_image('A1', 'PentestPeopleLogo.png')
    active_ws.write(5, 0, "Total IP's Scanned", LIGHT_FORMAT)
    active_ws.write(5, 1, ipaddresscount, NUMBER_FORMAT)

    # active_ws.write(6, 0, "Unique IP's Scanned", LIGHT_FORMAT) 
    # active_ws.write(6, 1, len(sorted_ips2), NUMBER_FORMAT)

    active_ws.write(7, 0, "", SM_DARK_FORMAT)
    active_ws.write(7, 1, "", SM_DARK_FORMAT)

    active_ws.write(8, 0, "Unique Critical Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(8, 1, len(COMMON_CRIT), NUMBER_FORMAT)

    active_ws.write(7, 0, "Unique High Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(7, 1, len(COMMON_HIGH), NUMBER_FORMAT)

    active_ws.write(10, 0, "Unique Medium Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(10, 1, len(COMMON_MED), NUMBER_FORMAT)

    active_ws.write(11, 0, "Unique Low Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(11, 1, len(COMMON_LOW), NUMBER_FORMAT)

    active_ws.write(12, 0, "Unique Informational Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(12, 1, len(COMMON_INFO), NUMBER_FORMAT)

    active_ws.write(13, 0, "", SM_DARK_FORMAT)
    active_ws.write(13, 1, "", SM_DARK_FORMAT)

    active_ws.write(14, 0, "Total Critical Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(14, 1, Totals['Critical'], NUMBER_FORMAT)

    active_ws.write(15, 0, "Total High Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(15, 1, Totals['High'], NUMBER_FORMAT)

    active_ws.write(16, 0, "Total Medium Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(16, 1, Totals['Medium'], NUMBER_FORMAT)

    active_ws.write(17, 0, "Total Low Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(17, 1, Totals['Low'], NUMBER_FORMAT)

    active_ws.write(18, 0, "Total Informational Vulnerabilities", LIGHT_FORMAT)
    active_ws.write(18, 1, Totals["Informational"], NUMBER_FORMAT)

    active_ws.write(19, 0, "", SM_DARK_FORMAT)
    active_ws.write(19, 1, "", SM_DARK_FORMAT)

    active_ws.write(20, 0, "Top 5 Seen Critical", LIGHT_FORMAT)
    if COMMON_CRIT:
        top_crit = sorted(COMMON_CRIT, key=lambda key:
        COMMON_CRIT[key], reverse=True)[:5]
        for crit in top_crit:
            active_ws.write(20 + top_crit.index(crit),
                            1, crit, WRAP_TEXT_FORMAT)

    active_ws.write(21, 0, "", SM_DARK_FORMAT)
    active_ws.write(21, 1, "", SM_DARK_FORMAT)

    active_ws.write(22, 0, "Top 5 Seen High", LIGHT_FORMAT)
    if COMMON_HIGH:
        top_high = sorted(COMMON_HIGH, key=lambda key:
        COMMON_HIGH[key], reverse=True)[:5]
        for high in top_high:
            active_ws.write(22 + top_high.index(high),
                            1, high, WRAP_TEXT_FORMAT)


####################################################################

def add_chart_data(data,WB):
    """
        Generation of graphs
    """
    print("\nGenerating Vulnerabilities by Severity graph")
    active_ws = WorksheetMap["Graph Data"]
    temp_cnt = 2
    for key, value in data.items():
        active_ws.write(temp_cnt, 0, key)
        active_ws.write(temp_cnt, 1, value)
        temp_cnt += 1
    active_ws.hide()
    active_ws = WorksheetMap["Graphs"]
    severity_chart = WB.add_chart({'type': 'pie'})

    # Configure Chart Data
    # Break down for range [SHEETNAME, START ROW-Header, COLUMN, END ROW, END
    # COLUMN]
    severity_chart.set_size({'width': 624, 'height': 480})
    severity_chart.add_series({
        'name': 'Total Vulnerabilities',
        'data_labels': {'value': 1},
        'categories': ["Graph Data", 2, 0, 6, 0],
        'values': ["Graph Data", 2, 1, 6, 1],
        'points': [
            #Informational
            {'fill': {'color': '#618ECD'}},
            #Low 
            {'fill': {'color': '#B2CE58'}},
            #Medium
            {'fill': {'color': '#FFD700'}},
            #High
            {'fill': {'color': '#FFA500'}},
            #Critical
            {'fill': {'color': '#B22221'}},
        ]
    })
    severity_chart.set_title({'name': 'Vulnerabilities by Severity'})
    severity_chart.set_legend({'font': {'size': 14}})

    # Set an Excel chart style. Colors with white outline and shadow.
    severity_chart.set_style(10)

    # Insert the chart into the worksheet (with an offset).
    active_ws.insert_chart('A2', severity_chart, {
        'x_offset': 25, 'y_offset': 10})

########################################################################

def add_report_data(report_data_list, the_file, NUMBER_FORMAT,WRAP_TEXT_FORMAT):
    """
        Function responsible for inserting data into the Full Report
        worksheet
    """
    print("\tInserting data into Full Report worksheet")
    # Retrieve correct worksheet from out Worksheet tracker
    report_ws = WorksheetMap['Full Report']
    # Resume inserting rows at our last unused row
    temp_cnt = RowTrack['Full Report']
    # Iterate over out VULN List and insert records to worksheet
    for reportitem in report_data_list:
        # If we have a valid Vulnerability publication date
        # lets generate the Days old cell value
        if reportitem["vuln_publication_date"] != '':
            date_format = "%Y/%m/%d"
            date_one = datetime.strptime(reportitem["vuln_publication_date"], date_format)
            date_two = datetime.strptime(str(date.today()).replace("-", "/"), date_format)
            report_ws.write(temp_cnt, 5,(date_two - date_one).days, NUMBER_FORMAT)
        else:
            report_ws.write(temp_cnt, 6, reportitem["vuln_publication_date"], NUMBER_FORMAT)
        report_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 1, reportitem['host-ip'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 2, int(reportitem["port"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 3, reportitem['host-fqdn'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 4, reportitem["vuln_publication_date"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 6, int(reportitem["severity"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 7, reportitem["risk_factor"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 8, int(reportitem["pluginID"]), NUMBER_FORMAT)
        report_ws.write(temp_cnt, 9, reportitem["pluginFamily"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 10, reportitem["pluginName"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 11, reportitem["description"], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 12, reportitem['synopsis'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 13, reportitem['plugin_output'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 14, reportitem['solution'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 15, reportitem['exploit_available'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 16, reportitem['exploitability_ease'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 17, reportitem['exploited_by_malware'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 18, reportitem['plugin_publication_date'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 19, reportitem['plugin_modification_date'], WRAP_TEXT_FORMAT)
        report_ws.write(temp_cnt, 20, reportitem['cve'], NUMBER_FORMAT)
        report_ws.write(temp_cnt, 21, reportitem['bid'], NUMBER_FORMAT)
        report_ws.write(temp_cnt, 22, reportitem['cvss_base_score'], NUMBER_FORMAT)
        report_ws.write(temp_cnt, 23, reportitem['cvss_temporal_score'], NUMBER_FORMAT)
        temp_cnt += 1
    # Save the last unused row for use on the next Nessus file
    RowTrack['Full Report'] = temp_cnt

#######################################################################


def add_cvss_info(cvss_data, the_file,WRAP_TEXT_FORMAT,NUMBER_FORMAT):
    """
        Add unique Plugin information
    """
    print("\tInserting data into CVSS worksheet")
    active_ws = WorksheetMap['CVSS Overview']
    temp_cnt = RowTrack['CVSS Overview']
    for key, value in cvss_data.items():
        active_ws.write(temp_cnt, 0, temp_cnt - 5, WRAP_TEXT_FORMAT)
        active_ws.write(temp_cnt, 1, key, WRAP_TEXT_FORMAT)
        active_ws.write(temp_cnt, 2, "=D{0}+E{1}".format(
            temp_cnt + 1, temp_cnt + 1), WRAP_TEXT_FORMAT)
        active_ws.write(temp_cnt, 3,
                        "=(B3*F{0})+(C3*H{1})+(D3*J{2})+(E3*L{3})+(F3*N{4})".format(
                            temp_cnt + 1, temp_cnt + 1, temp_cnt + 1, temp_cnt + 1, temp_cnt + 1),
                        WRAP_TEXT_FORMAT)
        active_ws.write(temp_cnt, 4,
                        "=(B3*G{0})+(C3*I{1})+(D3*K{2})+(E3*M{3})+(F3*O{4})".format(
                            temp_cnt + 1, temp_cnt + 1, temp_cnt + 1, temp_cnt + 1, temp_cnt + 1),
                        WRAP_TEXT_FORMAT)
        temp_col = 5
        for skey, svalue in value.items():  # pylint: unused-variable
            for dkey, dvalue in svalue.items():  # pylint: unused-variable
                active_ws.write(temp_cnt, temp_col, dvalue, NUMBER_FORMAT)
                temp_col += 1

        temp_cnt += 1
    RowTrack['CVSS Overview'] = temp_cnt

########################################################


def add_device_type(device_info, the_file,WRAP_TEXT_FORMAT,NUMBER_FORMAT):
    """
        Add Device Type information
    """
    print("\tInserting data into Device Type worksheet")
    device_ws = WorksheetMap['Device Type']
    temp_cnt = RowTrack['Device Type']
    for host in device_info:
        device_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 1, host['host-ip'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 2, host['host-fqdn'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 3, host['netbios-name'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 4, host['type'], WRAP_TEXT_FORMAT)
        device_ws.write(temp_cnt, 5, int(
            host['confidenceLevel']), NUMBER_FORMAT)
        temp_cnt += 1
    RowTrack['Device Type'] = temp_cnt

########################################################################


def add_vuln_info(vuln_list, the_file, WRAP_TEXT_FORMAT,NUMBER_FORMAT):
    """
        Add Vulnerability information
    """
    for key, value in Severities.items():
        print(
            "\tInserting data into {0} worksheet".format(value))
        vuln_ws = WorksheetMap[value]
        temp_cnt = RowTrack[value]
        for vuln in vuln_list:
            if not int(vuln['severity']) == key:
                continue
            if int(vuln['severity']) == 4:
                COMMON_CRIT[vuln['pluginName']] = COMMON_CRIT.get(
                    vuln['pluginName'], 0) + 1
            if int(vuln['severity']) == 3:
                COMMON_HIGH[vuln['pluginName']] = COMMON_HIGH.get(
                    vuln['pluginName'], 0) + 1
            if int(vuln['severity']) == 2:
                COMMON_MED[vuln['pluginName']] = COMMON_MED.get(
                    vuln['pluginName'], 0) + 1
            if int(vuln['severity']) == 1:
                COMMON_LOW[vuln['pluginName']] = COMMON_LOW.get(
                    vuln['pluginName'], 0) + 1
            if int(vuln['severity']) == 0:
                COMMON_INFO[vuln['pluginName']] = COMMON_INFO.get(
                    vuln['pluginName'], 0) + 1
            Totals[value] += 1
            vuln_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 1, vuln['host-ip'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 2, int(vuln['port']), NUMBER_FORMAT)
            vuln_ws.write(temp_cnt, 3, vuln[
                'vuln_publication_date'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 4, int(vuln['pluginID']), NUMBER_FORMAT)
            vuln_ws.write(temp_cnt, 5, vuln['pluginName'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 6, vuln[
                'exploit_available'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 7, vuln[
                'exploited_by_malware'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 8, vuln['cve'], WRAP_TEXT_FORMAT)
            vuln_ws.write(temp_cnt, 9, vuln['bid'], WRAP_TEXT_FORMAT)
            temp_cnt += 1
        RowTrack[value] = temp_cnt

###################################################################

def add_ms_process_info(proc_info, the_file,WRAP_TEXT_FORMAT):
    """
        Add MS Process information
    """
    print("\tInserting data into MS Process Info worksheet")
    ms_proc_ws = WorksheetMap['MS Running Process Info']
    temp_cnt = RowTrack['MS Running Process Info']
    for host in proc_info:
        for proc in host['processes'].split('\n'):
            ms_proc_ws.write(temp_cnt, 0, temp_cnt - 2, WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 1, host['host-ip'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 2, host['host-fqdn'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 3, host[
                'netbios-name'], WRAP_TEXT_FORMAT)
            ms_proc_ws.write(temp_cnt, 4, proc, WRAP_TEXT_FORMAT)
            temp_cnt += 1
    RowTrack['MS Running Process Info'] = temp_cnt

##################################################################




def add_plugin_info(plugin_count,WRAP_TEXT_FORMAT,NUMBER_FORMAT):
    """
        Add unique Plugin information
    """
    print("\nGenerating Plugin worksheet")
    active_ws = WorksheetMap['Plugin Counts']
    temp_cnt = RowTrack['Plugin Counts']
    for key, value in plugin_count.items():
        active_ws.write(temp_cnt, 0, key, WRAP_TEXT_FORMAT)
        active_ws.write(temp_cnt, 1, int(value[0]), NUMBER_FORMAT)
        active_ws.write(temp_cnt, 2, int(value[1]), NUMBER_FORMAT)
        temp_cnt += 1
    RowTrack['Plugin Counts'] = temp_cnt

def begin_parsing(file, NUMBER_FORMAT,WRAP_TEXT_FORMAT, WB, LIGHT_FORMAT,SM_DARK_FORMAT,BORDERLESS):  # pylint: disable=c-extension-no-member
    """
        Provides the initial starting point. Initiates parsing and then writes to
        the associated workbook sheets.
    """
    curr_iteration = 0
    vuln_data, device_data, ms_process_info, host_cvss, ipaddresscount = parse_nessus_file(file)
    seen_ip = 0
    count_ip_seen = 0
    count_ip_seen += seen_ip
    add_report_data(vuln_data, file, NUMBER_FORMAT,WRAP_TEXT_FORMAT )
    add_vuln_info(vuln_data, file,NUMBER_FORMAT,WRAP_TEXT_FORMAT)
    add_cvss_info(host_cvss, file,NUMBER_FORMAT,WRAP_TEXT_FORMAT)
    add_device_type(device_data, file,NUMBER_FORMAT,WRAP_TEXT_FORMAT)
    add_ms_process_info(ms_process_info, file,WRAP_TEXT_FORMAT)
   
    vuln_data = None
    device_data = None
    ms_process_info = None
    

    curr_iteration += 1
    add_chart_data(Totals, WB)
    add_plugin_info(UPluginNames,WRAP_TEXT_FORMAT, NUMBER_FORMAT)
    add_overview_data(Totals,ipaddresscount,LIGHT_FORMAT,NUMBER_FORMAT,SM_DARK_FORMAT,WRAP_TEXT_FORMAT)

#############################################################################
global count


def main(file):
    
    outputfile = ''
    
    if outputfile == '':
        inputValid3 = False
        while not inputValid3:
            inputRaw3 = input('Report Name:')
            inputRaw3 = inputRaw3.strip()
            outputfile = inputRaw3
            inputValid3 = True
    else:
        print('%sPlease add a file%s' % (fg(1), attr(0)))
    REPORT_NAME = "{0}".format(outputfile)
    
    directory = ''
    if directory == '':
        inputValid4 = False
        while not inputValid4:
            inputRaw4 = input('File Output Path in full path format e.g.: /Users/{username}/Desktop/:')
            inputRaw4 = inputRaw4.strip()
            directory = inputRaw4
            inputValid4 = True
    else:
        print('%sPlease enter a file output path%s' % (fg(1), attr(0)))
    REPORT_OUTPUT = "{0}".format(directory)

    WB = xlsxwriter.Workbook(
        '{0}{1}.xlsx'.format(REPORT_OUTPUT, REPORT_NAME), {'strings_to_urls': False, 'constant_memory': True})
    CENTER_BORDER_FORMAT = WB.add_format(
        {'bg_color': '#B0D351',
        'font_color': '#FFFFFF',
        'font_name': 'Helvetica Neue',
        'bold': True,
        'italic': True,
        'border_color': '#B0D351',
        'border': True})
    CENTER_BORDER_FORMAT.set_text_wrap()
    WRAP_TEXT_FORMAT = WB.add_format(
        {'border': True})
    WRAP_TEXT_FORMAT.set_text_wrap()
    NUMBER_FORMAT = WB.add_format(
        {'border': True, 'num_format': '0'})
    DARK_FORMAT = WB.add_format(
        {'bg_color': '#B0D351',
        'font_color': '#FFFFFF',
        'font_name': 'Helvetica Neue',
        'font_size': 22,
        'bold': 1,
        'border_color': '#B0D351',
        'border': 1,
        'align': 'center',
        'valign': 'vcenter'})
    SM_DARK_FORMAT = WB.add_format(
        {'bg_color': '#B0D351',
        'font_color': '#FFFFFF',
        'font_name': 'Helvetica Neue',
        'border_color': '#B0D351',
        'font_size': 12,
        'bold': 1,
        'border': 1})
    LIGHT_FORMAT = WB.add_format(
        {'bg_color': '#1E2330',
        'font_color': '#FFFFFF',
        'font_name': 'Helvetica Neue',
        'font_size': 12,
        'border': 1,
        'border_color': '#1E2330',
        'align': 'left',
        'valign': 'top'})

    BORDERLESS = WB.add_format(
        {'border':0})

    if IgnoreIDs:
        print(
            "\nIgnoring {0} Plugin ID's".format(len(IgnoreIDs)))
    
    generate_worksheets(WB, DARK_FORMAT, CENTER_BORDER_FORMAT, NUMBER_FORMAT)
    begin_parsing(file,NUMBER_FORMAT,WRAP_TEXT_FORMAT, WB, LIGHT_FORMAT,SM_DARK_FORMAT,BORDERLESS)
    
    WB.close()

    print("\nReport has been saved as {0}{1}.xlsx".format(REPORT_OUTPUT,REPORT_NAME))
    return (WB,WRAP_TEXT_FORMAT, NUMBER_FORMAT, DARK_FORMAT, SM_DARK_FORMAT,LIGHT_FORMAT)
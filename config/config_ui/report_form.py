def info_table(
            computerName, 
            platform, 
            installTime,
            localTimeZone, 
            ipAddr, 
            runAsUser, 
            adminRights, 
            startTime, 
            endTime,
            scanID
            ):
    html = """
            <h2>HERA Scan Report</h2>
            <table width="100%" id="info-table">
                <tr>
                    <th colspan="2">Scan Information</th>
                </tr>
                <tr>
                    <td>Scanner</td>
                    <td>Hera</td>
                </tr>
                <tr>
                    <td>Version</td>
                    <td>1</td>
                </tr>
                <tr>
                    <td>Computer Name</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Platform</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Install Time</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Local Timezone</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>IP Addresses</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Run as user</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Admin rights</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Start Time</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>End Time</td>
                    <td>{}</td>
                </tr>
                <tr>
                    <td>Scan ID</td>
                    <td>{}</td>
                </tr>
            </table>
    """.format(
            computerName, 
            platform, 
            installTime,
            localTimeZone, 
            ipAddr, 
            runAsUser, 
            adminRights, 
            startTime, 
            endTime,
            scanID
        )
    
    return html

def malware_table(malware_instances):

    html = """
    <table width="100%" id="malwares-table">
        <tbody>
            <tr>
                <th id="Malwares" colspan="2">Malware</th>
            </tr>
    """

    for index, malware in enumerate(malware_instances):
        html += """
            <tr>
                <td class="malware-key">
                    <div>Malware {}</div>
                </td>
                <td class="value">
                    <div class="field-group">
                        <pre>{}</pre>
                    </div>
                </td>
            </tr>
        """.format(index+1, malware.display())

    html += """
        </tbody>
    </table>
    """
    return html

def high_alert_table(eventlog):

    html = """
    <table width="100%" id="alert-table">
        <tbody>
            <tr>
                <th id="Alert" colspan="2">Alert</th>
            </tr>
    """
    list = []
    for event in eventlog:
        s = ""
        for key in event:
            s += f"{key}: {event[key]}\n"
        list.append(s)

    for index, i in enumerate(list):
        html += """
            <tr>
                <td class="alert-key">
                    <div>Alert {}</div>
                </td>
                <td class="value">
                    <div class="field-group">
                        <pre>{}</pre>
                    </div>
                </td>
            </tr>
        """.format(index+1, i)

    html += """
        </tbody>
    </table>
    """
    return html

def sus_files_table(files):

    html = """
    <table width="100%" id="files-table">
        <tbody>
            <tr>
                <th id="Files" colspan="2">Suspicious files</th>
            </tr>
    """
    list = []
    for file in files:
        s = ""
        for key in file:
            s += f"{key}: {file[key]}\n"
        list.append(s)

    for index, i in enumerate(list):
        html += """
            <tr>
                <td class="file-key">
                    <div>Suspicious File {}</div>
                </td>
                <td class="value">
                    <div class="field-group">
                        <pre>{}</pre>
                    </div>
                </td>
            </tr>
        """.format(index+1, i)

    html += """
        </tbody>
    </table>
    """
    return html


def report_form(
            computerName, 
            platform, 
            installTime,
            localTimeZone, 
            ipAddr, 
            runAsUser, 
            adminRights, 
            startTime, 
            endTime,
            scanID,
            malware_instances,
            log_high_alert,
            sus_files
        ):
    html_content = '''
    <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Report Form</title>
                <style>
                    table {
                        border-collapse: collapse;
                        width: 100%;
                        margin-top: 20px;
                    }
                    th, td {
                        border: 1px solid #dddddd;
                        text-align: left;
                        padding: 8px;
                        min-width: 100px;
                    }
                    th {
                        background-color: #f2f2f2;
                    }
                </style>
            </head>
            <body>
    '''
    html_content += info_table(
                        computerName, 
                        platform, 
                        installTime,
                        localTimeZone, 
                        ipAddr, 
                        runAsUser, 
                        adminRights, 
                        startTime, 
                        endTime,
                        scanID
                    )
    html_content += malware_table(malware_instances)
    html_content += high_alert_table(log_high_alert)
    html_content += sus_files_table(sus_files)
    html_content += '''
            </body>
        </html>    
    '''
    report_file = scanID + ".html"
    with open(report_file, "w", encoding="utf-8") as html_file:
        html_file.write(html_content)

    print("Done!!! Report is saved in " + report_file)

def report_form(
            computerName, 
            platform, 
            installTime, 
            ipAddr, 
            runAsUser, 
            adminRights, 
            startTime, 
            endTime,
            scanID
            ):
    html_content = """
    <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="X-UA-Compatible" content="IE=edge">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Report Form</title>
            <style>
                table {{
                    border-collapse: collapse;
                    width: 50%;
                    margin-top: 20px;
                }}
                th, td {{
                    border: 1px solid #dddddd;
                    text-align: left;
                    padding: 8px;
                }}
                th {{
                    background-color: #f2f2f2;
                }}
            </style>
        </head>
        <body>
            <h2>HERA Scan Report</h2>

            <table>
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

                <!-- More -->
            </table>
        </body>
        </html>
    """.format(
            computerName, 
            platform, 
            installTime, 
            ipAddr, 
            runAsUser, 
            adminRights, 
            startTime, 
            endTime,
            scanID
        )

    report_file = scanID + ".html"
    with open(report_file, "w") as html_file:
        html_file.write(html_content)

    print("Done!!! Report is saved in" + report_file)
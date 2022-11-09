# -*- coding: utf-8 -*-
import sys
import base64
from argparse import Namespace
from datetime import date, timedelta
import json
import requests
import os
import datetime
import subprocess
from urllib import parse
from shutil import which

from gvm.protocols.gmp import Gmp
from lxml.etree import Element
from terminaltables import AsciiTable


def error(*args):
    for arg in args:
        print(arg, end=" ")
    print()
    sys.exit(-1)


def check_args(args: Namespace) -> None:
    len_args = len(args.script) - 1
    if len_args < 5:
        message = """
        This script will download  report in CSV format
        for given month

        1. <day>    -- day of the report
        2. <month>  -- month of the report
        3. <year>   -- year of the report
        4. <DefectDojo API token>
        5. <DefectDojo base URL>

        Example:
            $ gvm-script --gmp-username name --gmp-password pass \
    ssh --hostname <gsm> scripts/monthly-report.gmp.py 01 11 2022 http://dd.example.com 0123456789abcdef
        """
        error(message)


def get_reports_xml(gmp: Gmp, from_date: date, to_date: date) -> Element:
    """Getting the Reports in the defined time period"""

    report_filter = (
        f"rows=-1 created>{from_date.isoformat()} and "
        f"created<{to_date.isoformat()}"
    )

    return gmp.get_reports(filter_string=report_filter)


def save_csv(gmp: Gmp, reports_xml: Element) -> None:
    report_list = reports_xml.xpath("report")

    format_id = None
    formats = gmp.get_report_formats()
    for format in formats.xpath("report_format"):
        format_id = format.xpath("@id")[0]
        name = format.xpath("name/text()")[0]
        if name == "CSV Results":
            break

    if not format_id:
        error("CSV format was not found, exiting")

    reports = []
    for report in report_list:
        report_id = report.xpath("report/@id")[0]
        name = report.xpath("name/text()")[0]
        task = report.xpath("task/name/text()")[0].strip()

        report_filter = (
            f"first=1 rows=-1 apply_overrides=1 notes=1 sort-reverse=severity"
        )

        res = gmp.get_report(report_id, report_format_id=format_id, filter_string=report_filter)

        csv = res.xpath("report/text()")[0]
        csv = base64.b64decode(csv)
        with open('%s.csv' % report_id, 'wb') as f:
            f.write(csv)
            reports.append([report_id, task])
    return reports


def find_product_by_project_name(dd_base_url, dd_auth_token, project_name):
    url = dd_base_url + '/api/v2/products/?' + parse.urlencode({"name": project_name})
    headers = {
        "accept": "application/json",
        "Authorization": "Token " + dd_auth_token,
        "Content-Type": "application/json",
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        if response.json()["count"] == 0:
            error("Error: no products found matching '", project_name, "'")
    else:
        error("Error: failure while retreiving product with name", project_name, "\n", response)

    return response.json()["results"][0]["id"]


def create_ad_hoc_engagement(dd_base_url, dd_auth_token, product_id):
    url = dd_base_url + '/api/v2/engagements/'
    headers = {
        "accept": "application/json",
        "Authorization": "Token " + dd_auth_token,
        "Content-Type": "application/json",
    }

    date = datetime.datetime.now()
    engagement_title="AdHoc Import from OpenVAS - " + date.strftime("%a, %d %b %Y %H:%M:%S")
    data = json.dumps({
      "tags": [],
      "name": engagement_title,
      "description": None,
      "version": "",
      "first_contacted": None,
      "target_start": date.strftime("%F"),
      "target_end": date.strftime("%F"),
      "reason": None,
      "active": True,
      "tracker": None,
      "test_strategy": None,
      "threat_model": False,
      "api_test": False,
      "pen_test": False,
      "check_list": False,
      "status": "Completed",
      "engagement_type": "Interactive",
      "build_id": "",
      "commit_hash": "",
      "branch_tag": "",
      "source_code_management_uri": None,
      "deduplication_on_engagement": False,
      "lead": None,
      "requester": None,
      "preset": None,
      "report_type": None,
      "product": product_id,
      "build_server": None,
      "source_code_management_server": None,
      "orchestration_engine": None
    })

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 201:
        return response.json()["id"]
    else:
        error("Error: failure while creating engagement", response)


def upload_scan_findings(dd_base_url, dd_auth_token, engagement_id, report_file_path):
    date = datetime.datetime.now()
    process = subprocess.Popen([
        "curl", "-sS", "-X", "POST", dd_base_url + "/api/v2/import-scan/",
        "-H",  "Authorization: Token " + dd_auth_token,
        "-H",  "Content-Type: multipart/form-data",
        "-F",  "scan_date="+date.strftime("%F"),
        "-F",  "minimum_severity=Info",
        "-F",  "active=true",
        "-F",  "verified=true",
        "-F",  "scan_type=OpenVAS CSV",
        "-F",  "file=@"+report_file_path+".csv",
        "-F",  "engagement="+str(engagement_id),
        "-F",  "close_old_findings=false",
        "-F",  "push_to_jira=false"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    error = stderr.decode("utf-8").strip()
    output = stdout.decode("utf-8").strip()
    if output != "":
        js_out = json.loads(output)
        return js_out["test"]
    else:
        error("Error: failure while uploading scan results to Defect Dojo\n", error)


def parse_json(json_input):
    try:
        data = json_input.read()
        try:
            json_element = json.loads(str(data, 'utf-8'))
        except:
            json_element = json.loads(data)
    except:
        raise Exception("Invalid format")

    return json_element


def is_curl_installed():
    return which("curl") is not None


def is_dd_server_reachable(dd_base_url):
    try:
        response = requests.get(dd_base_url + "/api/v2/")
        if response.status_code != 200:
            raise Exception()
    except:
        error("Error: Defect Dojo is not reachable")


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=undefined-variable

    check_args(args)

    day = int(args.script[1])
    month = int(args.script[2])
    year = int(args.script[3])
    from_date = date(year, month, day)
    to_date = from_date + timedelta(days=1)

    dd_base_url = args.script[4]
    dd_auth_token = args.script[5]

    reports_xml = get_reports_xml(gmp, from_date, to_date)
    reports = save_csv(gmp, reports_xml)
    print(reports)

    if is_curl_installed():

        is_dd_server_reachable(dd_base_url)

        for report in reports:
            project_name = report[1]
            report_path = report[0]
            product_id = find_product_by_project_name(dd_base_url, dd_auth_token, project_name)
            print("Fetching for product matching project name:", project_name)
            if product_id != None:
                print("Found product (ID: " + str(product_id) + ")")
                engagement_id = create_ad_hoc_engagement(dd_base_url, dd_auth_token, product_id)
                if engagement_id != None:
                    print("Created new AdHoc import engagement (ID: " + str(engagement_id) + ")")
                    test_id = upload_scan_findings(dd_base_url, dd_auth_token, engagement_id, report_path)
                    if test_id != None:
                        print("Imported findigs to test (ID: " + str(test_id) + ")")
            os.remove("%s.csv" % report_path)
    else:
        error("Error: curl was not found, please install it")


if __name__ == "__gmp__":
    main(gmp, args)

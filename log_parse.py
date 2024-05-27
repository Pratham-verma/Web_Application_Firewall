import xml.etree.ElementTree as ET
import urllib.parse
import base64
import os
import csv

log_path = 'bad_request.log'
output_csv_log = '2bad_req.csv'
class_flag = "bad"


class LogParse:
    badwords = ['sleep', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by', 'admin',
                'drop', 'script']

    @staticmethod
    def extract_features(method, path_enc, body_enc, headers):
        # Count percentages, spaces, and special characters in the raw (encoded) URL and body
        combined_raw = path_enc + body_enc
        raw_percentages = combined_raw.count("%")
        raw_spaces = combined_raw.count(" ")
        raw_special_chars = sum(combined_raw.count(c) for c in '$&|')

        # Decode the path and body for other feature extractions
        path = urllib.parse.unquote_plus(path_enc)
        body = urllib.parse.unquote_plus(body_enc)

        single_q = path.count("'") + body.count("'")
        double_q = path.count("\"") + body.count("\"")
        dashes = path.count("--") + body.count("--")
        braces = path.count("(") + body.count("(")
        spaces = path.count(" ") + body.count(" ")
        semicolons = path.count(";") + body.count(";")
        angle_brackets = path.count("<") + path.count(">") + body.count("<") + body.count(">")

        badwords_count = sum(path.lower().count(word) + body.lower().count(word) for word in LogParse.badwords)
        badwords_count += sum(headers[header].lower().count(word) for header in headers for word in LogParse.badwords)

        # Check if all counts exceed the threshold
        if raw_percentages > 3 and raw_spaces > 3 and raw_special_chars > 3:
            raw_percentages_count = raw_percentages
            raw_spaces_count = raw_spaces
            raw_special_chars_count = raw_special_chars
        else:
            raw_percentages_count = 0
            raw_spaces_count = 0
            raw_special_chars_count = 0

        path_length = len(path)
        body_length = len(body)

        return [method, path_enc, body_enc, single_q, double_q, dashes, braces, spaces, raw_percentages_count,
                semicolons, angle_brackets, raw_special_chars_count, path_length, body_length, badwords_count,
                class_flag]


def parse_log(log_path):
    result = {}
    if not os.path.exists(log_path):
        print("[+] Error!!!", log_path, "doesn't exist..")
        exit()

    try:
        tree = ET.parse(log_path)
    except Exception as e:
        print(
            '[+] Oops..! Please make sure binary data is not present in Log, like raw image dump, flash (.swf files) '
            'dump etc.')
        exit()

    root = tree.getroot()
    for reqs in root.findall('item'):
        raw_req = reqs.find('request').text
        raw_req = urllib.parse.unquote(raw_req)
        raw_resp = reqs.find('response').text
        result[raw_req] = raw_resp
    return result


def parse_raw_http_req(rawreq):
    try:
        raw = rawreq.decode('utf8')
    except Exception:
        raw = rawreq

    headers = {}
    sp = raw.split('\r\n\r\n', 1)
    if len(sp) > 1:
        head = sp[0]
        body = sp[1]
    else:
        head = sp[0]
        body = ""

    c1 = head.split('\n', head.count('\n'))
    request_line = c1[0].split(' ')
    method = request_line[0]
    path = request_line[1]
    http_version = request_line[2] if len(request_line) > 2 else "HTTP/1.0"

    for i in range(1, head.count('\n') + 1):
        slice1 = c1[i].split(': ', 1)
        if len(slice1) == 2:
            headers[slice1[0]] = slice1[1]
    return headers, method, body, path, http_version


# Write header to CSV file
with open(output_csv_log, 'w', newline='') as f:
    c = csv.writer(f)
    c.writerow(
        ["method", "path", "body", "single_q", "double_q", "dashes", "braces", "spaces", "percentages", "semicolons",
         "angle_brackets", "special_chars", "path_length", "body_length", "badwords_count", "class"])

# Parse the log and write the data to the CSV file
result = parse_log(log_path)

with open(output_csv_log, 'a', newline='') as f:
    c = csv.writer(f)
    for items in result:
        raw_req = base64.b64decode(items)
        headers, method, body, path, http_version = parse_raw_http_req(raw_req)
        features = LogParse.extract_features(method, path, body, headers)
        c.writerow(features)

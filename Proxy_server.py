from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib import request, error, parse
import numpy as np
import pandas as pd
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

badwords = ['sleep', 'uid', 'select', 'waitfor', 'delay', 'system', 'union', 'order by', 'group by', 'admin', 'drop',
            'script']


# Define the ExtractFeatures function outside the class
def ExtractFeatures(path, body):
    path = str(path)
    body = str(body)
    combined_raw = path + body
    raw_percentages = combined_raw.count("%")
    raw_spaces = combined_raw.count(" ")

    # Check if both counts exceed the threshold
    raw_percentages_count = raw_percentages if raw_percentages > 3 else 0
    raw_spaces_count = raw_spaces if raw_spaces > 3 else 0

    # Decode the path and body for other feature extractions
    path_decoded = urllib.parse.unquote_plus(path)
    body_decoded = urllib.parse.unquote_plus(body)

    single_q = path_decoded.count("'") + body_decoded.count("'")
    double_q = path_decoded.count("\"") + body_decoded.count("\"")
    dashes = path_decoded.count("--") + body_decoded.count("--")
    braces = path_decoded.count("(") + body_decoded.count("(")
    spaces = path_decoded.count(" ") + body_decoded.count(" ")
    semicolons = path_decoded.count(";") + body_decoded.count(";")
    angle_brackets = path_decoded.count("<") + path_decoded.count(">") + body_decoded.count("<") + body_decoded.count(
        ">")
    special_chars = sum(path_decoded.count(c) + body_decoded.count(c) for c in '$&|')

    badwords_count = sum(path_decoded.lower().count(word) + body_decoded.lower().count(word) for word in badwords)

    path_length = len(path_decoded)
    body_length = len(body_decoded)

    return [single_q, double_q, dashes, braces, spaces, raw_percentages_count, semicolons, angle_brackets,
            special_chars, path_length, body_length, badwords_count]


# Define the SimpleHTTPProxy class
class SimpleHTTPProxy(SimpleHTTPRequestHandler):
    proxy_routes = {}

    @classmethod
    def set_routes(cls, proxy_routes):
        cls.proxy_routes = proxy_routes

    def do_GET(self):
        parts = self.path.split('/')
        print(parts)
        if len(parts) > 3:
            path_part = parts[3]
            body = ""  # GET requests typically do not have a body
            live_data = ExtractFeatures(path_part, body)
            live_data = np.array(live_data).reshape(1, -1)  # Reshape for single prediction

            # Load the model inside the request handler
            with open('training_model.pkl', 'rb') as file:
                model = pickle.load(file)

            result = model.predict(live_data)  # Use the trained model for prediction
            print(result[0])
            if result[0] == 1:
                print('Intrusion Detected')

        if len(parts) >= 2:
            self.proxy_request('http://' + parts[2] + '/')
        else:
            super().do_GET()

    def proxy_request(self, url):
        try:
            response = request.urlopen(url)
        except error.HTTPError as e:
            print('err')
            self.send_response_only(e.code)
            self.end_headers()
            return
        self.send_response_only(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.copyfile(response, self.wfile)


# Set up and start the server
SimpleHTTPProxy.set_routes({'proxy_route': 'http://demo.testfire.net/'})
with HTTPServer(('127.0.0.1', 8080), SimpleHTTPProxy) as httpd:  # Correct reference to HTTPServer
    host, port = httpd.socket.getsockname()
    print(f'Listening on http://{host}:{port}')
    try:
        httpd.serve_forever()  # Corrected from serveforever to serve_forever
    except KeyboardInterrupt:  # Corrected from keyboardInterrupt to KeyboardInterrupt
        print("\nKeyboard interrupt received, exiting.")
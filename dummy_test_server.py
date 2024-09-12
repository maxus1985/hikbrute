from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ISAPI/Security/sessionLogin/capabilities', methods=['GET'])
def handle_capabilities():
    # Get JSON data from the POST request
    data = request.data

    # You can process the data here. For now, just print it
    print(f"Received data: {data}")


    resp  ="""<?xml version="1.0" encoding="UTF-8"?>
<SessionLoginCap version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
<sessionID>4afe0f018406ceaf0308</sessionID>
<challenge>00e7513c0348fc7ca099088aa3f6546b</challenge>
<iterations>100</iterations>
<isIrreversible>true</isIrreversible>
<salt>1481d8a86722797e30be1d9f491ee53233492d5ccf29df0bee5a00dbb14cfa79</salt>
</SessionLoginCap>"""

    return resp, 200

@app.route('/ISAPI/Security/sessionLogin', methods=['POST'])
def handle_login():
    # Get JSON data from the POST request
    data = request.data

    # You can process the data here. For now, just print it
    print(f"Received data: {data}")

    # Respond with a JSON message
    resp  ="""<?xml version="1.0" encoding="UTF-8"?>
<SessionLoginCap version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">

</SessionLoginCap>"""

    return resp, 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)

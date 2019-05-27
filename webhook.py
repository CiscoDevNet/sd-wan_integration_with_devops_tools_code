from flask import Flask, request, jsonify
import json
import os

app = Flask(__name__)

@app.route('/',methods=['POST'])
def alarms():
   try:
      data = json.loads(request.data)
      print(data)
   except Exception as exc:
      return jsonify(str(exc)), 500
   
   return jsonify("OK"), 200

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5001, debug=True)

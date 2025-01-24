import json
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/", methods=["POST"])
def process():
    try:
        data = request.get_json()
        if not isinstance(data, dict):
             return Response("Invalid JSON format", status=400)
        name = data.get("name")
        age = data.get("age")

        if not isinstance(name, str):
            return Response("Invalid name", status=400)

        if not isinstance(age, int):
              return Response("Invalid age", status=400)


        response_data = {"message": f"Hello {name}, you are {age} years old."}
        return Response(json.dumps(response_data), mimetype='application/json', status=200)

    except Exception as e:
       return Response(f"An error occurred: {str(e)}", status=500)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')
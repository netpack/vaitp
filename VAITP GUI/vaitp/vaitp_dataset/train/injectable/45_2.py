
import io
from PIL import Image
from flask import Flask, request, send_file, abort, make_response, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/', methods=['POST'])
def process_image():
    if 'image' not in request.files:
        return make_response(jsonify({'error': 'no image provided'}), 400)

    image_file = request.files['image']
    filename = secure_filename(image_file.filename)
    if filename == '':
        return make_response(jsonify({'error': 'bad filename'}), 400)

    try:
        img = Image.open(image_file)
        img.thumbnail((128, 128))
        img_buffer = io.BytesIO()
        img.save(img_buffer, format="JPEG")
        img_buffer.seek(0)
        return send_file(img_buffer, mimetype='image/jpeg')
    except:
        return make_response(jsonify({'error': 'error processing image'}), 400)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)
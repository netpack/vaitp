from flask import Flask, request
import json

app = Flask(__name__)

# Simulated database of CPEs
CPE_DATABASE = {
    "1": "CPE 1",
    "2": "CPE 2",
    "3": "CPE 3"
}

@app.route('/live/CPEManager/AXCampaignManager/delete_cpes_by_ids', methods=['DELETE'])
def delete_cpes_by_ids():
    cpe_ids_str = request.args.get('cpe_ids')
    
    if not cpe_ids_str:
        return {"status": "error", "message": "cpe_ids parameter missing"}, 400

    try:
        delete_ids = json.loads(cpe_ids_str)
        if not isinstance(delete_ids, list):
             return {"status": "error", "message": "cpe_ids must be a json list"}, 400
    except json.JSONDecodeError:
         return {"status": "error", "message": "Invalid cpe_ids json format"}, 400

    # Proceed with deletion of CPEs
    deleted_ids = []
    for cpe_id in delete_ids:
        if str(cpe_id) in CPE_DATABASE:
            del CPE_DATABASE[str(cpe_id)]
            deleted_ids.append(cpe_id)

    return {"status": "success", "deleted_ids": deleted_ids}, 200

if __name__ == '__main__':
    app.run(debug=True)
import json
from flask import Flask, request, abort

app = Flask(__name__)

# Simulated database of CPEs
CPE_DATABASE = {
    "1": "CPE 1",
    "2": "CPE 2",
    "3": "CPE 3"
}

@app.route('/live/CPEManager/AXCampaignManager/delete_cpes_by_ids', methods=['DELETE'])
def delete_cpes_by_ids():
    cpe_ids = request.args.get('cpe_ids')
    
    if not cpe_ids:
        abort(400, "Missing cpe_ids parameter")

    # Validate input to prevent eval injection
    try:
        cpe_ids_list = json.loads(cpe_ids)
        if not isinstance(cpe_ids_list, list) or not all(isinstance(i, str) for i in cpe_ids_list):
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        abort(400, "Invalid cpe_ids format. Must be a JSON array of strings.")

    # Proceed with deletion of CPEs
    for cpe_id in cpe_ids_list:
        if cpe_id in CPE_DATABASE:
            del CPE_DATABASE[cpe_id]

    return json.dumps({"status": "success", "deleted_ids": cpe_ids_list}), 200

if __name__ == '__main__':
    app.run()
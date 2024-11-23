from flask import Flask, request

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
    
    # Directly using eval on user input (vulnerable code)
    eval("delete_ids = " + cpe_ids)

    # Proceed with deletion of CPEs
    for cpe_id in delete_ids:
        if cpe_id in CPE_DATABASE:
            del CPE_DATABASE[cpe_id]

    return {"status": "success", "deleted_ids": delete_ids}, 200

if __name__ == '__main__':
    app.run()
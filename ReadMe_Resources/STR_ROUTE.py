@app.route("/employee/<string:name>", methods=["GET"])
@admin_required()
def get_employee(name):
    try:
        # Query by name (case-sensitive)
        emp = Employee_login.query.filter_by(name=name).first()

        if not emp:
            return jsonify({"error": f"No employee found with name '{name}'"}), 404

        # Example: return employee data as JSON
        return jsonify({
            "id": emp.id,
            "name": emp.name,
            "email": emp.email
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

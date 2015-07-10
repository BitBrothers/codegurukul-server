var Lead = require("../models/Lead.js");

exports.addLead = function (leadData) {
	console.log(leadData);
	var lead = new Lead({
		name: leadData.name,
		email: leadData.email
	});
	lead.courses.push(leadData.course);
	lead.save(function (err, lead) {
		if (err) console.log(err);
		else {
			console.log("lead added");
		}
	})
}
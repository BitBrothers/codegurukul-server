var request = require('request');
var secret = require('../config/secrets');
var config = new secret();
var User = require('../models/User');

var auth = config.razorpay.id + ':' + config.razorpay.secret;

exports.verifyPay = function(req,res,next){
	// console.log(req.body);
	var url = 'https://'+auth+'@api.razorpay.com/v1/payments/'+req.body.payment_id;
	request(url, function (error, response, body) {
		if(error)
			res.status(412).send(error);
		else{
			// console.log('Response:', JSON.parse(body));
			var data = JSON.parse(body);
			console.log(data);
			if (data.status == "failed") {
				return res.status(400).send("There was an error with your transaction")
			} else {
				if(data.id == req.body.payment_id){
					User.findById(req.user._id,function(err, user){
						if(err)
							res.send(err);
						else if(!user){
							res.status(404).send('User Not Found');
						}
						else{
							req.pay = true;
							next();
						}
					});
				}
				else{
					res.status(412).send('Id didnt Match');
				}
			}
		}

	});
};

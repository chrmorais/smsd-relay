INSERT INTO feeds (name, keyword, method, url) VALUES ('default', '', 'GET', 'http://localhost:8080/resources/SMS/Inlet/other/Post/Push?phoneNumber=%%phone%%&messageText=%%text%%&timeStamp=%%time%%');
INSERT INTO feeds (name, keyword, method, url) VALUES ('geo', 'geo', 'POST', 'http://localhost:5000/sms_feeds/');

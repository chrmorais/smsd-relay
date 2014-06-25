INSERT INTO feeds (name, keyword, method, url) VALUES ('default', '', 'POST', 'http://localhost:9056/ingest/sms/feed/?phone=<<phone>>&text=<<text>>&time=<<time>>&pass=fill_in');
INSERT INTO feeds (name, keyword, method, url) VALUES ('geo', 'geo', 'POST', 'http://localhost:9056/ingest/sms/feed/?feed=<<feed>>&phone=<<phone>>&text=<<text>>&time=<<time>>&pass=fill_in');

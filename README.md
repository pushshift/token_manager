# Purpose

Token Manager is used to coordinate the use of many Twitter user auth access keys so that they can be pooled together and treated as one large request pool.

This can be expanded to include worker threads or processes to make many calls to the Twitter API using a pool of user keys.

Token Manager keeps track of rate-limit data per key per API endpoint.
/**
 * Use known-working signature generation code to output signatures to be
 * expected in Tests.
 */

var crypto = require('crypto');

var base64url = 'HKYdFdnezle2yrI2_Ph3cHz144bISk-cvuAbeAAA999';
var key = new Buffer(base64url.replace(/_/g,'/').replace(/-/g,'+'), 'base64');
var hmac = crypto.createHmac('sha256', key);
hmac.update('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiYXIiLCJpc3MiOiJleGFtcGxlLmNvbSIsImRuIjoiQm9iIiwiZyI6W119');
console.log(hmac.digest('base64'));

hmac = crypto.createHmac('sha256', key);
hmac.update('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiYXIiLCJpc3MiOiJleGFtcGxlLmNvbSIsImRuIjoiQm9iIiwiZyI6W3siaWQiOjEyMzQsImRuIjoiR3JvdXAgMTIzNCJ9LHsiaWQiOjQyLCJkbiI6Ik1lYW5pbmcgR3JvdXAifV19');
console.log(hmac.digest('base64'));

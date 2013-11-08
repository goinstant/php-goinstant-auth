/**
 * Use known-working signature generation code to output signatures to be
 * expected in Tests.
 */

var crypto = require('crypto');

var base64url = 'HKYdFdnezle2yrI2_Ph3cHz144bISk-cvuAbeAAA999';
var key = new Buffer(base64url.replace(/_/g,'/').replace(/-/g,'+'), 'base64');
var hmac = crypto.createHmac('sha256', key);
hmac.update('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJnb2luc3RhbnQubmV0Iiwic3ViIjoiYmFyIiwiaXNzIjoiZXhhbXBsZS5jb20iLCJkbiI6IkJvYiIsImciOltdfQ');
console.log(hmac.digest('base64'));

hmac = crypto.createHmac('sha256', key);
hmac.update('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJnb2luc3RhbnQubmV0Iiwic3ViIjoiYmFyIiwiaXNzIjoiZXhhbXBsZS5jb20iLCJkbiI6IkJvYiIsImciOlt7ImlkIjoxMjM0LCJkbiI6Ikdyb3VwIDEyMzQifSx7ImlkIjo0MiwiZG4iOiJNZWFuaW5nIEdyb3VwIn1dfQ');
console.log(hmac.digest('base64'));

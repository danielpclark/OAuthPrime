
 -*- NOTE! According to one source oauth_signature uses DOUBLE
     encoded signature_string_base ALTHOUGH I have not been
     seeing evidence of this in sample strings.  Yahoo seems
     to DOUBLE encode for it's HMAC-SHA1 signature.  I have a
     feeling the double encoding is done just before the sha1
     generator.  It is possible it may need to vary depending
     on the website.  I plan to have rulesets added to known
     domains and their spec requirements as a built in feature.

 -*- Useful generator link
     http://oauth.googlecode.com/svn/code/javascript/example/signature.html
     and
     https://dev.twitter.com/apps/6083963/oauth

 -*- Details
     http://oauthbible.com/

 -*- Base string and url to submit are not the same thing.
     It's primarily for generating the signature.
     ANSWER AT http://oauth.net/core/1.0/#rfc.section.A.5.1

 -*- Signature is not passing.  I need to find the appropriate
     signature generation method.